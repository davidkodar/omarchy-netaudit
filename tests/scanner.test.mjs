// Run with: node --test tests/
// Nothing here touches the network beyond a mock router on 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  isPrivateGateway, classifySecurity, terseFields, xmlValue, findMappingService, readMappingTable,
  redactIPv4, scoreChecks, buildFindings, facts, changedFacts, describeChange, parseArgs,
} from '../scanner/scanner.mjs';

test('only private IPv4 gateways are accepted', () => {
  for (const ip of ['10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.1.1']) assert.equal(isPrivateGateway(ip), true, ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '192.169.1.1', '100.64.0.1', '999.1.1.1', 'fe80::1', '', undefined, '192.168.1']) {
    assert.equal(isPrivateGateway(ip), false, String(ip));
  }
});

test('no option accepts a target', () => {
  for (const arg of ['--host', '--target', '10.0.0.1', '--ip']) assert.throws(() => parseArgs([arg, '10.0.0.1']), /accepts no target/);
  assert.throws(() => parseArgs(['--dns', 'maybe']));
  assert.equal(parseArgs([]).dns, 'auto');
});

test('Wi-Fi security is classified', () => {
  assert.equal(classifySecurity('WPA2 WPA3'), 'strong');
  assert.equal(classifySecurity('WPA3'), 'strong');
  assert.equal(classifySecurity('WPA1 WPA2'), 'strong');
  assert.equal(classifySecurity('WPA1'), 'weak');
  assert.equal(classifySecurity('WEP'), 'weak');
  assert.equal(classifySecurity(''), 'weak');
  assert.equal(classifySecurity('--'), 'weak');
  assert.equal(classifySecurity('802.1X'), 'review');
});

test('nmcli terse lines split, with colons kept in the network name', () => {
  assert.deepEqual(terseFields('*:36:WPA2 WPA3:Home', 3), ['*', '36', 'WPA2 WPA3', 'Home']);
  assert.deepEqual(terseFields(' :1:WPA2:My\\:Net:5G', 3), [' ', '1', 'WPA2', 'My:Net:5G']);
  assert.deepEqual(terseFields(' :6::', 3), [' ', '6', '', '']);
});

test('addresses are redacted', () => {
  assert.equal(redactIPv4('192.168.1.25'), '192.168.1.x');
  assert.equal(redactIPv4('not an address'), '<redacted>');
  assert.equal(redactIPv4(''), '<redacted>');
});

const DESCRIPTION = (control) => `<?xml version="1.0"?><root><device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>${control}</controlURL></service>
</serviceList></device></root>`;

test('the mapping service must live on the gateway itself', () => {
  const found = findMappingService(DESCRIPTION('/ctl/IPConn'), 'http://192.168.1.1:5000/rootDesc.xml', '192.168.1.1');
  assert.equal(found.control, 'http://192.168.1.1:5000/ctl/IPConn');
  assert.equal(found.type, 'urn:schemas-upnp-org:service:WANIPConnection:1');
  // A description that points at another host is not followed.
  assert.equal(findMappingService(DESCRIPTION('http://203.0.113.9/ctl'), 'http://192.168.1.1:5000/rootDesc.xml', '192.168.1.1'), null);
  assert.equal(findMappingService(DESCRIPTION('https://192.168.1.1/ctl'), 'http://192.168.1.1:5000/rootDesc.xml', '192.168.1.1'), null);
  assert.equal(findMappingService('<root/>', 'http://192.168.1.1:5000/rootDesc.xml', '192.168.1.1'), null);
});

test('xml values are read with or without a namespace prefix', () => {
  assert.equal(xmlValue('<a><NewExternalPort>8080</NewExternalPort></a>', 'NewExternalPort'), '8080');
  assert.equal(xmlValue('<s:x><u:errorCode> 714 </u:errorCode></s:x>', 'errorCode'), '714');
  assert.equal(xmlValue('<a/>', 'missing'), '');
});

// A mock router: serves the given entries, then the given fault.
function mockRouter(entries, fault = 714) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.push({ action: req.headers.soapaction, body });
      const index = Number(/<NewPortMappingIndex>(\d+)</.exec(body)?.[1]);
      const e = entries[index];
      if (!e) {
        res.writeHead(500, { 'Content-Type': 'text/xml' });
        res.end(`<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>${fault}</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>`);
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/xml' });
      res.end(`<s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse>
<NewRemoteHost>${e.remote ?? ''}</NewRemoteHost><NewExternalPort>${e.ext}</NewExternalPort><NewProtocol>${e.proto}</NewProtocol>
<NewInternalPort>${e.int}</NewInternalPort><NewInternalClient>${e.client}</NewInternalClient><NewEnabled>1</NewEnabled>
<NewPortMappingDescription>${e.description}</NewPortMappingDescription></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>`);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    seen,
    service: { type: 'urn:schemas-upnp-org:service:WANIPConnection:1', control: `http://127.0.0.1:${server.address().port}/ctl` },
    close: () => new Promise((done) => server.close(done)),
  })));
}

test('the mapping table is read to its end and sanitized', async () => {
  const router = await mockRouter([
    { ext: 8080, int: 80, proto: 'TCP', client: '192.168.1.25', description: 'Living room <b>TV</b>' },
    { ext: 3074, int: 3074, proto: 'udp', client: '192.168.1.40', description: 'Console', remote: '203.0.113.7' },
  ]);
  try {
    const table = await readMappingTable(router.service, '192.168.1.25');
    assert.equal(table.length, 2);
    assert.deepEqual(table[0], {
      label: '<mapping-1>', protocol: 'TCP', externalPort: 8080, internalPort: 80, internalHost: '192.168.1.x',
      remoteHost: '<any-remote-host>', enabled: true, pointsAtThisComputer: true,
    });
    assert.equal(table[1].protocol, 'UDP');
    assert.equal(table[1].remoteHost, '<redacted-remote-host>');
    assert.equal(table[1].pointsAtThisComputer, false);
    // Nothing from the router's own wording, and no full address, survives.
    const saved = JSON.stringify(table);
    for (const secret of ['Living room', 'Console', '<b>', '192.168.1.25', '192.168.1.40', '203.0.113.7']) {
      assert.equal(saved.includes(secret), false, secret);
    }
    // Only the one read-only action was ever sent.
    assert.equal(router.seen.length, 3);
    for (const call of router.seen) assert.match(call.action, /#GetGenericPortMappingEntry"$/);
  } finally { await router.close(); }
});

test('an empty table is empty, and an unreadable one is unknown', async () => {
  for (const code of [713, 714, 402]) {
    const router = await mockRouter([], code);
    try { assert.deepEqual(await readMappingTable(router.service, ''), []); } finally { await router.close(); }
  }
  for (const code of [401, 606, 501]) {
    const router = await mockRouter([], code);
    try { assert.equal(await readMappingTable(router.service, ''), null); } finally { await router.close(); }
  }
});

const CHECKS = (over = {}) => ({
  tcp: { 22: 'not-reachable', 23: 'not-reachable', 80: 'not-reachable', 443: 'not-reachable', 7547: 'not-reachable' },
  upnp: { state: 'no-answer', mappingCount: 0, mappings: [] },
  wifi: { state: 'complete', security: 'strong', sameChannelNeighbours: 0, wps: 'off' },
  dns: { status: 'encrypted', source: 'measured' },
  ...over,
});

test('unknown checks leave the score alone and lower the coverage', () => {
  assert.deepEqual(scoreChecks(CHECKS()), { provisional: 100, earned: 80, known: 80, coverage: 80 });
  const wired = CHECKS({ wifi: { state: 'not-on-wifi', security: 'unknown', sameChannelNeighbours: null, wps: 'unknown' }, dns: { status: 'unknown', source: 'none' } });
  assert.deepEqual(scoreChecks(wired), { provisional: 100, earned: 30, known: 30, coverage: 30 });
  const telnet = CHECKS({ tcp: { 22: 'not-reachable', 23: 'reachable', 80: 'reachable', 443: 'reachable', 7547: 'not-reachable' } });
  assert.equal(scoreChecks(telnet).earned, 66);
});

test('a reachable port is never called exposed to the internet', () => {
  const open = CHECKS({ tcp: { 22: 'reachable', 23: 'reachable', 80: 'reachable', 443: 'not-reachable', 7547: 'reachable' } });
  const findings = buildFindings(open);
  assert.equal(findings.find((f) => f.id === 'tcp-23').severity, 'HIGH');
  for (const f of findings) assert.equal(/internet-exposed|exposed to the internet\.$/i.test(f.summary) && !/says nothing/.test(f.summary), false, f.summary);
  assert.equal(buildFindings(CHECKS({ tcp: { ...open.tcp, 443: 'reachable' } })).find((f) => f.id === 'tcp-80').state, 'open-https-available');
});

test('changes skip evidence appearing or disappearing', () => {
  const before = facts(CHECKS());
  const after = facts(CHECKS({
    upnp: { state: 'detected', mappingCount: 2, mappings: [] },
    wifi: { state: 'not-on-wifi', security: 'unknown', sameChannelNeighbours: null, wps: 'unknown' },
    dns: { status: 'plaintext', source: 'measured' },
  }));
  const changed = changedFacts(before, after);
  assert.deepEqual(changed.map((c) => c.key).sort(), ['dns', 'upnp', 'upnp-mappings']);
  assert.equal(describeChange({ key: 'dns', from: 'encrypted', to: 'plaintext' }), 'DNS: encrypted -> unencrypted');
  // One neighbour more or less is not a change; a crowded channel is.
  const one = facts(CHECKS({ wifi: { state: 'complete', security: 'strong', sameChannelNeighbours: 1, wps: 'off' } }));
  const two = facts(CHECKS({ wifi: { state: 'complete', security: 'strong', sameChannelNeighbours: 2, wps: 'off' } }));
  assert.deepEqual(changedFacts(one, two), []);
});
