// Run with: node --test tests/
// Nothing here touches the network beyond a mock router on 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import {
  isPrivateGateway, classifySecurity, classifyPorts, terseFields, xmlValue, findMappingService,
  readMappingTable, request, redactIPv4, scoreChecks, buildFindings, facts, changedFacts,
  describeChange, parseArgs,
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
  // With the adapter as a fourth field, the name is still the whole remainder.
  assert.deepEqual(terseFields('*:36:WPA3:wlan0:Caf\\: e:1', 4), ['*', '36', 'WPA3', 'wlan0', 'Caf: e:1']);
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

test('a router that never answers is unknown, not closed', () => {
  const silent = { 22: 'timeout', 23: 'timeout', 80: 'error', 443: 'timeout', 7547: 'timeout' };
  // No answer on any port and no sign of the router: nothing is known.
  assert.deepEqual(new Set(Object.values(classifyPorts(silent, false))), new Set(['unknown']));
  // The router is in the neighbour table: silence is a closed port, but an
  // attempt that never left this computer is still unknown.
  assert.deepEqual(classifyPorts(silent, true), { 22: 'not-reachable', 23: 'not-reachable', 80: 'unknown', 443: 'not-reachable', 7547: 'not-reachable' });
  // One clear answer proves the router is there.
  assert.deepEqual(classifyPorts({ 22: 'refused', 23: 'timeout', 80: 'open' }, false), { 22: 'not-reachable', 23: 'not-reachable', 80: 'reachable' });
  // Unknown ports earn nothing and count for nothing.
  const checks = CHECKS({ tcp: { 22: 'unknown', 23: 'unknown', 80: 'unknown', 443: 'unknown', 7547: 'unknown' } });
  assert.deepEqual(scoreChecks(checks), { provisional: 100, earned: 50, known: 50, coverage: 50 });
  const telnet = buildFindings(checks).find((f) => f.id === 'tcp-23');
  assert.equal(telnet.state, 'unknown');
  assert.match(telnet.summary, /^Unknown/);
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
  // UPnP going from silent to answering is evidence appearing, not a change.
  assert.deepEqual(changed.map((c) => c.key).sort(), ['dns']);
  assert.equal(describeChange({ key: 'dns', from: 'encrypted', to: 'plaintext' }), 'DNS: encrypted -> unencrypted');
  // One lost UPnP reply must not read as "UPnP switched off, mappings gone".
  const answering = facts(CHECKS({ upnp: { state: 'detected', mappingCount: 3, mappings: [] } }));
  for (const state of ['no-answer', 'refused', 'unknown']) {
    const silent = facts(CHECKS({ upnp: { state, mappingCount: 0, mappings: [] } }));
    assert.deepEqual(changedFacts(answering, silent), [], state);
    assert.deepEqual(changedFacts(silent, answering), [], state);
  }
  // A mapping appearing while the router answers is a change.
  const more = facts(CHECKS({ upnp: { state: 'detected', mappingCount: 4, mappings: [] } }));
  assert.deepEqual(changedFacts(answering, more), [{ key: 'upnp-mappings', from: '3', to: '4' }]);
  // One neighbour more or less is not a change; a crowded channel is.
  const one = facts(CHECKS({ wifi: { state: 'complete', security: 'strong', sameChannelNeighbours: 1, wps: 'off' } }));
  const two = facts(CHECKS({ wifi: { state: 'complete', security: 'strong', sameChannelNeighbours: 2, wps: 'off' } }));
  assert.deepEqual(changedFacts(one, two), []);
});

test('a router that ignores the index does not produce phantom mappings', async () => {
  const same = { ext: 8080, int: 80, proto: 'TCP', client: '192.168.1.25', description: 'x' };
  const router = await mockRouter(new Array(50).fill(same));
  try {
    const table = await readMappingTable(router.service, '');
    assert.equal(table.length, 1);
    assert.equal(router.seen.length, 2);
  } finally { await router.close(); }
});

// A raw server, for answers a well-behaved HTTP server would never give.
function rawServer(onConnection) {
  const server = net.createServer(onConnection);
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    url: `http://127.0.0.1:${server.address().port}/`,
    close: () => new Promise((done) => server.close(done)),
  })));
}

test('an answer cut short is an error, not a hang', async () => {
  const server = await rawServer((socket) => {
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 5000\r\n\r\n<root>');
      socket.end();
    });
  });
  try { await assert.rejects(request(server.url), /cut short/); } finally { await server.close(); }
});

test('a router that trickles its answer is given up on', { timeout: 15000 }, async () => {
  const timers = [];
  const server = await rawServer((socket) => {
    socket.on('error', () => {});
    socket.once('data', () => {
      socket.write('HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 5000\r\n\r\n');
      timers.push(setInterval(() => { if (!socket.destroyed) socket.write('x'); }, 500));
    });
  });
  const started = Date.now();
  try {
    await assert.rejects(request(server.url), /timeout/);
    assert.ok(Date.now() - started < 9000, 'gave up within the deadline');
  } finally { timers.forEach(clearInterval); await server.close(); }
});

test('the network guard only accepts a real network id', () => {
  // The background check passes the id of the network alerts were switched
  // on for; anything else must be refused, not ignored.
  assert.throws(() => parseArgs(['--only-network', 'not-an-id']), /network id/);
  assert.equal(parseArgs(['--only-network', '0123456789abcdef']).onlyNetwork, '0123456789abcdef');
});
