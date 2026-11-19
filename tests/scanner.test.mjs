// Run with: node --test tests/
// Nothing here touches the network beyond a mock router on 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  isPrivateGateway, isHomeLink, routerUrl, classifySecurity, classifyPorts, classifyDns,
  dnsChoiceFor, parseRouteGet, defaultRouteDevices, terseFields, xmlValue, findMappingService,
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
  // A declaration has to name the network it is about.
  assert.throws(() => parseArgs(['--dns', 'encrypted']), /needs --dns-network/);
  assert.equal(parseArgs(['--dns', 'encrypted', '--dns-network', '0123456789abcdef']).dns, 'encrypted');
  assert.equal(parseArgs([]).dns, 'auto');
});

test('Wi-Fi security is classified', () => {
  assert.equal(classifySecurity('WPA2 WPA3'), 'strong');
  assert.equal(classifySecurity('WPA3'), 'strong');
  // WPA2 with the first WPA still allowed accepts the old mode: not strong.
  assert.equal(classifySecurity('WPA1 WPA2'), 'legacy');
  assert.equal(classifySecurity('WPA WPA2'), 'legacy');
  const legacy = buildFindings(CHECKS({ wifi: { state: 'complete', security: 'legacy', sameChannelNeighbours: 0, wps: 'off' } }))
    .find((f) => f.id === 'wifi-security');
  assert.equal(legacy.severity, 'LOW');
  assert.match(legacy.summary, /first version of WPA/);
  assert.equal(scoreChecks(CHECKS({ wifi: { state: 'complete', security: 'legacy', sameChannelNeighbours: 0, wps: 'off' } })).earned, 60);
  assert.equal(classifySecurity('WPA2 WPA3'), 'strong');
  assert.equal(classifySecurity('WPA2 802.1X'), 'strong');
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
  // Nor one whose control address carries a query, credentials or a low port.
  for (const control of ['/apply.cgi?action=reboot', 'http://admin:admin@192.168.1.1:5000/ctl', 'http://192.168.1.1:23/ctl', '/ctl#x', '//203.0.113.9/ctl']) {
    assert.equal(findMappingService(DESCRIPTION(control), 'http://192.168.1.1:5000/rootDesc.xml', '192.168.1.1'), null, control);
  }
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
  // Only the standard's "no such entry" codes mean an empty table.
  for (const code of [713, 714]) {
    const router = await mockRouter([], code);
    try { assert.deepEqual(await readMappingTable(router.service, ''), []); } finally { await router.close(); }
  }
  // "Bad request" at the very first entry proves nothing about the table.
  for (const code of [402, 501, 401, 606, 503]) {
    const router = await mockRouter([], code);
    try { assert.equal(await readMappingTable(router.service, ''), null, String(code)); } finally { await router.close(); }
  }
  // After a real entry, 402 and 501 are how some routers end their table;
  // any other failure means the rest could not be read.
  const entry = { ext: 8080, int: 80, proto: 'TCP', client: '192.168.1.25', description: 'x' };
  for (const code of [713, 714, 402, 501]) {
    const router = await mockRouter([entry], code);
    try { assert.equal((await readMappingTable(router.service, '')).length, 1, String(code)); } finally { await router.close(); }
  }
  for (const code of [401, 503]) {
    const router = await mockRouter([entry], code);
    try { assert.equal(await readMappingTable(router.service, ''), null, String(code)); } finally { await router.close(); }
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

const RESOLVED = (globalMode, linkMode) => `Global
           Protocols: -LLMNR -mDNS ${globalMode}
         DNS Servers: 1.1.1.1#cloudflare-dns.com
Link 2 (eth0)
         Protocols: +DefaultRoute -LLMNR -mDNS ${linkMode}
       DNS Servers: 1.1.1.1
Link 5 (docker0)
         Protocols: -DefaultRoute -LLMNR -mDNS -DNSOverTLS
`;

test('opportunistic DNS over TLS is never called encrypted', () => {
  // Strict mode is the only one without a plain-text fallback.
  assert.equal(classifyDns(RESOLVED('+DNSOverTLS', '+DNSOverTLS')), 'encrypted');
  assert.equal(classifyDns(RESOLVED('DNSOverTLS=yes', 'DNSOverTLS=yes')), 'encrypted');
  // A server configured by name does not change what opportunistic means.
  assert.equal(classifyDns(RESOLVED('DNSOverTLS=opportunistic', 'DNSOverTLS=opportunistic')), 'opportunistic');
  assert.equal(classifyDns(RESOLVED('+DNSOverTLS', 'DNSOverTLS=opportunistic')), 'opportunistic');
  assert.equal(classifyDns(RESOLVED('-DNSOverTLS', '-DNSOverTLS')), 'plaintext');
  assert.equal(classifyDns(RESOLVED('+DNSOverTLS', '-DNSOverTLS')), 'plaintext');
  assert.equal(classifyDns(''), 'unknown');
  // It earns half, is listed as something to look at, and says why.
  const checks = CHECKS({ dns: { status: 'opportunistic', source: 'measured' } });
  assert.deepEqual(scoreChecks(checks), { provisional: 88, earned: 70, known: 80, coverage: 80 });
  const finding = buildFindings(checks).find((f) => f.id === 'dns');
  assert.equal(finding.state, 'opportunistic');
  assert.equal(finding.severity, 'LOW');
  assert.match(finding.summary, /fall back/);
});

test('a DNS declaration applies only on the network it was made for', () => {
  const home = '0123456789abcdef';
  const declared = { dns: 'encrypted', dnsNetwork: home };
  assert.equal(dnsChoiceFor(declared, home), 'encrypted');
  assert.equal(dnsChoiceFor(declared, 'fedcba9876543210'), 'auto');
  // An unidentified network is not the declared one.
  assert.equal(dnsChoiceFor(declared, ''), 'auto');
  assert.equal(dnsChoiceFor({ dns: 'auto', dnsNetwork: home }, home), 'auto');
  // A declaration that names no network applies nowhere.
  assert.equal(dnsChoiceFor({ dns: 'encrypted', dnsNetwork: '' }, 'fedcba9876543210'), 'auto');
  assert.throws(() => parseArgs(['--dns-network', 'nope']), /network id/);
});

test('the route is read as the kernel decides it', () => {
  assert.deepEqual(parseRouteGet('1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.25 uid 1000 \\    cache '),
    { via: '192.168.1.1', dev: 'eth0', src: '192.168.1.25' });
  // Through a tunnel there is no router to audit: no "via".
  assert.deepEqual(parseRouteGet('1.1.1.1 dev wg0 table 51820 src 10.2.0.2 uid 1000 \\    cache '),
    { via: '', dev: 'wg0', src: '10.2.0.2' });
  assert.deepEqual(parseRouteGet(''), { via: '', dev: '', src: '' });
  // Default routes in every table, including ones without a "via".
  assert.deepEqual(defaultRouteDevices([
    'default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.25 metric 100 ',
    'default dev wg0 table 51820 scope link ',
    'default via 10.8.0.1 dev tun0 table 200 ',
    '192.168.1.0/24 dev eth0 proto kernel scope link ',
    // The two half-routes a VPN can use instead of a default route.
    '0.0.0.0/1 via 10.8.0.1 dev tun1 ',
    '128.0.0.0/1 via 10.8.0.1 dev tun1 ',
    'default via fe80::1 dev eth0 proto ra metric 100 pref medium',
    '::/1 dev wg1 metric 1024 pref medium',
    '8000::/1 dev wg1 metric 1024 pref medium',
    'local 127.0.0.0/8 dev lo table local proto kernel scope host src 127.0.0.1 ',
    // Other shapes that carry everything: a multipath default, quarters, the
    // whole of the public IPv6 space.
    'default proto static metric 50 ',
    '\tnexthop via 192.168.1.1 dev eth0 weight 1 ',
    '\tnexthop via 10.9.0.1 dev wg2 weight 1 ',
    '64.0.0.0/2 dev tun2 ',
    '2000::/3 dev wg3 metric 1024 pref medium',
    // Routes that carry nothing, and ordinary narrow ones.
    'unreachable default dev lo metric 4294967295 pref medium',
    'blackhole default',
    'throw 100.64.0.0/10 table 52',
    '\tnexthop via 10.1.1.1 dev stray0 weight 1 ',
    'ff00::/8 dev eth0 table local metric 256 pref medium',
    '10.0.0.0/8 dev tun9 ',
  ].join('\n')), ['eth0', 'wg0', 'tun0', 'tun1', 'tun1', 'eth0', 'wg1', 'wg1', 'eth0', 'wg2', 'tun2', 'wg3']);
});

test('a request that lands somewhere other than its address is dropped', async () => {
  // "localhost" resolves to 127.0.0.1, so the machine connected to is not
  // the one named: the same check stops a request diverted through a proxy.
  const router = await mockRouter([]);
  try {
    const diverted = router.service.control.replace('127.0.0.1', 'localhost');
    // Where "localhost" means ::1 the connection is simply refused; either way it must not succeed.
    await assert.rejects(request(diverted), /not connected to the router|ECONNREFUSED/);
    assert.equal((await request(router.service.control, { method: 'POST', body: '<x/>' })).status, 500);
  } finally { await router.close(); }
});

test('proxy settings are gone before anything is sent', () => {
  for (const name of ['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY', 'NODE_USE_ENV_PROXY']) {
    assert.equal(process.env[name], undefined, name);
  }
});

test('only a real network card counts as a home link', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'netaudit-sys-'));
  const make = (dev, type, extras) => {
    fs.mkdirSync(path.join(root, dev));
    fs.writeFileSync(path.join(root, dev, 'type'), `${type}\n`);
    for (const extra of extras) fs.mkdirSync(path.join(root, dev, extra));
  };
  try {
    make('eth0', 1, ['device']);            // a cable
    make('wlan0', 1, ['device']);           // Wi-Fi
    make('tun0', 65534, []);                // a routed VPN
    make('tap0', 1, ['tun_flags']);         // a bridged VPN: Ethernet-shaped, no hardware
    make('zt0', 1, []);                     // ZeroTier and the like
    make('virbr0', 1, ['bridge']);          // a virtual machine bridge
    make('br0', 1, ['bridge', 'device']);
    make('bond0', 1, ['bonding']);
    make('ppp0', 512, ['device']);
    assert.equal(isHomeLink('eth0', root), true);
    assert.equal(isHomeLink('wlan0', root), true);
    for (const dev of ['tun0', 'tap0', 'zt0', 'virbr0', 'br0', 'bond0', 'ppp0', 'missing', '../eth0', '']) {
      assert.equal(isHomeLink(dev, root), false, dev);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('a forged reply cannot steer a request at the router', () => {
  const gw = '192.168.1.1';
  assert.equal(routerUrl('http://192.168.1.1:5000/rootDesc.xml', gw), 'http://192.168.1.1:5000/rootDesc.xml');
  assert.equal(routerUrl('http://192.168.1.1/igd.xml', gw), 'http://192.168.1.1/igd.xml');
  assert.equal(routerUrl('http://192.168.1.1:49152/dyndev/uuid:0014-bf09', gw), 'http://192.168.1.1:49152/dyndev/uuid:0014-bf09');
  for (const forged of [
    'http://admin:admin@192.168.1.1:5000/apply.cgi',     // credentials
    'http://192.168.1.1:5000/apply.cgi?action=reboot',   // a query
    'http://192.168.1.1:5000/x#frag',
    'http://192.168.1.1:23/x', 'http://192.168.1.1:443/x', 'http://192.168.1.1:22/',  // privileged ports
    'https://192.168.1.1/x', 'ftp://192.168.1.1/x', 'file:///etc/passwd',
    'http://192.168.1.2:5000/x', 'http://203.0.113.9/x', 'http://localhost:5000/x', 'http://192.168.1.1.evil.example/x',
    'http://192.168.1.1:5000/a b', 'http://192.168.1.1:5000/a%20b', 'http://192.168.1.1:5000/a;b=c',
    'http://192.168.1.1:5000/' + 'a'.repeat(300), 'not a url', '', undefined,
  ]) assert.equal(routerUrl(forged, gw), null, String(forged));
  // Other spellings of the same address are normalised to it, never to another.
  assert.equal(routerUrl('http://3232235777:5000/x', gw), 'http://192.168.1.1:5000/x');
});

test('DNS is read from every scope that can carry a lookup', () => {
  const status = (mode, globalProto, globalServers, linkProto) => `Global
           Protocols: -LLMNR -mDNS ${globalProto}
    resolv.conf mode: ${mode}
${globalServers ? '         DNS Servers: 9.9.9.9\n' : ''}Fallback DNS Servers: 9.9.9.9#dns.quad9.net
Link 2 (eth0)
         Protocols: +DefaultRoute -LLMNR -mDNS ${linkProto}
       DNS Servers: 192.168.1.1
`;
  assert.equal(classifyDns(status('stub', '+DNSOverTLS', true, '+DNSOverTLS')), 'encrypted');
  // Global servers answer too: plain text there is plain text.
  assert.equal(classifyDns(status('stub', '-DNSOverTLS', true, '+DNSOverTLS')), 'plaintext');
  assert.equal(classifyDns(status('stub', 'DNSOverTLS=opportunistic', true, '+DNSOverTLS')), 'opportunistic');
  // Without global servers the link decides.
  assert.equal(classifyDns(status('stub', '-DNSOverTLS', false, '+DNSOverTLS')), 'encrypted');
  // Programs that bypass the resolver make its setting meaningless.
  for (const mode of ['foreign', 'static', 'uplink', 'missing']) {
    assert.equal(classifyDns(status(mode, '+DNSOverTLS', true, '+DNSOverTLS')), 'unknown', mode);
  }
});

test('hostile XML from a router is read in linear time', () => {
  const started = Date.now();
  assert.equal(xmlValue('<errorCode '.repeat(40000), 'errorCode'), '');
  assert.equal(xmlValue('errorCode'.repeat(40000), 'errorCode'), '');
  assert.equal(findMappingService('<service>'.repeat(40000), 'http://192.168.1.1:5000/d.xml', '192.168.1.1'), null);
  assert.equal(xmlValue('<a><errorCode>714</errorCode></a>', 'errorCode'), '714');
  assert.equal(xmlValue('<a><u:errorCodeX>1</u:errorCodeX><u:errorCode attr="1"> 7 </u:errorCode></a>', 'errorCode'), '7');
  assert.ok(Date.now() - started < 1500, `took ${Date.now() - started} ms`);
});

test('an unanswering router is unknown even when it was seen before', () => {
  // classifyPorts is told whether the router is answering now, not whether it
  // once did; silence without that is never a closed port.
  assert.deepEqual(classifyPorts({ 22: 'timeout', 23: 'timeout' }, false), { 22: 'unknown', 23: 'unknown' });
});

test('a reply that is not a mapping entry is not a mapping', async () => {
  // A router (or a login page in front of it) that answers 200 with something else.
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<html><body>Please log in</body></html>'); });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const service = { type: 'urn:schemas-upnp-org:service:WANIPConnection:1', control: `http://127.0.0.1:${server.address().port}/ctl` };
    assert.equal(await readMappingTable(service, ''), null);
  } finally { await new Promise((done) => server.close(done)); }
  // A fault sent with status 200 is no entry either.
  const faulty = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => { res.writeHead(200); res.end('<s:Fault><UPnPError><errorCode>713</errorCode></UPnPError></s:Fault>'); });
  });
  await new Promise((resolve) => faulty.listen(0, '127.0.0.1', resolve));
  try {
    const service = { type: 'urn:schemas-upnp-org:service:WANIPConnection:1', control: `http://127.0.0.1:${faulty.address().port}/ctl` };
    assert.equal(await readMappingTable(service, ''), null);
  } finally { await new Promise((done) => faulty.close(done)); }
});

test('router XML is read correctly in its awkward forms', () => {
  // A letter that changes length in lower case must not shift what is read.
  const tricky = '<root><friendlyName>\u0130\u0130\u0130 Router</friendlyName><serviceType>urn:x</serviceType></root>';
  assert.equal(xmlValue(tricky, 'serviceType'), 'urn:x');
  assert.equal(xmlValue('<a><!-- <controlURL>/old</controlURL> --><controlURL>/new</controlURL></a>', 'controlURL'), '/new');
  assert.equal(xmlValue('<a><controlURL><![CDATA[/ctl/IPConn]]></controlURL></a>', 'controlURL'), '/ctl/IPConn');
  assert.equal(xmlValue('<A><CONTROLURL>/Up</CONTROLURL></A>', 'controlURL'), '/Up');
  assert.equal(xmlValue('<a><!-- never closed <controlURL>/x</controlURL>', 'controlURL'), '');
  const described = `<root><device><serviceList><!-- <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/commented</controlURL></service> -->
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/real</controlURL></service></serviceList></device></root>`;
  assert.equal(findMappingService(described, 'http://192.168.1.1:5000/d.xml', '192.168.1.1').control, 'http://192.168.1.1:5000/real');
});

test('a link that takes every lookup counts for DNS whatever its route flag', () => {
  const status = `Global
           Protocols: -LLMNR -mDNS +DNSOverTLS
    resolv.conf mode: stub
         DNS Servers: 9.9.9.9#dns.quad9.net
Link 2 (eth0)
         Protocols: +DefaultRoute -LLMNR -mDNS +DNSOverTLS
Link 7 (vpn0)
         Protocols: -DefaultRoute -LLMNR -mDNS -DNSOverTLS
       DNS Servers: 10.0.0.1
        DNS Domain: ~.
`;
  assert.equal(classifyDns(status), 'plaintext');
  assert.equal(classifyDns(status.replace('DNS Domain: ~.', 'DNS Domain: corp.example')), 'encrypted');
});

test('a router that cycles or drifts cannot inflate the mapping count', async () => {
  // The same entry for every index, with a field that changes each time.
  let calls = 0;
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      calls += 1;
      res.writeHead(200, { 'Content-Type': 'text/xml' });
      res.end(`<r><NewRemoteHost></NewRemoteHost><NewExternalPort>8080</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>80</NewInternalPort><NewInternalClient>192.168.1.25</NewInternalClient><NewEnabled>1</NewEnabled>
<NewLeaseDuration>${3600 - calls}</NewLeaseDuration></r>`);
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const service = { type: 'urn:schemas-upnp-org:service:WANIPConnection:1', control: `http://127.0.0.1:${server.address().port}/ctl` };
    assert.equal((await readMappingTable(service, '')).length, 1);
    assert.equal(calls, 2);
  } finally { await new Promise((done) => server.close(done)); }
  // A wildcard entry (external port 0) is an entry; it does not void the table.
  const router = await mockRouter([
    { ext: 0, int: 0, proto: 'TCP', client: '192.168.1.40', description: 'dmz' },
    { ext: 443, int: 443, proto: 'TCP', client: '192.168.1.40', description: 'web' },
  ]);
  try { assert.equal((await readMappingTable(router.service, '')).length, 2); } finally { await router.close(); }
});

test('a routing domain on a wrapped line still counts', () => {
  const status = `Global
           Protocols: -LLMNR -mDNS +DNSOverTLS
    resolv.conf mode: stub
         DNS Servers: 9.9.9.9#dns.quad9.net
Link 7 (vpn0)
         Protocols: -DefaultRoute -LLMNR -mDNS -DNSOverTLS
       DNS Servers: 10.0.0.1
        DNS Domain: corp.example lab.example
                    ~.
Link 2 (eth0)
         Protocols: +DefaultRoute -LLMNR -mDNS +DNSOverTLS
`;
  assert.equal(classifyDns(status), 'plaintext');
});

test('the helper never takes mise\'s installer stub for an installed Node.js', () => {
  const helper = fileURLToPath(new URL('../bin/netaudit', import.meta.url));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'netaudit-home-'));
  const bin = path.join(home, 'bin');
  const shims = path.join(home, '.local/share/mise/shims');
  fs.mkdirSync(bin); fs.mkdirSync(shims, { recursive: true });
  // A stand-in "mise" and a shim that links to it, as mise's shims do.
  fs.writeFileSync(path.join(bin, 'mise'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  fs.symlinkSync(path.join(bin, 'mise'), path.join(shims, 'node'));
  const ask = (pathVar, extra = '') => {
    const script = `eval "$(sed -n '/^installed_node() {/,/^}/p;/^is_mise_shim() {/,/^}/p' "$1")"; ${extra} installed_node || echo none`;
    return execFileSync('/bin/bash', ['-c', script, 'bash', helper], { env: { HOME: home, PATH: pathVar }, cwd: home, encoding: 'utf8' }).trim();
  };
  try {
    const system = '/usr/bin:/bin';
    const real = ask(system);     // whatever this machine really has, shim-free
    assert.ok(real === 'none' || (real.startsWith('/') && !real.includes('/mise/shims/')), real);
    // With the shim first on PATH, as in the Omarchy shell, the answer must
    // be the same real program, never the shim.
    assert.equal(ask(`${shims}:${system}`), real);
    // Nor a shell function, nor a bare word that PATH would resolve to the shim.
    assert.equal(ask(`${shims}:${system}`, 'node() { :; }; export -f node; mkdir -p node;'), real);
    // A real program under mise's installs folder is accepted.
    const installed = path.join(home, '.local/share/mise/installs/node/26.0.0/bin');
    fs.mkdirSync(installed, { recursive: true });
    fs.writeFileSync(path.join(installed, 'node'), '#!/bin/sh\n', { mode: 0o755 });
    assert.equal(ask(`${shims}:${bin}:${system}`), path.join(installed, 'node'));
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});
