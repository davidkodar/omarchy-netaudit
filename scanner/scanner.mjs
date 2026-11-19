#!/usr/bin/env node
// Read-only audit of this computer's own home gateway.
//
// Safety boundary: the only target is the private default gateway the
// operating system reports. There is no flag that accepts a host, and the
// script never logs in, grabs banners, or changes anything on the router.
//
// It needs nothing but Node.js and the tools every Omarchy system has:
// ip, nmcli, iw and resolvectl.

import net from 'node:net';
import fs from 'node:fs';
import http from 'node:http';
import dgram from 'node:dgram';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import { pathToFileURL } from 'node:url';

// Reports live in the owner's state folder, outside the plugin, so a plugin
// update never touches them and they are never committed by accident.
const STATE_DIR = process.env.NETAUDIT_STATE_DIR
  || path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state'), 'netaudit');
const REPORT = path.join(STATE_DIR, 'sanitized-report.json');
const PREVIOUS = path.join(STATE_DIR, 'previous-sanitized-report.json');

// Scored ports. Port 443 is probed too, unscored, only to learn whether the
// router offers an HTTPS admin page.
const PORTS = [
  { port: 22, name: 'SSH', weight: 6, severity: 'MEDIUM', actionId: 'ssh-off',
    action: 'Turn off SSH access on the router unless you use it yourself.' },
  { port: 23, name: 'Telnet', weight: 10, severity: 'HIGH', actionId: 'telnet-off',
    action: 'Turn off Telnet on the router; it sends passwords unencrypted.' },
  { port: 80, name: 'HTTP admin', weight: 4, severity: 'LOW', actionId: 'https-only',
    action: 'Use HTTPS-only for the router admin page if the router offers it.' },
  { port: 7547, name: 'TR-069 remote management', weight: 10, severity: 'MEDIUM', actionId: 'tr069-off',
    action: 'Turn off TR-069/CWMP remote management if your provider does not need it.' },
];
const HTTPS_PORT = 443;
const SEVERITY_ORDER = ['HIGH', 'MEDIUM', 'LOW', 'REVIEW'];
const DNS_CHOICES = ['auto', 'encrypted', 'plaintext', 'unknown'];

// ---------- arguments ----------

function parseArgs(argv) {
  const opts = { dns: 'auto', watch: false, minutes: 30, quiet: false, notify: false, maxAge: 0, onlyNetwork: '', printNetwork: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--dns') {
      opts.dns = argv[++i];
      if (!DNS_CHOICES.includes(opts.dns)) throw new Error(`--dns must be one of: ${DNS_CHOICES.join(', ')}`);
    } else if (arg === '--watch') {
      opts.watch = true;
      if (/^\d+$/.test(argv[i + 1] ?? '')) opts.minutes = Number(argv[++i]);
      if (opts.minutes < 5) throw new Error('--watch interval must be at least 5 minutes');
    } else if (arg === '--max-age') {
      opts.maxAge = Number(argv[++i]);
      if (!(opts.maxAge > 0)) throw new Error('--max-age needs a number of minutes');
    } else if (arg === '--only-network') {
      opts.onlyNetwork = String(argv[++i] ?? '');
      if (!/^[0-9a-f]{16}$/.test(opts.onlyNetwork)) throw new Error('--only-network needs a network id');
    } else if (arg === '--network-id') {
      opts.printNetwork = true;
    } else if (arg === '--quiet') {
      opts.quiet = true;
    } else if (arg === '--notify') {
      opts.notify = true;
    } else if (arg === '--help' || arg === '-h') {
      console.log([
        'Usage: node scanner.mjs [options]',
        '',
        '  --dns <auto|encrypted|plaintext|unknown>',
        '                 auto (default) reads this computer\'s resolver; the others',
        '                 declare what you know, e.g. that the router encrypts DNS.',
        '  --watch [min]  Rerun every N minutes (default 30) and print what changed.',
        '  --max-age <min>  Do nothing if the saved report is newer than this.',
        '  --notify       Send a desktop notification when a check changed.',
        '  --network-id   Print a scrambled id of the network this computer is on.',
        '  --only-network <id>  Do nothing unless this computer is on that network.',
        '  --quiet        Print nothing but errors.',
        '',
        'The target is always your own default gateway. No host can be supplied.',
        `Reports are saved in ${STATE_DIR}`,
      ].join('\n'));
      process.exit(0);
    } else {
      throw new Error(`Unknown option: ${arg} (this tool accepts no target or host)`);
    }
  }
  return opts;
}

// Runs a local, read-only command and resolves with its output, or '' when
// the command is missing or fails.
function run(command, args, timeout = 8000) {
  return new Promise((resolve) => {
    execFile(command, args, { timeout, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, LC_ALL: 'C' } },
      (error, stdout) => resolve(error ? '' : String(stdout)));
  });
}

// ---------- safety boundary ----------

function isPrivateGateway(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip ?? '');
  if (!m) return false;
  const [a, b, c, d] = m.slice(1).map(Number);
  if ([a, b, c, d].some((n) => n > 255)) return false;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

// The default gateway and the interface it is reached through, from the
// kernel's routing table. With several default routes (cable and Wi-Fi
// together) the one with the lowest metric is in use.
async function findRoute() {
  const routes = (await run('ip', ['-4', 'route', 'show', 'default']))
    .split('\n')
    .map((line) => ({
      via: /\bvia (\S+)/.exec(line)?.[1],
      dev: /\bdev (\S+)/.exec(line)?.[1] ?? '',
      metric: Number(/\bmetric (\d+)/.exec(line)?.[1] ?? 0),
    }))
    .filter((route) => route.via)
    .sort((a, b) => a.metric - b.metric);
  const route = routes[0];
  if (!isPrivateGateway(route?.via)) {
    throw new Error('Safety stop: the default gateway is missing or is not a private IPv4 address.');
  }
  // A VPN or other tunnel also has a private "gateway", but it is somebody
  // else's server, not a home router. Only cable and Wi-Fi links are audited.
  if (!isHomeLink(route.dev)) {
    throw new Error('Safety stop: the default route goes through a VPN or tunnel, not a home router.');
  }
  return { gateway: route.via, dev: route.dev };
}

// True for Ethernet-type links (cable and Wi-Fi), false for tun, WireGuard,
// PPP and the like.
function isHomeLink(dev) {
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(dev)) return false;
  try { return fs.readFileSync(`/sys/class/net/${dev}/type`, 'utf8').trim() === '1'; } catch { return false; }
}

// The gateway's entry in the neighbour table: whether the router has answered
// this computer lately, and its hardware address. The address is used only
// in memory, to tell one network from another; see networkId.
async function gatewayNeighbour(gateway, dev) {
  const line = (await run('ip', ['neigh', 'show', gateway, 'dev', dev])).split('\n')[0] ?? '';
  const mac = /\blladdr ([0-9a-f:]{17})\b/i.exec(line)?.[1]?.toLowerCase() ?? '';
  return { mac, alive: Boolean(mac) && !/\b(FAILED|INCOMPLETE)\b/.test(line) };
}

// A scrambled id for "this network": a salted hash of the router's hardware
// address, so two scans can be told to be of the same network without the
// address itself ever being stored. The salt is random and stays on this
// computer.
function networkId(mac) {
  if (!mac) return '';
  fs.mkdirSync(STATE_DIR, { recursive: true });
  const saltFile = path.join(STATE_DIR, 'salt');
  let salt = '';
  try { salt = fs.readFileSync(saltFile, 'utf8').trim(); } catch { /* made below */ }
  if (!/^[0-9a-f]{32}$/.test(salt)) {
    salt = crypto.randomBytes(16).toString('hex');
    fs.writeFileSync(saltFile, `${salt}\n`, { mode: 0o600 });
  }
  return crypto.createHash('sha256').update(`${salt}:${mac}`).digest('hex').slice(0, 16);
}

// This computer's own address on the way to the gateway. Used only to tell
// whether a port mapping points here; it is never stored.
async function localAddressFor(gateway) {
  return /\bsrc (\S+)/.exec(await run('ip', ['-4', 'route', 'get', gateway]))?.[1] ?? '';
}

// ---------- checks ----------

// Connect, then close at once. Nothing is sent or read. Resolves with how
// the attempt ended: 'open', 'refused' (the router answered "closed"),
// 'timeout' (no answer) or 'error' (the attempt never reached the router).
function probePort(host, port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    const done = (outcome) => { socket.destroy(); resolve(outcome); };
    socket.setTimeout(800);
    socket.once('connect', () => done('open'));
    socket.once('timeout', () => done('timeout'));
    socket.once('error', (error) => done(error.code === 'ECONNREFUSED' ? 'refused' : 'error'));
  });
}

// What the attempts say about each port. Silence only means "closed" when
// the router is known to be there: it answered on another port, or it is in
// the neighbour table. A router that cannot be reached at all is Unknown,
// never a pass.
function classifyPorts(outcomes, routerAlive) {
  const answered = Object.values(outcomes).some((o) => o === 'open' || o === 'refused');
  const result = {};
  for (const [port, outcome] of Object.entries(outcomes)) {
    if (outcome === 'open') result[port] = 'reachable';
    else if (outcome === 'refused') result[port] = 'not-reachable';
    else if (outcome === 'timeout' && (answered || routerAlive)) result[port] = 'not-reachable';
    else result[port] = 'unknown';
  }
  return result;
}

async function checkPorts(gateway, routerAlive) {
  const outcomes = {};
  await Promise.all([...PORTS.map((p) => p.port), HTTPS_PORT].map(async (port) => {
    // A single missed connection is not evidence that a port is closed, so
    // an attempt without a clear answer is repeated, three in all.
    let outcome = 'error';
    for (let attempt = 0; attempt < 3; attempt++) {
      outcome = await probePort(gateway, port);
      if (outcome === 'open' || outcome === 'refused') break;
    }
    outcomes[port] = outcome;
  }));
  return classifyPorts(outcomes, routerAlive);
}

// ----- UPnP -----
//
// Three read-only steps, all against the gateway alone: find it with an SSDP
// search, fetch its description, and read its port-mapping table one entry at
// a time with GetGenericPortMappingEntry. No other UPnP action is ever sent.

const SSDP_ADDRESS = '239.255.255.250';
const SSDP_PORT = 1900;
const GATEWAY_TYPES = [
  'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
  'urn:schemas-upnp-org:device:InternetGatewayDevice:2',
];
const MAPPING_SERVICES = [
  'urn:schemas-upnp-org:service:WANIPConnection:1',
  'urn:schemas-upnp-org:service:WANIPConnection:2',
  'urn:schemas-upnp-org:service:WANPPPConnection:1',
];
const MAX_MAPPINGS = 200;

// Searches for an internet gateway. Resolves with the description URL the
// gateway itself announced, 'other' when only some other device answered, or
// null when nothing did.
function discoverGateway(gateway, waitMs = 4000) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const timers = [];
    let sawOther = false;
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      timers.forEach(clearTimeout);
      try { socket.close(); } catch { /* already closed */ }
      resolve(value);
    };
    const search = () => {
      for (const type of GATEWAY_TYPES) {
        const message = Buffer.from([
          'M-SEARCH * HTTP/1.1', `HOST: ${SSDP_ADDRESS}:${SSDP_PORT}`, 'MAN: "ssdp:discover"', 'MX: 1', `ST: ${type}`, '', '',
        ].join('\r\n'));
        socket.send(message, SSDP_PORT, SSDP_ADDRESS, () => {});
      }
    };
    socket.on('error', () => finish(sawOther ? 'other' : null));
    socket.on('message', (data, remote) => {
      const location = /^location:\s*(\S+)/im.exec(data.subarray(0, 4096).toString('latin1'))?.[1];
      let host = null;
      try { host = new URL(location).hostname; } catch { /* not a usable answer */ }
      // Only the gateway's own answer, pointing back at the gateway, counts.
      if (remote.address === gateway && host === gateway && /^http:/i.test(location)) finish(location);
      else sawOther = true;
    });
    socket.bind(0, () => {
      // UDP loses packets, so the search goes out a few times.
      search();
      for (const delay of [300, 900, 1800]) timers.push(setTimeout(search, delay));
      timers.push(setTimeout(() => finish(sawOther ? 'other' : null), waitMs));
    });
  });
}

// One HTTP request to the gateway. It always settles: on a complete answer,
// an error, a connection closed mid-answer, an answer that is too large, or
// after six seconds whatever the router is doing.
function request(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn, value) => { if (!settled) { settled = true; clearTimeout(deadline); fn(value); } };
    const req = http.request(url, { method, headers }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > 512 * 1024) { req.destroy(); settle(reject, new Error('response too large')); return; }
        chunks.push(chunk);
      });
      res.on('end', () => (res.complete
        ? settle(resolve, { status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') })
        : settle(reject, new Error('response cut short'))));
      res.on('aborted', () => settle(reject, new Error('response cut short')));
      res.on('error', (error) => settle(reject, error));
      res.on('close', () => settle(reject, new Error('response cut short')));
    });
    const deadline = setTimeout(() => { req.destroy(); settle(reject, new Error('timeout')); }, 6000);
    req.on('error', (error) => settle(reject, error));
    if (body) req.write(body);
    req.end();
  });
}

function xmlValue(xml, tag) {
  return new RegExp(`<(?:\\w+:)?${tag}\\b[^>]*>([^<]*)</(?:\\w+:)?${tag}>`, 'i').exec(xml)?.[1]?.trim() ?? '';
}

// The control URL of the gateway's port-mapping service, from its description.
function findMappingService(description, location, gateway) {
  for (const block of description.match(/<service>[\s\S]*?<\/service>/gi) ?? []) {
    const type = xmlValue(block, 'serviceType');
    if (!MAPPING_SERVICES.includes(type)) continue;
    const base = xmlValue(description, 'URLBase') || location;
    let control;
    try { control = new URL(xmlValue(block, 'controlURL'), base); } catch { continue; }
    // Never follow a description that points anywhere but the gateway.
    if (control.hostname !== gateway || control.protocol !== 'http:') continue;
    return { type, control: control.href };
  }
  return null;
}

async function readMapping(service, index) {
  const body = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:GetGenericPortMappingEntry xmlns:u="${service.type}"><NewPortMappingIndex>${index}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body>
</s:Envelope>`;
  return request(service.control, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/xml; charset="utf-8"',
      'Content-Length': Buffer.byteLength(body),
      SOAPAction: `"${service.type}#GetGenericPortMappingEntry"`,
    },
    body,
  });
}

// Reads the whole port-mapping table, sanitized. Resolves with null when the
// table could not be read at all.
async function readMappingTable(service, here, budgetMs = 20000) {
  const mappings = [];
  const started = Date.now();
  let lastSeen = '';
  for (let index = 0; index < MAX_MAPPINGS; index++) {
    // A table that cannot be read in the time allowed is not a table.
    if (Date.now() - started > budgetMs) return null;
    const reply = await readMapping(service, index);
    if (reply.status !== 200) {
      // A router ends its table with a fault. Routers disagree on which (713,
      // 714, 402, 501), so any UPnP fault past the first entry ends it; at the
      // first entry only the "no such entry" codes mean an empty table, and
      // anything else means the table could not be read.
      const code = Number(xmlValue(reply.text, 'errorCode'));
      if (index === 0 && ![713, 714, 402].includes(code)) return null;
      break;
    }
    const internal = xmlValue(reply.text, 'NewInternalClient');
    // A router that ignores the index would answer the same entry for ever.
    const seen = ['NewExternalPort', 'NewProtocol', 'NewInternalPort', 'NewInternalClient', 'NewRemoteHost']
      .map((tag) => xmlValue(reply.text, tag)).join('|');
    if (seen === lastSeen) break;
    lastSeen = seen;
    mappings.push({
      label: `<mapping-${index + 1}>`,
      protocol: xmlValue(reply.text, 'NewProtocol').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 8),
      externalPort: Number(xmlValue(reply.text, 'NewExternalPort')) || 0,
      internalPort: Number(xmlValue(reply.text, 'NewInternalPort')) || 0,
      internalHost: redactIPv4(internal),
      remoteHost: xmlValue(reply.text, 'NewRemoteHost') ? '<redacted-remote-host>' : '<any-remote-host>',
      enabled: xmlValue(reply.text, 'NewEnabled') === '1',
      pointsAtThisComputer: here && internal ? internal === here : null,
    });
  }
  return mappings;
}

async function checkUpnp(gateway) {
  try {
    // One silent search is not evidence that UPnP is off, so search twice.
    let location = await discoverGateway(gateway);
    if (!location || location === 'other') {
      const second = await discoverGateway(gateway);
      location = second && second !== 'other' ? second : (location || second);
    }
    if (!location) return { state: 'no-answer', mappings: [] };
    if (location === 'other') return { state: 'refused', mappings: [] };

    const description = await request(location);
    const service = description.status === 200 ? findMappingService(description.text, location, gateway) : null;
    if (!service) return { state: 'unknown', mappings: [] };

    const mappings = await readMappingTable(service, await localAddressFor(gateway));
    if (!mappings) return { state: 'unknown', mappings: [] };
    return { state: 'detected', mappings };
  } catch {
    return { state: 'unknown', mappings: [] };
  }
}

// ----- Wi-Fi -----

function classifySecurity(text) {
  const s = text.toUpperCase().trim();
  // NetworkManager shows an open network as an empty field or "--".
  if (!s || s === '--') return 'weak';
  const modern = /WPA2|WPA3|RSN|SAE/.test(s);
  if (/WEP|TKIP|OPEN|NONE/.test(s) || (/WPA/.test(s) && !modern)) return 'weak';
  if (modern) return 'strong';
  return 'review';
}

// Splits one line of `nmcli -t` output into its first `count` fields; the
// rest of the line, colons and all, is the last field.
function terseFields(line, count) {
  const fields = [];
  let current = '';
  for (let i = 0; i < line.length; i++) {
    if (line[i] === '\\' && i + 1 < line.length) { current += line[++i]; continue; }
    if (line[i] === ':' && fields.length < count) { fields.push(current); current = ''; continue; }
    current += line[i];
  }
  fields.push(current);
  return fields;
}

// Whether the access point this computer is joined to advertises WPS, from
// the kernel's cached scan, which needs no extra rights. Nothing but the
// on/off answer leaves this function.
async function checkWps(iface) {
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(iface)) return 'unknown';
  const dump = await run('iw', ['dev', iface, 'scan', 'dump']);
  const joined = dump.split(/^(?=BSS )/m).find((block) => /^BSS .*-- associated/.test(block));
  if (!joined) return 'unknown';
  return /^\s*WPS:/m.test(joined) ? 'on' : 'off';
}

// The Wi-Fi this computer is on, from NetworkManager. Network names are read
// only to tell this network's own access points from the neighbours'; they
// are compared in memory and never printed or saved.
async function checkWifi(gateway) {
  const result = { state: 'unknown', security: 'unknown', sameChannelNeighbours: null, wps: 'unknown' };
  const list = await run('nmcli', ['-t', '-f', 'IN-USE,CHAN,SECURITY,DEVICE,SSID', 'device', 'wifi', 'list'], 20000);
  if (!list.trim()) {
    // No list: either no Wi-Fi hardware, the radio is off, or no nmcli.
    const radio = (await run('nmcli', ['radio', 'wifi'])).trim();
    return radio ? { ...result, state: 'not-on-wifi' } : result;
  }
  const networks = list.split('\n').filter(Boolean).map((line) => {
    const [inUse, channel, security, device, name] = terseFields(line, 4);
    return { inUse: inUse.trim() === '*', channel: Number(channel), security, device, name };
  });
  const current = networks.find((n) => n.inUse);
  if (!current) return { ...result, state: 'not-on-wifi' };

  // The Wi-Fi may be joined to a different network than the one the cable
  // leads to. Its results describe the audited router only when the Wi-Fi's
  // own gateway is that same router.
  const wifiRoutes = /^[A-Za-z0-9_.-]{1,32}$/.test(current.device)
    ? await run('ip', ['-4', 'route', 'show', 'default', 'dev', current.device]) : '';
  const sameRouter = wifiRoutes.split('\n').some((line) => /\bvia (\S+)/.exec(line)?.[1] === gateway);
  if (!sameRouter) return { ...result, state: 'other-network' };

  result.security = classifySecurity(current.security);
  result.wps = await checkWps(current.device);
  if (current.channel) {
    result.sameChannelNeighbours = networks.filter(
      (n) => !n.inUse && n.device === current.device && n.channel === current.channel && n.name !== current.name,
    ).length;
  }
  result.state = result.sameChannelNeighbours !== null ? 'complete' : 'partial';
  return result;
}

// ----- DNS -----
//
// With "auto" this computer's resolver is asked whether it encrypts its
// lookups (systemd-resolved, as Omarchy's DNS setting configures it). That
// says nothing about other devices at home; a router that encrypts DNS for
// everyone is something only the owner can declare.
async function checkDns(choice) {
  if (choice !== 'auto') {
    return {
      status: choice,
      source: choice === 'unknown' ? 'none' : 'declared',
      basis: choice === 'unknown' ? 'No explicit evidence supplied.' : 'Declared by the owner.',
    };
  }
  const status = await run('resolvectl', ['status']);
  const protocols = status.split('\n').filter((line) => /^\s*Protocols:/.test(line));
  if (!protocols.length) return { status: 'unknown', source: 'none', basis: 'This computer\'s resolver could not be read.' };
  // The links that carry lookups; fall back to the global line.
  const routed = protocols.filter((line) => /\+DefaultRoute/.test(line));
  const relevant = routed.length ? routed : protocols.slice(0, 1);
  const strict = relevant.every((line) => /\+DNSOverTLS|DNSOverTLS=yes/.test(line));
  const opportunistic = relevant.every((line) => /\+DNSOverTLS|DNSOverTLS=(yes|opportunistic)/.test(line));
  // "Opportunistic" falls back to unencrypted when a server cannot do TLS.
  // It counts as encrypted only with servers configured by name for TLS
  // (1.1.1.1#cloudflare-dns.com), which is how Omarchy's DNS setting writes
  // them; with whatever servers the network handed out, it proves nothing.
  const named = /^\s*DNS Servers:.*#/m.test(status);
  if (!strict && opportunistic && !named) {
    return { status: 'unknown', source: 'none', basis: 'DNS over TLS is opportunistic with unnamed servers; encryption is not assured.' };
  }
  return {
    status: strict || opportunistic ? 'encrypted' : 'plaintext',
    source: 'measured',
    basis: 'Measured on this computer (systemd-resolved, DNS over TLS).',
  };
}

// ---------- sanitizing ----------

function redactIPv4(ip) {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/.exec(ip ?? '');
  return m ? `${m[1]}.x` : '<redacted>';
}

// ---------- scoring ----------

function scoreChecks(checks) {
  let known = 0;
  let earned = 0;
  const add = (weight, points) => { known += weight; earned += points; };

  for (const { port, weight } of PORTS) {
    if (checks.tcp[port] === 'unknown') continue;
    add(weight, checks.tcp[port] === 'not-reachable' ? weight : 0);
  }
  // No UPnP answer stays Unknown: it may be switched off, or this computer's
  // firewall may have dropped the reply.
  if (checks.upnp.state === 'detected') add(20, checks.upnp.mappingCount === 0 ? 10 : 0);
  if (checks.wifi.security !== 'unknown') add(20, checks.wifi.security === 'strong' ? 20 : 0);
  if (checks.wifi.sameChannelNeighbours !== null) {
    const n = checks.wifi.sameChannelNeighbours;
    add(10, n === 0 ? 10 : n <= 2 ? 5 : 0);
  }
  if (checks.dns.status !== 'unknown') add(20, checks.dns.status === 'encrypted' ? 20 : 0);

  return {
    provisional: known ? Math.round((earned / known) * 100) : null,
    earned,
    known,
    coverage: known,
  };
}

// ---------- findings ----------

// Each finding carries a machine-readable `state` (and `actionId`) beside its
// English text, so a front end can show it in another language.
function buildFindings(checks) {
  const findings = [{
    id: 'target', severity: 'INFO', state: 'gateway-only',
    summary: 'Only the private default gateway was inspected, from inside the home network.',
  }];
  const httpsAdmin = checks.tcp[HTTPS_PORT] === 'reachable';

  for (const { port, name, severity, action, actionId } of PORTS) {
    const open = checks.tcp[port] === 'reachable';
    if (checks.tcp[port] === 'unknown') {
      findings.push({ id: `tcp-${port}`, severity: 'INFO', state: 'unknown',
        summary: `Unknown: the router did not answer, so ${name} (port ${port}) could not be checked.` });
    } else if (!open) {
      findings.push({ id: `tcp-${port}`, severity: 'INFO', state: 'closed',
        summary: `${name} (port ${port}) is not reachable from this computer.` });
    } else if (port === 80 && httpsAdmin) {
      findings.push({ id: 'tcp-80', severity: 'LOW', state: 'open-https-available', actionId: 'use-https',
        action: 'Open the router admin page with https:// instead of http://.',
        summary: 'The router admin page answers over plain HTTP from this computer. It also offers HTTPS.' });
    } else {
      findings.push({ id: `tcp-${port}`, severity, state: 'open', action, actionId,
        summary: `${name} (port ${port}) is reachable from this computer. This says nothing about exposure to the internet.` });
    }
  }

  const { state, mappingCount } = checks.upnp;
  if (state === 'detected' && mappingCount > 0) {
    findings.push({ id: 'upnp', severity: 'MEDIUM', state: 'on-mappings', count: mappingCount, actionId: 'upnp-review',
      summary: `UPnP is on and holds ${mappingCount} port mapping(s) that devices opened by themselves.`,
      action: 'Review the UPnP port mappings in the router and turn UPnP off if nothing needs it.' });
  } else if (state === 'detected') {
    findings.push({ id: 'upnp', severity: 'LOW', state: 'on-empty', actionId: 'upnp-off',
      summary: 'UPnP is on but holds no port mappings right now.',
      action: 'Turn UPnP off in the router if no game console or app needs it.' });
  } else if (state === 'refused') {
    findings.push({ id: 'upnp', severity: 'REVIEW', state: 'other-device', actionId: 'upnp-other',
      summary: 'A UPnP device answered that is not the default gateway, so it was not queried.',
      action: 'Find out which device on the network answers UPnP gateway searches.' });
  } else {
    findings.push({ id: 'upnp', severity: 'INFO', state: state === 'no-answer' ? 'unknown-no-answer' : 'unknown',
      summary: state === 'no-answer'
        ? 'Unknown: no UPnP answer. It is either off, or this computer\'s firewall dropped the reply.'
        : 'Unknown: the UPnP query did not complete.' });
  }

  const wifi = checks.wifi;
  if (wifi.security === 'weak') {
    findings.push({ id: 'wifi-security', severity: 'HIGH', state: 'weak', actionId: 'wifi-wpa',
      summary: 'The Wi-Fi uses weak or no encryption.',
      action: 'Switch the Wi-Fi to WPA2-AES or WPA3 in the router.' });
  } else if (wifi.security === 'review') {
    findings.push({ id: 'wifi-security', severity: 'REVIEW', state: 'review', actionId: 'wifi-check',
      summary: 'The Wi-Fi security mode could not be classified.',
      action: 'Check in the router that Wi-Fi security is WPA2-AES or WPA3.' });
  } else if (wifi.security === 'strong') {
    findings.push({ id: 'wifi-security', severity: 'INFO', state: 'strong', summary: 'The Wi-Fi uses WPA2 or WPA3.' });
  } else {
    findings.push({ id: 'wifi-security', severity: 'INFO',
      state: wifi.state === 'not-on-wifi' ? 'unknown-wired' : wifi.state === 'other-network' ? 'unknown-other' : 'unknown',
      summary: wifi.state === 'not-on-wifi'
        ? 'Unknown: this computer is not connected over Wi-Fi, so Wi-Fi was not checked.'
        : wifi.state === 'other-network'
          ? 'Unknown: the Wi-Fi this computer is on belongs to a different network than the router being audited.'
          : 'Unknown: Wi-Fi security could not be read.' });
  }

  if (wifi.wps === 'on') {
    findings.push({ id: 'wifi-wps', severity: 'LOW', state: 'on', actionId: 'wps-off',
      summary: 'The Wi-Fi advertises WPS, the join-by-button or PIN feature.',
      action: 'Turn off WPS in the router; switch it on only while you add a device.' });
  } else if (wifi.wps === 'off') {
    findings.push({ id: 'wifi-wps', severity: 'INFO', state: 'off', summary: 'The Wi-Fi does not advertise WPS.' });
  } else {
    findings.push({ id: 'wifi-wps', severity: 'INFO', state: 'unknown', summary: 'Unknown: WPS could not be read.' });
  }

  if (wifi.sameChannelNeighbours === null) {
    findings.push({ id: 'wifi-channel', severity: 'INFO', state: 'unknown',
      summary: 'Unknown: channel congestion could not be counted.' });
  } else if (wifi.sameChannelNeighbours > 2) {
    findings.push({ id: 'wifi-channel', severity: 'LOW', state: 'crowded', count: wifi.sameChannelNeighbours,
      actionId: 'wifi-channel',
      summary: `${wifi.sameChannelNeighbours} other networks share this Wi-Fi channel.`,
      action: 'Move the Wi-Fi to a less crowded channel, or set channel selection to automatic.' });
  } else {
    findings.push({ id: 'wifi-channel', severity: 'INFO', state: 'clear', count: wifi.sameChannelNeighbours,
      summary: `${wifi.sameChannelNeighbours} other network(s) share this Wi-Fi channel.` });
  }

  const dns = checks.dns;
  if (dns.status === 'plaintext') {
    const measured = dns.source === 'measured';
    findings.push({ id: 'dns', severity: 'MEDIUM', state: measured ? 'plaintext-measured' : 'plaintext-declared',
      actionId: measured ? 'dns-computer' : 'dns-router',
      summary: measured
        ? 'This computer sends its DNS lookups unencrypted.'
        : 'You reported that DNS lookups are sent unencrypted.',
      action: measured
        ? 'Choose an encrypted DNS provider for this computer, or turn on encrypted DNS in the router.'
        : 'Turn on DNS over TLS or DNS over HTTPS in the router or on your devices.' });
  } else if (dns.status === 'encrypted') {
    const measured = dns.source === 'measured';
    findings.push({ id: 'dns', severity: 'INFO', state: measured ? 'encrypted-measured' : 'encrypted-declared',
      summary: measured
        ? 'This computer encrypts its DNS lookups. Other devices at home are not covered by this check.'
        : 'You reported that DNS lookups are encrypted.' });
  } else {
    findings.push({ id: 'dns', severity: 'REVIEW', state: 'unknown', actionId: 'dns-check',
      summary: 'Unknown: DNS encryption could not be read on this computer.',
      action: 'Check your DNS settings and rerun with --dns encrypted or --dns plaintext.' });
  }

  findings.push({ id: 'privacy', severity: 'INFO', state: 'sanitized',
    summary: 'The report holds no network names, hardware addresses, device names or full IP addresses.' });
  return findings;
}

function topFixes(findings) {
  const picked = [];
  for (const severity of SEVERITY_ORDER) {
    for (const f of findings) {
      if (f.severity === severity && f.action && !picked.some((p) => p.action === f.action)) picked.push(f);
    }
  }
  return picked.slice(0, 3);
}

// ---------- change tracking ----------

// The facts worth telling the owner about when they change. The neighbour
// count is banded, because it flickers by one from scan to scan.
function facts(checks) {
  const n = checks.wifi?.sameChannelNeighbours;
  const out = {};
  for (const port of [...PORTS.map((p) => p.port), HTTPS_PORT]) out[`tcp-${port}`] = checks.tcp?.[port] ?? 'unknown';
  // One lost UPnP reply looks exactly like UPnP being switched off, so only
  // an answering router is a fact; silence is Unknown, and so is a mapping
  // count nobody could read.
  const upnpRead = checks.upnp?.state === 'detected';
  out['upnp'] = upnpRead ? 'detected' : 'unknown';
  out['upnp-mappings'] = upnpRead ? String(checks.upnp.mappingCount ?? 0) : 'unknown';
  out['wifi-security'] = checks.wifi?.security ?? 'unknown';
  out['wifi-wps'] = checks.wifi?.wps ?? 'unknown';
  out['wifi-channel'] = n === null || n === undefined ? 'unknown' : n === 0 ? 'clear' : n <= 2 ? 'few' : 'crowded';
  out['dns'] = checks.dns?.status ?? 'unknown';
  return out;
}

function changedFacts(before, after) {
  const items = [];
  for (const key of Object.keys(after)) {
    // Evidence appearing or going missing (plugging in a cable, an older
    // report without this check) is not a change in the network itself.
    if (before[key] === 'unknown' || after[key] === 'unknown') continue;
    if (before[key] !== after[key]) items.push({ key, from: before[key], to: after[key] });
  }
  return items;
}

// ---------- report ----------

async function runAudit(opts, route, neighbour) {
  const { gateway } = route;
  const [tcp, upnp, wifi, dns] = await Promise.all([
    checkPorts(gateway, neighbour.alive), checkUpnp(gateway), checkWifi(gateway), checkDns(opts.dns),
  ]);

  const checks = {
    tcp,
    upnp: { state: upnp.state, mappingCount: upnp.mappings.length, mappings: upnp.mappings },
    wifi,
    dns,
  };
  const findings = buildFindings(checks);
  const fixes = topFixes(findings);

  return {
    title: 'Home network privacy check',
    generatedAt: new Date().toISOString(),
    target: '<private-gateway>',
    network: redactIPv4(gateway),
    // A scrambled id of the router, so a later scan can tell whether it is
    // looking at the same network. Empty when the router's address is unknown.
    networkId: networkId(neighbour.mac),
    checks,
    score: scoreChecks(checks),
    findings,
    topFixes: fixes.map((f) => f.action),
    topFixIds: fixes.map((f) => f.actionId ?? ''),
    privacy: {
      containsSsid: false,
      containsBssid: false,
      containsMacAddress: false,
      containsDeviceNames: false,
      containsRawUpnpDescriptions: false,
      containsFullPrivateIp: false,
    },
  };
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

// Saves the report and returns what changed since the one before it.
function saveSanitizedReport(report) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  const previous = readJson(REPORT);
  let changes = [];
  // A report from another network (a different home, an office) is not a
  // "before" for this one: no score comparison, no changes.
  const sameNetwork = Boolean(previous && report.networkId && previous.networkId === report.networkId);
  if (previous) fs.copyFileSync(REPORT, PREVIOUS);
  if (sameNetwork) {
    if (previous.score?.provisional != null && report.score.provisional != null) {
      report.comparison = {
        previousScore: previous.score.provisional,
        currentScore: report.score.provisional,
        delta: report.score.provisional - previous.score.provisional,
        previousGeneratedAt: previous.generatedAt,
      };
    }
    if (previous.checks) changes = changedFacts(facts(previous.checks), facts(report.checks));
    // The most recent change stays on the report until another one replaces it.
    report.lastChange = changes.length
      ? { at: report.generatedAt, items: changes }
      : previous.lastChange ?? null;
  }
  // Written beside the report and renamed over it, so a reader never sees
  // half a file.
  const partial = `${REPORT}.${process.pid}.tmp`;
  fs.writeFileSync(partial, `${JSON.stringify(report, null, 2)}\n`);
  fs.renameSync(partial, REPORT);
  return changes;
}

// Plain English for the terminal and the desktop notification. The bar widget
// shows the same change in the owner's language from its own catalogue.
const FACT_NAMES = {
  'tcp-22': 'SSH', 'tcp-23': 'Telnet', 'tcp-80': 'Web admin', 'tcp-443': 'HTTPS admin',
  'tcp-7547': 'Remote management', upnp: 'UPnP', 'upnp-mappings': 'UPnP port mappings',
  'wifi-security': 'Wi-Fi security', 'wifi-wps': 'WPS', 'wifi-channel': 'Wi-Fi channel', dns: 'DNS',
};
const VALUE_NAMES = {
  'not-reachable': 'not reachable', detected: 'on', 'no-answer': 'no answer', refused: 'another device',
  review: 'unclear', few: 'a few neighbours', plaintext: 'unencrypted',
};

function describeChange({ key, from, to }) {
  return `${FACT_NAMES[key] ?? key}: ${VALUE_NAMES[from] ?? from} -> ${VALUE_NAMES[to] ?? to}`;
}

// A desktop notification through whichever sender this machine has.
async function notify(changes, report) {
  const body = `${changes.slice(0, 4).map(describeChange).join('\n')}\nScore: ${report.score.provisional ?? 'unknown'}/100`;
  for (const [command, args] of [
    ['omarchy-notification-send', ['Home network changed', body]],
    ['notify-send', ['Home network changed', body]],
  ]) {
    const sent = await new Promise((resolve) => execFile(command, args, { timeout: 5000 }, (error) => resolve(!error)));
    if (sent) return;
  }
}

function printReport(report) {
  const { score } = report;
  console.log(`\n${report.title}`);
  console.log(`Target: ${report.target} on ${report.network}`);
  console.log(score.provisional === null
    ? 'Score: unknown (no check produced evidence)'
    : `Provisional score: ${score.provisional}/100 (${score.earned} of ${score.known} known points; evidence coverage ${score.coverage}%)`);
  console.log('\nFindings');
  for (const f of report.findings) console.log(`  [${f.severity.padEnd(6)}] ${f.id}: ${f.summary}`);
  if (report.comparison) {
    const { previousScore, currentScore, delta } = report.comparison;
    console.log(`\nBefore/after: ${previousScore} -> ${currentScore} (${delta >= 0 ? '+' : ''}${delta})`);
  } else {
    console.log('\nBefore/after: no earlier scored report to compare with.');
  }
  console.log('\nTop actions');
  if (!report.topFixes.length) console.log('  None.');
  report.topFixes.forEach((action, i) => console.log(`  ${i + 1}. ${action}`));
  console.log(`\nSaved: ${REPORT}`);
}

// One audit. Resolves with null when --only-network names another network
// than the one this computer is on, in which case nothing was scanned.
async function auditOnce(opts) {
  const route = await findRoute();
  const neighbour = await gatewayNeighbour(route.gateway, route.dev);
  if (opts.onlyNetwork && networkId(neighbour.mac) !== opts.onlyNetwork) return null;
  const report = await runAudit(opts, route, neighbour);
  const changes = saveSanitizedReport(report);
  if (opts.notify && changes.length) await notify(changes, report);
  return { report, changes };
}

// ---------- watch mode ----------

async function watch(opts) {
  const first = await auditOnce(opts);
  if (first && !opts.quiet) printReport(first.report);
  console.log(`\nWatching: rerunning every ${opts.minutes} minutes. Press Ctrl+C to stop.`);

  setInterval(async () => {
    const stamp = new Date().toLocaleTimeString();
    try {
      const result = await auditOnce(opts);
      if (!result) {
        console.log(`[${stamp}] Skipped: this computer is on another network.`);
        return;
      }
      const { report, changes } = result;
      if (!changes.length) {
        console.log(`[${stamp}] No change.`);
        return;
      }
      console.log(`[${stamp}] CHANGED (score ${report.score.provisional ?? 'unknown'}):`);
      for (const change of changes) console.log(`  ${describeChange(change)}`);
    } catch (error) {
      console.log(`[${stamp}] Audit skipped: ${error.message}`);
    }
  }, opts.minutes * 60 * 1000);
}

// ---------- main ----------

// The pieces the tests exercise. Nothing here scans by being imported.
export {
  isPrivateGateway, classifySecurity, classifyPorts, terseFields, xmlValue, findMappingService,
  readMappingTable, request, redactIPv4, scoreChecks, buildFindings, facts, changedFacts,
  describeChange, parseArgs,
};

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  try {
    const opts = parseArgs(process.argv.slice(2));
    if (opts.printNetwork) {
      // For the helper: which network is this? Prints nothing when the
      // router's address is not known.
      const route = await findRoute();
      const id = networkId((await gatewayNeighbour(route.gateway, route.dev)).mac);
      if (id) console.log(id);
    } else if (opts.watch) {
      await watch(opts);
    } else {
      const saved = opts.maxAge ? readJson(REPORT) : null;
      const age = saved?.generatedAt ? (Date.now() - Date.parse(saved.generatedAt)) / 60000 : Infinity;
      if (!(age < opts.maxAge)) {
        const result = await auditOnce(opts);
        if (result && !opts.quiet) printReport(result.report);
      }
    }
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
