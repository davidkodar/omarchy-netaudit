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
// Nothing this program sends may go through a proxy: every request is to the
// router on the local link. The helper starts it without these variables;
// they are dropped here too, for anyone running it by hand.
for (const name of ['http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'NODE_USE_ENV_PROXY']) {
  delete process.env[name];
  delete process.env[name.toUpperCase()];
}

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
  const opts = { dns: 'auto', watch: false, minutes: 30, quiet: false, notify: false, maxAge: 0, onlyNetwork: '', printNetwork: false, dnsNetwork: '', rescore: false, cachedWifi: false };
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
    } else if (arg === '--dns-network') {
      opts.dnsNetwork = String(argv[++i] ?? '');
      if (!/^[0-9a-f]{16}$/.test(opts.dnsNetwork)) throw new Error('--dns-network needs a network id');
    } else if (arg === '--cached-wifi') {
      opts.cachedWifi = true;
    } else if (arg === '--rescore') {
      opts.rescore = true;
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
        '                 auto (default) reads this computer\'s resolver; encrypted and',
        '                 plaintext declare what you know of one network\'s router',
        '                 and need --dns-network.',
        '  --watch [min]  Rerun every N minutes (default 30) and print what changed.',
        '  --max-age <min>  Do nothing if the saved report is newer than this.',
        '  --notify       Send a desktop notification when a check changed.',
        '  --dns-network <id>  Apply a declared --dns only on that network.',
        '  --rescore      Apply --dns to the saved report without scanning anything.',
        '  --cached-wifi  Use the Wi-Fi list NetworkManager already has; do not rescan.',
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
  // A declaration is about one network; it has to say which.
  if ((opts.dns === 'encrypted' || opts.dns === 'plaintext') && !opts.dnsNetwork) {
    throw new Error(`--dns ${opts.dns} needs --dns-network <id>; --network-id prints the id of this network`);
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

// Two addresses used only as questions to the kernel: "which way would
// traffic to the internet go?". One sits in each half of the address space,
// because a VPN can take over the internet with two half-routes instead of a
// default route. Nothing is ever sent to either.
const ROUTE_PROBES = ['1.1.1.1', '192.0.2.1'];

// Reads one answer of `ip route get`.
function parseRouteGet(text) {
  const line = String(text).split('\n')[0] ?? '';
  return {
    via: /\bvia (\S+)/.exec(line)?.[1] ?? '',
    dev: /\bdev (\S+)/.exec(line)?.[1] ?? '',
    src: /\bsrc (\S+)/.exec(line)?.[1] ?? '',
  };
}

// The devices of every route that can carry internet traffic, in every
// routing table: default routes, and the half-routes (0.0.0.0/1, 128.0.0.0/1,
// ::/1, 8000::/1) some VPNs use in their place. A VPN often keeps these in a
// table of its own, selected by a policy rule, where the ordinary table still
// shows the cable.
function defaultRouteDevices(text) {
  const devices = [];
  let wide = false;
  for (const raw of String(text).split('\n')) {
    // The next hops of a multipath route are listed on lines of their own.
    if (/^\s+nexthop\b/.test(raw)) {
      const dev = /\bdev (\S+)/.exec(raw)?.[1];
      if (wide && dev) devices.push(dev);
      continue;
    }
    const words = raw.trim().split(/\s+/);
    // Routes that carry nothing ("unreachable default", "blackhole ...").
    if (['unreachable', 'blackhole', 'prohibit', 'throw'].includes(words[0])) { wide = false; continue; }
    const target = ['unicast', 'local', 'broadcast', 'multicast', 'anycast', 'nat'].includes(words[0]) ? words[1] : words[0];
    // "Wide" is the default route or any prefix of three bits or fewer:
    // 0.0.0.0/1 and 128.0.0.0/1, the /2 quarters, ::/1, 8000::/1, 2000::/3.
    const length = /\/(\d+)$/.exec(target ?? '')?.[1];
    wide = target === 'default' || (length !== undefined && Number(length) <= 3);
    if (!wide) continue;
    const dev = /\bdev (\S+)/.exec(raw)?.[1];
    if (dev) devices.push(dev);
  }
  return devices;
}

// The router traffic really leaves through, as the kernel decides it, policy
// rules included, and this computer's own address on that link. Stops unless
// the way out is a private router one hop away on a real network card, and no
// VPN or tunnel carries internet traffic in any routing table, IPv4 or IPv6.
async function findRoute() {
  const answers = [];
  for (const probe of ROUTE_PROBES) answers.push(parseRouteGet(await run('ip', ['-4', '-o', 'route', 'get', probe])));
  const out = answers[0];
  if (!out.dev) throw new Error('Safety stop: this computer has no route to the internet.');
  if (answers.some((a) => a.via !== out.via || a.dev !== out.dev)) {
    throw new Error('Safety stop: traffic is split between routes, as a VPN does, so the audit will not run.');
  }
  if (!out.via || !isHomeLink(out.dev)) {
    throw new Error('Safety stop: traffic leaves through a VPN, a tunnel or a virtual network, not a home router.');
  }
  if (!isPrivateGateway(out.via)) {
    throw new Error('Safety stop: the default gateway is not a private IPv4 address.');
  }
  const carriers = [
    ...defaultRouteDevices(await run('ip', ['-4', 'route', 'show', 'table', 'all'])),
    ...defaultRouteDevices(await run('ip', ['-6', 'route', 'show', 'table', 'all'])),
  ];
  if (carriers.some((dev) => dev !== 'lo' && !isHomeLink(dev))) {
    throw new Error('Safety stop: a VPN, a tunnel or a virtual network carries internet traffic, so the audit will not run.');
  }
  // The router has to be a direct neighbour on that same link, also for
  // traffic sent from the address the scan will use.
  const hop = parseRouteGet(await run('ip', ['-4', '-o', 'route', 'get', out.via]));
  if (hop.via || hop.dev !== out.dev || !net.isIPv4(hop.src)) {
    throw new Error('Safety stop: the default gateway is not directly reachable on the local link.');
  }
  const bound = parseRouteGet(await run('ip', ['-4', '-o', 'route', 'get', out.via, 'from', hop.src]));
  if (bound.via || bound.dev !== out.dev) {
    throw new Error('Safety stop: traffic from this computer\'s address would not go straight to the gateway.');
  }
  return { gateway: out.via, dev: out.dev, src: hop.src };
}

// True only for a real network card: a cable or Wi-Fi adapter. Tunnels are
// not (tun, WireGuard, PPP), and neither are the virtual Ethernet devices a
// VPN or a virtual machine can present, which look like a cable to most
// checks (tap devices, bridges, veth, VXLAN, ZeroTier): those have no
// hardware device behind them.
function isHomeLink(dev, root = '/sys/class/net') {
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(dev)) return false;
  const at = path.join(root, dev);
  try {
    if (fs.readFileSync(path.join(at, 'type'), 'utf8').trim() !== '1') return false;
    if (fs.existsSync(path.join(at, 'tun_flags'))) return false;
    if (fs.existsSync(path.join(at, 'bridge')) || fs.existsSync(path.join(at, 'bonding'))) return false;
    return fs.existsSync(path.join(at, 'device'));
  } catch { return false; }
}

// The gateway's entry in the neighbour table: whether the router has answered
// this computer lately, and its hardware address. The address is used only
// in memory, to tell one network from another; see networkId.
async function gatewayNeighbour(gateway, dev) {
  const line = (await run('ip', ['neigh', 'show', gateway, 'dev', dev])).split('\n')[0] ?? '';
  const mac = /\blladdr ([0-9a-f:]{17})\b/i.exec(line)?.[1]?.toLowerCase() ?? '';
  const state = /\b(REACHABLE|STALE|DELAY|PROBE|FAILED|INCOMPLETE|PERMANENT|NOARP)\b/.exec(line)?.[1] ?? '';
  return { mac, state };
}

// A scrambled id for "this network": a salted hash of the router's hardware
// address, so two scans can be told to be of the same network without the
// address itself ever being stored. The salt is random and stays on this
// computer.
function networkId(mac) {
  if (!mac) return '';
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const saltFile = path.join(STATE_DIR, 'salt');
  const read = () => { try { return fs.readFileSync(saltFile, 'utf8').trim(); } catch { return ''; } };
  let salt = read();
  if (!/^[0-9a-f]{32}$/.test(salt)) {
    // "wx" fails if another run made the file first; then theirs is used. A
    // file that is there but damaged is replaced.
    const fresh = `${crypto.randomBytes(16).toString('hex')}\n`;
    try { fs.writeFileSync(saltFile, fresh, { mode: 0o600, flag: 'wx' }); } catch { /* it exists */ }
    salt = read();
    if (!/^[0-9a-f]{32}$/.test(salt)) {
      try {
        fs.writeFileSync(`${saltFile}.${process.pid}.tmp`, fresh, { mode: 0o600 });
        fs.renameSync(`${saltFile}.${process.pid}.tmp`, saltFile);
      } catch { return ''; }
      salt = read();
      if (!/^[0-9a-f]{32}$/.test(salt)) return '';
    }
  }
  return crypto.createHash('sha256').update(`${salt}:${mac}`).digest('hex').slice(0, 16);
}

// ---------- checks ----------

// Connect, then close at once. Nothing is sent or read. Resolves with how
// the attempt ended: 'open', 'refused' (the router answered "closed"),
// 'timeout' (no answer) or 'error' (the attempt never reached the router).
function probePort(host, port, localAddress) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, localAddress });
    const done = (outcome) => { socket.destroy(); resolve(outcome); };
    socket.setTimeout(800);
    socket.once('connect', () => done('open'));
    socket.once('timeout', () => done('timeout'));
    socket.once('error', (error) => done(error.code === 'ECONNREFUSED' ? 'refused' : 'error'));
  });
}

// Whether the router is answering this computer right now. The attempts made
// the kernel look for it: REACHABLE means it has just answered. STALE is a
// memory of an old answer, and DELAY and PROBE mean the kernel is still
// asking, so those are waited on, for longer than the kernel takes to give
// up, and count only if they end in an answer.
async function routerAnswers(gateway, dev, waitMs = 8000) {
  const until = Date.now() + waitMs;
  for (;;) {
    const { state } = await gatewayNeighbour(gateway, dev);
    if (state === 'REACHABLE') return true;
    if (!['STALE', 'DELAY', 'PROBE'].includes(state) || Date.now() >= until) return false;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
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

async function checkPorts({ gateway, dev, src }) {
  const outcomes = {};
  await Promise.all([...PORTS.map((p) => p.port), HTTPS_PORT].map(async (port) => {
    // A single missed connection is not evidence that a port is closed, so
    // an attempt without a clear answer is repeated, three in all.
    let outcome = 'error';
    for (let attempt = 0; attempt < 3; attempt++) {
      outcome = await probePort(gateway, port, src);
      if (outcome === 'open' || outcome === 'refused') break;
    }
    outcomes[port] = outcome;
  }));
  // Silence is only a closed port if the router is there. One clear answer on
  // any port settles that; without one, the kernel is asked.
  const answered = Object.values(outcomes).some((o) => o === 'open' || o === 'refused');
  return classifyPorts(outcomes, answered || await routerAnswers(gateway, dev));
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

// The address of a UPnP description or control point, accepted only in its
// plainest form: http, the router's own IP address, port 80 or an
// unprivileged port, and a path made of ordinary characters. A reply to the
// search can be forged by any device on the network, so nothing in it may
// carry a user name, a password, a query string or a fragment: the scanner
// must not be steerable into sending the router a request of someone else's
// design.
function routerUrl(text, gateway, base) {
  let url;
  try { url = base ? new URL(String(text), base) : new URL(String(text)); } catch { return null; }
  const port = Number(url.port || 80);
  if (url.protocol !== 'http:' || url.hostname !== gateway) return null;
  if (url.username || url.password || url.search || url.hash) return null;
  if (port !== 80 && (port < 1024 || port > 65535)) return null;
  if (!/^\/[A-Za-z0-9_.~:\/-]{0,200}$/.test(url.pathname) || url.pathname.includes('..')) return null;
  return url.href;
}

// Searches for an internet gateway. Resolves with the description URL the
// gateway itself announced, 'other' when only some other device answered, or
// null when nothing did.
function discoverGateway(gateway, src, waitMs = 4000) {
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
      const location = /^location:[ \t]*(\S{1,300})/im.exec(data.subarray(0, 4096).toString('latin1'))?.[1];
      // Only the gateway's own answer, pointing back at the gateway, counts.
      const url = remote.address === gateway ? routerUrl(location, gateway) : null;
      if (url) finish(url);
      else sawOther = true;
    });
    socket.bind(0, src, () => {
      // The search leaves through the router's link and no other.
      try { socket.setMulticastInterface(src); } catch { finish(null); return; }
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
//
// It uses an agent of its own, which knows nothing of proxies, starts from
// this computer's address on the router's link, and gives up if the machine
// it finds itself connected to is not the one in the URL.
const DIRECT = new http.Agent({ keepAlive: false });

function request(url, { method = 'GET', headers = {}, body, localAddress } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn, value) => { if (!settled) { settled = true; clearTimeout(deadline); fn(value); } };
    const expected = new URL(url).hostname;
    const req = http.request(url, { method, headers, agent: DIRECT, localAddress }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > 128 * 1024) { req.destroy(); settle(reject, new Error('response too large')); return; }
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
    req.on('socket', (socket) => socket.once('connect', () => {
      if (socket.remoteAddress !== expected) { req.destroy(); settle(reject, new Error('not connected to the router')); }
    }));
    req.on('error', (error) => settle(reject, error));
    if (body) req.write(body);
    req.end();
  });
}

// The text of the first <tag>…</tag> in a piece of XML, with or without a
// namespace prefix. Written with plain searches, not a pattern: the XML comes
// from the router, and a pattern can be made to take minutes on hostile input.
// Lower case for ASCII letters only, so that positions in the folded text
// are positions in the original (some other letters change length).
function asciiLower(text) {
  return String(text).replace(/[A-Z]+/g, (letters) => letters.toLowerCase());
}

// XML with its comments removed, so that a commented-out value is not read.
function withoutComments(xml) {
  const text = String(xml);
  let out = '';
  let from = 0;
  for (;;) {
    const start = text.indexOf('<!--', from);
    if (start < 0) return out + text.slice(from);
    out += text.slice(from, start);
    const end = text.indexOf('-->', start + 4);
    if (end < 0) return out;
    from = end + 3;
  }
}

function xmlValue(xml, tag) {
  const text = withoutComments(xml);
  const lower = asciiLower(text);
  const name = asciiLower(tag);
  let from = 0;
  for (;;) {
    const at = lower.indexOf(name, from);
    if (at < 0) return '';
    from = at + name.length;
    // "<name" or "<prefix:name", then the end of the name.
    const before = lower.slice(Math.max(0, at - 33), at);
    if (!/<(?:[a-z0-9_-]{1,31}:)?$/.test(before)) continue;
    const next = lower[from];
    if (next !== '>' && next !== ' ' && next !== '\t' && next !== '\n' && next !== '\r') continue;
    const open = lower.indexOf('>', from);
    if (open < 0) return '';
    if (text.startsWith('<![CDATA[', open + 1)) {
      const end = text.indexOf(']]>', open + 10);
      return end < 0 ? '' : text.slice(open + 10, end).trim();
    }
    const close = lower.indexOf('<', open + 1);
    if (close < 0) return '';
    return text.slice(open + 1, close).trim();
  }
}

// The <service>…</service> blocks of a description, found the same way.
function serviceBlocks(description) {
  const text = withoutComments(description);
  const lower = asciiLower(text);
  const blocks = [];
  let from = 0;
  while (blocks.length < 64) {
    const start = lower.indexOf('<service>', from);
    if (start < 0) break;
    const end = lower.indexOf('</service>', start);
    if (end < 0) break;
    blocks.push(text.slice(start, end));
    from = end + 10;
  }
  return blocks;
}

// The control URL of the gateway's port-mapping service, from its description.
function findMappingService(description, location, gateway) {
  for (const block of serviceBlocks(description)) {
    const type = xmlValue(block, 'serviceType');
    if (!MAPPING_SERVICES.includes(type)) continue;
    // Never follow a description that points anywhere but the gateway, and
    // only to an address of the same plain form as the description's own.
    const base = routerUrl(xmlValue(description, 'URLBase') || location, gateway);
    const control = base ? routerUrl(xmlValue(block, 'controlURL'), gateway, base) : null;
    if (!control) continue;
    return { type, control };
  }
  return null;
}

async function readMapping(service, index, localAddress) {
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
    localAddress,
  });
}

// Reads the whole port-mapping table, sanitized. Resolves with null when the
// table could not be read at all.
async function readMappingTable(service, here, budgetMs = 20000, localAddress = undefined) {
  const mappings = [];
  const started = Date.now();
  const seen = new Set();
  for (let index = 0; index < MAX_MAPPINGS; index++) {
    // A table that cannot be read in the time allowed is not a table.
    if (Date.now() - started > budgetMs) return null;
    const reply = await readMapping(service, index, localAddress);
    if (reply.status !== 200) {
      // A router ends its table with a fault. 713 and 714 are the standard's
      // "no such entry". Some routers answer 402 or 501 there instead, but
      // those also mean "bad request", so they end a table only after at
      // least one entry was read; at the first entry they prove nothing, and
      // any other failure anywhere means the table could not be read.
      const code = Number(xmlValue(reply.text, 'errorCode'));
      if (code === 713 || code === 714) break;
      if (index > 0 && (code === 402 || code === 501)) break;
      return null;
    }
    // A page that answers "200 OK" without being a mapping entry (a login
    // page, a fault sent with the wrong status) is not a mapping: the table
    // could not be read.
    const portText = xmlValue(reply.text, 'NewExternalPort');
    const externalPort = Number(portText);
    // Port 0 is a wildcard entry, which some routers list.
    if (!xmlValue(reply.text, 'NewProtocol') || !/^\d{1,5}$/.test(portText) || externalPort > 65535) return null;
    const internal = xmlValue(reply.text, 'NewInternalClient');
    // A table holds one entry per remote host, external port and protocol.
    // The same three again means the router is ignoring the index, or going
    // round in circles: the table has been read.
    const key = ['NewRemoteHost', 'NewExternalPort', 'NewProtocol'].map((tag) => xmlValue(reply.text, tag)).join('|');
    if (seen.has(key)) break;
    seen.add(key);
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

async function checkUpnp({ gateway, src }) {
  try {
    // One silent search is not evidence that UPnP is off, so search twice.
    let location = await discoverGateway(gateway, src);
    if (!location || location === 'other') {
      const second = await discoverGateway(gateway, src);
      location = second && second !== 'other' ? second : (location || second);
    }
    if (!location) return { state: 'no-answer', mappings: [] };
    if (location === 'other') return { state: 'refused', mappings: [] };

    const description = await request(location, { localAddress: src });
    // What came back has to be a UPnP device description, or it is not read.
    const isDescription = description.status === 200 && description.text.includes('urn:schemas-upnp-org:device');
    const service = isDescription ? findMappingService(description.text, location, gateway) : null;
    if (!service) return { state: 'unknown', mappings: [] };

    const mappings = await readMappingTable(service, src, 20000, src);
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
  const words = s.split(/[\s,/]+/);
  const modern = words.some((w) => /^(WPA2|WPA3|RSN|SAE)/.test(w));
  const firstWpa = words.some((w) => w === 'WPA' || w === 'WPA1');
  if (words.some((w) => /^(WEP|TKIP|OPEN|NONE)/.test(w)) || (firstWpa && !modern)) return 'weak';
  // WPA2 with the first WPA still switched on accepts the old, broken mode.
  if (modern && firstWpa) return 'legacy';
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
async function checkWifi(route, routerMac, rescan = true) {
  const { gateway } = route;
  const result = { state: 'unknown', security: 'unknown', sameChannelNeighbours: null, wps: 'unknown' };
  // NetworkManager may make the Wi-Fi card look for networks again before it
  // answers. The background check asks for the list it already has instead.
  const list = await run('nmcli', ['-t', '-f', 'IN-USE,CHAN,SECURITY,DEVICE,SSID', 'device', 'wifi', 'list',
    '--rescan', rescan ? 'auto' : 'no'], 20000);
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
  // "Same" means the same hardware, not just the same address: a neighbour's
  // network very often uses the same 192.168 address for its own router.
  let sameRouter = current.device === route.dev;
  if (!sameRouter && /^[A-Za-z0-9_.-]{1,32}$/.test(current.device)) {
    const wifiRoutes = await run('ip', ['-4', 'route', 'show', 'default', 'dev', current.device]);
    const sameAddress = wifiRoutes.split('\n').some((line) => /\bvia (\S+)/.exec(line)?.[1] === gateway);
    const viaWifi = sameAddress ? (await gatewayNeighbour(gateway, current.device)).mac : '';
    // Same address, but this computer has not spoken to the router over the
    // Wi-Fi lately: it cannot be told whose router that is.
    if (sameAddress && (!viaWifi || !routerMac)) return { ...result, state: 'unconfirmed' };
    sameRouter = Boolean(viaWifi) && viaWifi === routerMac;
  }
  if (!sameRouter) return { ...result, state: 'other-network' };

  result.security = classifySecurity(current.security);
  result.wps = await checkWps(current.device);
  // A list that holds nothing but this network's own access points is not
  // evidence of an empty channel when it was not freshly gathered: the card
  // may simply not have looked lately.
  const sawOthers = networks.some((n) => !n.inUse && n.name !== current.name);
  if (current.channel && (rescan || sawOthers)) {
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
// What `resolvectl status` says about DNS over TLS on the links that carry
// lookups: 'encrypted' only in strict mode, where a server that cannot do
// TLS means no answer at all; 'opportunistic' when TLS is tried but the
// resolver may fall back to plain text without saying so, whichever server is
// configured; 'plaintext' when TLS is off; 'unknown' when it cannot be read.
function classifyDns(status) {
  const text = String(status);
  // Programs that read /etc/resolv.conf themselves only go through
  // systemd-resolved in "stub" mode. In any other mode they may talk to the
  // DNS servers directly, in plain text, whatever the resolver is set to.
  const mode = /^\s*resolv\.conf mode:\s*(\S+)/m.exec(text)?.[1];
  if (mode && mode !== 'stub') return 'unknown';

  const scopes = [];
  let field = '';
  for (const line of text.split('\n')) {
    if (/^(Global|Link \d+)/.test(line)) {
      field = '';
      scopes.push({ global: line.startsWith('Global'), protocols: '', servers: false, everything: false });
      continue;
    }
    const scope = scopes.at(-1);
    if (!scope) continue;
    // A long value runs on to further lines, which carry no label of their own.
    const label = /^\s*([A-Za-z][A-Za-z. ]*):/.exec(line)?.[1];
    if (label) field = label.trim();
    if (label && field === 'Protocols') scope.protocols = line;
    if (label && field === 'DNS Servers') scope.servers = true;
    // The routing domain "~." sends every lookup to this link.
    if (field === 'DNS Domain' && /(^|[\s:])~\.(\s|$)/.test(line)) scope.everything = true;
  }
  // Lookups go to the links that carry the default route, and to the global
  // servers when there are any; with neither, the global setting decides.
  const links = scopes.filter((scope) => !scope.global && (scope.everything || /\+DefaultRoute/.test(scope.protocols)));
  const global = scopes.find((scope) => scope.global && scope.protocols);
  const relevant = [...links];
  if (global && (global.servers || !links.length)) relevant.push(global);
  if (!relevant.length) return 'unknown';
  if (relevant.every((scope) => /\+DNSOverTLS|DNSOverTLS=yes/.test(scope.protocols))) return 'encrypted';
  if (relevant.every((scope) => /\+DNSOverTLS|DNSOverTLS=(yes|opportunistic)/.test(scope.protocols))) return 'opportunistic';
  return 'plaintext';
}

async function checkDns(choice) {
  if (choice !== 'auto') {
    return {
      status: choice,
      source: choice === 'unknown' ? 'none' : 'declared',
      basis: choice === 'unknown' ? 'No explicit evidence supplied.' : 'Declared by the owner.',
    };
  }
  const status = classifyDns(await run('resolvectl', ['status']));
  if (status === 'unknown') return { status, source: 'none', basis: 'This computer\'s resolver could not be read.' };
  return { status, source: 'measured', basis: 'Measured on this computer (systemd-resolved, DNS over TLS).' };
}

// A declaration ("my router encrypts DNS") is about one network. Anywhere
// else it does not apply, and DNS is measured instead.
function dnsChoiceFor(opts, currentNetwork) {
  if (opts.dns === 'auto' || opts.dns === 'unknown') return opts.dns;
  return opts.dnsNetwork && currentNetwork === opts.dnsNetwork ? opts.dns : 'auto';
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
  // Opportunistic encryption can fall back to plain text, so it earns half.
  if (checks.dns.status !== 'unknown') {
    add(20, checks.dns.status === 'encrypted' ? 20 : checks.dns.status === 'opportunistic' ? 10 : 0);
  }

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
  } else if (wifi.security === 'legacy') {
    findings.push({ id: 'wifi-security', severity: 'LOW', state: 'legacy', actionId: 'wifi-wpa',
      summary: 'The Wi-Fi still accepts the first version of WPA beside WPA2.',
      action: 'Switch the Wi-Fi to WPA2-AES or WPA3 in the router.' });
  } else if (wifi.security === 'review') {
    findings.push({ id: 'wifi-security', severity: 'REVIEW', state: 'review', actionId: 'wifi-check',
      summary: 'The Wi-Fi security mode could not be classified.',
      action: 'Check in the router that Wi-Fi security is WPA2-AES or WPA3.' });
  } else if (wifi.security === 'strong') {
    findings.push({ id: 'wifi-security', severity: 'INFO', state: 'strong', summary: 'The Wi-Fi uses WPA2 or WPA3.' });
  } else {
    findings.push({ id: 'wifi-security', severity: 'INFO',
      state: wifi.state === 'not-on-wifi' ? 'unknown-wired' : wifi.state === 'other-network' ? 'unknown-other'
        : wifi.state === 'unconfirmed' ? 'unknown-unconfirmed' : 'unknown',
      summary: wifi.state === 'not-on-wifi'
        ? 'Unknown: this computer is not connected over Wi-Fi, so Wi-Fi was not checked.'
        : wifi.state === 'other-network'
          ? 'Unknown: the Wi-Fi this computer is on belongs to a different network than the router being audited.'
          : wifi.state === 'unconfirmed'
            ? 'Unknown: it could not be confirmed that the Wi-Fi this computer is on belongs to the router being audited.'
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
  } else if (dns.status === 'opportunistic') {
    findings.push({ id: 'dns', severity: 'LOW', state: 'opportunistic', actionId: 'dns-strict',
      summary: 'This computer encrypts DNS lookups when the server allows it, but can fall back to unencrypted without warning.',
      action: 'For assured encryption, set systemd-resolved to strict DNS over TLS (DNSOverTLS=yes) with a server that supports it.' });
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
  const network = networkId(neighbour.mac);
  const [tcp, upnp, wifi, dns] = await Promise.all([
    checkPorts(route), checkUpnp(route), checkWifi(route, neighbour.mac, !opts.cachedWifi), checkDns(dnsChoiceFor(opts, network)),
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
    networkId: network,
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

// Written beside the report and renamed over it, so a reader never sees half
// a file. The report describes the owner's network: only the owner may read it.
function writeReport(report) {
  const partial = `${REPORT}.${process.pid}.tmp`;
  fs.writeFileSync(partial, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(partial, REPORT);
}

// Saves the report and returns what changed since the one before it.
function saveSanitizedReport(report) {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(STATE_DIR, 0o700); } catch { /* not ours to change */ }
  for (const name of fs.readdirSync(STATE_DIR)) {
    if (/\.\d+\.tmp$/.test(name)) { try { fs.unlinkSync(path.join(STATE_DIR, name)); } catch { /* in use */ } }
  }
  const previous = readJson(REPORT);
  let changes = [];
  // A report from another network (a different home, an office) is not a
  // "before" for this one: no score comparison, no changes.
  const sameNetwork = Boolean(previous && report.networkId && previous.networkId === report.networkId);
  if (previous) {
    fs.copyFileSync(REPORT, PREVIOUS);
    try { fs.chmodSync(PREVIOUS, 0o600); } catch { /* best effort */ }
  }
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
  writeReport(report);
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
  review: 'unclear', few: 'a few neighbours', plaintext: 'unencrypted', opportunistic: 'encrypted when possible',
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

// Applies the DNS choice to the saved report and saves it again. Nothing is
// sent anywhere: the other checks are kept exactly as the last scan left
// them, and DNS is either the owner's declaration or this computer's own
// resolver setting. This is what the widget's DNS links do, so that a click
// on a DNS link can never turn into a scan.
async function rescoreSaved(opts) {
  const report = readJson(REPORT);
  if (!report?.checks?.tcp) throw new Error('There is no saved report to update. Scan first.');
  report.checks.dns = await checkDns(dnsChoiceFor(opts, report.networkId || ''));
  report.score = scoreChecks(report.checks);
  report.findings = buildFindings(report.checks);
  const fixes = topFixes(report.findings);
  report.topFixes = fixes.map((f) => f.action);
  report.topFixIds = fixes.map((f) => f.actionId ?? '');
  if (report.comparison && typeof report.comparison.previousScore === 'number' && report.score.provisional != null) {
    report.comparison.currentScore = report.score.provisional;
    report.comparison.delta = report.score.provisional - report.comparison.previousScore;
  }
  writeReport(report);
  return report;
}

// One audit. Resolves with null when --only-network names another network
// than the one this computer is on, in which case nothing was scanned.
async function auditOnce(opts) {
  const route = await findRoute();
  const neighbour = await gatewayNeighbour(route.gateway, route.dev);
  if (opts.onlyNetwork && networkId(neighbour.mac) !== opts.onlyNetwork) return null;
  const report = await runAudit(opts, route, neighbour);
  // A VPN can come up, or the cable be moved, while a scan runs. The route is
  // looked up again, and if anything about it has changed the results are
  // thrown away: they may be about something else than was checked.
  const after = await findRoute();
  if (after.gateway !== route.gateway || after.dev !== route.dev || after.src !== route.src) {
    throw new Error('Safety stop: the network changed during the scan, so nothing was saved.');
  }
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
  isPrivateGateway, isHomeLink, routerUrl, asciiLower, classifySecurity, classifyPorts, classifyDns,
  dnsChoiceFor, parseRouteGet, defaultRouteDevices, terseFields, xmlValue, findMappingService,
  readMappingTable, request, redactIPv4, scoreChecks, buildFindings, facts, changedFacts,
  describeChange, parseArgs,
};

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  try {
    const opts = parseArgs(process.argv.slice(2));
    if (opts.rescore) {
      const report = await rescoreSaved(opts);
      if (!opts.quiet) printReport(report);
    } else if (opts.printNetwork) {
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
