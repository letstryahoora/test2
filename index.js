'use strict';
/*
 * Single-port panel: VLESS + Trojan over WebSocket (plain and TLS) and a web panel,
 * all on the one port a free Node.js host gives you. Zero npm dependencies.
 */
const net = require('net');
const http = require('http');
const tls = require('tls');
const dns = require('dns').promises;
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const VERSION = '0.3.2';
const PORT = Number(process.env.PORT || 8080);
const HOST = '0.0.0.0';
// Hostless app filesystems are read-only. Attach a persistent volume at /data.
const DATA_DIR = process.env.DATA_DIR || '/tmp/blackheart-panel-data';
const HOSTLESS_MODE = process.env.HOSTLESS_MODE !== '0';
const PANEL_HTML = path.join(__dirname, 'assets', 'panel.html');
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_FRAME = 16 * 1024 * 1024;
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

/* ------------------------------------------------------------------ state */
fs.mkdirSync(DATA_DIR, { recursive: true });
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const CERT_FILE = path.join(DATA_DIR, 'cert.json');
const rnd = (n) => crypto.randomBytes(n).toString('hex');

const GOOGLE = ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'ggpht.com', 'google.dev', 'withgoogle.com', 'gvt1.com'];
const OLD_FORCE = ['aistudio.google.com', 'ai.google.dev', 'generativelanguage.googleapis.com', 'gemini.google.com'];
const DEFAULT_SETTINGS = () => ({
  protocols: { vlessWs: false, vlessWsTls: true, trojanWs: false, trojanWsTls: true },
  bypassIran: true,
  bypassLan: true,
  forceProxyDomains: [...GOOGLE],
  sni: '',
  address: '',
  publicPort: 0,
  minConfigs: 10,
  sniList: ['www.speedtest.net', 'www.cloudflare.com', 'www.microsoft.com', 'www.apple.com', 'www.samsung.com'],
  fragment: { enabled: false, length: '100-200', interval: '1-1', packets: 'tlshello' },
  remoteDNS: 'https://1.1.1.1/dns-query',
  localDNS: '8.8.8.8',
  dohForUDP: 'https://1.1.1.1/dns-query',
});

let S; // persistent state
let httpServer; // HTTP server instance
function loadState() {
  let s = {};
  try { s = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch {}
  s.uuid = process.env.UUID || s.uuid || crypto.randomUUID();
  s.trojanPassword = s.trojanPassword || rnd(12);
  s.subToken = process.env.SUB_TOKEN || s.subToken || rnd(12);
  s.vlessPath = s.vlessPath || '/' + rnd(5);
  s.trojanPath = s.trojanPath || '/' + rnd(5);
  s.secret = s.secret || rnd(32);
  s.auth = s.auth || null;
  s.settings = { ...DEFAULT_SETTINGS(), ...(s.settings || {}) };
  if (HOSTLESS_MODE) {
    // Hostless public ingress is HTTPS; plaintext WS cannot be advertised.
    s.settings.protocols.vlessWs = false;
    s.settings.protocols.trojanWs = false;
  }
  if (JSON.stringify(s.settings.forceProxyDomains) === JSON.stringify(OLD_FORCE)) s.settings.forceProxyDomains = [...GOOGLE];
  delete s.settings.ports;
  s.rev = s.rev || 1;
  s.lastChange = s.lastChange || null;
  s.oldTokens = (s.oldTokens || []).filter((t) => t.until > Date.now());
  return s;
}
function saveState() {
  const tmp = STATE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(S, null, 2));
  fs.renameSync(tmp, STATE_FILE);
}

/* ------------------------------------------------------------------- auth */
const pbkdf2 = (pw, salt) =>
  new Promise((res, rej) => crypto.pbkdf2(pw, salt, 100000, 32, 'sha256', (e, k) => (e ? rej(e) : res(k.toString('base64')))));
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
async function setPassword(pw) {
  if (typeof pw !== 'string' || pw.length < 8) throw new Error('رمز باید حداقل ۸ کاراکتر باشد');
  const salt = rnd(16);
  S.auth = { salt, hash: await pbkdf2(pw, salt) };
  saveState();
}
async function checkPassword(pw) {
  if (!S.auth || typeof pw !== 'string') return false;
  return safeEq(await pbkdf2(pw, S.auth.salt), S.auth.hash);
}
const sign = (exp) => crypto.createHmac('sha256', S.secret).update(String(exp)).digest('hex');
function sessionCookie(req) {
  const exp = Math.floor(Date.now() / 1000) + 7 * 86400;
  return `sess=${exp}.${sign(exp)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${7 * 86400}${(req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https') ? '; Secure' : ''}`;
}
function isAuthed(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)sess=(\d+)\.([0-9a-f]+)/);
  return !!(m && S.auth && Number(m[1]) > Date.now() / 1000 && safeEq(sign(m[1]), m[2]));
}
const fails = new Map(); // ip -> {n, until}
const realIp = new Map(); // inner loopback port -> real client ip (TLS path)
const ipOf = (req) => (req.socket.remoteAddress === '127.0.0.1' && realIp.get(req.socket.remotePort)) || req.socket.remoteAddress || '?';
const blocked = (ip) => (fails.get(ip)?.until || 0) > Date.now();
function noteFail(ip) {
  const f = fails.get(ip) || { n: 0, until: 0 };
  f.n += 1;
  if (f.n >= 8) { f.until = Date.now() + 10 * 60 * 1000; f.n = 0; }
  fails.set(ip, f);
}

/* ------------------------------------------- self-signed cert (pure Node) */
const der = (tag, ...parts) => {
  const body = Buffer.concat(parts), n = body.length;
  const len = n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
};
const SEQ = (...p) => der(0x30, ...p);
const OID = (s) => {
  const a = s.split('.').map(Number), out = [a[0] * 40 + a[1]];
  for (const v of a.slice(2)) { const t = [v & 127]; let x = v >> 7; while (x) { t.unshift((x & 127) | 128); x >>= 7; } out.push(...t); }
  return der(0x06, Buffer.from(out));
};
const utc = (d) => der(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));

function makeCert() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const serial = crypto.randomBytes(8); serial[0] &= 0x7f; serial[0] |= 0x01;
  const name = SEQ(der(0x31, SEQ(OID('2.5.4.3'), der(0x0c, Buffer.from('localhost')))));
  const sigAlg = SEQ(OID('1.2.840.10045.4.3.2'));
  const now = Date.now();
  const tbs = SEQ(
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, serial),
    sigAlg,
    name,
    SEQ(utc(new Date(now - 86400e3)), utc(new Date(now + 5 * 365 * 86400e3))),
    name,
    publicKey.export({ type: 'spki', format: 'der' })
  );
  const sig = crypto.sign('sha256', tbs, { key: privateKey, dsaEncoding: 'der' });
  const certDer = SEQ(tbs, sigAlg, der(0x03, Buffer.concat([Buffer.from([0]), sig])));
  const b64 = certDer.toString('base64').match(/.{1,64}/g).join('\n');
  return {
    cert: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`,
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}
function loadCert() {
  try {
    const c = JSON.parse(fs.readFileSync(CERT_FILE, 'utf8'));
    const left = new Date(new crypto.X509Certificate(c.cert).validTo) - Date.now();
    if (left > 30 * 86400e3) return c;
  } catch {}
  const c = makeCert();
  fs.writeFileSync(CERT_FILE, JSON.stringify(c));
  return c;
}

/* -------------------------------------------------------- WebSocket (RFC 6455) */
class WS extends EventEmitter {
  constructor(sock, head) {
    super();
    this.sock = sock;
    this.buf = Buffer.alloc(0);
    this.frag = [];
    this.fragLen = 0;
    this.closed = false;
    sock.setNoDelay(true);
    sock.on('data', (d) => this._data(d));
    sock.on('close', () => this._end());
    sock.on('error', () => this._end());
    if (head && head.length) this._data(head);
  }
  _end() { if (!this.closed) { this.closed = true; this.emit('close'); } }
  _data(d) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, d]) : d;
    for (;;) {
      const b = this.buf;
      if (b.length < 2) return;
      const fin = !!(b[0] & 0x80), op = b[0] & 15, masked = !!(b[1] & 0x80);
      let len = b[1] & 0x7f, p = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); p = 4; }
      else if (len === 127) {
        if (b.length < 10) return;
        const big = b.readBigUInt64BE(2);
        if (big > BigInt(MAX_FRAME)) return this.terminate();
        len = Number(big); p = 10;
      }
      if (!masked || len > MAX_FRAME) return this.terminate();
      if (b.length < p + 4 + len) return;
      const mask = b.subarray(p, p + 4);
      const payload = Buffer.from(b.subarray(p + 4, p + 4 + len));
      for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3];
      this.buf = b.subarray(p + 4 + len);
      if (op === 8) { this.close(); return; }
      if (op === 9) { this._frame(0x8a, payload); continue; }
      if (op === 10) continue;
      if (op === 0 || op === 1 || op === 2) {
        if (op !== 0) { this.frag = []; this.fragLen = 0; this.binary = op === 2; }
        this.frag.push(payload);
        this.fragLen += len;
        if (this.fragLen > MAX_FRAME) return this.terminate();
        if (fin) {
          const msg = this.frag.length === 1 ? this.frag[0] : Buffer.concat(this.frag);
          this.frag = []; this.fragLen = 0;
          if (this.binary) this.emit('message', msg);
        }
      }
    }
  }
  _frame(first, payload) {
    const n = payload.length;
    const hdr = n < 126 ? Buffer.from([first, n]) : n < 65536 ? Buffer.from([first, 126, n >> 8, n & 255])
      : (() => { const h = Buffer.alloc(10); h[0] = first; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); return h; })();
    if (this.closed || this.sock.destroyed) return false;
    this.sock.cork();
    this.sock.write(hdr);
    const ok = this.sock.write(payload);
    this.sock.uncork();
    return ok;
  }
  send(buf) { return this._frame(0x82, buf); }
  pause() { this.sock.pause(); }
  resume() { this.sock.resume(); }
  close() {
    if (!this.closed && !this.sock.destroyed) { try { this.sock.end(Buffer.from([0x88, 0x00])); } catch {} }
    setTimeout(() => this.sock.destroy(), 2000).unref();
  }
  terminate() { this.sock.destroy(); }
}

/* -------------------------------------------------------- proxy protocols */
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_DEST === '1';
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}
async function dial(host, port) {
  let ip = host;
  if (!net.isIP(host)) ip = (await dns.lookup(host)).address;
  if (!ALLOW_PRIVATE && isPrivateIp(ip)) throw new Error('private destination blocked');
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: ip, port });
    const t = setTimeout(() => s.destroy(new Error('connect timeout')), 10000);
    s.setNoDelay(true);
    s.once('connect', () => { clearTimeout(t); resolve(s); });
    s.once('error', (e) => { clearTimeout(t); reject(e); });
  });
}

function sniOf(b) {
  try {
    if (b[0] !== 0x16 || b[5] !== 1) return null;
    let p = 43;
    p += 1 + b[p];
    p += 2 + b.readUInt16BE(p);
    p += 1 + b[p];
    const end = p + 2 + b.readUInt16BE(p); p += 2;
    while (p + 4 <= end) {
      const t = b.readUInt16BE(p), l = b.readUInt16BE(p + 2); p += 4;
      if (t === 0) return b.subarray(p + 5, p + 5 + b.readUInt16BE(p + 3)).toString().toLowerCase();
      p += l;
    }
  } catch {}
  return null;
}
const isForced = (n) => S.settings.forceProxyDomains.some((d) => n === d || n.endsWith('.' + d));

/** Shared relay: first message is parsed by `parse`; the rest is piped to the remote. */
function relay(ws, early, parse) {
  let remote = null, dnsHandler = null;
  const cleanup = () => { try { remote && remote.destroy(); } catch {} ws.close(); };
  const toRemote = (c) => { if (!remote.write(c)) { ws.pause(); remote.once('drain', () => ws.resume()); } };
  async function onMsg(chunk) {
    if (dnsHandler) return dnsHandler(chunk);
    if (remote) return toRemote(chunk);
    const h = parse(chunk);
    if (h.error) throw new Error(h.error);
    if (h.udp) {
      if (h.port !== 53) throw new Error('only DNS over UDP is supported');
      dnsHandler = makeDns(ws, h.resp);
      return dnsHandler(h.payload);
    }
    let target = h.address;
    if (net.isIP(target)) { const n = sniOf(h.payload); if (n && isForced(n)) target = n; }
    remote = await dial(target, h.port);
    let header = h.resp;
    remote.on('data', (d) => {
      const out = header ? Buffer.concat([header, d]) : d;
      header = null;
      if (!ws.send(out)) { remote.pause(); ws.sock.once('drain', () => remote.resume()); }
    });
    remote.on('error', cleanup);
    remote.on('close', cleanup);
    if (h.payload.length) toRemote(h.payload);
  }
  let chain = Promise.resolve();
  const push = (c) => { chain = chain.then(() => onMsg(c)).catch(cleanup); };
  ws.on('message', push);
  ws.on('close', cleanup);
  if (early && early.length) push(early);
}

function readAddr(buf, p, type) {
  if (type === 1) return [buf.subarray(p, p + 4).join('.'), p + 4];
  if (type === 3) { const l = buf[p]; return [buf.subarray(p + 1, p + 1 + l).toString(), p + 1 + l]; }
  if (type === 4) { const g = []; for (let i = 0; i < 8; i++) g.push(buf.readUInt16BE(p + i * 2).toString(16)); return [g.join(':'), p + 16]; }
  return [null, p];
}

function vlessParser() {
  const id = Buffer.from(S.uuid.replace(/-/g, ''), 'hex');
  return (buf) => {
    if (buf.length < 24) return { error: 'short header' };
    if (!crypto.timingSafeEqual(buf.subarray(1, 17), id)) return { error: 'bad uuid' };
    let p = 18 + buf[17];
    const cmd = buf[p++];
    if (cmd !== 1 && cmd !== 2) return { error: 'bad command' };
    const port = buf.readUInt16BE(p); p += 2;
    const type = buf[p++];
    // VLESS numbering: 1=ipv4, 2=domain, 3=ipv6 (Trojan/SOCKS5 use 1, 3, 4)
    const atyp = { 1: 1, 2: 3, 3: 4 }[type];
    if (!atyp) return { error: 'bad address type' };
    const [address, np] = readAddr(buf, p, atyp);
    if (!address || np > buf.length) return { error: 'bad address' };
    return { udp: cmd === 2, port, address, payload: buf.subarray(np), resp: Buffer.from([buf[0], 0]) };
  };
}

function trojanParser() {
  const want = crypto.createHash('sha224').update(S.trojanPassword).digest('hex');
  return (buf) => {
    if (buf.length < 62) return { error: 'short header' };
    if (!safeEq(buf.subarray(0, 56).toString('latin1'), want)) return { error: 'bad password' };
    if (buf[56] !== 13 || buf[57] !== 10) return { error: 'bad header' };
    let p = 58;
    const cmd = buf[p++];
    if (cmd !== 1) return { error: 'only CONNECT is supported' };
    const type = buf[p++];
    const [address, np] = readAddr(buf, p, type);
    if (!address || np + 4 > buf.length) return { error: 'bad address' };
    const port = buf.readUInt16BE(np);
    return { udp: false, port, address, payload: buf.subarray(np + 4), resp: null };
  };
}

function makeDns(ws, resp) {
  let header = resp, buf = Buffer.alloc(0);
  return async (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 2) {
      const len = buf.readUInt16BE(0);
      if (buf.length < 2 + len) break;
      const q = buf.subarray(2, 2 + len);
      buf = buf.subarray(2 + len);
      try {
        const r = await fetch(S.settings.dohForUDP, { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: q });
        const a = Buffer.from(await r.arrayBuffer());
        const lenb = Buffer.alloc(2); lenb.writeUInt16BE(a.length);
        const out = Buffer.concat(header ? [header, lenb, a] : [lenb, a]);
        header = null;
        ws.send(out);
      } catch {}
    }
  };
}

function decodeEarly(proto) {
  if (!proto) return null;
  try { return Buffer.from(proto.split(',')[0].trim().replace(/-/g, '+').replace(/_/g, '/'), 'base64'); } catch { return null; }
}

function onUpgrade(req, socket, head) {
  const p = new URL(req.url, 'http://x').pathname;
  const kind = p === S.vlessPath ? 'vless' : p === S.trojanPath ? 'trojan' : null;
  const key = req.headers['sec-websocket-key'];
  if (!kind || !key || !/websocket/i.test(req.headers.upgrade || '')) return socket.destroy();
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  const proto = req.headers['sec-websocket-protocol'];
  const echo = proto ? `Sec-WebSocket-Protocol: ${proto.split(',')[0].trim()}\r\n` : '';
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n${echo}\r\n`);
  socket.on('error', () => {});
  const ws = new WS(socket, head);
  relay(ws, decodeEarly(proto), kind === 'vless' ? vlessParser() : trojanParser());
}


/* ----------------------------------------------------------- subscriptions */
const PROTO_DEFS = [
  { key: 'vlessWs', name: 'VLESS-WS', kind: 'vless', tls: false },
  { key: 'vlessWsTls', name: 'VLESS-WS-TLS', kind: 'vless', tls: true },
  { key: 'trojanWs', name: 'Trojan-WS', kind: 'trojan', tls: false },
  { key: 'trojanWsTls', name: 'Trojan-WS-TLS', kind: 'trojan', tls: true },
];

const FPS = ['chrome', 'firefox', 'safari', 'ios', 'edge', 'random'];
function endpointsFor(req, tlsOnly) {
  const st = S.settings;
  let u;
  try { u = new URL('http://' + (req.headers.host || 'localhost')); } catch { u = new URL('http://localhost'); }
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  const host = st.address || process.env.DOMAIN || (forwardedHost || u.hostname).replace(/^\[|\]$/g, '');
  // Hostless terminates public HTTPS at its edge. WebSocket configs therefore use WSS/443.
  const port = st.publicPort || Number(process.env.PUBLIC_PORT) || (HOSTLESS_MODE ? 443 : Number(u.port) || 80);
  const sni = st.sni || (net.isIP(host) ? '' : host);
  const ports = [port];
  const base = ports.flatMap((pt) => PROTO_DEFS.filter((d) => st.protocols[d.key] && (!tlsOnly || d.tls) && (!HOSTLESS_MODE || d.tls)).map((d) => ({ d, pt })));
  if (!base.length) return [];
  const rounds = Math.min(8, Math.max(1, Math.ceil(st.minConfigs / base.length)));
  const out = [];
  for (let r = 0; r < rounds; r++) {
    for (const { d, pt } of base) {
      const alt = r === 0 || !st.sniList.length ? '' : st.sniList[(r - 1) % st.sniList.length];
      out.push({
        ...d, host, port: pt, fp: FPS[r % FPS.length],
        sni: d.tls ? alt || sni : '', hostHeader: alt || (d.tls && sni) || host,
        name: `👑 ${d.kind === 'vless' ? 'VLESS' : 'Trojan'} ${d.tls ? 'TLS' : 'WS'} · ${pt}${rounds > 1 ? ' · ' + (r + 1) : ''}`,
        path: d.kind === 'vless' ? S.vlessPath : S.trojanPath,
        secret: d.kind === 'vless' ? S.uuid : S.trojanPassword,
      });
    }
  }
  return out;
}
const wsPath = (e) => e.path + '?ed=2560';
const hostFmt = (h) => (h.includes(':') ? `[${h}]` : h);

function buildLinks(eps) {
  const lines = eps.map((e) => {
    const q = new URLSearchParams({ security: e.tls ? 'tls' : 'none', type: 'ws', host: e.hostHeader, path: wsPath(e) });
    if (e.kind === 'vless') q.set('encryption', 'none');
    if (e.tls) {
      if (e.sni) q.set('sni', e.sni);
      q.set('fp', e.fp); q.set('alpn', 'http/1.1'); q.set('allowInsecure', '1');
    }
    return `${e.kind}://${e.secret}@${hostFmt(e.host)}:${e.port}?${q}#${encodeURIComponent(e.name)}`;
  });
  return Buffer.from(lines.join('\n')).toString('base64');
}

function xrayRouting(st, dnsOut) {
  const rules = [];
  if (st.forceProxyDomains.length) rules.push({ type: 'field', domain: st.forceProxyDomains.map((d) => 'domain:' + d), outboundTag: 'proxy' });
  if (st.bypassLan) rules.push({ type: 'field', ip: ['geoip:private'], outboundTag: 'direct' });
  if (st.bypassIran) {
    rules.push({ type: 'field', domain: ['regexp:.*\\.ir$', 'geosite:category-ir'], outboundTag: 'direct' });
    rules.push({ type: 'field', ip: ['geoip:ir'], outboundTag: 'direct' });
  }
  rules.push({ type: 'field', network: 'tcp,udp', outboundTag: 'proxy' });
  return { domainStrategy: 'IPIfNonMatch', rules };
}

function buildXray(eps, fragmentMode) {
  const st = S.settings;
  const servers = [];
  if (st.bypassIran) servers.push({ address: st.localDNS, domains: ['regexp:.*\\.ir$', 'geosite:category-ir'], expectIPs: ['geoip:ir'] });
  if (st.forceProxyDomains.length) servers.push({ address: st.remoteDNS, domains: st.forceProxyDomains.map((d) => 'domain:' + d) });
  servers.push(st.remoteDNS, st.localDNS);
  const configs = (fragmentMode ? eps.filter((e) => e.tls) : eps).map((e) => {
    const frag = fragmentMode && e.tls;
    const stream = {
      network: 'ws',
      security: e.tls ? 'tls' : 'none',
      tlsSettings: e.tls ? { serverName: e.sni || undefined, allowInsecure: true, fingerprint: e.fp, alpn: ['http/1.1'] } : undefined,
      wsSettings: { path: wsPath(e), headers: { Host: e.hostHeader } },
      sockopt: frag ? { dialerProxy: 'fragment' } : undefined,
    };
    const proxy = e.kind === 'vless'
      ? { tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: e.host, port: e.port, users: [{ id: e.secret, encryption: 'none' }] }] }, streamSettings: stream }
      : { tag: 'proxy', protocol: 'trojan', settings: { servers: [{ address: e.host, port: e.port, password: e.secret }] }, streamSettings: stream };
    return {
      remarks: e.name,
      log: { loglevel: 'warning' },
      dns: { servers, queryStrategy: 'UseIP' },
      inbounds: [
        { tag: 'socks', port: 10808, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing: { enabled: true, destOverride: ['http', 'tls'] } },
        { tag: 'http', port: 10809, listen: '127.0.0.1', protocol: 'http', settings: {} },
      ],
      outbounds: [
        proxy,
        ...(frag ? [{ tag: 'fragment', protocol: 'freedom', settings: { fragment: { packets: st.fragment.packets, length: st.fragment.length, interval: st.fragment.interval } }, streamSettings: { sockopt: { tcpNoDelay: true } } }] : []),
        { tag: 'direct', protocol: 'freedom', settings: {} },
        { tag: 'block', protocol: 'blackhole', settings: {} },
      ],
      routing: xrayRouting(st),
    };
  });
  return JSON.stringify(configs, null, 2);
}

// Targets sing-box 1.11+. The Iran rule-sets are downloaded by the client; the .ir suffix rule works without them.
function buildSingbox(eps) {
  const st = S.settings;
  const proxies = eps.map((e) => {
    const base = {
      type: e.kind, tag: e.name, server: e.host, server_port: e.port,
      transport: { type: 'ws', path: e.path, headers: { Host: e.hostHeader }, max_early_data: 2560, early_data_header_name: 'Sec-WebSocket-Protocol' },
    };
    if (e.kind === 'vless') base.uuid = e.secret; else base.password = e.secret;
    if (e.tls) base.tls = { enabled: true, insecure: true, server_name: e.sni || undefined, alpn: ['http/1.1'], utls: { enabled: true, fingerprint: e.fp } };
    return base;
  });
  const names = proxies.map((p) => p.tag);
  const rules = [{ action: 'sniff' }, { protocol: 'dns', action: 'hijack-dns' }];
  if (st.forceProxyDomains.length) rules.push({ domain_suffix: st.forceProxyDomains, action: 'route', outbound: 'select' });
  if (st.bypassLan) rules.push({ ip_is_private: true, action: 'route', outbound: 'direct' });
  const ruleSets = [];
  if (st.bypassIran) {
    rules.push({ domain_suffix: ['.ir'], action: 'route', outbound: 'direct' });
    rules.push({ rule_set: ['geoip-ir', 'geosite-ir'], action: 'route', outbound: 'direct' });
    const base = 'https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/';
    for (const t of ['geoip-ir', 'geosite-ir']) ruleSets.push({ tag: t, type: 'remote', format: 'binary', url: `${base}${t}.srs`, download_detour: 'select' });
  }
  return JSON.stringify({
    log: { level: 'warn' },
    dns: {
      servers: [{ tag: 'remote', address: st.remoteDNS, detour: 'select' }, { tag: 'local', address: st.localDNS, detour: 'direct' }],
      rules: [...(st.forceProxyDomains.length ? [{ domain_suffix: st.forceProxyDomains, server: 'remote' }] : []), ...(st.bypassIran ? [{ domain_suffix: ['.ir'], server: 'local' }] : [])],
      strategy: 'prefer_ipv4',
    },
    inbounds: [
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 },
      { type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'], auto_route: true, strict_route: true, stack: 'mixed' },
    ],
    outbounds: [
      { type: 'selector', tag: 'select', outbounds: ['auto', ...names], default: 'auto' },
      { type: 'urltest', tag: 'auto', outbounds: names, url: 'https://www.gstatic.com/generate_204', interval: '5m' },
      ...proxies,
      { type: 'direct', tag: 'direct' },
    ],
    route: { auto_detect_interface: true, rules, rule_set: ruleSets, final: 'select' },
  }, null, 2);
}

const q = (v) => JSON.stringify(String(v));
function buildClash(eps) {
  const st = S.settings;
  const list = eps.filter((e) => e.kind === 'vless' || e.tls); // Clash has no plain-WS Trojan
  const proxies = list.map((e) => {
    const common = `  - name: ${q(e.name)}
    type: ${e.kind}
    server: ${q(e.host)}
    port: ${e.port}
    ${e.kind === 'vless' ? 'uuid' : 'password'}: ${q(e.secret)}
    udp: true
    network: ws
${e.kind === 'vless' ? `    tls: ${e.tls}\n` : ''}${e.tls ? `    skip-cert-verify: true\n    client-fingerprint: ${e.fp}\n    alpn: [http/1.1]\n${e.sni ? `    ${e.kind === 'vless' ? 'servername' : 'sni'}: ${q(e.sni)}\n` : ''}` : ''}    ws-opts:
      path: ${q(e.path)}
      headers: { Host: ${q(e.hostHeader)} }
      max-early-data: 2560
      early-data-header-name: Sec-WebSocket-Protocol`;
    return common;
  }).join('\n');
  const names = list.map((e) => `      - ${q(e.name)}`).join('\n');
  const rules = [];
  for (const d of st.forceProxyDomains) rules.push(`  - DOMAIN-SUFFIX,${d},Select`);
  if (st.bypassLan) rules.push('  - GEOIP,LAN,DIRECT,no-resolve');
  if (st.bypassIran) rules.push('  - DOMAIN-SUFFIX,ir,DIRECT', '  - GEOSITE,category-ir,DIRECT', '  - GEOIP,IR,DIRECT');
  rules.push('  - MATCH,Select');
  const policy = st.forceProxyDomains.length ? '  nameserver-policy:\n' + st.forceProxyDomains.map((d) => `    ${q('+.' + d)}: ${q(st.remoteDNS)}`).join('\n') + '\n' : '';
  return `mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
ipv6: false
dns:
  enable: true
  ipv6: false
  nameserver: [${q(st.remoteDNS)}]
  default-nameserver: [${q(st.localDNS)}]
${policy}proxies:
${proxies}
proxy-groups:
  - name: Select
    type: select
    proxies:
      - Auto
${names}
  - name: Auto
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    proxies:
${names}
rules:
${rules.join('\n')}
`;
}
const FORMATS = {
  links: [(r) => buildLinks(endpointsFor(r)), 'text/plain'],
  xray: [(r) => buildXray(endpointsFor(r), false), 'application/json'],
  fragment: [(r) => buildXray(endpointsFor(r, true), true), 'application/json'],
  singbox: [(r) => buildSingbox(endpointsFor(r)), 'application/json'],
  clash: [(r) => buildClash(endpointsFor(r)), 'text/yaml'],
};

/* ----------------------------------------------------------- settings input */
const HOST_RE = /^[A-Za-z0-9.-]{1,253}$|^[0-9a-fA-F:]{2,45}$/;
const RANGE_RE = /^\d{1,5}-\d{1,5}$/;
function applySettings(input) {
  const st = JSON.parse(JSON.stringify(S.settings));
  if (input.protocols) for (const k of Object.keys(st.protocols)) if (k in input.protocols) st.protocols[k] = !!input.protocols[k];
  if (!Object.values(st.protocols).some(Boolean)) throw new Error('حداقل یک پروتکل باید فعال باشد');
  for (const k of ['bypassIran', 'bypassLan']) if (k in input) st[k] = !!input[k];
  if ('forceProxyDomains' in input) {
    const l = (Array.isArray(input.forceProxyDomains) ? input.forceProxyDomains : String(input.forceProxyDomains).split(/[\s,]+/)).map((x) => String(x).trim().toLowerCase()).filter(Boolean);
    for (const d of l) if (!/^[a-z0-9.-]+$/.test(d)) throw new Error('دامنه نامعتبر: ' + d);
    st.forceProxyDomains = [...new Set(l)].slice(0, 100);
  }
  for (const k of ['sni', 'address']) if (k in input) {
    const v = String(input[k]).trim();
    if (v && !HOST_RE.test(v)) throw new Error(k + ' نامعتبر');
    st[k] = v;
  }
  if ('publicPort' in input) {
    const n = Number(input.publicPort) || 0;
    if (n < 0 || n > 65535) throw new Error('پورت نامعتبر');
    st.publicPort = n;
  }
  if ('minConfigs' in input) {
    const n = Number(input.minConfigs);
    if (!Number.isInteger(n) || n < 1 || n > 40) throw new Error('حداقل تعداد کانفیگ باید بین ۱ تا ۴۰ باشد');
    st.minConfigs = n;
  }
  if ('sniList' in input) {
    const l = [...new Set((Array.isArray(input.sniList) ? input.sniList : String(input.sniList).split(/[\s,]+/)).map((x) => String(x).trim().toLowerCase()).filter(Boolean))];
    for (const d of l) if (!/^[a-z0-9.-]+$/.test(d)) throw new Error('SNI نامعتبر: ' + d);
    st.sniList = l.slice(0, 20);
  }
  if (input.fragment) {
    const f = { ...st.fragment, ...input.fragment };
    if (!RANGE_RE.test(f.length) || !RANGE_RE.test(f.interval)) throw new Error('فرمت fragment باید مثل 100-200 باشد');
    if (!['tlshello', '1-3'].includes(f.packets)) throw new Error('packets نامعتبر');
    f.enabled = !!f.enabled;
    st.fragment = f;
  }
  for (const k of ['remoteDNS', 'dohForUDP']) if (k in input) {
    if (!/^https:\/\/[^\s]+$/.test(input[k])) throw new Error(k + ' باید آدرس https باشد');
    st[k] = input[k];
  }
  if ('localDNS' in input) {
    if (!net.isIP(String(input.localDNS))) throw new Error('localDNS باید آی‌پی باشد');
    st.localDNS = input.localDNS;
  }
  const changed = Object.keys(st).filter((k) => JSON.stringify(st[k]) !== JSON.stringify(S.settings[k]));
  S.settings = st;
  if (changed.length) bump(changed.join(', '));
  saveState();
}
function bump(summary) { S.rev += 1; S.lastChange = { rev: S.rev, at: Date.now(), summary }; }
const publicSettings = () => ({
  rev: S.rev, lastChange: S.lastChange,
  ...S.settings,
  uuid: S.uuid, trojanPassword: S.trojanPassword, subToken: S.subToken,
  vlessPath: S.vlessPath, trojanPath: S.trojanPath,
});

/* -------------------------------------------------------------- HTTP layer */
const SEC_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
};
const sendJson = (res, data, status = 200, extra = {}) => {
  res.writeHead(status, { 'content-type': 'application/json', ...SEC_HEADERS, ...extra });
  res.end(JSON.stringify(data));
};
const decoy = (res) => {
  res.writeHead(404, { 'content-type': 'text/html', server: 'nginx' });
  res.end('<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n');
};
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', (c) => { n += c.length; if (n > 65536) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

async function handleApi(req, res, p) {
  try {
    if (p === '/api/state' && req.method === 'GET') {
      return sendJson(res, { version: VERSION, setup: !!S.auth, authed: isAuthed(req), needsSetupKey: !!process.env.SETUP_KEY, secure: !!req.socket.encrypted });
    }
    if (req.method !== 'POST' && req.method !== 'PUT' && req.method !== 'GET') return sendJson(res, { error: 'method' }, 405);
    let body = {};
    if (req.method !== 'GET') {
      if (!(req.headers['content-type'] || '').includes('application/json')) return sendJson(res, { error: 'bad content-type' }, 415);
      body = await readBody(req);
    }
    const ip = ipOf(req);
    if (p === '/api/setup' && req.method === 'POST') {
      if (S.auth) return sendJson(res, { error: 'قبلاً تنظیم شده است' }, 409);
      if (blocked(ip)) return sendJson(res, { error: 'تلاش زیاد؛ بعداً امتحان کن' }, 429);
      if (process.env.SETUP_KEY && !safeEq(body.setupKey || '', process.env.SETUP_KEY)) { noteFail(ip); return sendJson(res, { error: 'کلید راه‌اندازی اشتباه است' }, 403); }
      await setPassword(body.password);
      return sendJson(res, { ok: true }, 200, { 'set-cookie': sessionCookie(req) });
    }
    if (p === '/api/login' && req.method === 'POST') {
      if (blocked(ip)) return sendJson(res, { error: 'تلاش زیاد؛ ۱۰ دقیقه بعد امتحان کن' }, 429);
      if (!(await checkPassword(body.password))) { noteFail(ip); return sendJson(res, { error: 'رمز اشتباه است' }, 401); }
      fails.delete(ip);
      return sendJson(res, { ok: true }, 200, { 'set-cookie': sessionCookie(req) });
    }
    if (p === '/api/logout' && req.method === 'POST') {
      return sendJson(res, { ok: true }, 200, { 'set-cookie': 'sess=; Path=/; HttpOnly; Max-Age=0' });
    }
    if (!isAuthed(req)) return sendJson(res, { error: 'unauthorized' }, 401);
    if (p === '/api/settings' && req.method === 'GET') return sendJson(res, publicSettings());
    if (p === '/api/settings' && req.method === 'PUT') { await applySettings(body); return sendJson(res, publicSettings()); }
    if (p === '/api/exit-info' && req.method === 'GET') {
      try {
        const j = await (await fetch('https://ipinfo.io/json', { signal: AbortSignal.timeout(6000) })).json();
        return sendJson(res, { ip: j.ip, country: j.country, city: j.city, org: j.org });
      } catch { return sendJson(res, { error: 'آی‌پی خروجی سرور قابل دریافت نبود' }, 502); }
    }
    if (p === '/api/rotate-uuid' && req.method === 'POST') { S.uuid = crypto.randomUUID(); bump('uuid'); saveState(); return sendJson(res, publicSettings()); }
    if (p === '/api/rotate-sub' && req.method === 'POST') { S.oldTokens.push({ token: S.subToken, until: Date.now() + 30 * 86400e3 }); S.subToken = rnd(12); bump('subToken'); saveState(); return sendJson(res, publicSettings()); }
    if (p === '/api/password' && req.method === 'POST') {
      if (!(await checkPassword(body.current))) { noteFail(ip); return sendJson(res, { error: 'رمز فعلی اشتباه است' }, 401); }
      await setPassword(body.next);
      return sendJson(res, { ok: true }, 200, { 'set-cookie': sessionCookie(req) });
    }
    return sendJson(res, { error: 'not found' }, 404);
  } catch (e) {
    return sendJson(res, { error: e.message || 'error' }, 400);
  }
}

function onRequest(req, res) {
  const p = new URL(req.url, 'http://x').pathname;
  if (p === '/health') {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    return res.end('ok');
  }
  if (p.startsWith('/panel/')) {
    const f = p.slice(7);
    if (f === 'manifest.json') {
      res.writeHead(200, { 'content-type': 'application/manifest+json' });
      return res.end(JSON.stringify({ name: 'Panel', short_name: 'Panel', start_url: '/panel', display: 'standalone', background_color: '#070b14', theme_color: '#070b14', icons: [192, 512].map((n) => ({ src: `/panel/icon-${n}.png`, sizes: `${n}x${n}`, type: 'image/png' })) }));
    }
    if (['logo.png', 'icon-192.png', 'icon-512.png'].includes(f)) {
      try {
        const b = fs.readFileSync(path.join(__dirname, 'assets', f));
        res.writeHead(200, { 'content-type': 'image/png', 'cache-control': 'public, max-age=86400', 'x-content-type-options': 'nosniff' });
        return res.end(b);
      } catch {}
    }
    return decoy(res);
  }
  if (p === '/panel' || p === '/knight') {
    let html;
    try { html = fs.readFileSync(PANEL_HTML); } catch { res.writeHead(500); return res.end('assets/panel.html is missing — upload the assets folder'); }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', ...SEC_HEADERS, 'content-security-policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'" });
    return res.end(html);
  }
  if (p.startsWith('/api/')) return handleApi(req, res, p);
  if (p.startsWith('/sub/')) {
    const [, , token, fmt] = p.split('/');
    const f = FORMATS[fmt];
    const isOld = S.oldTokens.some((t) => safeEq(token || '', t.token));
    if (!f || !(safeEq(token || '', S.subToken) || isOld)) return decoy(res);
    const b64 = (t) => 'base64:' + Buffer.from(t).toString('base64');
    const publicProto = req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https' ? 'https' : 'http';
    const publicHost = String(req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(',')[0].trim();
    const origin = `${publicProto}://${publicHost}`;
    const lc = S.lastChange;
    const note = isOld ? `لینک ساب تغییر کرده؛ لینک جدید را جایگزین کن: ${origin}/sub/${S.subToken}/${fmt}`
      : lc && Date.now() - lc.at < 86400e3 ? `تنظیمات پنل تغییر کرد (نسخه ${lc.rev}). ساب به‌روز شد؛ در برنامه Update کن.` : '';
    res.writeHead(200, { 'content-type': `${f[1]}; charset=utf-8`, ...SEC_HEADERS, 'profile-update-interval': '1', 'profile-title': b64(`Panel r${S.rev}`), ...(note ? { announce: b64(note) } : {}) });
    return res.end(f[0](req));
  }
  return decoy(res);
}

/* ------------------------------------------- Hostless HTTP app entrypoint */
// Hostless routes HTTPS to this HTTP listener. Its edge owns the public TLS certificate.
// WebSocket upgrade requests continue through the HTTP server; raw TCP/TLS sniffing is
// intentionally removed because Hostless apps expose HTTP services, not arbitrary TCP ports.
function main() {
  S = loadState();
  if (process.env.PANEL_PASSWORD) {
    const salt = rnd(16);
    pbkdf2(process.env.PANEL_PASSWORD, salt).then((hash) => {
      S.auth = { salt, hash };
      saveState();
    }).catch((e) => log('password init failed:', e.message));
  }
  saveState();
  httpServer = http.createServer(onRequest);
  httpServer.on('upgrade', onUpgrade);
  httpServer.on('clientError', (e, sock) => sock.destroy());
  httpServer.keepAliveTimeout = 65000;
  httpServer.headersTimeout = 66000;
  httpServer.listen(PORT, HOST, () => {
    log(`Hostless panel v${VERSION} listening on ${HOST}:${PORT}`);
    log('public URL: https://<your-hostless-app-domain>/panel');
    log(`persistent data directory: ${DATA_DIR}`);
  });
}
process.on('uncaughtException', (e) => log('uncaught', e.message));
process.on('unhandledRejection', (e) => log('unhandled', e && e.message));
main();
