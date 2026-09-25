'use strict';

// No recording, access logs, credential handling, external listeners, or downloads.
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomBytes, timingSafeEqual } = require('node:crypto');

const LOOPBACK = '127.0.0.1';
const BUFFER_LIMIT = 1024 * 1024;
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
  '.otf': 'font/otf', '.wasm': 'application/wasm',
};

function validPort(value, allowZero = false) {
  return Number.isInteger(value) && value >= (allowZero ? 0 : 1) && value <= 65535;
}

function staticPath(rawUrl) {
  if (!rawUrl.startsWith('/') || rawUrl.startsWith('//')) return null;
  let decoded;
  try { decoded = decodeURIComponent(rawUrl.split('?')[0]); } catch { return null; }
  if (/[\\:%\x00-\x1f\x7f<>|"?#*]/.test(decoded)) return null;
  if (decoded === '/') return 'vnc.html';
  const parts = decoded.slice(1).split('/');
  if (parts.some(part => !part || part === '.' || part === '..' || /[. ]$/.test(part))) return null;
  if (decoded !== '/vnc.html' && !/^\/(?:app|core|vendor)\//.test(decoded)) return null;
  return parts.join(path.sep);
}

async function createServer({ root, dependencyDir, vncPort, port = 0 }) {
  if (!path.isAbsolute(root) || !path.isAbsolute(dependencyDir) ||
      !validPort(vncPort) || !validPort(port, true)) throw new Error('Invalid console configuration.');
  const realRoot = await fs.promises.realpath(root);
  if (!(await fs.promises.stat(realRoot)).isDirectory()) throw new Error('Invalid noVNC directory.');
  // Upstream noVNC starts from inline modules. Allow only the exact staged
  // bootstrap bytes, not arbitrary inline scripts or unsafe-eval.
  const html = (await fs.promises.readFile(path.join(realRoot, 'vnc.html'), 'utf8')).replace(/\r\n?/g, '\n');
  const bootstrapHashes = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)]
    .filter(match => !/\bsrc\s*=/i.test(match[1]))
    .map(match => `'sha256-${createHash('sha256').update(match[2]).digest('base64')}'`);
  const { WebSocketServer, WebSocket } = require(path.join(dependencyDir, 'ws'));
  const token = randomBytes(32).toString('hex');
  const tokenBytes = Buffer.from(token);
  const peers = new Set();
  let authority;
  let origin;

  function headers(response) {
    response.setHeader('Cache-Control', 'no-store, max-age=0');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('Expires', '0');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    response.setHeader('Content-Security-Policy', [
      "default-src 'self'", `script-src 'self' ${bootstrapHashes.join(' ')}`, "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:", "font-src 'self'",
      `connect-src 'self' ws://${authority}`, "worker-src 'self' blob:",
      "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'none'",
    ].join('; '));
  }

  const server = http.createServer(async (request, response) => {
    headers(response);
    const reject = (status) => { response.writeHead(status); response.end(); };
    if (request.headers.host !== authority) return reject(403);
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      response.setHeader('Allow', 'GET, HEAD');
      return reject(405);
    }
    const relative = staticPath(request.url);
    if (!relative) return reject(404);
    let handle;
    try {
      // Reject junctions/symlinks, including links inside otherwise allowed asset directories.
      let candidate = realRoot;
      for (const part of relative.split(path.sep)) {
        candidate = path.join(candidate, part);
        if ((await fs.promises.lstat(candidate)).isSymbolicLink()) return reject(404);
      }
      const realFile = await fs.promises.realpath(candidate);
      const inside = path.relative(realRoot, realFile);
      if (inside.startsWith('..' + path.sep) || inside === '..' || path.isAbsolute(inside)) return reject(404);
      handle = await fs.promises.open(realFile, 'r');
      const info = await handle.stat();
      if (!info.isFile()) return reject(404);
      response.setHeader('Content-Type', TYPES[path.extname(realFile).toLowerCase()] || 'application/octet-stream');
      response.setHeader('Content-Length', info.size);
      response.writeHead(200);
      if (request.method === 'HEAD') return response.end();
      const stream = handle.createReadStream({ autoClose: true });
      handle = null;
      stream.on('error', () => response.destroy());
      response.on('close', () => stream.destroy());
      stream.pipe(response);
    } catch {
      if (!response.headersSent) reject(404);
      else response.destroy();
    } finally {
      if (handle) await handle.close().catch(() => {});
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.on('clientError', (_error, socket) => socket.destroy());
  const sockets = new WebSocketServer({
    noServer: true, perMessageDeflate: false, maxPayload: BUFFER_LIMIT,
    handleProtocols: protocols => protocols.has('binary') ? 'binary' : false,
  });

  server.on('upgrade', (request, socket, head) => {
    socket.on('error', () => {});
    const deny = () => socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    if (request.method !== 'GET' || request.headers.host !== authority ||
        request.headers.origin !== origin || !request.url.startsWith('/websockify?')) return deny();
    let parsed;
    try { parsed = new URL(request.url, origin); } catch { return deny(); }
    const supplied = parsed.searchParams.getAll('token');
    if (parsed.pathname !== '/websockify' || parsed.hash || supplied.length !== 1 ||
        [...parsed.searchParams.keys()].some(key => key !== 'token')) return deny();
    const bytes = Buffer.from(supplied[0]);
    if (bytes.length !== tokenBytes.length || !timingSafeEqual(bytes, tokenBytes)) return deny();
    sockets.handleUpgrade(request, socket, head, ws => sockets.emit('connection', ws));
  });

  sockets.on('connection', ws => {
    const tcp = net.createConnection({ host: LOOPBACK, port: vncPort });
    peers.add(tcp);
    tcp.setNoDelay(true);
    tcp.setTimeout(5000, () => tcp.destroy());
    tcp.once('connect', () => tcp.setTimeout(0));
    tcp.on('error', () => ws.terminate());
    tcp.on('close', () => { peers.delete(tcp); ws.terminate(); });
    ws.on('error', () => tcp.destroy());
    ws.on('close', () => tcp.destroy());
    ws.on('message', (data, isBinary) => {
      if (!isBinary) { ws.close(1003, 'Binary frames required'); tcp.end(); return; }
      if (tcp.destroyed || tcp.writableLength + data.length > BUFFER_LIMIT) {
        ws.terminate(); tcp.destroy(); return;
      }
      if (!tcp.write(data)) ws.pause();
    });
    tcp.on('drain', () => { if (ws.readyState === WebSocket.OPEN) ws.resume(); });
    tcp.on('data', data => {
      if (ws.readyState !== WebSocket.OPEN || ws.bufferedAmount + data.length > BUFFER_LIMIT) {
        tcp.destroy(); ws.terminate(); return;
      }
      tcp.pause();
      ws.send(data, { binary: true }, error => {
        if (error) tcp.destroy();
        else if (!tcp.destroyed) tcp.resume();
      });
    });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: LOOPBACK, port, exclusive: true }, () => {
      server.removeListener('error', reject);
      authority = `${LOOPBACK}:${server.address().port}`;
      origin = `http://${authority}`;
      resolve();
    });
  });
  const url = `${origin}/vnc.html?autoconnect=1&resize=scale&path=${encodeURIComponent(`websockify?token=${token}`)}`;
  async function close() {
    for (const client of sockets.clients) client.terminate();
    for (const peer of peers) peer.destroy();
    const done = new Promise(resolve => server.close(resolve));
    server.closeAllConnections();
    sockets.close();
    await done;
  }
  return { server, url, close };
}

async function main(args) {
  const values = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    if (!['--root', '--dependency-dir', '--vnc-port', '--port'].includes(key) ||
        Object.hasOwn(values, key) || !args[i + 1]) throw new Error('Invalid arguments.');
    values[key] = args[i + 1];
  }
  const proxy = await createServer({
    root: values['--root'], dependencyDir: values['--dependency-dir'],
    vncPort: Number(values['--vnc-port']), port: Number(values['--port'] ?? 0),
  });
  const stop = () => { proxy.close().catch(() => { process.exitCode = 1; }); };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  proxy.server.on('error', stop);
  process.stdout.write(JSON.stringify({ url: proxy.url }) + '\n');
}

module.exports = { createServer, staticPath };
if (require.main === module) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write('Console proxy failed; verify staged noVNC/ws files and local port availability.\n');
    process.exitCode = 1;
  });
}
