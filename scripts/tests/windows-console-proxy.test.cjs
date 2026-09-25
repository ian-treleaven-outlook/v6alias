'use strict';

// Run from D:\v6alias: node --test scripts\tests\windows-console-proxy.test.cjs
// Network tests use only local synthetic data, never SSH, the lab, or a user's console.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const { once } = require('node:events');
const { randomUUID } = require('node:crypto');
const { spawn } = require('node:child_process');
const { createServer, staticPath } = require('../windows-console-proxy.cjs');

const project = path.resolve(__dirname, '..', '..');
const dependencyDir = path.join(project, 'state', 'windows-server-2025', 'console', 'node_modules');
let wsPackage;
try { wsPackage = require(path.join(dependencyDir, 'ws')); } catch {}

test('static paths are confined before URL normalization or Windows path handling', () => {
  assert.equal(staticPath('/'), 'vnc.html');
  assert.equal(staticPath('/vnc.html?ignored=true'), 'vnc.html');
  assert.equal(staticPath('/core/rfb.js'), path.join('core', 'rfb.js'));
  for (const value of [
    '/app/../secret.txt', '/app/%2e%2e/secret.txt', '/app/%2e%2e%2fsecret.txt',
    '/app/%252e%252e/secret.txt', '/app/%5c..%5csecret.txt', '/app/..%20/secret.txt',
    '/core/code.js:secret', '/app/%00file', '/app/%ZZ', '//other/app/a',
    'http://other/app/a', '/app//a', '/app/./a', '/.git/config', '/scripts/a',
    '/state/a', '/vendor/trailing.', '/core/a#fragment', '/core/a%3fhidden',
  ]) assert.equal(staticPath(value), null, value);
});

test('configuration fails before loading dependencies or binding any port', async () => {
  for (const vncPort of [0, -1, 65536, 1.5, '5900', NaN]) {
    await assert.rejects(createServer({ root: project, dependencyDir, vncPort }), /Invalid console configuration/);
  }
  await assert.rejects(createServer({ root: 'relative', dependencyDir, vncPort: 5900 }));
  await assert.rejects(createServer({ root: project, dependencyDir: 'relative', vncPort: 5900 }));
  await assert.rejects(createServer({ root: project, dependencyDir, vncPort: 5900, port: -1 }));
});

function request(base, target, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(base, { path: target, method, headers }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers,
        body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end();
  });
}

function rejectedUpgrade(base, target, origin, host) {
  return new Promise((resolve, reject) => {
    const headers = { Connection: 'Upgrade', Upgrade: 'websocket',
      'Sec-WebSocket-Key': 'MDEyMzQ1Njc4OWFiY2RlZg==', 'Sec-WebSocket-Version': '13' };
    if (origin !== undefined) headers.Origin = origin;
    if (host !== undefined) headers.Host = host;
    const req = http.request(base, { path: target, headers }, response => {
      response.resume();
      resolve(response.statusCode);
    });
    req.on('upgrade', (_response, socket) => { socket.destroy(); reject(new Error('Unexpected upgrade')); });
    req.on('error', reject);
    req.end();
  });
}

test('loopback HTTP/WebSocket integration with a fake VNC server', {
  skip: !wsPackage && 'Stage ws in state\\windows-server-2025\\console\\node_modules first.',
  timeout: 20000,
}, async t => {
  const fixture = path.relative(process.cwd(), path.join(__dirname, `.console-fixture-${randomUUID()}`));
  const root = path.resolve(fixture, 'noVNC');
  const peers = new Set();
  let connectionCount = 0;
  let proxy;
  let cli;
  const backend = net.createServer(socket => {
    connectionCount++;
    peers.add(socket);
    socket.on('close', () => peers.delete(socket));
    socket.on('error', () => {});
    socket.write('RFB 003.008\n');
    socket.on('data', data => socket.write(data));
  });
  t.after(async () => {
    if (cli && cli.exitCode === null && cli.signalCode === null) { cli.kill(); await once(cli, 'exit'); }
    if (proxy) await proxy.close();
    for (const peer of peers) peer.destroy();
    await new Promise(resolve => backend.close(resolve));
    await fs.promises.rm(fixture, { recursive: true, force: true });
  });
  await fs.promises.mkdir(path.join(fixture, 'noVNC', 'app'), { recursive: true });
  await fs.promises.mkdir(path.join(fixture, 'noVNC', 'core'));
  await fs.promises.mkdir(path.join(fixture, 'outside'));
  const bootstrap = "\nimport UI from './app/ui.js';\nUI.start();\n";
  await fs.promises.writeFile(path.join(fixture, 'noVNC', 'vnc.html'),
    `<!doctype html><title>Fixture</title><script type="module">${bootstrap}</script>`);
  await fs.promises.writeFile(path.join(fixture, 'noVNC', 'core', 'rfb.js'), 'export default {};');
  await fs.promises.writeFile(path.join(fixture, 'outside', 'secret.txt'), 'not public');
  await fs.promises.symlink(path.resolve(fixture, 'outside'), path.join(fixture, 'noVNC', 'app', 'escape'),
    process.platform === 'win32' ? 'junction' : 'dir');
  backend.listen({ host: '127.0.0.1', port: 0, exclusive: true });
  await once(backend, 'listening');
  const vncPort = backend.address().port;
  proxy = await createServer({ root, dependencyDir, vncPort });
  assert.equal(proxy.server.address().address, '127.0.0.1');
  const url = new URL(proxy.url);
  const wsPath = '/' + url.searchParams.get('path');
  const token = new URL(wsPath, url).searchParams.get('token');
  assert.match(token, /^[a-f0-9]{64}$/);
  assert.equal(url.searchParams.get('autoconnect'), '1');

  await t.test('static resources, HEAD, MIME and protective headers', async () => {
    const page = await request(url.origin, '/vnc.html');
    assert.equal(page.status, 200);
    assert.match(page.body, /Fixture/);
    assert.match(page.headers['cache-control'], /no-store/);
    assert.equal(page.headers['referrer-policy'], 'no-referrer');
    assert.equal(page.headers['x-content-type-options'], 'nosniff');
    assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/);
    const { createHash } = require('node:crypto');
    const hash = createHash('sha256').update(bootstrap).digest('base64');
    assert.ok(page.headers['content-security-policy'].includes(`'sha256-${hash}'`));
    assert.ok(!page.headers['content-security-policy'].includes("script-src 'self' 'unsafe-inline'"));
    assert.ok(page.headers['content-security-policy'].includes(`ws://${url.host}`));
    const head = await request(url.origin, '/vnc.html', { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.body, '');
    assert.equal(head.headers['content-length'], page.headers['content-length']);
    const js = await request(url.origin, '/core/rfb.js');
    assert.match(js.headers['content-type'], /text\/javascript/);
    assert.equal((await request(url.origin, '/vnc.html', { method: 'POST' })).status, 405);
    assert.equal((await request(url.origin, '/vnc.html', { headers: { Host: 'localhost' } })).status, 403);
  });

  await t.test('traversal, alternate data streams and escaping junctions are rejected', async () => {
    for (const target of ['/app/%2e%2e/%2e%2e/outside/secret.txt', '/app/escape/secret.txt',
      '/app/%5c..%5c..%5coutside%5csecret.txt', '/vnc.html:secret', '/state/private.txt',
      '/app/%00bad', '/app/%E0%A4%A']) {
      const response = await request(url.origin, target);
      assert.equal(response.status, 404, target);
      assert.equal(response.body, '');
    }
  });

  await t.test('upgrade requires the exact origin, path and invocation nonce', async () => {
    for (const origin of [undefined, 'null', 'https://example.invalid', `http://localhost:${url.port}`,
      `${url.origin}/`, `https://${url.host}`, 'http://127.0.0.1:1']) {
      assert.equal(await rejectedUpgrade(url.origin, wsPath, origin), 403);
    }
    for (const target of ['/websockify', '/websockify?token=', '/websockify?token=' + '0'.repeat(64),
      '/elsewhere?token=' + token, wsPath + '&token=' + token, wsPath + '&extra=1',
      '/app/../websockify?token=' + token]) {
      assert.equal(await rejectedUpgrade(url.origin, target, url.origin), 403);
    }
    assert.equal(await rejectedUpgrade(url.origin, wsPath, url.origin, `localhost:${url.port}`), 403);
    assert.equal(connectionCount, 0);
  });

  await t.test('binary traffic bridges both ways; text and oversized payloads disconnect', async () => {
    const endpoint = `ws://${url.host}${wsPath}`;
    const client = new wsPackage.WebSocket(endpoint, ['binary'], { origin: url.origin });
    const greeting = once(client, 'message');
    await once(client, 'open');
    const [banner, binary] = await greeting;
    assert.equal(banner.toString(), 'RFB 003.008\n');
    assert.equal(binary, true);
    const echo = once(client, 'message');
    client.send(Buffer.from([0, 1, 127, 255]));
    assert.deepEqual((await echo)[0], Buffer.from([0, 1, 127, 255]));
    const textClosed = once(client, 'close');
    client.send('not binary');
    await textClosed;
    const large = new wsPackage.WebSocket(endpoint, { origin: url.origin });
    await once(large, 'open');
    const largeClosed = once(large, 'close');
    large.send(Buffer.alloc(1024 * 1024 + 1));
    await largeClosed;
  });

  await t.test('CLI announces exactly one loopback URL and regenerates its nonce', async () => {
    cli = spawn(process.execPath, [path.join(project, 'scripts', 'windows-console-proxy.cjs'),
      '--root', root, '--dependency-dir', dependencyDir, '--vnc-port', String(vncPort)],
    { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let stdout = '';
    let stderr = '';
    cli.stdout.on('data', data => { stdout += data; });
    cli.stderr.on('data', data => { stderr += data; });
    while (!stdout.includes('\n')) {
      if (cli.exitCode !== null) throw new Error('Proxy CLI exited before its announcement.');
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    const ready = JSON.parse(stdout.trim());
    assert.deepEqual(Object.keys(ready), ['url']);
    const second = new URL(ready.url);
    assert.equal(second.hostname, '127.0.0.1');
    assert.notEqual(second.searchParams.get('path'), url.searchParams.get('path'));
    assert.equal((await request(second.origin, '/vnc.html')).status, 200);
    assert.equal(stdout.trim().split('\n').length, 1);
    assert.equal(stderr, '');
    cli.kill();
    await once(cli, 'exit');
  });

  await t.test('exclusive bind collision fails instead of picking another listener', async () => {
    await assert.rejects(createServer({ root, dependencyDir, vncPort, port: url.port * 1 }), { code: 'EADDRINUSE' });
  });
});
