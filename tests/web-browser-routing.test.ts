import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { Script } from 'node:vm';

const require = createRequire(import.meta.url);

test('real Chromium sibling tabs retain their proxy and never fall back to a direct connection', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const helpers = [
    'web-browser-tabs',
    'web-zoom',
    'web-session-attempt',
    'tunnel-lease-registry',
    'keyed-single-flight',
    'keyed-task-tracker',
    'extension-mutation-guard',
    'web-new-window-navigation',
    'bitwarden-active-tab-bridge',
  ]
    .map((name) =>
      readFileSync(new URL(`../electron/${name}.ts`, import.meta.url), 'utf8').replace(
        /^export /gm,
        '',
      ),
    )
    .join('\n');
  const managerStart = source.indexOf('class WebSurfaceManager');
  const managerEnd = source.indexOf('function clampWindowDimension', managerStart);
  const controller = stripTypeScriptTypes(helpers + source.slice(managerStart, managerEnd), {
    mode: 'transform',
  });
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-web-browser-routing-'));
  try {
    const harnessPath = join(directory, 'routing.cjs');
    writeFileSync(
      harnessPath,
      `
      const assert = require('node:assert/strict');
      const { randomUUID } = require('node:crypto');
      const net = require('node:net');
      const http = require('node:http');
      const dgram = require('node:dgram');
      const { app, BrowserWindow, WebContentsView: NativeWebContentsView, Menu, net: electronNet, session: electronSession } = require('electron');
      // Native children of a hidden Windows window have no display surface to capture.
      // Offscreen Chromium supplies real page pixels without opening a visible test window.
      function WebContentsView(options) {
        return new NativeWebContentsView({ ...options, webPreferences: { ...options.webPreferences, offscreen: true } });
      }
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      const authSession = { authorizationEpoch: 1, isAccessAllowed: true };
      const isAuthorizationEpochCurrent = epoch => epoch === authSession.authorizationEpoch;
      const webMaxUrlLength = 4096;
      const validateWebTarget = value => value;
      const describeWebNavigationError = () => 'Navigation failed';
      const describeWebLoadFailure = () => 'Page unavailable';
      const afterBitwardenPopupInputEvent = operation => operation();
      const releaseNativeTunnelLease = async () => {};
      ${controller}
      const waitFor = async (predicate, label = 'Browser state') => {
        const deadline = Date.now() + 10000;
        while (!(await predicate())) {
          if (Date.now() > deadline) throw new Error(label + ' timed out');
          await new Promise(resolve => setTimeout(resolve, 10));
        }
      };
      app.whenReady().then(async () => {
        const requests = [], submissions = [], proxied = [], sockets = new Set(), datagrams = [], cookieRequests = new Map();
        const server = http.createServer((request, response) => {
          requests.push(request.url);
          cookieRequests.set(request.url, request.headers.cookie || '');
          let body = '';
          request.on('data', chunk => { body += chunk; });
          request.on('end', () => {
            submissions.push({ url: request.url, method: request.method, body });
            if (request.url === '/icon-redirect') {
              response.writeHead(302, { Location: 'http://gateway.internal:' + server.address().port + '/icon.svg?probe=redirect' });
              response.end(); return;
            }
            if (request.url === '/icon.svg' || request.url.startsWith('/icon.svg?')) {
              response.setHeader('Content-Type', 'image/svg+xml');
              response.end('<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><rect width="16" height="16" fill="green"/><image href="http://127.0.0.1:' + server.address().port + '/favicon-escape"/></svg>');
              return;
            }
            response.setHeader('Content-Type', 'text/html');
            response.setHeader('Set-Cookie', 'iconAuth=browser-one; SameSite=Lax');
            response.end('<title>' + (request.url === '/help' ? 'Help' : 'Gateway') + '</title><link rel="icon" href="/icon.svg"><h1>Internal console</h1>');
          });
        });
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const targetPort = server.address().port;
        const proxy = net.createServer(client => {
          sockets.add(client);
          client.on('error', () => {});
          client.on('close', () => sockets.delete(client));
          let buffer = Buffer.alloc(0), greeting = true;
          const receive = chunk => {
            buffer = Buffer.concat([buffer, chunk]);
            if (greeting) {
              if (buffer.length < 2 || buffer.length < 2 + buffer[1]) return;
              assert.equal(buffer[0], 5);
              buffer = buffer.subarray(2 + buffer[1]);
              greeting = false;
              client.write(Buffer.from([5, 0]));
            }
            if (buffer.length < 5) return;
            const type = buffer[3];
            const hostStart = type === 3 ? 5 : 4;
            const hostLength = type === 3 ? buffer[4] : type === 1 ? 4 : 16;
            const packetLength = hostStart + hostLength + 2;
            if (buffer.length < packetLength) return;
            const host = type === 3 ? buffer.subarray(hostStart, hostStart + hostLength).toString() : [...buffer.subarray(hostStart, hostStart + hostLength)].join('.');
            proxied.push(host);
            assert.equal(buffer.readUInt16BE(packetLength - 2), targetPort);
            const leftover = buffer.subarray(packetLength);
            client.pause();
            client.off('data', receive);
            const upstream = net.connect(targetPort, '127.0.0.1', () => {
              client.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
              if (leftover.length) upstream.write(leftover);
              client.pipe(upstream); upstream.pipe(client); client.resume();
            });
            upstream.on('error', () => client.destroy());
            client.on('close', () => upstream.destroy());
          };
          client.on('data', receive);
        });
        await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
        const endpoint = '127.0.0.1:' + proxy.address().port;
        globalThis.getNativeBackend = () => ({ acquireTunnelRoute: async () => ({ active: true, socksEndpoint: endpoint }) });
        globalThis.runBackend = async (_action, request) => ({ url: request.address, host: new URL(request.address).hostname, protocol: 'http', port: targetPort, ignoreCertErrors: false, tunnelConfigId: request.tunnelConfigId });
        const owner = new BrowserWindow({ show: false, width: 900, height: 700 });
        const manager = new WebSurfaceManager();
        try {
          await owner.loadURL('data:text/html,<title>Browser owner</title>');
          await manager.open(owner, { sessionId: 'routed', attempt: 1, address: 'http://gateway.internal:' + targetPort + '/', protocol: 'http', tunnelConfigId: 'vpn-route' });
          const record = manager.surfaces.get('routed');
          manager.setBounds(owner, { sessionId: 'routed', x: 0, y: 0, width: 900, height: 650, visible: true });
          const first = record.view.webContents;
          first.setBackgroundThrottling(false);
          await waitFor(() => first.getTitle() === 'Gateway' && !first.isLoading());
          await waitFor(() => Boolean(record.tabs.snapshot('vpn').tabs[0].favicon), 'Initial favicon');
          const favicon = record.tabs.snapshot('vpn').tabs[0].favicon;
          assert.ok(favicon.startsWith('data:image/svg+xml;base64,'));
          assert.ok(proxied.includes('gateway.internal'));
          assert.equal(await owner.webContents.executeJavaScript('new Promise(resolve => { const icon = new Image(); icon.onload = () => resolve(icon.naturalWidth); icon.onerror = () => resolve(0); icon.src = ' + JSON.stringify(favicon) + '; })'), 16);
          assert.equal(requests.includes('/favicon-escape'), false, 'Workspace favicons must not make their own network requests');
          // Renderer menus must retain real page pixels while their native sibling is hidden.
          await first.executeJavaScript("document.body.style.background = 'rgb(40, 160, 80)'; window.overlayState = 42; true");
          const originalLease = record.tunnelLeaseId;
          assert.equal(first.isOffscreen(), true);
          await new Promise(resolve => {
            first.once('paint', resolve);
            first.startPainting();
            first.invalidate();
          });
          // A paint notification can precede the offscreen surface becoming capturable.
          await waitFor(async () => {
            try { return !(await first.capturePage()).isEmpty(); }
            catch { return false; }
          });
          const pageBounds = { sessionId: 'routed', x: 0, y: 0, width: 900, height: 650, visible: true };
          const previewId = randomUUID();
          const preview = await manager.setBounds(owner, { ...pageBounds, visible: false, capturePreview: true, previewId });
          assert.ok(preview && preview.startsWith('data:image/jpeg;base64,'));
          assert.equal(record.view.getVisible(), true, 'Keep the live page until the renderer has painted');
          const color = await owner.webContents.executeJavaScript('new Promise(resolve => { const image = new Image(); image.onload = () => { document.body.append(image); const canvas = document.createElement("canvas"); canvas.width = image.naturalWidth; canvas.height = image.naturalHeight; const ctx = canvas.getContext("2d"); ctx.drawImage(image, 0, 0); resolve(Array.from(ctx.getImageData(400, 400, 1, 1).data)); }; image.onerror = () => resolve([]); image.src = ' + JSON.stringify(preview) + '; })');
          assert.ok(Math.abs(color[0] - 40) < 5 && Math.abs(color[1] - 160) < 5 && Math.abs(color[2] - 80) < 5, 'The overlay must show page pixels, not an empty capture');
          await manager.setBounds(owner, { ...pageBounds, visible: false, previewId });
          assert.equal(record.view.getVisible(), false);
          await owner.webContents.executeJavaScript('document.querySelector("img").remove()');
          await manager.setBounds(owner, pageBounds);
          assert.equal(record.view.getVisible(), true);
          assert.equal(record.view.webContents, first);
          assert.equal(await first.executeJavaScript('window.overlayState'), 42);
          assert.equal(record.tunnelLeaseId, originalLease);
          const menus = [];
          const buildMenu = Menu.buildFromTemplate.bind(Menu);
          Menu.buildFromTemplate = template => {
            const menu = buildMenu(template);
            menu.popup = () => menus.push(menu);
            return menu;
          };
          // Hidden Windows windows cannot receive a focused native right-click. Dispatch the
          // native WebContents event and verify the real Electron menu it constructs.
          first.emit('context-menu', {}, { linkURL: '', selectionText: '', isEditable: false,
            editFlags: { canSelectAll: true } });
          assert.equal(menus.length, 1);
          assert.ok(menus[0].items.some(item => item.label === 'Reload'));
          assert.ok(menus[0].items.some(item => item.label === 'Select all'));
          Menu.buildFromTemplate = buildMenu;
          await first.executeJavaScript("document.cookie = 'profile=one'; true");
          await first.executeJavaScript("window.open('http://switch.internal:" + targetPort + "/help', '_blank', 'nodeIntegration=yes,contextIsolation=no,sandbox=no,nodeIntegrationInSubFrames=yes,nodeIntegrationInWorker=yes,webviewTag=yes'); true", true);
          await waitFor(() => record.tabs.size === 2 && record.view.webContents.getTitle() === 'Help');
          const second = record.view.webContents;
          assert.equal(second.session, first.session);
          assert.equal(second.getLastWebPreferences().sandbox, true);
          assert.equal(second.getLastWebPreferences().contextIsolation, true);
          assert.equal(second.getLastWebPreferences().nodeIntegration, false);
          assert.equal(await second.executeJavaScript('typeof require'), 'undefined');
          const workerGlobals = await second.executeJavaScript('new Promise(resolve => { const url = URL.createObjectURL(new Blob(["postMessage([typeof process, typeof require])"], {type: "text/javascript"})); const worker = new Worker(url); worker.onmessage = event => { worker.terminate(); URL.revokeObjectURL(url); resolve(event.data); }; })');
          assert.deepEqual(workerGlobals, ['undefined', 'undefined']);
          // Favicon requests are native, but must retain the source page's cookie authority.
          await first.session.cookies.set({ url: 'http://gateway.internal:' + targetPort, name: 'strictGateway', value: 'synthetic', sameSite: 'strict' });
          await first.session.cookies.set({ url: 'http://switch.internal:' + targetPort, name: 'strictSwitch', value: 'synthetic', sameSite: 'strict' });
          const iconRequest = async (url, expectedPath) => {
            second.emit('page-favicon-updated', {}, [url]);
            await waitFor(() => cookieRequests.has(expectedPath), 'Favicon ' + expectedPath);
            return cookieRequests.get(expectedPath);
          };
          assert.equal(await iconRequest('http://gateway.internal:' + targetPort + '/icon.svg?probe=cross', '/icon.svg?probe=cross'), '', 'Cross-origin favicon must not send cookies owned by another site');
          assert.match(await iconRequest('http://switch.internal:' + targetPort + '/icon.svg?probe=same', '/icon.svg?probe=same'), /strictSwitch=synthetic/);
          assert.equal(await iconRequest('http://switch.internal:' + targetPort + '/icon-redirect', '/icon.svg?probe=redirect'), '', 'Redirects must not widen favicon credential authority');
          assert.match(cookieRequests.get('/icon-redirect'), /strictSwitch=synthetic/);
          second.openDevTools({ mode: 'right', activate: false });
          await new Promise(resolve => setImmediate(resolve));
          assert.equal(second.isDevToolsOpened(), false);
          assert.equal(await second.executeJavaScript('Boolean(window.opener)'), true);
          assert.ok(proxied.includes('gateway.internal'));
          assert.ok(proxied.includes('switch.internal'));
          assert.equal(first.getTitle(), 'Gateway');
          await first.executeJavaScript("const form = document.createElement('form'); form.action = 'http://forms.internal:" + targetPort + "/form'; form.method = 'POST'; form.target = '_blank'; form.innerHTML = '<input name=section value=network>'; document.body.append(form); form.submit(); true", true);
          await waitFor(() => record.tabs.size === 3 && record.view.webContents.getTitle() === 'Gateway');
          assert.deepEqual(submissions.find(item => item.url === '/form'), { url: '/form', method: 'POST', body: 'section=network' });
          await first.executeJavaScript("const link = document.createElement('a'); link.href = 'http://docs.internal:" + targetPort + "/help'; link.target = '_blank'; document.body.append(link); link.click(); true", true);
          await waitFor(() => record.tabs.size === 4 && record.view.webContents.getTitle() === 'Help');
          await manager.command(owner, { sessionId: 'routed', operation: 'new-tab' });
          await manager.command(owner, { sessionId: 'routed', operation: 'navigate', url: 'http://gateway.internal:' + targetPort + '/settings' });
          await waitFor(() => record.view.webContents.getTitle() === 'Gateway');
          assert.match(await record.view.webContents.executeJavaScript('document.cookie'), /profile=one/);
          // Loopback itself must also use SOCKS; Chromium normally bypasses it unless configured.
          await manager.command(owner, { sessionId: 'routed', operation: 'navigate', url: 'http://127.0.0.1:' + targetPort + '/via-proxy' });
          await waitFor(() => requests.includes('/via-proxy'));
          assert.ok(proxied.includes('127.0.0.1'));
          for (const socket of sockets) socket.destroy();
          await new Promise(resolve => proxy.close(resolve));
          await manager.command(owner, { sessionId: 'routed', operation: 'navigate', url: 'http://127.0.0.1:' + targetPort + '/no-direct-fallback' });
          await waitFor(() => Boolean(record.tabs.snapshot('vpn').tabs.find(tab => tab.id === record.tabs.activeId).error));
          assert.equal(requests.includes('/no-direct-fallback'), false);
          await manager.open(owner, { sessionId: 'direct', attempt: 1, address: 'http://127.0.0.1:' + targetPort + '/direct', protocol: 'http' });
          const direct = manager.surfaces.get('direct');
          await waitFor(() => direct.view.webContents.getTitle() === 'Gateway');
          assert.notEqual(direct.view.webContents.session, first.session);
          assert.equal((await direct.view.webContents.session.cookies.get({ name: 'profile' })).length, 0);
          // WebTransport bypasses webRequest; a real UDP listener exposes that leak.
          for (const name of ['control', 'blocked']) {
            const socket = dgram.createSocket('udp4');
            const probe = { socket, name, packets: 0 };
            socket.on('message', () => { probe.packets++; });
            await new Promise(resolve => socket.bind(0, '127.0.0.1', resolve));
            datagrams.push(probe);
          }
          const transport = port => "window.udpTransport = new WebTransport('https://127.0.0.1:" + port + "/'); window.udpTransport.ready.catch(() => {}); window.udpTransport.closed.catch(() => {}); true";
          await direct.view.webContents.executeJavaScript(transport(datagrams[0].socket.address().port));
          await waitFor(() => datagrams[0].packets > 0);
          await direct.view.webContents.executeJavaScript('window.udpTransport.close(); true');
          globalThis.getNativeBackend = () => ({
            acquireTunnelRoute: async () => ({ active: true, socksEndpoint: '' }),
            bindTunnelForwarder: async () => ({ host: '127.0.0.1', port: targetPort }),
          });
          await manager.open(owner, { sessionId: 'forwarder', attempt: 1, address: 'http://forwarded.internal:' + targetPort + '/', protocol: 'http', tunnelConfigId: 'vpn-route' });
          const forwarded = manager.surfaces.get('forwarder');
          await waitFor(() => forwarded.view.webContents.getTitle() === 'Gateway');
          const forwarderOpener = forwarded.view.webContents;
          assert.equal(await forwarderOpener.executeJavaScript("window.forwarderPopup = window.open('http://forwarded.internal:" + targetPort + "/forwarder-popup?flow=login#reply', 'forwarded-auth'); Boolean(window.forwarderPopup)", true), true, 'A rewritten popup must return its Chromium WindowProxy');
          await waitFor(() => forwarded.tabs.size === 2 && forwarded.view.webContents.getURL().endsWith('/forwarder-popup?flow=login#reply') && !forwarded.view.webContents.isLoading(), 'Forwarder popup');
          const forwarderPopup = forwarded.view.webContents;
          assert.equal(forwarderPopup.session, forwarderOpener.session);
          assert.equal(await forwarderPopup.executeJavaScript('Boolean(window.opener)'), true);
          await forwarderPopup.executeJavaScript("window.opener.forwarderReply = 'received'; true");
          assert.equal(await forwarderOpener.executeJavaScript('window.forwarderReply'), 'received');
          assert.equal(await forwarderOpener.executeJavaScript('window.forwarderPopup.closed'), false);
          await forwarderOpener.executeJavaScript("(() => { const form = document.createElement('form'); form.action = 'http://forwarded.internal:" + targetPort + "/forwarder-form'; form.method = 'POST'; form.target = '_blank'; form.innerHTML = '<input name=section value=routes>'; document.body.append(form); form.submit(); return true; })()", true);
          await waitFor(() => forwarded.tabs.size === 3 && forwarded.view.webContents.getURL().endsWith('/forwarder-form') && !forwarded.view.webContents.isLoading(), 'Forwarder POST popup');
          assert.deepEqual(submissions.find(item => item.url === '/forwarder-form'), { url: '/forwarder-form', method: 'POST', body: 'section=routes' });
          await forwarderOpener.executeJavaScript("(() => { const form = document.createElement('form'); form.action = 'http://forwarded.internal:" + targetPort + "/forwarder-retarget'; form.method = 'POST'; form.target = 'forwarded-auth'; form.innerHTML = '<input name=section value=auth>'; document.body.append(form); form.submit(); return true; })()", true);
          await waitFor(() => forwarderPopup.getURL().endsWith('/forwarder-retarget') && !forwarderPopup.isLoading(), 'Retargeted forwarder POST');
          assert.deepEqual(submissions.find(item => item.url === '/forwarder-retarget'), { url: '/forwarder-retarget', method: 'POST', body: 'section=auth' });
          assert.equal(forwarded.tabs.size, 3, 'A named popup must reuse its original native guest');
          assert.equal(await forwarderPopup.executeJavaScript('Boolean(window.opener)'), true);
          assert.equal(await forwarderOpener.executeJavaScript("Boolean(window.open('http://outside.internal:" + targetPort + "/forwarder-escape'))", true), false);
          assert.equal(forwarded.tabs.size, 3);
          assert.equal(requests.includes('/forwarder-escape'), false);
          assert.equal(await forwarderOpener.executeJavaScript("fetch('http://forwarded.internal:" + targetPort + "/forwarder-subresource').then(() => 'loaded', () => 'blocked')"), 'blocked');
          assert.equal(requests.includes('/forwarder-subresource'), false, 'Only authorized main-frame requests may be rewritten');
          await forwarded.view.webContents.executeJavaScript(transport(datagrams[1].socket.address().port));
          const outcome = await forwarded.view.webContents.executeJavaScript("Promise.race([window.udpTransport.ready.then(() => 'connected', () => 'rejected'), new Promise(resolve => setTimeout(() => resolve('pending'), 1000))])");
          assert.equal(outcome, 'rejected', 'The forwarder must reject unproxied WebTransport');
          assert.equal(datagrams[1].packets, 0, 'The forwarder emitted direct UDP');
          await manager.command(owner, { sessionId: 'forwarder', operation: 'new-tab' });
          await manager.command(owner, { sessionId: 'forwarder', operation: 'navigate', url: 'http://forwarded.internal:' + targetPort + '/help' });
          await waitFor(() => forwarded.view.webContents.getTitle() === 'Help');
          assert.equal(await forwarded.view.webContents.session.resolveProxy('http://127.0.0.1:' + targetPort + '/help'), 'DIRECT');
          assert.equal(await forwarded.view.webContents.session.resolveProxy('ws://127.0.0.1:' + targetPort + '/socket'), 'DIRECT');
          assert.match(await forwarded.view.webContents.session.resolveProxy('https://outside.invalid/'), /^SOCKS5 /);
          manager.backendStopped();
          assert.equal(manager.surfaces.has('routed'), false);
          assert.equal(manager.surfaces.has('forwarder'), false);
          assert.equal(manager.surfaces.has('direct'), true);
        } finally {
          manager.closeForWindow(owner);
          owner.destroy();
          for (const socket of sockets) socket.destroy();
          for (const probe of datagrams) probe.socket.close();
          proxy.close();
          server.closeAllConnections(); server.close();
        }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    new Script(readFileSync(harnessPath, 'utf8'), { filename: harnessPath });
    const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 60_000, windowsHide: true },
    );
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
