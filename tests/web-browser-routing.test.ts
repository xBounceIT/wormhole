import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Script } from 'node:vm';
import { build } from 'vite';

const require = createRequire(import.meta.url);

test('real Chromium sibling tabs retain their proxy and never fall back to a direct connection', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const helpers = [
    'web-browser-tabs',
    'web-tunnel-endpoint',
    'web-zoom',
    'web-session-attempt',
    'tunnel-lease-registry',
    'tunnel-route-snapshot',
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
  const fixture = fileURLToPath(new URL('./fixtures/browser-https.go', import.meta.url));
  const httpsServer = spawn('go', ['run', fixture], {
    stdio: ['pipe', 'pipe', 'inherit'],
    timeout: 180_000,
    windowsHide: true,
  });
  const exited = once(httpsServer, 'close');
  try {
    const lines = createInterface({ input: httpsServer.stdout });
    const [address] = await Promise.race([
      once(lines, 'line'),
      exited.then(() => {
        throw new Error('HTTPS fixture exited before listening');
      }),
    ]);
    const tlsPort = Number(new URL(address).port);
    assert.ok(tlsPort > 0 && tlsPort <= 65535);
    const harnessPath = join(directory, 'routing.cjs');
    const vaultModule = join(directory, 'vault-web.cjs');
    const vaultEntry = join(directory, 'vault-entry.ts');
    writeFileSync(
      vaultEntry,
      [
        'export { VaultWebConnections, parseVaultWebRequest } from ' +
          JSON.stringify(resolve('electron/vault-web-connections.ts')) +
          ';',
        'export { VaultWebIpc } from ' + JSON.stringify(resolve('electron/vault-web-ipc.ts')) + ';',
        'export { vaultID } from ' + JSON.stringify(resolve('electron/vault-contract.ts')) + ';',
        'export { webPlan, webRequest } from ' +
          JSON.stringify(resolve('tests/fixtures/vault-web.ts')) +
          ';',
      ].join('\n'),
    );
    const output = await build({
      configFile: false,
      logLevel: 'silent',
      build: {
        ssr: true,
        write: false,
        minify: false,
        rolldownOptions: {
          input: vaultEntry,
          output: { format: 'cjs' },
          external: ['node:crypto'],
        },
      },
    });
    const chunks = (Array.isArray(output) ? output : [output])
      .flatMap((o) => o.output)
      .filter((o) => o.type === 'chunk');
    assert.equal(chunks.length, 1);
    writeFileSync(vaultModule, chunks[0].code);
    writeFileSync(
      harnessPath,
      `
      const assert = require('node:assert/strict');
      const { randomUUID } = require('node:crypto');
      const { VaultWebConnections, parseVaultWebRequest, VaultWebIpc, vaultID, webPlan, webRequest } = require(${JSON.stringify(vaultModule)});
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
      const isAuthorizationEpochCurrent = epoch => authSession.isAccessAllowed && epoch === authSession.authorizationEpoch;
      const webMaxUrlLength = 4096;
      const isQuitting = false;
      const authLockRequested = false;
      const tunnelClosedMessage = 'The VPN connection stopped.';
      const validateWebTarget = value => value;
      const describeWebNavigationError = () => 'Navigation failed';
      const describeWebLoadFailure = () => 'Page unavailable';
      const recordDiagnostic = () => {};
      const reportWarning = () => {};
      const afterBitwardenPopupInputEvent = operation => operation();
      const releaseNativeTunnelLease = async () => {};
      // Simulate the native relay service here. Its wire protocol and sockets are tested in Go.
      const getBrowserRelayBackend = () => ({
        openWebTunnelEndpoint: async () => {
          let port;
          const streams = new Set();
          const relay = net.createServer(client => {
            if (!port) return client.destroy();
            const upstream = net.connect(port, '127.0.0.1');
            const close = () => { client.destroy(); upstream.destroy(); streams.delete(close); };
            client.on('error', close); upstream.on('error', close);
            client.on('close', close); upstream.on('close', close);
            streams.add(close);
            client.pipe(upstream).pipe(client);
          });
          await new Promise(resolve => relay.listen(0, '127.0.0.1', resolve));
          const disconnect = async () => {
            port = undefined;
            for (const close of streams) close();
          };
          return {
            port: relay.address().port,
            connect: async upstream => { port = upstream; },
            disconnect,
            close: async () => { await disconnect(); relay.close(); },
          };
        },
      });
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
            if (request.url.startsWith('/external-button.svg')) {
              response.setHeader('Content-Type', 'image/svg+xml');
              response.setHeader('Access-Control-Allow-Origin', '*');
              // Match CDN icons with a viewBox, white paths and no intrinsic width/height.
              response.end('<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" viewBox="0 0 512 512"><path d="M0 0h512v512H0z" style="fill-rule:evenodd;clip-rule:evenodd;fill:#fff"/></svg>');
              return;
            }
            response.setHeader('Content-Type', 'text/html');
            response.setHeader('Set-Cookie', 'iconAuth=browser-one; SameSite=Lax');
            response.end('<title>' + (request.url === '/help' ? 'Help' : 'Gateway') + '</title><link rel="icon" href="/icon.svg"><h1>Internal console</h1>');
          });
        });
        await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
        const targetPort = server.address().port;
        const tlsPort = ${tlsPort};
        const createSocksProxy = () => net.createServer(client => {
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
            const port = buffer.readUInt16BE(packetLength - 2);
            // Serve the same certificate on a second port of the test appliance.
            const otherTlsOrigin = host === 'appliance.test' && port === 443;
            assert.ok(port === targetPort || port === tlsPort || otherTlsOrigin);
            const leftover = buffer.subarray(packetLength);
            client.pause();
            client.off('data', receive);
            const upstream = net.connect(otherTlsOrigin ? tlsPort : port, '127.0.0.1', () => {
              client.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
              if (leftover.length) upstream.write(leftover);
              client.pipe(upstream); upstream.pipe(client); client.resume();
            });
            upstream.on('error', () => client.destroy());
            client.on('close', () => upstream.destroy());
          };
          client.on('data', receive);
        });
        let proxy = createSocksProxy();
        let exitSocks, exitForwarder, replacementForwarder;
        await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
        globalThis.getNativeBackend = () => ({
          acquireTunnelRoute: async ({ onExit, tunnelConfigId }) => {
            exitSocks = onExit;
            return { active: true, socksEndpoint: '127.0.0.1:' + proxy.address().port, configuredTunnelId: tunnelConfigId };
          },
        });
        globalThis.runBackend = async (action, request) => {
          if (action === 'extension-read') return { enabled: false };
          const url = new URL(request.address);
          return { url: url.href, host: url.hostname, protocol: request.protocol, port: Number(url.port), ignoreCertErrors: request.ignoreCertErrors === true, tunnelConfigId: request.tunnelConfigId };
        };
        const owner = new BrowserWindow({ show: false, width: 900, height: 700 });
        const manager = new WebSurfaceManager();
        try {
          await owner.loadURL('data:text/html,<title>Browser owner</title>');
          const tlsAddress = 'https://appliance.test:' + tlsPort + '/';
          const certificateErrors = new Set();
          app.on('certificate-error', (_event, contents, url, error) => {
            if (url === tlsAddress && error.includes('ERR_CERT_')) certificateErrors.add(contents.id);
          });
          for (const [sessionId, ignoreCertErrors] of [['tls-opt-in', true], ['tls-strict', false]]) {
            await manager.open(owner, { sessionId, attempt: 1, address: tlsAddress, protocol: 'https', tunnelConfigId: 'vpn-route', ignoreCertErrors });
            const tlsBrowser = manager.surfaces.get(sessionId);
            const contents = tlsBrowser.view.webContents;
            if (ignoreCertErrors) {
              await waitFor(() => contents.getTitle() === 'HTTPS appliance', 'Opted-in TLS navigation');
              await assert.rejects(contents.loadURL('https://appliance.test/'), { code: /^ERR_CERT_/ });
            } else {
              await waitFor(() => tlsBrowser.tabs.snapshot('vpn').tabs[0].error, 'Strict TLS rejection');
            }
            assert.ok(certificateErrors.has(contents.id), 'The certificate error must reach the native app event');
            assert.equal(tlsBrowser.vpn.status, 'active');
            manager.close(sessionId);
          }
          assert.ok(proxied.includes('appliance.test'));
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
          // Button images are decoded by the guest renderer, unlike native favicon fetches.
          // Use another origin that only the VPN route can resolve and inspect actual SVG pixels.
          const externalSvg = 'http://assets.example.com:' + targetPort + '/external-button.svg';
          const svgPixels = await first.executeJavaScript('new Promise(resolve => { const image = new Image(); image.crossOrigin = "anonymous"; image.onload = () => { image.decode().then(() => { const canvas = document.createElement("canvas"); canvas.width = 80; canvas.height = 80; const ctx = canvas.getContext("2d"); ctx.drawImage(image, 0, 0, 80, 80); resolve({ decoded: image.naturalWidth > 0 && image.naturalHeight > 0, pixel: Array.from(ctx.getImageData(40, 40, 1, 1).data) }); }).catch(() => resolve(null)); }; image.onerror = () => resolve(null); image.src = ' + JSON.stringify(externalSvg) + '; })');
          assert.deepEqual(svgPixels, { decoded: true, pixel: [255, 255, 255, 255] }, 'A third-party SVG must load and render through the browser VPN route');
          assert.ok(proxied.includes('assets.example.com'), 'External button images must use the same VPN route as the page');
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
          // Run the actual vault preparation actor and browser controller against real Chromium.
          // Only native Go planning/route transport are faked here (covered by native-client tests).
          const seed = webPlan(webRequest(), true), routedNode = randomUUID(), directNode = randomUUID();
          const workspaceId = seed.binding.workspaceId;
          let routeClosed, leases = 0, quickAdmissions = 0, quickRetirements = 0;
          const quickRefs = new Map();
          const closed = new Promise(resolve => { routeClosed = resolve; });
          const nativePlan = q => {
            const routed = q.nodeId === routedNode || Boolean(quickRefs.get(q.nodeId)?.tunnelId), p = webPlan(q, routed);
            Object.assign(p.binding, { protocol: 'http', host: routed ? 'gateway.internal' : '127.0.0.1', port: targetPort,
              tunnelConfigId: routed ? seed.binding.tunnelConfigId : '' });
            p.route = routed ? { ...seed.route, ...p.binding } : null;
            p.target = { url: 'http://' + p.binding.host + ':' + targetPort + (routed ? '/vault-routed' : '/vault-direct'),
              protocol: 'http', host: p.binding.host, port: targetPort, ignoreCertErrors: false,
              ...(routed ? { tunnelConfigId: p.binding.tunnelConfigId } : {}) };
            if (quickRefs.has(q.nodeId)) p.temporary = true;
            return p;
          };
          const nativeConnections = new VaultWebConnections({ workspaceId: () => workspaceId,
            authorized: epoch => epoch === 2, plan: async q => nativePlan(q),
            quickTarget: async (target, sessionId, epoch, accepted) => {
              assert.equal(accepted(), true); quickAdmissions++;
              const id = randomUUID(); quickRefs.set(id, target);
              return { reference: { workspaceId, id, sessionId, epoch }, release: async () => {
                if (!quickRefs.has(id)) return;
                const token = nativeManager.vaultSessionOwners.get(sessionId);
                if (token?.partition) {
                  assert.equal(token.views?.size ?? 0, 0, 'No running view may outlive target retirement');
                  assert.equal((await electronSession.fromPartition(token.partition).cookies.get({})).length, 0,
                    'Profile cookies retire before native target authority');
                }
                quickRefs.delete(id); quickRetirements++;
              } };
            },
            routes: {
              acquire: async (q, epoch, ownerActive) => {
                assert.equal(ownerActive(), true); leases++;
                const binding = nativePlan({ ...q, epoch, workspaceId, credentialOverride: '', requestId: randomUUID() }).route;
                const endpoint = '127.0.0.1:' + proxy.address().port;
                return { binding, endpoint, active: true, closed, release: async () => routeClosed() };
              }, close: async () => routeClosed(), closeAll: async () => routeClosed(),
            },
          });
          const nativeManager = new WebSurfaceManager({ active: () => true, connections: nativeConnections });
          // Both production lifetimes are singletons. Give this second test
          // instance its own partition sequence instead of reusing legacy profiles.
          nativeManager.isolatedPartitionSequence = 100;
          const nativeOwners = new Set([owner.webContents]);
          const nativeIpc = new VaultWebIpc({ workspace: () => true,
            trusted: event => nativeOwners.has(event.sender), authorize: async run => run(),
            open: (contents, request, current) => nativeManager.open(BrowserWindow.fromWebContents(contents), request, current),
            close: (contents, id) => nativeManager.closeForContents(contents, id),
            closeAll: () => nativeManager.stopVaultSessions(),
          });
          const nativeId = randomUUID();
          const nativeResponse = await nativeIpc.open({ sender: owner.webContents }, { sessionId: nativeId, nodeId: routedNode, attempt: 1 });
          assert.equal(nativeResponse.proxyUrl, undefined);
          assert.equal(nativeResponse.browser.route, 'vpn');
          const nativeRecord = nativeManager.surfaces.get(nativeId), nativeFirst = nativeRecord.view.webContents;
          await waitFor(() => nativeFirst.getTitle() === 'Gateway' && !nativeFirst.isLoading());
          await nativeFirst.executeJavaScript("document.cookie = 'nativeVault=private-session'; window.onbeforeunload = () => false; true");
          await nativeManager.command(owner, { sessionId: nativeId, operation: 'new-tab' });
          await nativeManager.command(owner, { sessionId: nativeId, operation: 'navigate', url: 'http://gateway.internal:' + targetPort + '/help' });
          await waitFor(() => nativeRecord.view.webContents.getTitle() === 'Help');
          const nativeSecond = nativeRecord.view.webContents, nativeSession = nativeFirst.session;
          assert.equal(nativeSecond.session, nativeSession);
          assert.equal(leases, 1);
          const quickId = randomUUID();
          await nativeIpc.open({ sender: owner.webContents }, { sessionId: quickId, attempt: 1, quickTarget: {
            protocol: 'http', host: 'gateway.internal', port: targetPort, credentialId: '',
            tunnelId: seed.binding.tunnelConfigId, sshAutoSudo: false, httpPath: '/vault-routed', ignoreCertificateErrors: false, rdp: null } });
          const quickRecord = nativeManager.surfaces.get(quickId), quickFirst = quickRecord.view.webContents;
          await waitFor(() => quickFirst.getTitle() === 'Gateway' && !quickFirst.isLoading());
          await quickFirst.executeJavaScript("document.cookie = 'nativeQuick=private-session'; true");
          const quickFirstId = quickRecord.tabs.activeId;
          await nativeManager.command(owner, { sessionId: quickId, operation: 'new-tab' });
          await nativeManager.command(owner, { sessionId: quickId, operation: 'navigate', url: 'http://gateway.internal:' + targetPort + '/help' });
          await waitFor(() => quickRecord.view.webContents.getTitle() === 'Help');
          const quickSecond = quickRecord.view.webContents;
          assert.match(await quickSecond.executeJavaScript('document.cookie'), /nativeQuick=private-session/);
          await nativeManager.command(owner, { sessionId: quickId, operation: 'close-tab', tabId: quickFirstId });
          await waitFor(() => quickFirst.isDestroyed());
          assert.equal(quickSecond.isDestroyed(), false);
          assert.equal(leases, 2, 'Each browser owns one shared route, regardless of tab count');
          assert.equal(quickAdmissions, 1); assert.equal(quickRetirements, 0);
          assert.match(await nativeSecond.executeJavaScript('document.cookie'), /nativeVault=private-session/);
          assert.match(await nativeSession.resolveProxy('http://127.0.0.1:' + targetPort), /^SOCKS5 /);
          const loopbackTab = record.view.webContents;
          await waitFor(() => loopbackTab.getURL().endsWith('/via-proxy') && !loopbackTab.isLoading());
          await first.executeJavaScript("document.querySelector('h1').textContent = 'Unsaved browser state'");
          const oldProxy = proxy;
          const oldProxyPort = proxy.address().port;
          exitSocks();
          oldProxy.removeAllListeners('connection');
          oldProxy.on('connection', (socket) => socket.destroy());
          for (const socket of sockets) socket.destroy();
          assert.equal(record.vpn.status, 'disconnected');
          assert.equal(first.isDestroyed(), false);
          // A page may hide broken images in onerror: a missing broken-image badge is not proof
          // of successful decoding. Check that scenario without allowing direct resource access.
          const failedSvg = await first.executeJavaScript('new Promise(resolve => { const image = new Image(); image.onload = () => resolve({ loaded: true }); image.onerror = () => { image.style.display = "none"; resolve({ loaded: false, hidden: image.style.display === "none", width: image.naturalWidth }); }; image.src = ' + JSON.stringify(externalSvg + '?disconnected') + '; })');
          assert.deepEqual(failedSvg, { loaded: false, hidden: true, width: 0 });
          assert.equal(requests.includes('/external-button.svg?disconnected'), false, 'External SVG requests must fail closed when the VPN stops');
          await nativeManager.command(owner, { sessionId: nativeId, operation: 'navigate', url: 'http://127.0.0.1:' + targetPort + '/vault-no-direct-fallback' });
          await waitFor(() => nativeRecord.tabs.snapshot('vpn').tabs.some(tab => tab.error));
          assert.equal(requests.includes('/vault-no-direct-fallback'), false);
          routeClosed();
          await waitFor(() => nativeFirst.isDestroyed() && nativeSecond.isDestroyed(), 'Native route loss closes every tab');
          await nativeIpc.closeAll();
          assert.equal((await nativeSession.cookies.get({})).length, 0, 'Lock removes native authentication cookies');
          assert.equal(quickRetirements, 1); assert.equal(quickRefs.size, 0);
          const directId = randomUUID();
          await nativeIpc.open({ sender: owner.webContents }, { sessionId: directId, nodeId: directNode, attempt: 1 });
          const nativeDirect = nativeManager.surfaces.get(directId).view.webContents, directSession = nativeDirect.session;
          await waitFor(() => nativeDirect.getTitle() === 'Gateway' && !nativeDirect.isLoading());
          const quickDirectId = randomUUID();
          await nativeIpc.open({ sender: owner.webContents }, { sessionId: quickDirectId, attempt: 1, quickTarget: { protocol: 'http', host: '127.0.0.1', port: targetPort, credentialId: '', tunnelId: '', sshAutoSudo: false, httpPath: '/vault-direct', ignoreCertificateErrors: false, rdp: null } });
          const quickDirect = nativeManager.surfaces.get(quickDirectId).view.webContents;
          await waitFor(() => quickDirect.getTitle() === 'Gateway' && !quickDirect.isLoading());
          assert.equal(await directSession.resolveProxy('http://127.0.0.1:' + targetPort), 'DIRECT');
          await directSession.cookies.set({ url: 'http://127.0.0.1:' + targetPort, name: 'nativeDirect', value: 'private-session' });
          owner.webContents.reload();
          await waitFor(() => nativeDirect.isDestroyed(), 'Root reload closes native direct tab');
          await nativeIpc.closeAll();
          assert.equal((await directSession.cookies.get({})).length, 0);
          assert.equal(quickAdmissions, 2); assert.equal(quickRetirements, 2); assert.equal(quickRefs.size, 0);
          await waitFor(() => !owner.webContents.isLoading());
          await assert.rejects(manager.command(owner, { sessionId: 'routed', operation: 'navigate', url: 'http://127.0.0.1:' + targetPort + '/no-direct-fallback' }), /Reconnect the VPN/);
          await loopbackTab.executeJavaScript("location.href = '/no-direct-fallback'; true");
          assert.equal(await loopbackTab.executeJavaScript("fetch('/no-direct-fallback').then(() => 'loaded', () => 'blocked')"), 'blocked');
          assert.ok(loopbackTab.getURL().endsWith('/via-proxy'));
          assert.equal(requests.includes('/no-direct-fallback'), false);
          proxy = createSocksProxy();
          await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
          assert.notEqual(proxy.address().port, oldProxyPort);
          oldProxy.close();
          const firstProxy = await first.session.resolveProxy(first.getURL());
          assert.equal(await manager.command(owner, { sessionId: 'routed', operation: 'reconnect-vpn' }), true);
          assert.equal(record.vpn.status, 'active');
          assert.equal(await first.session.resolveProxy(first.getURL()), firstProxy);
          assert.equal(await first.executeJavaScript("document.querySelector('h1').textContent"), 'Unsaved browser state');
          assert.equal(await first.executeJavaScript("fetch('/resume-socks').then(response => response.ok)"), true);
          assert.ok(requests.includes('/resume-socks'));
          const tabCount = record.tabs.size;
          second.close();
          await waitFor(() => second.isDestroyed() && record.tabs.size === tabCount - 1, 'Closed SOCKS tab');
          assert.equal(manager.surfaces.get('routed'), record);
          assert.match(await first.session.resolveProxy('http://gateway.internal:' + targetPort), /^SOCKS5 /);
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
            acquireTunnelRoute: async ({ onExit, tunnelConfigId }) => {
              exitForwarder = onExit;
              return { active: true, socksEndpoint: '', configuredTunnelId: tunnelConfigId };
            },
            bindTunnelForwarder: async () => ({ host: '127.0.0.1', port: replacementForwarder?.address().port ?? targetPort }),
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
          const origin = new URL(forwarderOpener.getURL()).origin;
          assert.equal(await forwarded.view.webContents.session.resolveProxy(origin + '/help'), 'DIRECT');
          assert.equal(await forwarded.view.webContents.session.resolveProxy(origin.replace(/^http/, 'ws') + '/socket'), 'DIRECT');
          const forwarderSession = forwarded.view.webContents.session;
          assert.equal(await forwarderSession.resolveProxy('https://outside.invalid/'), 'SOCKS5 127.0.0.1:0');
          await forwarderOpener.executeJavaScript("localStorage.setItem('draft', 'in progress')");
          exitForwarder();
          assert.equal(forwarded.vpn.status, 'disconnected');
          assert.equal(await forwarderOpener.executeJavaScript("fetch('/offline').then(() => 'loaded', () => 'blocked')"), 'blocked');
          assert.equal(requests.includes('/offline'), false);
          replacementForwarder = http.createServer((request, response) => response.end('reconnected'));
          await new Promise(resolve => replacementForwarder.listen(0, '127.0.0.1', resolve));
          assert.equal(await manager.command(owner, { sessionId: 'forwarder', operation: 'reconnect-vpn' }), true);
          assert.equal(new URL(forwarderOpener.getURL()).origin, origin);
          assert.equal(await forwarderOpener.executeJavaScript("localStorage.getItem('draft')"), 'in progress');
          assert.equal(await forwarderOpener.executeJavaScript("fetch('/resume-forwarder').then(response => response.text())"), 'reconnected');
          manager.backendStopped();
          assert.equal(manager.surfaces.get('routed'), record);
          assert.equal(manager.surfaces.get('forwarder'), forwarded);
          assert.equal(forwarded.vpn.status, 'disconnected');
          assert.equal(manager.surfaces.has('direct'), true);
          manager.close('forwarder');
          await waitFor(async () => (await forwarderSession.resolveProxy(origin + '/help')) === 'SOCKS5 127.0.0.1:0', 'Retired forwarder proxy');
          const closingOwner = new BrowserWindow({ show: false });
          await closingOwner.loadURL('data:text/html,<title>Closing browser owner</title>');
          const closingContents = closingOwner.webContents; nativeOwners.add(closingContents);
          const closingId = randomUUID();
          await nativeIpc.open({ sender: closingContents }, { sessionId: closingId, attempt: 1,
            quickTarget: { protocol: 'http', host: '127.0.0.1', port: targetPort, credentialId: '', tunnelId: '', sshAutoSudo: false, httpPath: '/vault-direct', ignoreCertificateErrors: false, rdp: null } });
          const closingView = nativeManager.surfaces.get(closingId).view.webContents;
          await waitFor(() => closingView.getTitle() === 'Gateway' && !closingView.isLoading());
          closingOwner.destroy();
          await waitFor(() => closingView.isDestroyed());
          await nativeIpc.closeAll();
          assert.equal(quickAdmissions, 3); assert.equal(quickRetirements, 3);
          assert.equal(nativeManager.vaultSessionOwners.size, 0);
          assert.equal(quickRefs.size, 0);

        } finally {
          manager.closeForWindow(owner);
          owner.destroy();
          for (const socket of sockets) socket.destroy();
          for (const probe of datagrams) probe.socket.close();
          proxy.close();
          replacementForwarder?.close();
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
    httpsServer.stdin.end();
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
    await exited;
  }
});
