import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session } from 'node:inspector/promises';
import { declarations, mainSyntax, visitSyntax } from './fixtures/main-source.ts';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  tunnelAuthenticationContext,
  tunnelAuthenticationEnvelope,
} from './fixtures/vault-tunnel-authentication.ts';
import { tunnelCookieContext } from './fixtures/vault-tunnel-cookie.ts';
import { tunnelBrowserContext } from './fixtures/vault-tunnel-browser.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';

test('production prompt factory selects its dedicated document and preload in development and packaged builds', () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  for (const rendererUrl of [undefined, 'http://localhost:5173', 'http://localhost:5173/']) {
    for (const isPackaged of [false, true]) {
      let options: any;
      const dialog = runInNewContext(
        stripTypeScriptTypes(
          declarations(source, ['vaultTunnelAuthenticationDialog']) +
            '\nvaultTunnelAuthenticationDialog;',
        ),
        {
          VaultTunnelAuthenticationDialog: class {
            constructor(value: any) {
              options = value;
            }
          },
          createApplicationWindow: (value: any) => value,
          ipcMain: {},
          rendererUrl,
          app: { isPackaged },
          URL,
          path,
          pathToFileURL,
          __dirname: path.resolve('dist-electron'),
        },
      );
      assert.ok(dialog);
      assert.match(
        options.url,
        rendererUrl && !isPackaged
          ? /^http:\/\/localhost:5173\/vault-tunnel-authentication.html$/
          : /\/dist\/vault-tunnel-authentication.html$/,
      );
      assert.equal(
        options.preload,
        path.resolve('dist-electron/vault-tunnel-authentication-preload.cjs'),
      );
      const value = {};
      assert.equal(options.createWindow(value), value);
    }
  }
  const scripts = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
  ).scripts;
  for (const file of [
    'vault-tunnel-authentication.test.ts',
    'vault-tunnel-authentication-dialog.test.ts',
    'vault-tunnel-authentication-wiring.test.ts',
    'vault-tunnel-authentication-screen.test.ts',
    'vault-tunnel-authentication-native.test.ts',
  ]) {
    for (const script of ['test:vault-client', 'preformat:check', 'prelint'])
      assert.ok(scripts[script].split(' ').includes('tests/' + file), script + ' missing ' + file);
  }
});

test('production SAML window factory stays in the native approval-window coordinator', async (t) => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  let options: any;
  const calls: any[] = [];
  runInNewContext(stripTypeScriptTypes(declarations(source, ['vaultTunnelBrowserDialog'])), {
    VaultTunnelBrowserDialog: class {
      constructor(value: any) {
        options = value;
      }
    },
    createApplicationWindow: (value: any) => value,
    mcpApprovalWindowCoordinator: {
      presentTunnelAuthWindow: (w: any) => calls.push(['present', w]),
      forgetTunnelAuthWindow: (w: any) => calls.push(['forget', w]),
    },
  });
  const window = {};
  assert.equal(options.createWindow(window), window);
  options.present(window);
  options.forget(window);
  assert.deepEqual(calls, [
    ['present', window],
    ['forget', window],
  ]);
  let received: any,
    authority = {};
  const request = { credentialOverride: 'original-override' },
    current = () => true,
    failed = () => {},
    signal = new AbortController().signal;
  const profiler =
    process.execArgv.includes('--experimental-test-coverage') || process.env.NODE_V8_COVERAGE
      ? undefined
      : new Session();
  if (profiler) {
    profiler.connect();
    t.after(() => profiler.disconnect());
    await profiler.post('Profiler.enable');
    await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  }
  runInNewContext(
    stripTypeScriptTypes(declarations(source, ['vaultTunnelBrowserDialog'])),
    {
      VaultTunnelBrowserDialog: class {
        constructor(value: any) {
          options = value;
        }
      },
      VaultVPNBrowserSession: class {
        constructor(value: any) {
          received = value;
        }
      },
      vaultBackend: {
        vpnSSOAuthority: (accepted: any) => {
          assert.equal(accepted, current);
          return authority;
        },
      },
      backendPath: () => 'original-backend',
      mcpApprovalWindowCoordinator: {},
      createApplicationWindow: () => assert.fail('unexpected window creation'),
    },
    { filename: 'vpn-storage-factory.js' },
  );
  assert.ok(
    options.storage({ window, current, failed, signal, request, context: tunnelCookieContext() }),
  );
  assert.equal(received.request, request);
  assert.equal(received.authority, authority);
  assert.equal(received.executable, 'original-backend');
  assert.equal(received.failed, failed);
  const fallback = { primary: { kind: 9 }, fallback: { kind: 2 } };
  options.storage({
    window,
    current,
    failed,
    signal,
    request,
    context: tunnelCookieContext(),
    fallback,
  });
  assert.equal(received.fallback, fallback);
  assert.ok(options.storage({ window, current, signal, request, context: tunnelBrowserContext() }));
  assert.equal(received.context.binding.kind, 9);
  const sharedAuthority = {},
    sharedRequest = { ...request, credentialOverride: '', workspaceId: 'shared-source' };
  authority = sharedAuthority;
  assert.ok(
    options.storage({
      window,
      current,
      signal,
      request: sharedRequest,
      context: tunnelCookieContext(),
    }),
  );
  assert.equal(received.request, sharedRequest);
  assert.equal(received.authority, sharedAuthority);
  assert.ok(
    options.storage({
      window,
      current,
      signal,
      request: sharedRequest,
      context: tunnelBrowserContext(),
    }),
  );
  assert.equal(received.context.binding.kind, 9);
  assert.throws(() => options.storage({ window, current, signal, context: tunnelCookieContext() }));
  if (profiler) {
    const report = await profiler.post('Profiler.takePreciseCoverage');
    const script = report.result.find((s) => s.url === 'vpn-storage-factory.js');
    assert.ok(script);
    const method = script.functions.find((f) => f.functionName === 'storage');
    assert.ok(method);
    const extent = method.ranges[0];
    const blocks = script.functions
      .filter(
        (f) =>
          f.ranges[0].startOffset >= extent.startOffset &&
          f.ranges[0].endOffset <= extent.endOffset,
      )
      .flatMap((f) => f.ranges);
    const percent = (100 * blocks.filter((r) => r.count > 0).length) / blocks.length;
    t.diagnostic('native SSO factory ' + percent.toFixed(2) + '% V8 blocks');
    assert.ok(percent >= coverageThreshold);
  }
  const scripts = JSON.parse(
    readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
  ).scripts;
  for (const file of [
    'vault-tunnel-browser.test.ts',
    'vault-tunnel-browser-dialog.test.ts',
    'vault-tunnel-browser-native.test.ts',
    'vault-tunnel-browser-packaging.test.ts',
    'vault-tunnel-cookie.test.ts',
    'vault-tunnel-cookie-dialog.test.ts',
    'vault-tunnel-cookie-native.test.ts',
  ])
    for (const script of ['test:vault-client', 'prelint', 'preformat:check'])
      assert.ok(scripts[script].split(' ').includes('tests/' + file));
});

test('all four native route brokers parent VPN prompts to their exact live session owner', async (t) => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8'),
    nodes: any[] = [],
    fallbackNodes: any[] = [];
  let ownerMethod: any;
  visitSyntax(mainSyntax(source), (n) => {
    if (n.type === 'NewExpression' && n.callee.name === 'SealedRouteBroker') {
      const authentication = n.arguments[0].properties.find(
        (p: any) => p.key?.name === 'authentication',
      );
      assert.ok(authentication, 'protected route missing native challenge flow');
      nodes.push(authentication.value);
      const fallback = n.arguments[0].properties.find((p: any) => p.key?.name === 'fallback');
      assert.ok(fallback, 'protected route missing independent native fallback authority');
      fallbackNodes.push(fallback.value);
    }
    if (n.type === 'ClassMethod' && n.key?.name === 'vaultOwnerForSession') ownerMethod = n;
  });
  assert.equal(nodes.length, 4);
  assert.ok(ownerMethod);
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const c = tunnelAuthenticationContext(),
    owner = {},
    parent = { webContents: owner };
  let present = true,
    prompted = 0,
    closed = 0,
    expectedFallback: any;
  const originalRequest = Object.freeze({ credentialOverride: 'original-override' });
  const windows = {
    getAllWindows: () => (present ? [{ webContents: {} }, parent] : [{ webContents: {} }]),
  };
  const scope = {
    BrowserWindow: windows,
    webSurfaces: {
      vaultOwnerForSession: (id: string) =>
        id === c.binding.sessionId && present ? parent : undefined,
    },
    vaultRdpController: {
      ownerForSession: (id: string) => (id === c.binding.sessionId && present ? owner : undefined),
    },
    vaultVncController: {
      ownerForSession: (id: string) => (id === c.binding.sessionId && present ? owner : undefined),
    },
    vaultTunnelBrowserDialog: {
      open: async (p: any, current: any, value: any, signal: any, request: any, fallback: any) => {
        assert.equal(p, parent);
        assert.ok(current());
        assert.ok(!signal.aborted);
        assert.equal(request, originalRequest);
        assert.equal(fallback, expectedFallback);
        return value;
      },
      cancelChallenge: async (value: any) => value,
    },
    vaultTunnelAuthenticationDialog: {
      open: async (p: any, current: any, value: any, signal: any) => {
        assert.equal(p, parent);
        assert.equal(current(), true);
        assert.equal(value, c);
        assert.equal(signal.aborted, false);
        prompted++;
        return tunnelAuthenticationEnvelope();
      },
      cancelChallenge: async (value: any) => {
        assert.equal(value, c);
        closed++;
      },
    },
  };
  for (const [index, n] of nodes.entries()) {
    const script = stripTypeScriptTypes(
        '(function(){return ' + source.slice(n.start, n.end) + ';})',
      ),
      fn = runInNewContext(script, scope, { filename: 'tunnel-auth-wiring-' + index + '.js' });
    const callbacks = fn.call({ terminalOwners: new Map([[c.binding.sessionId, owner]]) });
    assert.deepEqual(
      await callbacks.prompt(c, () => true, new AbortController().signal),
      tunnelAuthenticationEnvelope(),
    );
    await callbacks.close(c);
    const browser = { ...tunnelBrowserContext(), binding: { ...c.binding } };
    assert.equal(
      await callbacks.prompt(browser, () => true, new AbortController().signal, originalRequest),
      browser,
    );
    assert.equal(await callbacks.close(browser), browser);
    const cookie = { ...tunnelCookieContext(), binding: { ...c.binding, kind: 2 } };
    assert.equal(
      await callbacks.prompt(cookie, () => true, new AbortController().signal, originalRequest),
      cookie,
    );
    assert.equal(await callbacks.close(cookie), cookie);
    expectedFallback = { primary: { ...c.binding, kind: 9 }, fallback: cookie.binding };
    assert.equal(
      await callbacks.prompt(
        cookie,
        () => true,
        new AbortController().signal,
        originalRequest,
        expectedFallback,
      ),
      cookie,
    );
    expectedFallback = undefined;
    present = false;
    await assert.rejects(
      callbacks.prompt(c, () => true, new AbortController().signal),
      /owner unavailable/,
    );
    present = true;
  }
  for (const [index, n] of fallbackNodes.entries()) {
    const query = Object.freeze({ primary: c.binding, fallbackRequestId: c.challengeId });
    const sealedQuery = Object.freeze({ binding: query, publicKey: 'fresh-recipient' });
    const callbacks = runInNewContext(
      stripTypeScriptTypes('(' + source.slice(n.start, n.end) + ')'),
      {
        vaultBackend: {
          tunnelFallbackPlan: async (q: any) => {
            assert.equal(q, query);
            return query;
          },
          tunnelFallbackBundle: async (q: any) => {
            assert.equal(q, sealedQuery);
            return sealedQuery;
          },
        },
      },
      { filename: 'tunnel-auth-fallback-wiring-' + index + '.js' },
    );
    assert.equal(await callbacks.plan(query), query);
    assert.equal(await callbacks.bundle(sealedQuery), sealedQuery);
  }
  assert.equal(prompted, 4);
  assert.equal(closed, 4);
  const method = runInNewContext(
    stripTypeScriptTypes(
      '(class Owner {' + source.slice(ownerMethod.start, ownerMethod.end) + '})',
    ),
    {},
    { filename: 'tunnel-auth-owner.js' },
  );
  const manager = new method();
  manager.vaultSessionOwners = new Map([[c.binding.sessionId, { owner: parent }]]);
  assert.equal(manager.vaultOwnerForSession(c.binding.sessionId), parent);
  assert.equal(manager.vaultOwnerForSession(c.challengeId), undefined);
  const report = await inspector.post('Profiler.takePreciseCoverage'),
    scripts = report.result.filter((s) => s.url.startsWith('tunnel-auth-'));
  assert.equal(scripts.length, 9);
  for (const script of scripts) {
    const blocks = script.functions.flatMap((f) => f.ranges),
      percent = (100 * blocks.filter((b) => b.count > 0).length) / blocks.length;
    assert.ok(percent >= coverageThreshold, script.url + ' ' + percent);
    t.diagnostic(script.url + ' ' + percent.toFixed(2) + '% V8 blocks');
  }
});

test('isolated VPN preload exposes exactly the three challenge channels and ciphertext submission', () => {
  const source = readFileSync(
    new URL('../electron/vault-tunnel-authentication-preload.cts', import.meta.url),
    'utf8',
  );
  for (const platform of ['win32', 'linux']) {
    let api: any;
    const calls: any[] = [];
    runInNewContext(
      stripTypeScriptTypes(source).replace(
        /import\s*{\s*contextBridge,\s*ipcRenderer\s*}\s*from 'electron';/,
        '',
      ),
      {
        process: { platform },
        contextBridge: {
          exposeInMainWorld: (name: string, value: any) => {
            assert.equal(name, 'vaultTunnelAuthentication');
            api = value;
          },
        },
        ipcRenderer: {
          invoke: (...args: any[]) => {
            calls.push(args);
            return Promise.resolve(true);
          },
        },
      },
    );
    assert.deepEqual(Object.keys(api).sort(), [
      'cancel',
      'contentProtectionAvailable',
      'context',
      'submit',
    ]);
    assert.equal(api.contentProtectionAvailable, platform !== 'linux');
    const envelope = tunnelAuthenticationEnvelope();
    api.context();
    api.submit(envelope);
    api.cancel();
    assert.equal(calls.length, 3);
    assert.equal(calls[0][0], 'vault-tunnel-authentication:context');
    assert.equal(calls[1][0], 'vault-tunnel-authentication:submit');
    assert.equal(calls[1][1], envelope);
    assert.equal(calls[2][0], 'vault-tunnel-authentication:cancel');
  }
});
