import { EventEmitter } from 'node:events';
import { VaultVncIpc } from '../electron/vault-vnc-ipc.ts';
import { vncConnectRequest, vaultVncQuickTarget } from '../src/vnc-connect.ts';
import { quickConnectStartsImmediately, quickConnectTunnelId } from '../src/quick-connect-state.ts';
import { transformWithOxc } from 'vite';
import { ipcRegistration, mainSyntax, visitSyntax } from './fixtures/main-source.ts';
import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { randomUUID } from 'node:crypto';
import { Session } from 'node:inspector/promises';
import { parseVaultVncCommand } from '../electron/vault-vnc-controller.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';

test('actual VNC IPC selects the vault branch, verifies the main document and keeps cleanup outside authorization', async (t) => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8'),
    filename = 'wormhole-vault-vnc-ipc.js';
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  let handler!: (event: any, input: any, ...extra: any[]) => Promise<any>,
    vault = true,
    trusted = true,
    fail = false,
    lost = false,
    running = true,
    quitting = false,
    current = true;
  const calls: any[] = [],
    sender = Object.assign(new EventEmitter(), { id: 1, isDestroyed: () => false, send() {} });
  const active = new Set<string>();
  const ipc = new VaultVncIpc({
    workspace: () => vault,
    trusted: () => trusted,
    controller: {
      has: (id) => active.has(id),
      command: async (...args: any[]) => {
        calls.push(['vault', ...args]);
        if (fail) throw Error('private native diagnostic');
        active.add(args[2].sessionId);
      },
      closeForOwner: async (...args: any[]) => {
        calls.push(['cancel', ...args]);
        active.delete(args[1]);
      },
      closeAll: async () => {
        active.clear();
      },
    },
    authorize: async (run, cleanup) => {
      calls.push(['authorize']);
      if (lost) {
        await cleanup();
        throw Error('locked');
      }
      if (!running) throw Error('stopping');
      return run(5);
    },
    quickTarget: async () => {
      throw Error('unused');
    },
  });
  t.after(async () => {
    fail = lost = false;
    await ipc.closeAll();
  });
  runInNewContext(
    stripTypeScriptTypes(ipcRegistration(source, 'vnc:command')),
    {
      ipcMain: {
        handle: (channel: string, fn: typeof handler) => {
          assert.equal(channel, 'vnc:command');
          handler = fn;
        },
      },
      vaultBackend: {
        get isVaultWorkspace() {
          return vault;
        },
      },
      parseVaultVncCommand,
      isTrustedVaultSender: () => trusted,
      vaultVncIpc: ipc,
      get isQuitting() {
        return quitting;
      },
      parseVncCommand: (value: any) => {
        if (!value?.action) throw Error('invalid');
        return value;
      },
      getNativeBackend: () => ({
        send: async (...args: any[]) => {
          calls.push(['legacy', ...args]);
          return { ok: true };
        },
      }),
      vncSessionAttempts: {
        begin: () => 1,
        cancel: (id: string) => calls.push(['legacy-cancel', id]),
        isCurrent: () => current,
      },
      cliOperationTimeoutMs: 60000,
      serializeAuthOperation: async (fn: any) => fn(),
      requireWorkspaceAuth: async () => {},
    },
    { filename },
  );
  const id = randomUUID(),
    nodeId = randomUUID(),
    q = { action: 'vnc.connect', sessionId: id, nodeId },
    event = { sender };
  assert.equal((await handler(event, q)).ok, true);
  assert.equal(calls.at(-1)[0], 'vault');
  assert.equal(calls.at(-1)[4], 5);
  assert.equal(calls.at(-1)[2](), true);
  const before = calls.length;
  for (const input of [null, { ...q, password: 'secret' }, { ...q, host: 'attacker' }])
    assert.equal((await handler(event, input)).ok, false);
  assert.equal((await handler(event, q, 'extra')).ok, false);
  assert.equal(calls.length, before);
  trusted = false;
  assert.equal((await handler(event, q)).ok, false);
  trusted = true;
  const authCount = () => calls.filter((c) => c[0] === 'authorize').length;
  const previous = authCount();
  assert.equal((await handler(event, { action: 'vnc.disconnect', sessionId: id })).ok, true);
  assert.equal(authCount(), previous);
  assert.equal(calls.at(-1)[0], 'cancel');
  for (const mode of ['native', 'lock', 'shutdown']) {
    fail = mode === 'native';
    lost = mode === 'lock';
    running = mode !== 'shutdown';
    const result = await handler(event, q);
    assert.equal(result.ok, false);
    assert.equal(result.error, 'VNC connection could not be completed.');
  }
  fail = false;
  lost = false;
  running = true;
  vault = false;
  quitting = true;
  assert.equal((await handler(event, q)).ok, false);
  quitting = false;
  assert.equal((await handler(event, {})).ok, false);
  assert.equal((await handler(event, { action: 'vnc.disconnect', sessionId: id })).ok, true);
  assert.equal(calls.at(-1)[2], 60000);
  current = false;
  assert.equal((await handler(event, q)).ok, false);
  current = true;
  assert.equal((await handler(event, q)).ok, true);
  assert.equal(calls.at(-1)[0], 'legacy');
  assert.equal(
    (await handler(event, { action: 'vnc.key', sessionId: id, keysym: 1, down: true })).ok,
    true,
  );
  const coverage = await inspector.post('Profiler.takePreciseCoverage');
  const script = coverage.result.find((s) => s.url === filename)!;
  assert.ok(script);
  const ranges = script.functions.flatMap((f) => f.ranges);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`VNC IPC V8 block coverage ${percent.toFixed(2)}%`);
  assert.ok(percent >= coverageThreshold);
});

test('actual VNC main initialization binds native client methods and waits for both shutdown acknowledgements', async (t) => {
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('const vaultVncRoutes ='),
    end = source.indexOf('let nativeResourceShutdownPromise:', start);
  let controllerOptions: any,
    admissionOptions: any,
    routeOptions: any,
    allowed = true,
    unlocked = true,
    failController = false,
    failRoute = false,
    failDialog = false;
  const calls: string[] = [];
  const marker = { public: 'only' };
  const contents = {},
    parent = { webContents: contents };
  let currentOwner: any = contents;
  const owner = {
    unlockedWorkspaceId: 'workspace',
    isVaultWorkspace: true,
    isSharedWorkspace: false,
    beginQuickTarget: async (q: any, accepted: () => boolean) => {
      assert.equal(accepted(), true);
      return q;
    },
    tunnelPlan: async (q: any) => q,
    tunnelBundle: async (q: any) => q,
    vncBundle: async (q: any) => q,
    vncPlan: async (q: any) => q,
    vncManualBundle: async (q: any) => q,
    connectionRoute: async (q: any) => q,
    routedVncBundle: async (q: any) => q,
    prepareVNCBitwarden: async (q: any, recipient: any, current: () => boolean) => {
      assert.equal(recipient, marker);
      assert.equal(current(), true);
      return q;
    },
  };
  const result = runInNewContext(
    stripTypeScriptTypes(source.slice(start, end) + '\n({stopVaultVncSessions})'),
    {
      SealedRouteBroker: class {
        constructor(options: any) {
          routeOptions = options;
        }
        async closeAll() {
          calls.push('route');
          if (failRoute) throw Error('private');
        }
      },
      SealedVncBackend: class {
        constructor(options: any) {
          controllerOptions = options;
        }
      },
      VaultVncController: class {
        constructor(create: any, authorize: any) {
          create(() => {});
          assert.equal(authorize(5), true);
        }
        ownerForSession() {
          return currentOwner;
        }
        async closeAll() {
          calls.push('controller');
          if (failController) throw Error('private');
        }
      },
      VaultVncIpc: class {
        constructor(options: any) {
          admissionOptions = options;
        }
        closeAll() {
          return admissionOptions.controller.closeAll();
        }
      },
      isTrustedVaultSender: (e: any) => e.trusted === true,
      runAuthorizedOperation: (run: any, cleanup: any) =>
        allowed
          ? run(4)
          : cleanup().then(() => {
              throw Error('locked');
            }),
      requireNativeResourcesRunning: () => {
        if (!allowed) throw Error('stopping');
      },
      BrowserWindow: { getAllWindows: () => [parent] },
      vaultVncPasswordDialog: {
        cancel: async () => {
          calls.push('dialog');
          if (failDialog) throw Error('private window failure');
        },
        open: (...args: any[]) => {
          assert.equal(args[0], parent);
          return Promise.resolve(args[2]);
        },
      },
      backendPath: () => '/backend',
      wormholeDatabasePath: () => '/workspace.db',
      resolveVaultVNCBitwarden: async (options: any) => {
        assert.equal(options.executable, '/backend');
        assert.equal(options.databasePath, '/workspace.db');
        assert.equal(options.signal.aborted, false);
        assert.equal(await options.prepare(marker), options.request);
        return options.request;
      },
      vaultBackend: new Proxy(owner, {
        get: (object, key) =>
          key === 'unlockedWorkspaceId'
            ? unlocked
              ? object.unlockedWorkspaceId
              : undefined
            : object[key as keyof typeof owner],
      }),
      isAuthorizationEpochCurrent: (epoch: number) => allowed && epoch === 4,
    },
    { filename: 'wormhole-vault-vnc-main-setup.js' },
  );
  assert.equal(admissionOptions.workspace(), true);
  assert.equal(admissionOptions.trusted({ trusted: true }), true);
  assert.equal(admissionOptions.trusted({ trusted: false }), false);
  assert.equal(
    await admissionOptions.authorize(
      async (epoch: number) => epoch,
      async () => {},
    ),
    5,
  );
  assert.deepEqual(
    JSON.parse(
      JSON.stringify(await admissionOptions.quickTarget(marker, 'session', 5, () => true)),
    ),
    { workspaceId: 'workspace', sessionId: 'session', epoch: 5, target: marker },
  );
  assert.equal(routeOptions.executable(), '/backend');
  assert.equal(controllerOptions.workspaceId(), 'workspace');
  assert.equal(controllerOptions.authorized(5), true);
  assert.equal(controllerOptions.authorized(4), false);
  for (const method of ['plan', 'bundle']) assert.equal(await routeOptions[method](marker), marker);
  for (const method of ['bundle']) assert.equal(await controllerOptions[method](marker), marker);
  const resolverSignal = new AbortController().signal;
  assert.equal(await controllerOptions.bitwarden(marker, resolverSignal, () => true), marker);
  owner.isSharedWorkspace = true;
  assert.equal(await controllerOptions.bitwarden(marker, resolverSignal, () => true), undefined);
  for (const method of ['resolve', 'bundle'])
    assert.equal(await controllerOptions.route[method](marker), marker);
  for (const method of ['plan', 'bundle'])
    assert.equal(await controllerOptions.manual[method](marker), marker);
  const context = { binding: { sessionId: 'public-session' } };
  assert.equal(
    await controllerOptions.manual.prompt(context, () => true, new AbortController().signal),
    context,
  );
  currentOwner = undefined;
  await assert.rejects(
    controllerOptions.manual.prompt(context, () => true, new AbortController().signal),
    /owner unavailable/,
  );
  allowed = false;
  assert.equal(routeOptions.authorized(5), false);
  await assert.rejects(
    admissionOptions.authorize(
      async () => {},
      async () => {},
    ),
    /locked/,
  );
  unlocked = false;
  assert.throws(() => admissionOptions.quickTarget(marker, 'session', 5, () => true), /locked/);
  assert.equal(controllerOptions.authorized(5), false);
  assert.equal(routeOptions.workspaceId(), undefined);
  for (const failure of ['none', 'controller', 'route', 'dialog']) {
    failDialog = failure === 'dialog';
    failController = failure === 'controller';
    failRoute = failure === 'route';
    calls.length = 0;
    const pending = result.stopVaultVncSessions();
    if (failure === 'none') await pending;
    else await assert.rejects(pending, /VNC shutdown could not be confirmed/);
    assert.deepEqual(calls, ['dialog', 'controller', 'route']);
  }
  const report = await inspector.post('Profiler.takePreciseCoverage');
  const script = report.result.find((s) => s.url === 'wormhole-vault-vnc-main-setup.js')!;
  const ranges = script.functions.flatMap((f) => f.ranges);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic('VNC main setup ' + percent.toFixed(2) + '% V8 blocks');
  assert.ok(percent >= coverageThreshold);
});

test('main creates the password document with its dedicated URL, preload and window factory', () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf('const vaultVncPasswordDialog ='),
    end = source.indexOf('\n});', start) + 4;
  assert.ok(start > 0 && end > start);
  for (const packaged of [false, true]) {
    let options: any,
      created = false;
    runInNewContext(stripTypeScriptTypes(source.slice(start, end)), {
      VaultVncPasswordDialog: class {
        constructor(value: any) {
          options = value;
        }
      },
      ipcMain: {},
      createApplicationWindow: () => {
        created = true;
      },
      rendererUrl: 'http://localhost:5173',
      app: { isPackaged: packaged },
      URL,
      path: { join: (...v: string[]) => v.join('/'), resolve: (...v: string[]) => v.join('/') },
      pathToFileURL: (v: string) => ({ href: 'file://' + v }),
      __dirname: '/app/electron',
    });
    assert.equal(options.preload, '/app/electron/vault-vnc-password-preload.cjs');
    assert.match(
      options.url,
      packaged
        ? /^file:.*vault-vnc-password.html$/
        : /^http:\/\/localhost:5173\/vault-vnc-password.html$/,
    );
    options.createWindow({});
    assert.equal(created, true);
  }
});

test('actual App Quick VNC submit and SessionSurface reach the public native schema without a saved node', async (t) => {
  await captureVncAppCoverage(t);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  let submit = '',
    surface = '';
  visitSyntax(mainSyntax(app, true), (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === 'submitQuickConnect')
      submit = app.slice(node.start, node.end);
    if (
      node.type === 'FunctionDeclaration' &&
      ['SessionSurface', 'SessionSurfaceContent'].includes(node.id?.name)
    )
      surface += app.slice(node.start, node.end) + '\n';
  });
  assert.ok(submit && surface);
  const { code } = await transformWithOxc(
    surface + '\nSessionSurface;',
    'quick-vnc-app-surface.tsx',
    { jsx: { runtime: 'classic' } },
  );
  const renderSurface = runInNewContext(
    code,
    {
      React: {
        createElement: (type: any, props: any, ...children: any[]) =>
          typeof type === 'function' ? type(props) : { type, props, children },
      },
      isFileBrowserProtocol: () => false,
      Suspense: 'suspense',
      SessionSurfaceFallback: 'fallback',
      VncSurface: 'vnc-surface',
    },
    { filename: 'wormhole-app-vnc-surface.js' },
  );
  for (const mode of ['vault', 'local'])
    for (const saved of [false, true]) {
      let sessions: any[] = [];
      const errors: string[] = [];
      const form: any = {
        name: 'Quick',
        host: 'vnc.example',
        port: '5900',
        protocol: 'vnc',
        useSavedCredentials: saved,
        credential: saved ? randomUUID() : 'none',
        tunnel: 'off',
        sshAutoSudo: 'off',
        rdp: {},
      };
      Object.defineProperties(form, {
        username: {
          get() {
            throw Error('ordinary username accessed');
          },
        },
        inlinePassword: {
          get() {
            throw Error('ordinary password accessed');
          },
        },
      });
      const scope: any = {
        authState: { mode },
        newConnectionForm: form,
        connectionAuthenticationSelectionComplete: true,
        connectionAuthenticationSelectionError: 'choose',
        quickConnectSubmitInFlight: { current: false },
        setEditorError: (v: string) => errors.push(v),
        effectiveSshAutoSudoMode: () => 'off',
        canConfigureConnectionSshAutoSudo: false,
        isFileBrowserProtocol: () => false,
        newSessionToken: randomUUID,
        quickConnectStartsImmediately,
        quickConnectTunnelId,
        vaultVncQuickTarget,
        setSessions: (update: any) => (sessions = update(sessions)),
        setSelectedSessionId() {},
        setActivePage() {},
        setNewConnectionForm() {},
        setNewConnectionOpen() {},
      };
      const invoke = runInNewContext(
        stripTypeScriptTypes(submit + '\nsubmitQuickConnect;'),
        scope,
        { filename: 'wormhole-app-vnc-quick.js' },
      );
      invoke({ preventDefault() {} });
      assert.deepEqual(errors, []);
      assert.equal(sessions.length, 1);
      const session = sessions[0],
        updates: any[] = [];
      const rendered = renderSurface({
        session,
        vault: mode === 'vault',
        isAuthorized: true,
        onVncStatusChange: (...v: any[]) => updates.push(v),
        onReconnectSession: (...v: any[]) => updates.push(v),
        onBitwardenUnlockRequired: (...v: any[]) => updates.push(v),
      });
      assert.equal(rendered.type, 'suspense');
      const child = rendered.children[0];
      assert.equal(child.type, 'vnc-surface');
      const q = vncConnectRequest(child.props.session, mode === 'vault');
      if (mode === 'vault') {
        assert.ok(parseVaultVncCommand(q));
        assert.equal('nodeId' in q, false);
        assert.equal('password' in q, false);
        assert.equal((q as any).quickTarget.host, 'vnc.example');
        assert.equal((q as any).quickTarget.credentialId, saved ? form.credential : '');
        assert.equal((q as any).manualPassword, undefined);
        assert.equal(session.id.startsWith('session-quick-'), false);
        scope.quickConnectSubmitInFlight.current = false;
        form.host = 'bad/path';
        invoke({ preventDefault() {} });
        assert.equal(sessions.length, 1);
        assert.equal(errors.length, 1);
        form.host = 'vnc.example';
        form.useSavedCredentials = true;
        form.credential = 'none';
        invoke({ preventDefault() {} });
        assert.equal(sessions.length, 1);
        assert.equal(errors.length, 2);
      } else {
        assert.equal((q as any).host, 'vnc.example');
        assert.equal('quickTarget' in q, false);
        assert.ok(session.id.startsWith('session-quick-'));
      }
      child.props.onReconnect();
      child.props.onStatusChange('idle');
      child.props.onStatusChange('disconnected');
      child.props.onStatusChange('connected');
      child.props.onBitwardenUnlockRequired('unlock', () => {});
      assert.equal(updates.length, 4);
    }
});

test('actual saved VNC and duplicated native desktop tabs retain canonical vault session identity', async (t) => {
  await captureVncAppCoverage(t);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const parts: string[] = [];
  visitSyntax(mainSyntax(app, true), (node) => {
    if (
      node.type === 'FunctionDeclaration' &&
      ['openConnection', 'duplicateSession'].includes(node.id?.name)
    )
      parts.push(app.slice(node.start, node.end));
  });
  assert.equal(parts.length, 2);
  for (const mode of ['vault', 'local']) {
    const id = randomUUID(),
      rdpCalls: any[] = [],
      legacyPrompts: string[] = [],
      scope: any = {
        authState: { mode },
        sessions: [],
        sessionsRef: { current: [] },
        treeRef: { current: [] },
        sessionCloseGate: { current: { reopenAfterClose: () => false } },
        webSessionOpenInFlight: { current: new Map() },
        sessionResourceReleaseGate: { current: { reset() {} } },
        savedConnectionAddressForEditor: (_p: string, host: string) => host,
        isFileBrowserProtocol: () => false,
        newSessionToken: randomUUID,
        setSelectedSessionId() {},
        setActivePage() {},
        setSessions: (update: any) => {
          scope.sessions = update(scope.sessions);
          scope.sessionsRef.current = scope.sessions;
        },
        setRdpCredentialForm() {},
        setRdpCredentialPrompt: (id: string) => legacyPrompts.push(id),
        retryRdpSession: (...v: any[]) => rdpCalls.push(v),
        window: { setTimeout: (fn: () => void) => fn() },
      };
    const invoke = runInNewContext(
      stripTypeScriptTypes(parts.join('\n') + '\n({openConnection,duplicateSession})'),
      scope,
      { filename: 'wormhole-app-vnc-catalog.js' },
    );
    invoke.openConnection({
      kind: 'connection',
      id,
      name: 'Saved VNC',
      protocol: 'vnc',
      host: 'vnc.example',
    });
    if (mode === 'vault')
      assert.ok(parseVaultVncCommand(vncConnectRequest(scope.sessions[0], true)));
    else assert.equal(scope.sessions[0].id, 'session-' + id);
    invoke.duplicateSession(scope.sessions[0].id);
    assert.equal(scope.sessions.length, 2);
    assert.notEqual(scope.sessions[1].id, scope.sessions[0].id);
    if (mode === 'vault')
      assert.ok(parseVaultVncCommand(vncConnectRequest(scope.sessions[1], true)));
    else assert.ok(scope.sessions[1].id.startsWith('session-duplicate-'));
    scope.sessions[0] = { ...scope.sessions[0], protocol: 'rdp', rdpManualCredentials: true };
    invoke.duplicateSession(scope.sessions[0].id);
    if (mode === 'vault') {
      assert.equal(
        legacyPrompts.length,
        0,
        'a protected RDP duplicate cannot open the ordinary password dialog',
      );
      assert.deepEqual(rdpCalls, [[scope.sessions[1].id, true]]);
    } else assert.equal(legacyPrompts.length, 1);
  }
});

test('saved protected RDP Connect retains its temporary account after a disconnect', async (t) => {
  await captureVncAppCoverage(t);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  let source = '';
  visitSyntax(mainSyntax(app, true), (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === 'requestRdpCredentials')
      source = app.slice(node.start, node.end);
  });
  assert.ok(source);
  const id = randomUUID(),
    calls: any[] = [];
  const invoke = runInNewContext(
    stripTypeScriptTypes(source + '\nrequestRdpCredentials;'),
    {
      authState: { mode: 'vault' },
      sessionsRef: {
        current: [{ id, nodeId: randomUUID(), protocol: 'rdp', rdpManualCredentials: true }],
      },
      setSelectedSessionId() {},
      setActivePage() {},
      startRdpSession: (...v: any[]) => calls.push(v),
    },
    { filename: 'wormhole-app-vnc-rdp-connect.js' },
  );
  invoke(id);
  assert.equal(calls.length, 1);
  assert.equal(calls[0][2], true);
});

test('actual App VNC status transition retains public manual intent across disconnect and duplicate', async (t) => {
  await captureVncAppCoverage(t);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  let callback = '';
  visitSyntax(mainSyntax(app, true), (node) => {
    if (
      node.type === 'JSXAttribute' &&
      node.name?.name === 'onVncStatusChange' &&
      node.value?.expression?.type === 'ArrowFunctionExpression'
    )
      callback = app.slice(node.value.expression.start, node.value.expression.end);
  });
  assert.ok(callback);
  const id = randomUUID(),
    other = { id: randomUUID(), status: 'connected' };
  let sessions: any[] = [{ id, status: 'connecting' }, other];
  const transition = runInNewContext(
    stripTypeScriptTypes('(' + callback + ')'),
    {
      setSessions: (update: any) => (sessions = update(sessions)),
    },
    { filename: 'wormhole-app-vnc-status.js' },
  );
  transition(id, 'connecting', true);
  assert.equal(sessions[0].vncManualPassword, true);
  transition(id, 'closed');
  assert.equal(sessions[0].vncManualPassword, true);
  assert.equal(sessions[1], other);
  transition(id, 'connecting', false);
  assert.equal(sessions[0].vncManualPassword, false);
});

async function captureVncAppCoverage(t: TestContext) {
  const inspector = new Session();
  inspector.connect();
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  t.after(async () => {
    try {
      const report = await inspector.post('Profiler.takePreciseCoverage');
      const scripts = report.result.filter((s) => s.url.startsWith('wormhole-app-vnc-'));
      assert.ok(scripts.length > 0);
      const directory = process.env.WORMHOLE_TEST_VNC_APP_COVERAGE;
      if (directory) {
        mkdirSync(directory, { recursive: true });
        writeFileSync(join(directory, randomUUID() + '.json'), JSON.stringify(scripts));
      }
    } finally {
      inspector.disconnect();
    }
  });
}
