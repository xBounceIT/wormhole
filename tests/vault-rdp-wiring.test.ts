import { transformWithOxc } from 'vite';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session } from 'node:inspector/promises';
import { randomUUID } from 'node:crypto';
import { declarations, ipcRegistration, mainSyntax, visitSyntax } from './fixtures/main-source.ts';
import { assertRdpSurfaceOwner } from '../electron/rdp-framebuffer.ts';
import { confirmRdpCertificate } from '../electron/rdp-certificate.ts';
import { vaultRdpConnectRequest, vaultRdpQuickTarget } from '../src/rdp-connect.ts';
import { parseVaultRdpOpenRequest } from '../electron/vault-rdp-ipc.ts';
import { SessionCloseGate } from '../src/session-lifecycle.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
const tick = () => new Promise<void>((r) => setImmediate(r));

test('actual main RDP guards route every protected command before the legacy service', async (t) => {
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const filename = 'wormhole-vault-rdp-guards.js',
    handlers = new Map<string, any>(),
    calls: any[] = [];
  let owned = true,
    running = true;
  const channels = [
    'vault:rdp-open',
    'rdp:start',
    'rdp:input',
    'rdp:resize',
    'rdp:command',
    'rdp:system-client-capability',
    'rdp:open-system',
  ];
  runInNewContext(
    stripTypeScriptTypes(
      channels.map((c) => ipcRegistration(source, c, c !== 'vault:rdp-open')).join('\n'),
    ),
    {
      ipcMain: { handle: (c: string, fn: any) => handlers.set(c, fn) },
      vaultBackend: {
        get isVaultWorkspace() {
          return owned;
        },
      },
      vaultRdpIpc: {
        handles: () => owned,
        ...Object.fromEntries(
          ['open', 'input', 'resize', 'command'].map((method) => [
            method,
            async (...args: any[]) => {
              calls.push([method, ...args]);
              return { type: 'ack' };
            },
          ]),
        ),
      },
      requireNativeResourcesRunning: () => {
        if (!running) throw Error('stopping');
      },
    },
    { filename },
  );
  const event = { sender: {} },
    q = { sessionId: randomUUID(), nodeId: randomUUID() };
  assert.equal((await handlers.get('vault:rdp-open')(event, q)).type, 'ack');
  await assert.rejects(async () => handlers.get('vault:rdp-open')(event, q, 'extra'));
  running = false;
  await assert.rejects(async () => handlers.get('vault:rdp-open')(event, q));
  running = true;
  await assert.rejects(handlers.get('rdp:start')(event, q), /protected/);
  for (const c of ['rdp:input', 'rdp:resize', 'rdp:command']) {
    assert.equal((await handlers.get(c)(event, q)).type, 'ack');
    assert.equal(calls.at(-1)[0], c.slice(4));
    await assert.rejects(handlers.get(c)(event, q, 'secret'));
  }
  assert.equal((await handlers.get('rdp:system-client-capability')(event, q)).supported, false);
  assert.equal((await handlers.get('rdp:open-system')(event, q)).ok, false);
  owned = false;
  for (const c of channels.filter((c) => c !== 'vault:rdp-open'))
    assert.equal(await handlers.get(c)(event, q), 'legacy');
  const report = await inspector.post('Profiler.takePreciseCoverage');
  const ranges = report.result.find((s) => s.url === filename)!.functions.flatMap((f) => f.ranges);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`Actual main protected RDP guard coverage ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('actual main RDP initialization binds vault, owner, route and certificate hooks and joins shutdown', async (t) => {
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const filename = 'wormhole-vault-rdp-setup.js',
    calls: any[] = [],
    placements = new Map();
  let route: any,
    relay: any,
    admission: any,
    authorize: any,
    certificate: any,
    observe: any,
    allowed = true,
    shared = false,
    workspace: string | undefined = 'workspace',
    failController = false,
    failCredentials = false,
    failRoute = false,
    running = true,
    trusted = true,
    parentDestroyed = false,
    selectedOwner: any;
  const sender = {},
    parent = { webContents: sender, isDestroyed: () => parentDestroyed };
  selectedOwner = sender;
  const scope: any = {
    process: { platform: 'win32' },
    vaultWindowPolicy: { requiresContentProtection: false },
    vaultRdpCredentialsDialog: {
      cancel: async () => {
        calls.push(['credentials-stop']);
        if (failCredentials) throw Error('document');
      },
      open: async (...args: any[]) => {
        calls.push(['credential-document', ...args]);
        return { opaque: true };
      },
    },
    SealedRouteBroker: class {
      constructor(o: any) {
        route = o;
      }
      closeAll() {
        calls.push(['route-stop']);
        return failRoute ? Promise.reject(Error('route')) : Promise.resolve();
      }
    },
    SealedRdpBackend: class {
      constructor(o: any) {
        relay = o;
      }
    },
    VaultRdpController: class {
      constructor(create: any, valid: any, confirm: any, notify: any) {
        create((e: any) => calls.push(['event', e]));
        authorize = valid;
        certificate = confirm;
        observe = notify;
      }
      ownerForSession() {
        return selectedOwner;
      }
      control(...args: any[]) {
        calls.push(['control', ...args]);
        return Promise.resolve({ type: 'ack' });
      }
      closeAll() {
        calls.push(['rdp-stop']);
        return failController ? Promise.reject(Error('rdp')) : Promise.resolve();
      }
    },
    VaultRdpIpc: class {
      constructor(o: any) {
        admission = o;
      }
      closeAll() {
        return admission.controller.closeAll();
      }
    },
    backendPath: () => '/backend',
    wormholeDatabasePath: () => '/workspace.db',
    rdpManualTarget: (q: any) => q.context.binding,
    resolveVaultRDPBitwarden: async (options: any) => {
      assert.equal(options.executable, '/backend');
      assert.equal(options.databasePath, '/workspace.db');
      assert.equal(options.signal.aborted, false);
      return options.prepare({ opaque: true });
    },
    vaultBackend: {
      get unlockedWorkspaceId() {
        return workspace;
      },
      get isVaultWorkspace() {
        return !!workspace;
      },
      get isSharedWorkspace() {
        return shared;
      },
      prepareRDPBitwarden: async (q: unknown, recipient: any, accepted: () => boolean) => {
        assert.equal(recipient.opaque, true);
        assert.equal(accepted(), true);
        return q;
      },
      prepareManualRDPBitwarden: async (q: unknown, recipient: any, accepted: () => boolean) => {
        assert.equal(recipient.opaque, true);
        assert.equal(accepted(), true);
        return q;
      },
      ...Object.fromEntries(
        [
          'tunnelPlan',
          'tunnelBundle',
          'connectionRoute',
          'rdpBundle',
          'routedRdpBundle',
          'rdpPlan',
          'rdpManualBundle',
          'beginQuickTarget',
        ].map((method) => [
          method,
          async (q: any) => {
            calls.push([method, q]);
            return q;
          },
        ]),
      ),
    },
    isAuthorizationEpochCurrent: (epoch: number) => allowed && epoch === 6,
    authSession: {
      get isAccessAllowed() {
        return allowed;
      },
      requireUnlocked: () => {
        if (!allowed) throw Error('locked');
      },
    },
    ensureAuthSession: async () => calls.push(['initialized']),
    runAuthorizedOperation: async (run: any, cleanup: any) => {
      if (!allowed) {
        await cleanup();
        throw Error('locked');
      }
      return run(6);
    },
    requireNativeResourcesRunning: () => {
      if (!running) throw Error('stopping');
    },
    isTrustedVaultSender: () => trusted,
    BrowserWindow: {
      getAllWindows: () => [parent],
      fromWebContents: (owner: any) => (owner === sender ? parent : undefined),
    },
    confirmRdpCertificate,
    showCoordinatedMessageBox: async () => ({ response: 1 }),
    rdpSurfacePlacements: placements,
    assertRdpSurfaceOwner,
    rememberRdpSurfacePlacement: (owner: any, id: string, bounds: any) =>
      placements.set(id, { owner, bounds }),
    currentRdpSurfaceScreenBounds: (_owner: any, id: string) => placements.get(id)?.bounds,
    nativeWindowHandle: () => '123',
    forgetRdpSurfacePlacement: (id: string) => {
      calls.push(['forget', id]);
      placements.delete(id);
    },
    treeTooltips: { raiseForWindow: () => calls.push(['tooltip']) },
  };
  const names = ['vaultRdpRoutes', 'vaultRdpController', 'vaultRdpIpc', 'stopVaultRdpSessions'];
  const stop = runInNewContext(
    stripTypeScriptTypes(declarations(source, names) + '\nstopVaultRdpSessions'),
    scope,
    { filename },
  );
  assert.equal(route.executable(), '/backend');
  assert.equal(route.workspaceId(), workspace);
  assert.equal(relay.workspaceId(), workspace);
  const linked = { sessionId: 'rdp-session' };
  const temporary = { context: { binding: linked }, manual: { opaque: true } };
  const bitwardenSignal = new AbortController().signal;
  assert.equal(await relay.bitwarden(linked, bitwardenSignal, () => true), linked);
  assert.equal(await relay.manual.bitwarden(temporary, bitwardenSignal, () => true), temporary);
  shared = true;
  assert.equal(await relay.bitwarden(linked, bitwardenSignal, () => true), undefined);
  assert.equal(await relay.manual.bitwarden(temporary, bitwardenSignal, () => true), undefined);
  shared = false;
  for (const value of [true, false]) {
    allowed = value;
    assert.equal(route.authorized(7), value);
    assert.equal(relay.authorized(7), value);
    assert.equal(authorize(7), value);
  }
  allowed = true;
  workspace = undefined;
  assert.equal(authorize(7), false);
  assert.equal(admission.workspace(), false);
  assert.throws(() => admission.quickTarget({}, 'session', 7, () => true), /locked/);
  workspace = 'workspace';
  assert.equal(admission.workspace(), true);
  const accepted = () => true;
  const target = { public: true };
  await admission.quickTarget(target, 'session', 7, accepted);
  assert.deepEqual(JSON.parse(JSON.stringify(calls.at(-1))), [
    'beginQuickTarget',
    { workspaceId: workspace, sessionId: 'session', epoch: 7, target },
  ]);
  assert.equal(admission.trusted({}), true);
  trusted = false;
  assert.equal(admission.trusted({}), false);
  trusted = true;
  for (const fn of [
    route.plan,
    route.bundle,
    relay.bundle,
    relay.route.resolve,
    relay.route.bundle,
  ])
    assert.equal(await fn('public'), 'public');
  const signal = new AbortController().signal,
    context = { binding: { sessionId: 'public-session' } };
  await relay.manual.plan({ public: 'plan' });
  assert.equal(calls.at(-1)[0], 'rdpPlan');
  await relay.manual.bundle({ opaque: 'envelope' });
  assert.equal(calls.at(-1)[0], 'rdpManualBundle');
  await relay.manual.prompt(context, () => true, signal);
  assert.equal(calls.at(-1)[0], 'credential-document');
  assert.equal(calls.at(-1)[1], parent);
  selectedOwner = undefined;
  await assert.rejects(relay.manual.prompt(context, () => true, signal));
  selectedOwner = sender;
  relay.onEvent({ type: 'connected' });
  await admission.unlocked();
  allowed = false;
  await assert.rejects(admission.unlocked());
  allowed = true;
  assert.equal(
    await admission.authorize(
      async (epoch: number) => epoch,
      async () => {},
    ),
    7,
  );
  running = false;
  await assert.rejects(
    admission.authorize(
      async () => {},
      async () => {},
    ),
  );
  running = true;
  const event = { sender },
    id = randomUUID(),
    bounds = { x: -20, y: 3, width: 800, height: 600 };
  assert.equal(admission.surface(event, id, bounds).ownerWindow, '123');
  assert.equal(admission.surface(event, id).requireContentProtection, undefined);
  scope.vaultWindowPolicy.requiresContentProtection = true;
  assert.equal(admission.surface(event, id).requireContentProtection, true);
  scope.process.platform = 'darwin';
  assert.equal(admission.surface(event, id).requireContentProtection, undefined);
  assert.deepEqual(admission.surface(event, id).bounds, bounds);
  assert.throws(() => admission.surface({ sender: {} }, id));
  parentDestroyed = true;
  assert.throws(() => admission.surface(event, id));
  parentDestroyed = false;
  placements.set(id, { owner: {} });
  assert.throws(() => admission.surface(event, id));
  admission.forget(id);
  const notice = {
    type: 'certificate',
    sessionId: id,
    lifecycleId: randomUUID(),
    certificate: { host: 'host', fingerprint: 'fingerprint' },
  };
  certificate(notice, sender);
  await tick();
  assert.equal(calls.at(-1)[0], 'control');
  assert.equal(calls.at(-1)[4].certificateAccepted, true);
  selectedOwner = undefined;
  certificate(notice, sender);
  await tick();
  assert.equal(calls.at(-1)[4].certificateAccepted, false);
  selectedOwner = sender;
  observe({ type: 'frame' }, sender);
  observe({ type: 'frameEnd' }, sender);
  observe({ type: 'connected' }, {});
  observe({ type: 'connected' }, sender);
  assert.equal(calls.at(-1)[0], 'tooltip');
  await stop();
  failCredentials = true;
  await assert.rejects(stop(), /confirmed/);
  failCredentials = false;
  failController = true;
  await assert.rejects(stop(), /confirmed/);
  failController = false;
  failRoute = true;
  await assert.rejects(stop(), /confirmed/);
  failRoute = false;
  const report = await inspector.post('Profiler.takePreciseCoverage');
  const ranges = report.result.find((s) => s.url === filename)!.functions.flatMap((f) => f.ranges);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`Actual main RDP setup coverage ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('actual local App saved RDP dispatch and preload expose only the protected node request', async (t) => {
  await captureRdpAppCoverage(t);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const file = mainSyntax(app, true);
  let selected = '';
  visitSyntax(file, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === 'startRdpSession')
      selected = app.slice(node.start, node.end);
  });
  assert.ok(selected);
  const id = randomUUID(),
    nodeId = randomUUID(),
    calls: any[] = [],
    saved = new Set(),
    current = { id, nodeId, protocol: 'rdp' };
  const state: any = { mode: 'vault' },
    bounds = { x: 0, y: 0, width: 800, height: 600 };
  const start = runInNewContext(
    stripTypeScriptTypes(selected + '\nstartRdpSession'),
    {
      authState: state,
      sessionsRef: { current: [current] },
      rdpEditAttempts: { current: { cancel: () => {} } },
      rdpSessionAttempts: { current: { begin: () => 1, isCurrent: () => true } },
      rdpSavedCredentialAttempts: { current: saved },
      setSessions: () => {},
      defaultRdpProfile: () => ({ host: 'legacy-only' }),
      waitForRdpSurfaceBounds: async () => bounds,
      sessionResourceReleaseGate: { current: { waitForRelease: async () => {}, reset: () => {} } },
      sessionCloseGate: { current: { activeSessionIds: () => new Set() } },
      vaultRdpConnectRequest,
      window: {
        wormhole: {
          openVaultRdpSession: async (q: any) => calls.push(['vault', q]),
          startRdpSession: async (q: any) => calls.push(['legacy', q]),
        },
      },
      isBitwardenUnlockError: () => false,
      requiresRdpCredentialPrompt: () => false,
    },
    { filename: 'wormhole-app-rdp-startRdpSession.js' },
  );
  start(id, { username: 'must-not-relay', domain: 'private', password: 'renderer-value' }, false);
  await tick();
  assert.equal(calls[0][0], 'vault');
  assert.deepEqual(Object.keys(calls[0][1]).sort(), ['bounds', 'nodeId', 'sessionId']);
  assert.equal(calls[0][1].nodeId, nodeId);
  assert.equal(saved.has(id), false);
  start(id, { username: '', domain: '', password: 'private' }, true);
  await tick();
  assert.equal(calls.length, 2);
  assert.equal(calls[1][0], 'vault');
  assert.deepEqual(Object.keys(calls[1][1]).sort(), [
    'bounds',
    'manualCredentials',
    'nodeId',
    'sessionId',
  ]);
  assert.equal(calls[1][1].manualCredentials, true);
  state.mode = 'local';
  start(id, { username: '', domain: '', password: '' }, false);
  await tick();
  assert.equal(calls.at(-1)[0], 'legacy');
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const bridge: any = runInNewContext(
    stripTypeScriptTypes(declarations(preload, ['wormholeBridge']) + '\nwormholeBridge'),
    {
      ipcRenderer: { invoke: async (...args: any[]) => calls.push(args) },
      process: { platform: 'win32' },
    },
  );
  await bridge.openVaultRdpSession({ sessionId: id, nodeId, bounds });
  assert.equal(calls.at(-1)[0], 'vault:rdp-open');
  for (const key of ['rdpBundle', 'routedRdpBundle', 'recipient', 'sealRdp'])
    assert.equal(key in bridge, false);
});

test('actual main geometry synchronization coalesces owner moves and routes protected surfaces without a legacy client', async (t) => {
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const filename = 'wormhole-vault-rdp-placement.js',
    tasks: (() => void)[] = [],
    calls: any[] = [],
    pending = new Map(),
    placements = new Map();
  let destroyed = false;
  const owner = { id: 1, webContents: {}, isDestroyed: () => destroyed },
    bounds = { x: -20, y: 3, width: 800, height: 600 };
  placements.set('sealed', { owner, rendererBounds: bounds });
  placements.set('legacy', { owner, rendererBounds: bounds });
  placements.set('foreign', { owner: {}, rendererBounds: bounds });
  placements.set('unavailable', { owner, rendererBounds: undefined });
  const scope: any = {
    setImmediate: (fn: () => void) => {
      tasks.push(fn);
      return fn;
    },
    rdpOwnerSyncTasks: pending,
    rdpSurfacePlacements: placements,
    nativeWindowHandle: (value: unknown) => {
      assert.equal(value, owner);
      return '123';
    },
    toScreenBounds: (value: unknown, rect: any) => {
      assert.equal(value, owner);
      return rect ? { ...rect, x: rect.x + 100, y: rect.y + 200 } : undefined;
    },
    vaultRdpController: {
      has: (id: string) => id === 'sealed',
      control: async (value: unknown, current: () => boolean, id: string, command: any) => {
        assert.equal(value, owner.webContents);
        assert.equal(current(), true);
        calls.push(['sealed', id, command]);
        throw Error('close raced with move');
      },
    },
    rdpClient: {
      resize: async (request: any, hwnd: string) => calls.push(['legacy', request, hwnd]),
    },
  };
  const sync = runInNewContext(
    stripTypeScriptTypes(
      declarations(source, ['scheduleRdpSurfacePlacementSync']) +
        '\nscheduleRdpSurfacePlacementSync',
    ),
    scope,
    { filename },
  );
  sync(owner);
  sync(owner);
  assert.equal(tasks.length, 1, 'owner moves coalesce before native I/O');
  tasks.shift()!();
  await tick();
  assert.equal(pending.size, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(calls)), [
    ['sealed', 'sealed', { op: 'resize', bounds: { ...bounds, x: 80, y: 203 } }],
    ['legacy', { sessionId: 'legacy', bounds: { ...bounds, x: 80, y: 203 } }, '123'],
  ]);
  scope.rdpClient = undefined;
  sync(owner);
  tasks.shift()!();
  await tick();
  assert.equal(calls.length, 3, 'protected placement works without starting the legacy client');
  assert.equal(calls[2][0], 'sealed');
  sync(owner);
  destroyed = true;
  tasks.shift()!();
  assert.equal(calls.length, 3, 'retired owner cannot send geometry');
  sync(owner);
  assert.equal(tasks.length, 0);
  assert.equal(pending.size, 0);
  const report = await inspector.post('Profiler.takePreciseCoverage');
  const ranges = report.result.find((s) => s.url === filename)!.functions.flatMap((f) => f.ranges);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`Actual main RDP placement coverage ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('actual RDP credential entry keeps protected saved and unsaved attempts out of ordinary password state', async (t) => {
  await captureRdpAppCoverage(t);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  let selected = '';
  visitSyntax(mainSyntax(app, true), (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === 'requestRdpCredentials')
      selected = app.slice(node.start, node.end);
  });
  assert.ok(selected);
  const calls: any[] = [],
    id = randomUUID();
  const state: any = { mode: 'vault' };
  const sessions: any = { current: [] };
  const request = runInNewContext(
    stripTypeScriptTypes(selected + '\nrequestRdpCredentials'),
    {
      authState: state,
      sessionsRef: sessions,
      setSelectedSessionId: (value: string) => calls.push(['selected', value]),
      setActivePage: (value: string) => calls.push(['page', value]),
      startRdpSession: (...args: any[]) => calls.push(['connect', ...args]),
      setRdpCredentialForm: (value: any) => calls.push(['form', value]),
      setRdpCredentialSelection: (value: string) => calls.push(['credential', value]),
      setRdpCredentialSave: (value: boolean) => calls.push(['save', value]),
      setRdpCredentialPrompt: (value: string) => calls.push(['prompt', value]),
      manualCredentialSelectionValue: 'manual',
    },
    { filename: 'wormhole-app-rdp-requestRdpCredentials.js' },
  );
  for (const saved of [false, true]) {
    sessions.current = [{ id, protocol: 'rdp', ...(saved ? { nodeId: randomUUID() } : {}) }];
    calls.length = 0;
    await request(id);
    assert.deepEqual(
      calls.map((c) => c[0]),
      ['selected', 'page', 'connect'],
    );
    assert.equal(calls[2][1], id);
    assert.equal(calls[2][3], false, 'native saved admission has no ordinary manual credentials');
  }
  state.mode = 'local';
  calls.length = 0;
  sessions.current = [{ id, protocol: 'rdp' }];
  await request(id);
  assert.deepEqual(
    calls.map((c) => c[0]),
    ['selected', 'page', 'form', 'credential', 'save', 'prompt'],
  );
  assert.equal(calls.at(-1)[1], id, 'unprotected legacy manual prompt remains available');
  for (const current of [[], [{ id, protocol: 'ssh' }]]) {
    sessions.current = current;
    calls.length = 0;
    await request(id);
    assert.equal(calls.length, 0);
  }
});

test('actual main RDP credential document uses the dedicated preload and exact packaged or development URL', async (t) => {
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const code = stripTypeScriptTypes(declarations(source, ['vaultRdpCredentialsDialog']));
  for (const [url, packaged] of [
    [undefined, false],
    ['http://127.0.0.1:5173', false],
    ['http://127.0.0.1:5173/', false],
    ['http://127.0.0.1:5173', true],
  ] as const) {
    let options: any;
    const scope = {
      VaultRdpCredentialsDialog: class {
        constructor(value: any) {
          options = value;
        }
      },
      ipcMain: {},
      createApplicationWindow: (options: any) => ({ options }),
      rendererUrl: url,
      app: { isPackaged: packaged },
      path,
      pathToFileURL,
      URL,
      __dirname: path.resolve('/app/dist-electron'),
    };
    runInNewContext(code, scope, { filename: 'wormhole-rdp-credential-document.js' });
    assert.equal(options.ipc, scope.ipcMain);
    assert.equal(options.preload, path.join(scope.__dirname, 'vault-rdp-credentials-preload.cjs'));
    assert.equal(
      options.url,
      url && !packaged
        ? 'http://127.0.0.1:5173/vault-rdp-credentials.html'
        : pathToFileURL(path.resolve(scope.__dirname, '..', 'dist', 'vault-rdp-credentials.html'))
            .href,
    );
    const window = options.createWindow({ sandbox: true });
    assert.deepEqual(window.options, { sandbox: true });
  }
  const report = await inspector.post('Profiler.takePreciseCoverage');
  const scripts = report.result.filter((s) => s.url === 'wormhole-rdp-credential-document.js');
  assert.ok(scripts.length > 0);
  const ranges = scripts.flatMap((s) => s.functions.flatMap((f) => f.ranges));
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`Main RDP credential document ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});
test('actual local manual RDP retry joins old resources and never opens the ordinary password form', async (t) => {
  await captureRdpAppCoverage(t);
  const binding = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const connectBindings: string[] = [];
  visitSyntax(mainSyntax(binding, true), (node) => {
    if (
      node.type === 'JSXAttribute' &&
      node.name?.name === 'onConnectRdp' &&
      node.value?.expression?.type === 'Identifier'
    )
      connectBindings.push(node.value.expression.name);
  });
  assert.equal(
    connectBindings.filter((name) => name === 'retryRdpSession').length,
    1,
    'disconnected Connect must preserve the temporary-account intent and join old cleanup',
  );
  assert.equal(
    connectBindings.includes('requestRdpCredentials'),
    false,
    'the saved-only entry must not bypass reconnect policy',
  );
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  let selected = '';
  visitSyntax(mainSyntax(app, true), (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === 'retryRdpSession')
      selected = app.slice(node.start, node.end);
  });
  assert.ok(selected);
  for (const [mode, manual, closed] of [
    ['vault', true, true],
    ['vault', undefined, true],
    ['vault', true, false],
    ['vault', false, true],
    ['local', false, true],
  ] as const) {
    const id = randomUUID(),
      calls: any[] = [];
    let release!: (closed: boolean) => void;
    const close = new Promise<boolean>((r) => (release = r));
    const retry = runInNewContext(
      stripTypeScriptTypes(selected + '\nretryRdpSession'),
      {
        authState: { mode },
        sessionsRef: {
          current: [
            {
              id,
              nodeId: randomUUID(),
              protocol: 'rdp',
              rdpStatus: 'failed',
              rdpManualCredentials: manual === undefined,
            },
          ],
        },
        canDisconnectRemoteDesktopSession: () => false,
        disconnectRemoteDesktopSession: async () => {
          calls.push(['close']);
          return close;
        },
        startRdpSession: (...args: any[]) => calls.push(['manual', ...args]),
        requestRdpCredentials: async () => calls.push(['saved']),
      },
      { filename: 'wormhole-app-rdp-retryRdpSession.js' },
    );
    retry(id, manual);
    await tick();
    if (manual || (mode === 'vault' && manual === undefined)) {
      assert.deepEqual(calls, [['close']]);
      release(closed);
      await tick();
      if (closed) {
        assert.deepEqual(JSON.parse(JSON.stringify(calls.at(-1))), [
          'manual',
          id,
          { username: '', domain: '', password: '' },
          true,
        ]);
      } else assert.equal(calls.length, 1);
    } else assert.deepEqual(calls, [['saved']]);
  }
});

test('actual protected RDP entry mounts only the dedicated API and startup root', async (t) => {
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const source = readFileSync(new URL('../src/vault-rdp-credentials.ts', import.meta.url), 'utf8');
  const syntax = mainSyntax(source);
  const imports = syntax.program.body.filter((n: any) => n.type === 'ImportDeclaration');
  let code = source;
  for (const node of imports.reverse()) code = code.slice(0, node.start) + code.slice(node.end);
  const filename = 'wormhole-rdp-document-entry.js';
  for (const api of [undefined, { context() {} }])
    for (const root of [null, {}]) {
      const calls: unknown[][] = [];
      runInNewContext(
        stripTypeScriptTypes(code),
        {
          window: { vaultRdpCredentials: api },
          document: {
            querySelector: (selector: string) => {
              assert.equal(selector, '.startup-card');
              return root;
            },
          },
          mountVaultRdpCredentialsScreen: (...args: unknown[]) => calls.push(args),
        },
        { filename },
      );
      assert.equal(calls.length, api && root ? 1 : 0);
      if (api && root) assert.deepEqual(calls[0], [root, api]);
    }
  const report = await inspector.post('Profiler.takePreciseCoverage');
  const scripts = report.result.filter((s) => s.url === filename);
  const ranges = scripts.flatMap((s) => s.functions.flatMap((f) => f.ranges));
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`Protected RDP entry ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('actual local catalog RDP creation reaches the IPC with a canonical ID and reopens in the same credential mode', async (t) => {
  await captureRdpAppCoverage(t);
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const names = new Set([
    'openConnection',
    'requestRdpCredentials',
    'startRdpSession',
    'retryRdpSession',
  ]);
  const functions: string[] = [];
  visitSyntax(mainSyntax(source, true), (node) => {
    if (node.type === 'FunctionDeclaration' && names.has(node.id?.name))
      functions.push(source.slice(node.start, node.end));
  });
  assert.equal(functions.length, names.size);
  for (const mode of ['vault', 'local']) {
    const id = randomUUID(),
      requests: any[] = [],
      closes: string[] = [];
    let rendered: any[] = [];
    const scope: any = {
      authState: { mode },
      sessionsRef: { current: [] },
      treeRef: { current: [] },
      sessionCloseGate: {
        current: { reopenAfterClose: () => false, activeSessionIds: () => new Set() },
      },
      webSessionOpenInFlight: { current: new Map() },
      sessionResourceReleaseGate: { current: { reset() {}, waitForRelease: async () => {} } },
      rdpEditAttempts: { current: { cancel() {} } },
      rdpSessionAttempts: { current: { begin: () => 1, isCurrent: () => true } },
      rdpSavedCredentialAttempts: { current: new Set() },
      setSessions: (update: any) => {
        rendered = update(rendered);
        scope.sessionsRef.current = rendered;
      },
      setSelectedSessionId() {},
      setActivePage() {},
      isFileBrowserProtocol: () => false,
      savedConnectionAddressForEditor: (_protocol: string, host: string) => host,
      refreshRdpSystemClientCapability() {},
      defaultRdpProfile: () => ({}),
      waitForRdpSurfaceBounds: async () => ({ x: 0, y: 0, width: 800, height: 600 }),
      vaultRdpConnectRequest,
      canDisconnectRemoteDesktopSession: () => true,
      disconnectRemoteDesktopSession: async (id: string) => {
        closes.push(id);
        return true;
      },
      isBitwardenUnlockError: () => false,
      requiresRdpCredentialPrompt: () => false,
      window: {
        setTimeout: (fn: () => void) => fn(),
        wormhole: {
          openVaultRdpSession: async (value: any) => {
            assert.ok(parseVaultRdpOpenRequest(value));
            requests.push(value);
          },
          startRdpSession: async (value: any) => requests.push(value),
        },
      },
    };
    const open = runInNewContext(
      stripTypeScriptTypes(functions.join('\n') + '\nopenConnection'),
      scope,
      { filename: 'wormhole-app-rdp-catalog.js' },
    );
    const node = {
      id,
      kind: 'connection',
      protocol: 'rdp',
      name: 'Desktop',
      host: 'desktop.example',
    };
    open(node);
    await tick();
    await tick();
    assert.equal(rendered.length, 1);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].sessionId, mode === 'vault' ? id : `session-${id}`);
    rendered[0].rdpStatus = 'failed';
    rendered[0].rdpManualCredentials = true;
    open(node);
    await tick();
    await tick();
    assert.equal(rendered.length, 1, 'catalog reopening reuses the owned tab');
    assert.equal(requests.length, 2);
    assert.equal(closes.length, 1, 'old attempt is joined before reopening');
    if (mode === 'vault') {
      assert.equal(requests[1].manualCredentials, true);
      assert.equal(requests[1].nodeId, id);
      assert.deepEqual(Object.keys(requests[1]).sort(), [
        'bounds',
        'manualCredentials',
        'nodeId',
        'sessionId',
      ]);
    } else assert.equal(requests[1].manualCredentials, false, 'legacy saved behavior remains');
  }
});

test('actual local edit and deletion retain canonical RDP tab ownership and cancel queued reopen', async (t) => {
  await captureRdpAppCoverage(t);
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const node = randomUUID();
  let selectedId = '';
  visitSyntax(mainSyntax(source, true), (value) => {
    if (
      value.type === 'VariableDeclaration' &&
      value.declarations.some((d: any) => d.id?.name === 'editedSessionId')
    )
      selectedId = source.slice(value.start, value.end);
  });
  assert.ok(selectedId);
  const selection = stripTypeScriptTypes(selectedId + '\neditedSessionId');
  for (const id of [node, `session-${node}`]) {
    assert.equal(
      runInNewContext(
        selection,
        {
          editingId: node,
          sessionsRef: { current: [{ id, nodeId: node }] },
        },
        { filename: 'wormhole-app-rdp-edit-id.js' },
      ),
      id,
    );
  }
  assert.equal(
    runInNewContext(
      selection,
      { editingId: node, sessionsRef: { current: [] } },
      { filename: 'wormhole-app-rdp-edit-id.js' },
    ),
    `session-${node}`,
  );
  assert.equal(
    runInNewContext(
      selection,
      { editingId: undefined, sessionsRef: { current: [] } },
      { filename: 'wormhole-app-rdp-edit-id.js' },
    ),
    '',
  );
  let selected = '';
  visitSyntax(mainSyntax(source, true), (value) => {
    if (value.type === 'FunctionDeclaration' && value.id?.name === 'closeSessionsForNodeIds')
      selected = source.slice(value.start, value.end);
  });
  assert.ok(selected);
  const gate = new SessionCloseGate(),
    releases: Array<() => void> = [];
  let reopened = 0;
  const closing = [node, `session-${node}`].map((id) =>
    gate.run(id, () => new Promise<void>((resolve) => releases.push(resolve))),
  );
  for (const id of [node, `session-${node}`])
    assert.equal(
      gate.reopenAfterClose(id, () => reopened++),
      true,
    );
  const remove = runInNewContext(
    stripTypeScriptTypes(selected + '\ncloseSessionsForNodeIds'),
    {
      sessionCloseGate: { current: gate },
      sessionsRef: { current: [] },
    },
    { filename: 'wormhole-app-rdp-closeSessionsForNodeIds.js' },
  );
  await remove(new Set([node]));
  releases.forEach((release) => release());
  await Promise.all(closing);
  assert.equal(reopened, 0, 'deleted nodes cannot be recreated by either old or protected tab IDs');
});

test('actual local SessionSurface offers temporary entry for saved and quick protected RDP connections', async (t) => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const components: string[] = [];
  visitSyntax(mainSyntax(app, true), (node) => {
    if (
      node.type === 'FunctionDeclaration' &&
      ['SessionSurface', 'SessionSurfaceContent'].includes(node.id?.name)
    )
      components.push(app.slice(node.start, node.end));
  });
  assert.equal(components.length, 2);
  const source = components.join('\n');
  const { code } = await transformWithOxc(source + '\nSessionSurface;', 'session-rdp.tsx', {
    jsx: { runtime: 'classic' },
  });
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const filename = 'wormhole-app-rdp-surface.js';
  const component = runInNewContext(
    code,
    {
      React: {
        createElement: (type: unknown, props: unknown) =>
          typeof type === 'function' ? type(props) : { type, props },
      },
      isFileBrowserProtocol: () => false,
      canOpenRdpSystemClient: () => false,
      RdpSurface: 'rdp-surface',
    },
    { filename },
  );
  const id = randomUUID();
  for (const vault of [false, true])
    for (const saved of [false, true, 'quick']) {
      const calls: unknown[][] = [];
      const result = component({
        session: { id, protocol: 'rdp', ...(saved ? { nodeId: randomUUID() } : {}) },
        vault,
        onConnectRdp: (...args: unknown[]) => calls.push(['connect', ...args]),
        onRetryRdp: (...args: unknown[]) => calls.push(['retry', ...args]),
      });
      assert.equal(result.type, 'rdp-surface');
      result.props.onConnect();
      result.props.onRetry();
      assert.deepEqual(calls, [
        ['connect', id],
        ['retry', id],
      ]);
      assert.equal(
        typeof result.props.onEnterCredentials,
        vault && saved ? 'function' : 'undefined',
      );
      if (vault && saved) {
        result.props.onEnterCredentials();
        assert.deepEqual(calls.at(-1), ['retry', id, true]);
      }
    }
  const report = await inspector.post('Profiler.takePreciseCoverage');
  const script = report.result.find((s) => s.url === filename)!;
  let start = -1,
    end = -1;
  visitSyntax(mainSyntax(code), (node) => {
    if (node.type === 'CallExpression' && node.arguments[0]?.name === 'RdpSurface') {
      const action = node.arguments[1]?.properties?.find(
        (p: any) => p.key?.name === 'onEnterCredentials',
      );
      if (action) {
        start = action.start;
        end = action.end;
      }
    }
  });
  assert.ok(start >= 0 && end > start);
  const ranges = script.functions
    .flatMap((f) => f.ranges)
    .filter((r) => r.startOffset >= start && r.endOffset <= end);
  assert.ok(ranges.length > 0);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`Local RDP protected credential action ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

async function captureRdpAppCoverage(t: TestContext) {
  const inspector = new Session();
  inspector.connect();
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  t.after(async () => {
    try {
      const report = await inspector.post('Profiler.takePreciseCoverage');
      const scripts = report.result.filter((s) => s.url.startsWith('wormhole-app-rdp-'));
      assert.ok(scripts.length > 0, 'actual App VM coverage missing');
      const directory = process.env.WORMHOLE_TEST_RDP_APP_COVERAGE;
      if (directory) {
        mkdirSync(directory, { recursive: true });
        writeFileSync(path.join(directory, randomUUID() + '.json'), JSON.stringify(scripts));
      }
    } finally {
      inspector.disconnect();
    }
  });
}

test('actual protected Quick RDP submit and retry carry public metadata and use an isolated temporary account', async (t) => {
  await captureRdpAppCoverage(t);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const names = new Set([
    'submitQuickConnect',
    'startRdpSession',
    'requestRdpCredentials',
    'retryRdpSession',
  ]);
  const functions: string[] = [];
  let defaults = '';
  visitSyntax(mainSyntax(app, true), (node) => {
    if (node.type === 'FunctionDeclaration' && names.has(node.id?.name))
      functions.push(app.slice(node.start, node.end));
    if (node.type === 'VariableDeclarator' && node.id?.name === 'defaultRdpSettings')
      defaults = app.slice(node.init.start, node.init.end);
  });
  assert.equal(functions.length, names.size);
  assert.ok(defaults);
  const rdp = runInNewContext(stripTypeScriptTypes('(' + defaults + ')'), {});
  for (const saved of [false, true]) {
    const requests: any[] = [],
      errors: string[] = [];
    let rendered: any[] = [];
    const form: any = {
      name: 'Quick',
      host: 'quick.example',
      port: saved ? '' : '3389',
      protocol: 'rdp',
      rdp: { ...rdp },
      useSavedCredentials: saved,
      credential: saved ? randomUUID() : 'none',
      tunnel: 'off',
      sshAutoSudo: 'off',
    };
    Object.defineProperties(form, {
      username: {
        get() {
          throw Error('ordinary username read');
        },
      },
      inlinePassword: {
        get() {
          throw Error('ordinary password read');
        },
      },
    });
    const scope: any = {
      authState: { mode: 'vault' },
      newConnectionForm: form,
      connectionAuthenticationSelectionComplete: true,
      connectionAuthenticationSelectionError: 'choose',
      quickConnectSubmitInFlight: { current: false },
      canConfigureConnectionSshAutoSudo: false,
      effectiveSshAutoSudoMode: () => 'off',
      quickConnectStartsImmediately: () => false,
      quickConnectTunnelId: (_p: string, v: string) => (v === 'off' ? undefined : v),
      newSessionToken: randomUUID,
      isFileBrowserProtocol: () => false,
      vaultRdpQuickTarget,
      vaultRdpConnectRequest,
      sessionsRef: { current: [] },
      setSessions: (update: any) => {
        rendered = update(rendered);
        scope.sessionsRef.current = rendered;
      },
      setEditorError: (error: string) => errors.push(error),
      setSelectedSessionId() {},
      setActivePage() {},
      setNewConnectionForm() {},
      setNewConnectionOpen() {},
      rdpEditAttempts: { current: { cancel() {} } },
      rdpSessionAttempts: { current: { begin: () => 1, isCurrent: () => true } },
      rdpSavedCredentialAttempts: { current: new Set() },
      sessionResourceReleaseGate: { current: { waitForRelease: async () => {}, reset() {} } },
      sessionCloseGate: { current: { activeSessionIds: () => new Set() } },
      waitForRdpSurfaceBounds: async () => ({ x: 0, y: 0, width: 800, height: 600 }),
      defaultRdpProfile: (session: any) => session.rdpProfile ?? {},
      canDisconnectRemoteDesktopSession: () => true,
      disconnectRemoteDesktopSession: async () => true,
      isBitwardenUnlockError: () => false,
      window: {
        setTimeout: (fn: () => void) => fn(),
        wormhole: {
          openVaultRdpSession: async (q: any) => {
            assert.ok(parseVaultRdpOpenRequest(q));
            requests.push(q);
          },
        },
      },
    };
    const invoke = runInNewContext(
      stripTypeScriptTypes(
        functions.join('\n') + '\n({submitQuickConnect,retryRdpSession,requestRdpCredentials})',
      ),
      scope,
      { filename: 'wormhole-app-rdp-quick.js' },
    );
    invoke.submitQuickConnect({ preventDefault() {} });
    await tick();
    await tick();
    assert.deepEqual(errors, []);
    assert.equal(rendered.length, 1);
    assert.equal(requests.length, 1);
    const q = requests[0];
    assert.equal('nodeId' in q, false);
    assert.equal(q.quickTarget.host, 'quick.example');
    assert.equal(q.quickTarget.rdp.domain, '');
    assert.equal(q.quickTarget.credentialId, saved ? form.credential : '');
    assert.equal(q.manualCredentials, saved ? undefined : true);
    assert.equal(rendered[0].rdpProfile.domain, '');
    invoke.retryRdpSession(q.sessionId, true);
    await tick();
    await tick();
    assert.equal(requests.length, 2);
    assert.equal(requests[1].manualCredentials, true);
    assert.equal(
      requests[1].quickTarget.credentialId,
      '',
      'manual retry cannot borrow the saved primary',
    );
    invoke.retryRdpSession(q.sessionId);
    await tick();
    await tick();
    assert.equal(requests[2].manualCredentials, true, 'retry retains the selected temporary mode');
    rendered[0].rdpManualCredentials = false;
    invoke.requestRdpCredentials(q.sessionId);
    await tick();
    await tick();
    assert.equal(
      requests.at(-1).manualCredentials,
      saved ? undefined : true,
      'Connect with no selected primary opens protected entry',
    );
    scope.quickConnectSubmitInFlight.current = false;
    form.host = 'bad/host';
    invoke.submitQuickConnect({ preventDefault() {} });
    assert.equal(rendered.length, 1);
    assert.equal(errors.length, 1);
    assert.equal(scope.quickConnectSubmitInFlight.current, false);
    form.host = 'quick.example';
    form.useSavedCredentials = true;
    form.credential = 'none';
    invoke.submitQuickConnect({ preventDefault() {} });
    assert.equal(errors.length, 2);
    assert.equal(rendered.length, 1);
  }
});

test('actual Quick RDP fields keep username, domain and password in the dedicated document', async (t) => {
  await captureRdpAppCoverage(t);
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const fields: string[] = [];
  let condition = '';
  visitSyntax(mainSyntax(app, true), (node) => {
    if (node.type === 'VariableDeclarator' && node.id?.name === 'nativeQuickCredentialConnection')
      condition = app.slice(node.init.start, node.init.end);
    if (
      node.type === 'JSXExpressionContainer' &&
      node.expression?.type === 'ConditionalExpression' &&
      app
        .slice(node.expression.test.start, node.expression.test.end)
        .includes('nativeQuickCredentialConnection')
    )
      fields.push(app.slice(node.start, node.end));
  });
  assert.equal(fields.length, 3);
  assert.ok(condition);
  const { code } = await transformWithOxc(
    'const nativeQuickCredentialConnection = ' + condition + '; <>' + fields.join('\n') + '</>',
    'quick-rdp-fields.tsx',
    { jsx: { runtime: 'classic' } },
  );
  for (const [mode, editor] of [
    ['vault', 'quick'],
    ['vault', 'saved'],
    ['local', 'quick'],
  ]) {
    const rendered = runInNewContext(
      code,
      {
        authState: { mode },
        connectionEditorMode: editor,
        nativeSavedConnection: mode === 'vault' && editor === 'saved',
        newConnectionForm: {
          protocol: 'rdp',
          useSavedCredentials: false,
          username: '',
          inlinePassword: '',
          rdp: { domain: '' },
        },
        React: {
          createElement: (type: any, props: any, ...children: any[]) => ({ type, props, children }),
        },
        Input: 'input',
        Label: 'label',
        PasswordInput: 'password',
        Button: 'button',
        isFileBrowserProtocol: () => false,
        editingConnectionHasInlineCredential: false,
        editingConnectionId: null,
        nativeConnectionPassword: { current: null },
        connectionInlinePasswordPlaceholder: () => '',
      },
      { filename: 'wormhole-app-rdp-quick-fields.js' },
    );
    const text = JSON.stringify(rendered);
    for (const name of ['connection-username', 'connection-inline-password', 'rdp-domain'])
      assert.equal(text.includes(name), !(mode === 'vault' && editor === 'quick'));
    assert.equal(text.includes('protected window'), mode === 'vault' && editor === 'quick');
  }
});
