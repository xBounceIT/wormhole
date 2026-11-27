import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { declarations } from './fixtures/main-source.ts';
import { parseVaultWebRequest } from '../electron/vault-web-open.ts';
import { vaultWebQuickTarget } from '../src/web-connect.ts';
import { randomUUID } from 'node:crypto';

const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');

test('actual main web-open parser admits only an exact protected Quick target and preserves legacy targets', () => {
  const parse = runInNewContext(
    stripTypeScriptTypes(declarations(source, ['isWebOpenRequest']) + '\nisWebOpenRequest;'),
    {
      isRecord: (v: any) => v !== null && typeof v === 'object' && !Array.isArray(v),
      isSshSessionId: (v: any) => typeof v === 'string' && v.length > 0,
      isTunnelID: (v: any) => typeof v === 'string' && v.length === 36,
      webMaxAddressLength: 4096,
      parseVaultWebRequest,
    },
  );
  const q = {
    sessionId: randomUUID(),
    attempt: 1,
    quickTarget: vaultWebQuickTarget({ protocol: 'https', host: 'https://host/path?q=x#page' }),
  };
  assert.equal(parse(q), true);
  for (const bad of [
    null,
    { ...q, sessionId: 'session-quick-id' },
    { ...q, attempt: 0 },
    { ...q, nodeId: randomUUID() },
    { ...q, address: 'override' },
    { ...q, password: 'private' },
    { ...q, quickTarget: { ...q.quickTarget, username: 'private' } },
  ])
    assert.equal(parse(bad), false);
  assert.equal(parse({ sessionId: 'legacy', attempt: 1, nodeId: 'saved' }), true);
  assert.equal(
    parse({ sessionId: 'legacy', attempt: 1, address: 'host/path', protocol: 'https' }),
    true,
  );
});

test('actual web IPC gates every vault action on the trusted main document and preserves unauthenticated close', async (t) => {
  const start = source.indexOf("ipcMain.handle('web:open'"),
    end = source.indexOf("ipcMain.on('ssh:terminal-ack'", start);
  const filename = 'wormhole-vault-web-ipc.js';
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const handlers = new Map<string, any>(),
    calls: any[] = [];
  let trusted = true,
    vault = true,
    allowed = true,
    ownerPresent = true,
    destroyed = false,
    running = true,
    native = false,
    lost = false;
  const owner = { isDestroyed: () => destroyed },
    event = { sender: {} };
  let queued: (() => void) | undefined;
  runInNewContext(
    stripTypeScriptTypes(source.slice(start, end)),
    {
      ipcMain: { handle: (name: string, fn: any) => handlers.set(name, fn), on() {} },
      vaultBackend: {
        get isVaultWorkspace() {
          return vault;
        },
      },
      isTrustedVaultSender: () => trusted,
      requireNativeResourcesRunning: () => {
        if (!running) throw Error('stopping');
      },
      isWebOpenRequest: (q: any) => Boolean(q?.nodeId),
      isWebBoundsRequest: (q: any) => Boolean(q?.sessionId),
      isWebCommandRequest: (q: any) => Boolean(q?.operation),
      isSshSessionId: (q: any) => typeof q === 'string',
      BrowserWindow: { fromWebContents: () => (ownerPresent ? owner : null) },
      authSession: {
        get isAccessAllowed() {
          return allowed;
        },
      },
      vaultWebIpc: {
        handles: () => native,
        open: async (...args: any[]) => {
          calls.push(['protected-open', ...args]);
          return { public: true };
        },
        close: async (...args: any[]) => {
          calls.push(['protected-close', ...args]);
        },
      },
      webSurfaces: {
        open: async (...args: any[]) => {
          calls.push(['open', ...args]);
          return { public: true };
        },
        closeForOwner: (...args: any[]) => calls.push(['close', ...args]),
        setBounds: (...args: any[]) => calls.push(['bounds', ...args]),
        hideAll: () => calls.push(['hide']),
        command: async (...args: any[]) => calls.push(['command', ...args]),
      },
      runAuthorizedOperation: async (fn: any, cancel: any) => {
        if (lost) {
          cancel();
          throw Error('locked');
        }
        return fn();
      },
      serializeAuthOperation: async (fn: any) => {
        queued?.();
        return fn();
      },
      requireWorkspaceAuth: async () => {
        if (!allowed) throw Error('locked');
      },
    },
    { filename },
  );
  const invoke = (name: string, q: any, ...extra: any[]) =>
    handlers.get('web:' + name)(event, q, ...extra);
  const open = { sessionId: 'id', nodeId: 'node', attempt: 1 },
    bounds = { sessionId: 'id' },
    command = { sessionId: 'id', operation: 'reload' };
  assert.deepEqual(JSON.parse(JSON.stringify(await invoke('open', open))), { public: true });
  const accepted = calls[0][3];
  assert.equal(accepted(), true);
  for (const [name, q] of [
    ['open', open],
    ['set-bounds', bounds],
    ['command', command],
    ['close', 'id'],
  ] as const) {
    const before = calls.length;
    await assert.rejects(invoke(name, q, 'extra'), /Invalid vault web owner/);
    trusted = false;
    await assert.rejects(invoke(name, q), /Invalid vault web owner/);
    assert.equal(accepted(), false);
    trusted = true;
    assert.equal(calls.length, before);
    await assert.rejects(invoke(name, null));
  }
  running = false;
  await assert.rejects(invoke('open', open), /stopping/);
  running = true;
  ownerPresent = false;
  await assert.rejects(invoke('open', open), /unavailable/);
  for (const [name, q] of [
    ['set-bounds', bounds],
    ['command', command],
    ['close', 'id'],
  ] as const)
    await invoke(name, q);
  ownerPresent = true;
  destroyed = true;
  await assert.rejects(invoke('open', open), /unavailable/);
  for (const [name, q] of [
    ['set-bounds', bounds],
    ['command', command],
    ['close', 'id'],
  ] as const)
    await invoke(name, q);
  destroyed = false;
  await invoke('set-bounds', bounds);
  assert.equal(calls.at(-1)[0], 'bounds');
  allowed = false;
  await invoke('set-bounds', bounds);
  assert.equal(calls.at(-1)[0], 'hide');
  await invoke('close', 'id');
  assert.equal(calls.at(-1)[0], 'close');
  await assert.rejects(invoke('command', command), /locked/);
  lost = true;
  await assert.rejects(invoke('open', open), /locked/);
  lost = false;
  allowed = true;
  queued = () => {
    trusted = false;
  };
  await assert.rejects(invoke('command', command), /Invalid vault web owner/);
  queued = undefined;
  trusted = true;
  await invoke('command', command);
  assert.equal(calls.at(-1)[0], 'command');
  vault = false;
  trusted = false;
  await invoke('command', command);
  await invoke('open', open);
  native = true;
  await invoke('open', open);
  assert.equal(calls.at(-1)[0], 'protected-open');
  await invoke('close', 'id');
  assert.equal(calls.at(-1)[0], 'protected-close');
  await assert.rejects(invoke('open', open, 'extra'), /Invalid vault web owner/);
  await assert.rejects(invoke('close', 'id', 'extra'), /Invalid vault web owner/);
  native = false;
  await assert.rejects(invoke('open', { ...open, quickTarget: {} }), /Protected Quick Connect/);
  const coverage = await inspector.post('Profiler.takePreciseCoverage');
  const script = coverage.result.find((s) => s.url === filename)!;
  const ranges = script.functions.flatMap((f) => f.ranges);
  const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
  t.diagnostic(`Web IPC V8 block coverage ${percent.toFixed(2)}%`);
  assert.ok(percent >= coverageThreshold);
});

test('actual web initialization binds the native client, authorization epoch and owned route broker', async () => {
  const start = source.indexOf('const vaultWebConnections ='),
    end = source.indexOf('class NativeSshBackend', start);
  let route: any,
    web: any,
    manager: any,
    admission: any,
    currentWindow: any,
    allowed = true,
    running = true;
  const owner = { isDestroyed: () => false };
  currentWindow = owner;
  const calls: any[] = [];
  const backend: any = {
    unlockedWorkspaceId: 'workspace',
    isVaultWorkspace: true,
    webPlan: async (q: any) => q,
    webSessionArchive: (plan: any, current: any) => ({ plan, current }),
    checkWebSessionViews: async (workspaceId: any, views: any) => {
      calls.push(['verify-views', workspaceId, views]);
      return [false];
    },
    tunnelPlan: async (q: any) => q,
    tunnelBundle: async (q: any) => q,
    beginQuickTarget: async (q: any, accepted: any) => {
      calls.push([q, accepted]);
      return q;
    },
  };
  const init = runInNewContext(
    stripTypeScriptTypes(source.slice(start, end) + '\n({webSurfaces, vaultWebConnections})'),
    {
      VaultWebIpc: class {
        constructor(q: any) {
          admission = q;
        }
      },
      VaultWebConnections: class {
        constructor(q: any) {
          web = q;
        }
      },
      SealedRouteBroker: class {
        constructor(q: any) {
          route = q;
        }
      },
      WebSurfaceManager: class {
        constructor(q: any) {
          manager = q;
        }
        open(...args: any[]) {
          calls.push(['open', ...args]);
          return Promise.resolve('opened');
        }
        closeForContents(...args: any[]) {
          calls.push(['close', ...args]);
          return Promise.resolve();
        }
        stopVaultSessions() {
          calls.push(['all']);
          return Promise.resolve();
        }
      },
      vaultBackend: backend,
      backendPath: () => 'native',
      isAuthorizationEpochCurrent: (epoch: number) => allowed && epoch === 4,
      isTrustedVaultSender: (event: any) => event.trusted,
      BrowserWindow: { fromWebContents: () => currentWindow },
      runAuthorizedOperation: (run: any) => run(),
      requireNativeResourcesRunning: () => {
        if (!running) throw Error('stopping');
      },
    },
  );
  assert.equal(manager.connections, init.vaultWebConnections);
  assert.equal(manager.active(), true);
  backend.isVaultWorkspace = false;
  assert.equal(manager.active(), false);
  assert.equal(web.workspaceId(), 'workspace');
  assert.equal(route.workspaceId(), 'workspace');
  assert.equal(route.executable(), 'native');
  for (const opts of [web, route]) {
    assert.equal(opts.authorized(5), true);
    assert.equal(opts.authorized(4), false);
    allowed = false;
    assert.equal(opts.authorized(5), false);
    allowed = true;
    backend.unlockedWorkspaceId = undefined;
    assert.equal(opts.authorized(5), false);
    backend.unlockedWorkspaceId = 'workspace';
  }
  const marker = {};
  assert.equal(await web.plan(marker), marker);
  assert.equal(web.archive(marker, web.authorized).current, web.authorized);
  assert.deepEqual(await web.checkViews('workspace', marker), [false]);
  assert.deepEqual(calls.at(-1), ['verify-views', 'workspace', marker]);
  assert.equal(await route.plan(marker), marker);
  assert.equal(await route.bundle(marker), marker);
  const accepted = () => true;
  assert.equal((await web.quickTarget(marker, 'session', 5, accepted)).epoch, 5);
  assert.equal(calls.at(-1)[1], accepted);
  assert.deepEqual(JSON.parse(JSON.stringify(calls.at(-1)[0])), {
    workspaceId: 'workspace',
    sessionId: 'session',
    epoch: 5,
    target: marker,
  });
  backend.unlockedWorkspaceId = undefined;
  assert.throws(() => web.quickTarget(marker, 'session', 5, accepted), /locked/);
  assert.equal(admission.workspace(), false);
  backend.isVaultWorkspace = true;
  assert.equal(admission.workspace(), true);
  assert.equal(admission.trusted({ trusted: true }), true);
  assert.equal(admission.trusted({ trusted: false }), false);
  assert.equal(
    await admission.authorize(
      async () => marker,
      async () => {},
    ),
    marker,
  );
  running = false;
  await assert.rejects(
    admission.authorize(
      async () => marker,
      async () => {},
    ),
    /stopping/,
  );
  assert.equal(await admission.open(owner, marker, accepted), 'opened');
  assert.equal(calls.at(-1)[1], owner);
  await admission.close(owner, 'id');
  assert.equal(calls.at(-1)[0], 'close');
  await admission.closeAll();
  assert.equal(calls.at(-1)[0], 'all');
  currentWindow = undefined;
  assert.throws(() => admission.open(owner, marker, accepted), /unavailable/);
  currentWindow = { isDestroyed: () => true };
  assert.throws(() => admission.open(owner, marker, accepted), /unavailable/);
});

test('actual native shutdown waits for web cleanup and propagates an unconfirmed web stop', async () => {
  const start = source.indexOf('let nativeResourceShutdownPromise:'),
    end = source.indexOf('function scheduleUnlockedBackgroundWork', start);
  for (const failure of ['none', 'web', 'rdp']) {
    let finish!: () => void, finishRdp!: () => void;
    const webStop = new Promise<void>((resolve, reject) => {
      finish = () => (failure === 'web' ? reject(Error('private web diagnostic')) : resolve());
    });
    const rdpStop = new Promise<void>((resolve, reject) => {
      finishRdp = () => (failure === 'rdp' ? reject(Error('private RDP diagnostic')) : resolve());
    });
    let settled = false;
    const result = runInNewContext(
      stripTypeScriptTypes(source.slice(start, end) + '\n({shutdownNativeResources})'),
      {
        vaultLockMonitor: { deactivate() {} },
        vncSessionAttempts: { cancelAll() {} },
        cancelPreparingRdpStarts() {},
        serialBackend: undefined,
        sealedSerial: { closeAll: async () => {} },
        rdpClient: undefined,
        nativeBackend: undefined,
        stopVaultVncSessions: async () => {},
        stopVaultBitwardenCLIUnlock: async () => {},
        stopVaultRdpSessions: () => rdpStop,
        vaultSshIpc: { closeAll: async () => {} },
        sshBackend: { dispose: async () => {}, backendStopped() {} },
        vaultBackend: { stop: async () => {} },
        vaultCreateDialog: { cancel: async () => {} },
        vaultMigrationSetupDialog: { cancel: async () => {} },
        vaultOSMigrationDialog: { cancel: async () => {} },
        vaultRootSetupDialog: { cancel: async () => {} },
        vaultUpgradeSetupDialog: { cancel: async () => {} },
        vaultReauthenticationDialog: { cancel: async () => {} },
        vaultSharedDialog: { cancel: async () => {} },
        vaultSharedSetupDialog: { cancel: async () => {} },
        vaultNotesDialog: { cancel() {} },
        vaultCredentialsDialog: { cancel() {} },
        vaultLinuxClipboard: undefined,
        vaultTunnelDialog: { cancel: async () => {} },
        vaultWebIpc: { closeAll: () => webStop },
        webSurfaces: { backendStopped() {} },
        releaseAllRdpTunnels: async () => {},
        rdpTunnelLeases: { clear() {} },
        rdpTunnelLeaseSessions: { clear() {} },
        console: { warn() {} },
      },
    );
    const pending = result.shutdownNativeResources();
    assert.equal(result.shutdownNativeResources(), pending, 'shutdown remains single-flight');
    const observed = pending.then(
      () => {
        settled = true;
      },
      (error: Error) => {
        settled = true;
        return error;
      },
    );
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false);
    finish();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(settled, false, 'web cleanup cannot bypass the pending RDP cleanup');
    finishRdp();
    const error = await observed;
    assert.equal(Boolean(error), failure !== 'none');
  }
});
