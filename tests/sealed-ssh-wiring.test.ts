import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { KeyedSingleFlight } from '../electron/keyed-single-flight.ts';

test('application SSH broker routes vault opens, commands and retirement without legacy credential resolution', async (t) => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const selected = source.slice(
    source.indexOf('class NativeSshBackend {'),
    source.indexOf('function serializeAuthOperation'),
  );
  const script = stripTypeScriptTypes(selected + '\nNativeSshBackend');
  const filename = 'wormhole-sealed-ssh-main.js';
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const calls: any[] = [];
  let routeOptions: any;
  let dialogAnswer = 1,
    parentDestroyed = false;
  const parent = { isDestroyed: () => parentDestroyed };
  const messages: any[] = [];
  const trusted: any[] = [];
  let options: any,
    active = true,
    current = true,
    admitted = true,
    failStop = false;
  const vaultBackend = {
    isSharedWorkspace: false,
    unlockedWorkspaceId: 'workspace',
    sshBundle: async (q: any) => q,
    sshHostPlan: async (q: any) => q,
    trustSshHost: async (q: any, confirm: any, accepted: any) => {
      assert.ok(accepted());
      await confirm('ssh-host-trust', { vaultId: 'workspace' }, async () => {
        trusted.push(q);
      });
    },
    trustSharedSshHost: async (q: any, confirm: any, accepted: any) => {
      assert.ok(accepted());
      await confirm({ shared: true }, accepted, () => {
        calls.push(['shared-pin', q.received]);
      });
    },
    connectionRoute: async (q: any) => q,
    routedSshBundle: async (q: any) => q,
    tunnelPlan: async (q: any) => q,
    tunnelBundle: async (q: any) => q,
  };
  class Sealed {
    constructor(value: any) {
      options = value;
    }
    open(q: any, epoch: number, owner: () => boolean) {
      calls.push(['open', q, epoch, owner]);
      return Promise.resolve({
        sessionId: q.sessionId,
        host: 'vault-host',
        port: 22,
        username: 'vault-user',
        fingerprint: 'pin',
      });
    }
    has() {
      return active;
    }
    hasReservation() {
      return active;
    }
    send(...args: any[]) {
      calls.push(['send', ...args]);
    }
    close(id: string) {
      calls.push(['close', id]);
      return Promise.resolve();
    }
    closeAll() {
      calls.push(['close-all']);
      return failStop ? Promise.reject(Error('unconfirmed')) : Promise.resolve();
    }
  }
  const Native = runInNewContext(
    script,
    {
      SealedSshBackend: Sealed,
      KeyedSingleFlight,
      BrowserWindow: { fromWebContents: () => parent },
      showCoordinatedMessageBox: async (_parent: any, options: any) => {
        messages.push(options);
        return { response: dialogAnswer };
      },
      vaultReauthenticationDialog: {
        open: async (
          _parent: any,
          accepted: any,
          operation: string,
          _descriptor: any,
          submit: any,
          signal: AbortSignal,
        ) => {
          assert.ok(accepted());
          assert.equal(operation, 'ssh-host-trust');
          assert.ok(!signal.aborted);
          return submit();
        },
      },
      vaultSharedDialog: {
        open: async (
          owner: any,
          current: () => boolean,
          mode: string,
          startup: any,
          submit: () => void,
          signal: AbortSignal,
        ) => {
          assert.equal(owner, parent);
          assert.equal(mode, 'trust-ssh-host');
          assert.ok(startup.shared && current() && !signal.aborted);
          submit();
        },
      },
      SealedRouteBroker: class {
        constructor(value: any) {
          routeOptions = value;
        }
      },
      backendPath: () => '/backend',
      wormholeDatabasePath: () => '/database',
      electronUserDataPath: () => '/user-data',
      vaultBackend,
      vaultSshIpc: { isQuickTarget: () => false },
      vaultSshCredentialsDialog: { cancel: async () => {} },
      isTrustedVaultSender: (event: any) => event.trusted !== false,
      isAuthorizationEpochCurrent: () => admitted,
      parseSshBackendEvent: () => undefined,
      requireAuthorizationEpoch: () => {
        if (!admitted) throw Error('locked');
      },
      runBitwardenBackend: () => {
        throw Error('legacy credential path entered');
      },
      SshTerminalDelivery: class {
        remove(id: string) {
          calls.push(['remove', id]);
        }
        clear() {}
      },
      TunnelLeaseRegistry: class {
        releaseAll() {
          return Promise.resolve();
        }
      },
      SharedSshRoutes: class {
        clear() {}
      },
      WebSessionAttemptTracker: class {
        begin() {
          return 1;
        }
        isCurrent() {
          return current;
        }
        cancel(id: string) {
          calls.push(['cancel', id]);
        }
      },
      mcpApprovalWindowCoordinator: { reset: () => [] },
      releaseNativeTunnelLease: () => {},
      clearTimeout,
      console,
    },
    { filename },
  );
  const native = new Native();
  native.handleLine = (line: string) => calls.push(['line', line]);
  assert.equal(options.executable(), '/backend');
  assert.deepEqual(JSON.parse(JSON.stringify(options.fileEditing())), {
    databasePath: '/database',
    userDataPath: '/user-data',
  });
  assert.equal(options.workspaceId(), 'workspace');
  assert.equal(options.authorized(1), true);
  assert.equal(await options.bundle('bundle'), 'bundle');
  assert.equal(await options.route.resolve('plan'), 'plan');
  assert.equal(await options.route.bundle('routed'), 'routed');
  assert.equal(routeOptions.executable(), '/backend');
  assert.equal(routeOptions.workspaceId(), 'workspace');
  assert.ok(routeOptions.authorized(1));
  assert.equal(await routeOptions.plan('plan'), 'plan');
  assert.equal(await routeOptions.bundle('route'), 'route');
  options.onLine('event');
  let url = 'file:///app',
    destroyed = false;
  const owner = { getURL: () => url, isDestroyed: () => destroyed };
  const request = { sessionId: 'session', nodeId: 'node', columns: 80, rows: 24 };
  const result = await native.open(request, 0, owner);
  assert.equal(result.host, 'vault-host');
  native.assertSftpOwner({ sender: owner }, request.sessionId);
  assert.throws(() => native.assertSftpOwner({ sender: {} }, request.sessionId), /owner/);
  assert.throws(
    () => native.assertSftpOwner({ sender: owner, trusted: false }, request.sessionId),
    /owner/,
  );

  const opened = calls.find((c) => c[0] === 'open');
  assert.equal(opened[2], 1);
  assert.equal(opened[3](), true);
  url = 'file:///other';
  assert.equal(opened[3](), false);
  url = 'file:///app';
  destroyed = true;
  assert.equal(opened[3](), false);
  destroyed = false;
  for (const change of [
    { nodeId: undefined },
    { manualCredentials: true },
    { manualKeyPassphrase: true },
    { password: 'private' },
    { keyPassphrase: 'private' },
    { username: 'override' },
    { host: 'override' },
    { tunnelConfigId: 'vpn' },
  ])
    await assert.rejects(native.open({ ...request, ...change }, 0, owner), /not available/);
  await native.open({ ...request, mode: 'sftp' }, 0, owner);
  assert.equal(calls.filter((c) => c[0] === 'open').at(-1)[1].mode, 'sftp');
  current = false;
  await assert.rejects(native.open(request, 0, owner), /closed before it could start/);
  current = true;
  admitted = false;
  await assert.rejects(native.open(request, 0, owner), /locked/);
  assert.equal(options.authorized(1), false);
  admitted = true;
  assert.equal(await options.host.plan('host-plan'), 'host-plan');
  const hostPlan = { binding: { host: 'ssh.example', port: 22 }, fingerprint: '' };
  for (const fingerprint of ['', 'SHA256:old']) {
    hostPlan.fingerprint = fingerprint;
    await options.host.confirm(
      request,
      hostPlan,
      'SHA256:new',
      () => true,
      new AbortController().signal,
    );
    assert.equal(messages.at(-1).defaultId, 0);
    assert.equal(messages.at(-1).cancelId, 0);
    assert.match(messages.at(-1).detail, /ssh.example:22/);
    assert.match(messages.at(-1).detail, /SHA256:new/);
    assert.equal(messages.at(-1).type, fingerprint ? 'warning' : 'question');
  }
  assert.equal(trusted.length, 2);
  vaultBackend.isSharedWorkspace = true;
  await options.host.confirm(
    request,
    hostPlan,
    'SHA256:changed',
    () => true,
    new AbortController().signal,
  );
  assert.deepEqual(calls.at(-1), ['shared-pin', 'SHA256:changed']);
  vaultBackend.isSharedWorkspace = false;
  dialogAnswer = 0;
  await assert.rejects(
    options.host.confirm(request, hostPlan, 'SHA256:new', () => true, new AbortController().signal),
    /cancelled/,
  );
  dialogAnswer = 1;
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(
    options.host.confirm(request, hostPlan, 'SHA256:new', () => true, aborted.signal),
    /unavailable/,
  );
  parentDestroyed = true;
  await assert.rejects(
    options.host.confirm(request, hostPlan, 'SHA256:new', () => true, new AbortController().signal),
    /unavailable/,
  );
  parentDestroyed = false;
  await assert.rejects(
    options.host.confirm(
      { ...request, sessionId: 'absent' },
      hostPlan,
      'SHA256:new',
      () => true,
      new AbortController().signal,
    ),
    /unavailable/,
  );
  await assert.rejects(
    options.host.confirm(
      request,
      hostPlan,
      'SHA256:new',
      () => false,
      new AbortController().signal,
    ),
    /unavailable/,
  );
  let checks = 0;
  await assert.rejects(
    options.host.confirm(
      request,
      hostPlan,
      'SHA256:new',
      () => ++checks === 1,
      new AbortController().signal,
    ),
    /cancelled/,
  );
  assert.equal(trusted.length, 2);
  native.sendInput('session', 'YQ==');
  assert.equal(calls.at(-1)[0], 'send');
  assert.throws(() => native.ensureStarted(), /Legacy SSH/);
  native.prepareForLock();
  await native.stopSealedSessions();
  await native.close('session');
  assert.equal(native.terminalOwners.has('session'), false);
  vaultBackend.unlockedWorkspaceId = '';
  assert.equal(options.authorized(1), false);
  active = false;
  native.assertSftpOwner({ sender: {} }, 'legacy');
  native.child = {
    killed: false,
    stdin: {
      destroyed: false,
      write: (line: string) => calls.push(['legacy-write', JSON.parse(line)]),
    },
  };
  native.ensureStarted();
  native.sendInput('legacy', 'Yg==');
  assert.equal(calls.at(-1)[0], 'legacy-write');
  native.child = undefined;
  await native.dispose();
  failStop = true;
  await assert.rejects(native.dispose(), /termination could not be confirmed/);
  assert.equal(native.shutdownUnconfirmed, true);
  assert.throws(() => native.ensureStarted(), /unconfirmed/);
  failStop = false;
  await native.dispose();
  native.prepareForLock();
  await Promise.resolve();
  const coverage = await inspector.post('Profiler.takePreciseCoverage');
  await inspector.post('Profiler.stopPreciseCoverage');
  const ranges = [
    [script.indexOf('    assertSftpOwner('), script.indexOf('    sharedRoutes =')],
    [script.indexOf('    sealed ='), script.indexOf('    terminalDelivery =')],
    [
      script.indexOf(
        '        if (vaultBackend.unlockedWorkspaceId)',
        script.indexOf('async openCurrent'),
      ),
      script.indexOf('        let bitwardenCredential'),
    ],
    [script.indexOf('    stopSealedSessions('), script.indexOf('    async close(')],
    [
      script.indexOf(
        '        if (this.hasProtectedReservation(sessionId))',
        script.indexOf('async close('),
      ),
      script.indexOf('        // Native resources'),
    ],
    [
      script.indexOf('        if (typeof command.session_id'),
      script.indexOf('        const child', script.indexOf('    write(command')),
    ],
  ];
  const blocks = new Map<string, number>();
  for (const entry of coverage.result.filter((e) => e.url === filename))
    for (const fn of entry.functions)
      for (const block of fn.ranges)
        if (
          ranges.some(
            ([start, end]) =>
              start >= 0 && end > start && block.startOffset >= start && block.endOffset <= end,
          )
        )
          blocks.set(
            `${block.startOffset}:${block.endOffset}`,
            (blocks.get(`${block.startOffset}:${block.endOffset}`) ?? 0) + block.count,
          );
  assert.ok(blocks.size > 0);
  const percent = (100 * [...blocks.values()].filter((v) => v > 0).length) / blocks.size;
  t.diagnostic(`main sealed SSH branches: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('vault SSH opening IPC requires the trusted document before invoking the broker', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const selected = source.slice(
    source.indexOf("ipcMain.handle('ssh:open'"),
    source.indexOf("ipcMain.handle('ssh:trust-host-key'"),
  );
  let handler: any,
    trusted = false,
    opened = 0;
  runInNewContext(stripTypeScriptTypes(selected), {
    ipcMain: {
      handle: (_name: string, callback: any) => {
        handler = callback;
      },
    },
    requireNativeResourcesRunning: () => {},
    isSshOpenRequest: () => true,
    vaultBackend: { isVaultWorkspace: true, unlockedWorkspaceId: 'vault' },
    vaultSshIpc: {
      handles: () => true,
      open: async () => {
        opened++;
      },
    },
    isTrustedVaultSender: () => trusted,
    runAuthorizedOperation: (callback: any) => callback(1),
    sshBackend: {
      open: () => {
        opened++;
        return Promise.resolve();
      },
      close: () => Promise.resolve(),
    },
  });
  await assert.rejects(handler({ sender: {} }, { sessionId: 'id' }), /owner/);
  assert.equal(opened, 0);
  trusted = true;
  await handler({ sender: {} }, { sessionId: 'id' });
  assert.equal(opened, 1);
});

test('every SFTP IPC checks its current owner after asynchronous authorization', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const selected = source.slice(
    source.indexOf("ipcMain.handle('ssh:sftp-edit'"),
    source.indexOf("ipcMain.handle('ssh:close'"),
  );
  const handlers = new Map<string, (...args: any[]) => Promise<unknown>>();
  let owner = true,
    calls = 0,
    checks = 0,
    changeOwner = false;
  const methods = [
    'edit',
    'prepareEditClose',
    'shareSftp',
    'listSftpTree',
    'openSftp',
    'listSftp',
    'listLocalSftp',
    'operateSftp',
    'startSftpTransfer',
    'decideSftpConflict',
    'cancelSftpTransfer',
    'closeSftp',
  ];
  const backend: Record<string, any> = Object.fromEntries(
    methods.map((method) => [
      method,
      () => {
        calls++;
      },
    ]),
  );
  const event = { sender: {} };
  backend.assertSftpOwner = (received: unknown, id: unknown) => {
    assert.equal(received, event);
    assert.equal(id, 'session');
    checks++;
    if (!owner) throw Error('Invalid vault SFTP owner.');
  };
  backend.captureOwner = () => {
    if (!owner) throw Error('Invalid vault SFTP owner.');
    return () => {
      if (!owner) throw Error('Invalid vault SFTP owner.');
    };
  };
  runInNewContext(stripTypeScriptTypes(selected), {
    ipcMain: { handle: (name: string, callback: any) => handlers.set(name, callback) },
    vaultSshIpc: { handles: () => false },
    sshBackend: backend,
    requireNativeResourcesRunning: () => {},
    requireWorkspaceAuth: async () => {
      if (changeOwner) owner = false;
    },
    serializeAuthOperation: (fn: any) => fn(),
    runAuthorizedOperation: async (fn: any) => {
      await Promise.resolve();
      if (changeOwner) owner = false;
      return fn();
    },
    ...Object.fromEntries(
      [
        'isSshSessionId',
        'isSftpEditRequest',
        'isSftpRequestId',
        'isSftpPane',
        'isLocalSftpPath',
        'isSftpPath',
        'isSftpOperationRequest',
        'isSftpTransferRequest',
        'isSftpTransferId',
        'isSftpTransferDecision',
      ].map((name) => [name, () => true]),
    ),
  });
  const inputs: Record<string, any[]> = {
    'ssh:sftp-edit': ['session', {}],
    'ssh:sftp-edit-close': ['session'],
    'ssh:sftp-share': ['session', 'new-session'],
    'ssh:sftp-tree-list': ['session', 'remote', '/', 'request'],
    'ssh:sftp-open': ['session', 'request'],
    'ssh:sftp-list': ['session', '/', 'request'],
    'ssh:sftp-local-list': ['session', '/', 'request'],
    'ssh:sftp-operation': ['session', {}],
    'ssh:sftp-transfer': ['session', {}],
    'ssh:sftp-transfer-decision': ['session', 'transfer', 'item', 'skip', false],
    'ssh:sftp-transfer-cancel': ['session', 'transfer', 'item'],
    'ssh:sftp-close': ['session'],
  };
  assert.equal(handlers.size, methods.length);
  for (const [name, handler] of handlers) {
    owner = true;
    changeOwner = false;
    const before = calls,
      checked = checks;
    await handler(event, ...inputs[name]!);
    assert.equal(calls, before + 1, name);
    assert.equal(checks, checked + 1, name);
    owner = false;
    await assert.rejects(handler(event, ...inputs[name]!), /owner/);
    assert.equal(calls, before + 1, name);
    if (name !== 'ssh:sftp-close') {
      owner = true;
      changeOwner = true;
      await assert.rejects(handler(event, ...inputs[name]!), /owner/);
      assert.equal(calls, before + 1, name);
    }
  }
});

test('vault SFTP events are delivered only to their owner and stop when locked', () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const selected = source.slice(
    source.indexOf('  private broadcast(event: SshBackendEvent)'),
    source.indexOf('  private broadcastMcpApprovalCancellation('),
  );
  const authSession = { isAccessAllowed: true };
  const sent: any[] = [];
  let destroyed = false,
    sealed = true;
  const owner = { isDestroyed: () => destroyed, send: (...args: any[]) => sent.push(args) };
  const Native = runInNewContext(stripTypeScriptTypes(`class Native { ${selected} }; Native`), {
    authSession,
    BrowserWindow: { getAllWindows: () => [] },
    windowCloseCoordinators: new Set(),
  });
  const native = new Native();
  native.sealed = { has: () => sealed };
  native.terminalOwners = new Map([['session', owner]]);
  const event = { type: 'sftp.ready', sessionId: 'session' };
  native.broadcast(event);
  assert.deepEqual(sent, [['ssh:event', event]]);
  authSession.isAccessAllowed = false;
  native.broadcast(event);
  authSession.isAccessAllowed = true;
  destroyed = true;
  native.broadcast(event);
  destroyed = false;
  native.terminalOwners.clear();
  native.broadcast(event);
  sealed = false;
  native.broadcast(event);
  assert.equal(sent.length, 1);
});

test('shared SFTP app wiring owns the new tab without releasing the source transport', async (t) => {
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const selected = source.slice(
    source.indexOf('  async shareSftp('),
    source.indexOf('  listSftpTree('),
  );
  const vaultBackend = { unlockedWorkspaceId: 'vault' };
  const filename = 'wormhole-shared-sftp-main.js';
  const Native = runInNewContext(
    stripTypeScriptTypes(
      `class Native { ${source.slice(source.indexOf('  hasProtectedReservation('), source.indexOf('  ownsProtected('))} ${selected} }; Native`,
    ),
    {
      vaultBackend,
    },
    { filename },
  );
  const native = new Native();
  let url = 'file:///app',
    destroyed = false,
    generation = 0;
  const owner = { getURL: () => url, isDestroyed: () => destroyed };
  const aliases = new Set(['source']);
  native.activeSessions = new Set(['source']);
  native.openWaiters = new Map();
  native.pendingConnections = new Map();
  native.terminalOwners = new Map([['source', owner]]);
  native.terminalAdmissions = new Map();
  native.protectedMembers = new Map();
  native.connectionAttempts = { begin: () => ++generation };
  let accepted: () => boolean = () => false;
  let resolve!: (value: unknown) => void, reject!: (error: Error) => void;
  native.sealed = {
    has: (id: string) => aliases.has(id),
    hasReservation: (id: string) => aliases.has(id),
    shareSftp: (from: string, id: string, current: () => boolean) => {
      assert.equal(from, 'source');
      accepted = current;
      assert.ok(current());
      aliases.add(id);
      return new Promise((a, b) => {
        resolve = a;
        reject = b;
      });
    },
  };
  for (const candidate of [undefined, { ...owner }])
    await assert.rejects(native.shareSftp('source', 'files', candidate), /unavailable/);
  destroyed = true;
  await assert.rejects(native.shareSftp('source', 'files', owner), /unavailable/);
  destroyed = false;
  const pending = native.shareSftp('source', 'files', owner);
  assert.equal(native.terminalOwners.get('files'), owner);
  await assert.rejects(native.shareSftp('source', 'files', owner), /unavailable/);
  native.terminalOwners.delete('source');
  assert.ok(accepted(), 'closing the source must not revoke the file tab');
  url = 'file:///another';
  assert.equal(accepted(), false);
  url = 'file:///app';
  destroyed = true;
  assert.equal(accepted(), false);
  destroyed = false;
  resolve({ sessionId: 'files' });
  await pending;
  assert.equal(native.pendingConnections.size, 0);
  assert.equal(native.terminalOwners.get('files'), owner);
  native.terminalOwners.set('source', owner);
  const failed = native.shareSftp('source', 'failure', owner);
  aliases.delete('failure');
  reject(Error('failed'));
  await assert.rejects(failed, /failed/);
  assert.equal(native.terminalOwners.has('failure'), false);
  const replaced = native.shareSftp('source', 'replacement', owner);
  const newOwner = {};
  native.pendingConnections.set('replacement', 999);
  native.terminalOwners.set('replacement', newOwner);
  aliases.delete('replacement');
  reject(Error('cancelled'));
  await assert.rejects(replaced);
  assert.equal(native.terminalOwners.get('replacement'), newOwner);
  assert.equal(native.pendingConnections.get('replacement'), 999);
  aliases.delete('source');
  await assert.rejects(native.shareSftp('source', 'not-native', owner), /unavailable/);
  vaultBackend.unlockedWorkspaceId = '';
  const calls: any[] = [];
  native.sharedRoutes = { attach: (...args: any[]) => calls.push(args) };
  native.write = (command: unknown) => calls.push(command);
  native.waitForConnection = (_id: string, start: () => void) => {
    start();
    return Promise.resolve();
  };
  await native.shareSftp('source', 'legacy');
  assert.equal(calls[1].source_session_id, 'source');
  native.waitForConnection = () => Promise.reject(Error('legacy failure'));
  native.releaseTunnel = (id: string) => calls.push(id);
  await assert.rejects(native.shareSftp('source', 'legacy-failure'), /legacy failure/);
  assert.equal(calls.at(-1), 'legacy-failure');
  const coverage = await inspector.post('Profiler.takePreciseCoverage');
  await inspector.post('Profiler.stopPreciseCoverage');
  const blocks = coverage.result
    .filter((entry) => entry.url === filename)
    .flatMap((entry) => entry.functions.flatMap((fn) => fn.ranges));
  assert.ok(blocks.length > 0);
  const percent = (100 * blocks.filter((block) => block.count > 0).length) / blocks.length;
  t.diagnostic(`shared SFTP main wiring: ${percent.toFixed(2)}% V8 blocks`);
  assert.ok(percent >= coverageThreshold);
});

test('retired vault file tabs can close without granting file access or editor startup', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const ownerCheck = source.slice(
    source.indexOf('  assertSftpOwner('),
    source.indexOf('  private readonly sharedRoutes'),
  );
  const preflight = source.slice(
    source.indexOf('  private editCloseTargets('),
    source.indexOf('  async finishEditClose('),
  );
  const vaultBackend = { unlockedWorkspaceId: 'vault' };
  const Native = runInNewContext(
    stripTypeScriptTypes(`class Native { ${ownerCheck} ${preflight} }; Native`),
    {
      vaultBackend,
      isTrustedVaultSender: (event: any) => event.trusted,
    },
  );
  const native = new Native(),
    owner = {},
    event = { sender: owner, trusted: true };
  native.sealed = { has: (id: string) => id === 'live', connectedSessionIds: () => ['live'] };
  native.terminalOwners = new Map([['live', owner]]);
  native.assertSftpOwner(event, 'retired', true);
  assert.throws(() => native.assertSftpOwner(event, 'retired'), /owner/);
  assert.throws(() => native.assertSftpOwner({ sender: {}, trusted: true }, 'live', true), /owner/);
  assert.throws(
    () => native.assertSftpOwner({ ...event, trusted: false }, 'retired', true),
    /owner/,
  );
  native.child = { killed: false };
  native.edit = (id: string) => {
    if (id === 'live') return { edits: [] };
    throw Error('legacy editor entered');
  };
  assert.equal(await native.prepareEditClose('live'), true);
  assert.equal(await native.prepareEditClose('retired'), true);
  const closeSource = source.slice(
    source.indexOf("ipcMain.handle('ssh:close'"),
    source.indexOf("ipcMain.handle('serial:open'"),
  );
  let close!: (event: unknown, id: string) => Promise<void>,
    closed = 0;
  native.close = () => {
    closed++;
  };
  runInNewContext(stripTypeScriptTypes(closeSource), {
    ipcMain: {
      handle: (_name: string, handler: typeof close) => {
        close = handler;
      },
    },
    isSshSessionId: () => true,
    sshBackend: native,
    vaultSshIpc: { handles: () => false },
  });
  await assert.rejects(close({ sender: {}, trusted: true }, 'live'), /owner/);
  await close(event, 'live');
  await close(event, 'retired');
  await assert.rejects(close({ ...event, trusted: false }, 'retired'), /owner/);
  assert.equal(closed, 2);
  vaultBackend.unlockedWorkspaceId = '';
  assert.equal(await native.prepareEditClose('live'), true);
  await assert.rejects(native.prepareEditClose('retired'), /legacy editor entered/);
});

test('application editor requests correlate sessions, retire waiters and scope close preflight', async (t) => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const selected = source.slice(
    source.indexOf('  private readonly editWaiters'),
    source.indexOf('  private child:', source.indexOf('  private readonly editWaiters')),
  );
  const handler = source.slice(
    source.indexOf('  private handleLine(line: string): void {'),
    source.indexOf('  private broadcast(event: SshBackendEvent)'),
  );
  const script = stripTypeScriptTypes(`class Native { ${selected} ${handler} }; Native`);
  const filename = 'vault-sftp-main-edit.js';
  const inspector = new Session();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  const vaultBackend = { unlockedWorkspaceId: 'vault' };
  const timers = new Set<() => void>(),
    messages: any[] = [],
    sent: any[] = [];
  const owner = {},
    other = {},
    parent = {};
  let answer = 1,
    parentAvailable = true;
  const Native = runInNewContext(
    script,
    {
      vaultBackend,
      randomUUID,
      Set,
      Map,
      setTimeout: (fn: () => void) => {
        timers.add(fn);
        return fn;
      },
      clearTimeout: (fn: () => void) => timers.delete(fn),
      parseMcpBackendMessage: () => undefined,
      parseSshBackendEvent: JSON.parse,
      BrowserWindow: {
        fromWebContents: () => (parentAvailable ? parent : undefined),
        getFocusedWindow: () => undefined,
        getAllWindows: () => [],
      },
      showCoordinatedMessageBox: async (p: any, message: any) => {
        assert.equal(p, parent);
        messages.push(message);
        return { response: answer };
      },
      windowCloseCoordinators: new Map(),
    },
    { filename },
  );
  const native = new Native();
  native.terminalAdmissions = new Map();
  native.protectedMembers = new Map();
  native.sealed = {
    has: (id: string) => ['one', 'two'].includes(id),
    connectedSessionIds: () => ['one', 'two'],
  };
  native.terminalOwners = new Map([
    ['one', owner],
    ['two', other],
  ]);
  native.ensureStarted = () => {
    if (vaultBackend.unlockedWorkspaceId) throw Error('no legacy');
  };
  native.write = (q: any) => sent.push(q);
  native.broadcast = () => {};
  native.openWaiters = new Map();
  native.activeSessions = new Set();
  native.retainedMismatchSessions = new Set();
  native.terminalDelivery = { remove: () => {} };
  native.releaseTunnel = () => Promise.resolve();
  const p = native.edit('one', { operation: 'list' });
  const q = sent.at(-1);
  native.handleLine(
    JSON.stringify({ type: 'sftp.edit', sessionId: 'two', requestId: q.request_id, edits: [] }),
  );
  assert.equal(native.editWaiters.size, 1);
  native.handleLine(
    JSON.stringify({ type: 'sftp.edit', sessionId: 'one', requestId: q.request_id, edits: [] }),
  );
  await p;
  assert.equal(timers.size, 0);
  const closed = native.edit('one', { operation: 'list' });
  native.handleLine(JSON.stringify({ type: 'closed', sessionId: 'other' }));
  assert.equal(native.editWaiters.size, 1);
  native.handleLine(JSON.stringify({ type: 'closed', sessionId: 'one' }));
  await assert.rejects(closed, /retained/);
  assert.equal(timers.size, 0);
  const expired = native.edit('two', { operation: 'list' });
  [...timers][0]();
  timers.clear();
  await assert.rejects(expired, /timed out/);
  native.write = () => {
    throw Error('stopped');
  };
  await assert.rejects(native.edit('two', { operation: 'list' }), /stopped/);
  await assert.rejects(native.edit('retired', { operation: 'list' }), /no legacy/);
  for (let i = 0; i < 128; i++) native.editWaiters.set(String(i), {});
  await assert.rejects(native.edit('two', { operation: 'list' }), /Too many/);
  native.editWaiters.clear();
  native.terminalOwners.set('one', owner);
  const calls: any[] = [];
  let failure = '',
    pending = true;
  native.edit = async (id: string, request: any) => {
    calls.push([id, request]);
    return {
      error: failure,
      edits: pending
        ? [
            { id: 'file', pending: true, recovered: false },
            { id: 'old', pending: true, recovered: true },
          ]
        : [],
    };
  };
  assert.equal(await native.prepareEditClose('sftp-recovery', owner), true);
  assert.deepEqual(
    calls.map((c) => c[0]),
    ['one'],
  );
  assert.match(messages[0].message, /1 edited/);
  calls.length = 0;
  await native.finishEditClose();
  assert.deepEqual(
    calls.map((c) => c[0]),
    ['one', 'two'],
  );
  answer = 0;
  assert.equal(await native.prepareEditClose('one'), false);
  parentAvailable = false;
  assert.equal(await native.prepareEditClose('one'), false);
  pending = false;
  assert.equal(await native.prepareEditClose('one'), true);
  failure = 'native failed';
  await assert.rejects(native.prepareEditClose('one'), /native failed/);
  await assert.rejects(native.finishEditClose('two'), /native failed/);
  assert.equal(await native.prepareEditClose('retired'), true);
  vaultBackend.unlockedWorkspaceId = '';
  native.child = { killed: false };
  failure = '';
  assert.equal(await native.prepareEditClose('legacy'), true);
  await native.finishEditClose('legacy');
  native.child.killed = true;
  assert.equal(await native.prepareEditClose('legacy'), true);
  const coverage = await inspector.post('Profiler.takePreciseCoverage');
  await inspector.post('Profiler.stopPreciseCoverage');
  const cutoff = script.indexOf('    handleLine(');
  const blocks = coverage.result
    .filter((e) => e.url === filename)
    .flatMap((e) => e.functions.flatMap((f) => f.ranges))
    .filter((b) => b.endOffset <= cutoff);
  const percent = (100 * blocks.filter((b) => b.count > 0).length) / blocks.length;
  assert.ok(blocks.length > 10);
  t.diagnostic(`main editor request/preflight coverage ${percent.toFixed(1)}% V8 blocks`);
  assert.ok(percent >= 80);
});
