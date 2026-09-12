import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');

// scripts/test-coverage.ts excludes process entrypoints and TSX from loaded-module coverage.
// Execute their production handlers here; mcp-approval-ui.test.ts also mounts the real UI in Electron.

function extract(source: string, start: string, end: string) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `Missing production block: ${start}`);
  return source.slice(startIndex, endIndex);
}

const parser = runInNewContext(
  stripTypeScriptTypes(
    [
      'const sshMaxSessionIdLength = 128;',
      extract(main, 'function isRecord(', '\n}').concat('\n}'),
      extract(main, 'function isSshSessionId(', 'function isUuid('),
      extract(main, 'function isMcpRequestId(', 'type TunnelBrowserEvent'),
      'parseMcpBackendMessage;',
    ].join('\n'),
  ),
) as (line: string) => Record<string, unknown> | undefined;

const modes = ['full-access', 'always-ask', 'first-access'] as const;
const sessionApproval = {
  type: 'mcp.approval',
  request_id: 'request',
  session_id: 'session',
  host: 'host.example',
  port: 22,
  username: 'user',
  title: 'Shell',
  tool: 'read_terminal',
};
const openApproval = {
  ...sessionApproval,
  approval_kind: 'open_connection',
  tool: 'open_connection',
  connection_id: 'session',
  protocol: 'ssh',
};

test('MCP validates modes and allows automatic dispatch only for a validated connection open', () => {
  for (const mode of modes) {
    const message = parser(JSON.stringify({ ...openApproval, approval_mode: mode }));
    assert.equal(message?.approvalMode, mode);
    assert.equal(message?.approvalKind, 'open_connection');
    const response = parser(
      JSON.stringify({
        type: 'mcp.response',
        request_id: 'status',
        mcp_status: {
          enabled: true,
          running: true,
          port: 8765,
          endpoint: 'http://127.0.0.1:8765/mcp',
          approvalMode: mode,
        },
      }),
    );
    assert.equal((response?.status as Record<string, unknown> | undefined)?.approvalMode, mode);
  }
  for (const mode of ['always-ask', 'first-access']) {
    assert.equal(
      parser(JSON.stringify({ ...sessionApproval, approval_mode: mode }))?.approvalMode,
      mode,
    );
  }
  assert.equal(parser(JSON.stringify(sessionApproval))?.approvalMode, 'first-access');
  for (const mode of [null, false, '', 'automatic', 1, {}, []]) {
    assert.equal(parser(JSON.stringify({ ...openApproval, approval_mode: mode })), undefined);
  }
  assert.equal(
    parser(JSON.stringify({ ...sessionApproval, approval_mode: 'full-access' })),
    undefined,
  );
  for (const tool of ['list_sessions', 'list_connections']) {
    const inventory = {
      type: 'mcp.approval',
      request_id: 'request',
      session_id: 'mcp-inventory',
      title: 'Wormhole workspace',
      tool,
      approval_kind: 'tool',
      approval_mode: 'always-ask',
    };
    assert.equal(parser(JSON.stringify(inventory))?.approvalKind, 'tool');
    assert.equal(parser(JSON.stringify({ ...inventory, approval_mode: 'full-access' })), undefined);
    assert.equal(
      parser(JSON.stringify({ ...inventory, approval_mode: 'first-access' })),
      undefined,
    );
    assert.equal(parser(JSON.stringify({ ...inventory, tool: 'run_command' })), undefined);
  }
  for (const override of [
    { connection_id: 'different' },
    { protocol: 'invalid' },
    { path: 2 },
    { host: 'x'.repeat(4097) },
  ]) {
    assert.equal(
      parser(JSON.stringify({ ...openApproval, approval_mode: 'full-access', ...override })),
      undefined,
    );
  }
});

test('MCP setting IPC validates before forwarding and preserves workspace authorization', async () => {
  const calls: string[] = [];
  const handlers = new Map<string, (event: unknown, value: unknown) => Promise<unknown>>();
  let authorized = true;
  runInNewContext(
    stripTypeScriptTypes(
      [
        extract(main, 'function isMcpApprovalMode(', 'function parseMcpBackendMessage('),
        extract(
          main,
          "ipcMain.handle('mcp:set-approval-mode'",
          "ipcMain.handle('mcp:regenerate-token'",
        ),
      ].join('\n'),
    ),
    {
      ipcMain: {
        handle: (name: string, handler: (event: unknown, value: unknown) => Promise<unknown>) =>
          handlers.set(name, handler),
      },
      serializeAuthOperation: (operation: () => Promise<unknown>) => operation(),
      requireWorkspaceAuth: async () => {
        calls.push('authorize');
        if (!authorized) throw Error('locked');
      },
      sshBackend: {
        setMcpApprovalMode: async (mode: string) => {
          calls.push(mode);
          return { approvalMode: mode };
        },
      },
    },
  );
  const handle = handlers.get('mcp:set-approval-mode')!;
  for (const mode of modes) await handle(null, mode);
  assert.deepEqual(
    calls,
    modes.flatMap((mode) => ['authorize', mode]),
  );
  calls.length = 0;
  await assert.rejects(handle(null, 'invalid'), /invalid/);
  assert.deepEqual(calls, []);
  authorized = false;
  await assert.rejects(handle(null, 'full-access'), /locked/);
  assert.deepEqual(calls, ['authorize']);
});

test('MCP approval acknowledgements cannot authorize an open across a workspace lock', async () => {
  for (const outcome of ['approved', 'locked', 'reunlocked', 'rejected']) {
    const authSession = { isAccessAllowed: true, authorizationEpoch: 1 };
    const finished: string[] = [];
    const handlers = new Map<string, (event: unknown, value: unknown) => Promise<unknown>>();
    const entered = Promise.withResolvers<void>();
    const reply = Promise.withResolvers<void>();
    runInNewContext(
      stripTypeScriptTypes(
        [
          extract(main, 'function isRecord(', '\n}').concat('\n}'),
          extract(main, 'function parseMcpApproval(', 'function registerIpcHandlers('),
          extract(
            main,
            'function isAuthorizationEpochCurrent(',
            'async function clearBitwardenSessionAfterAuthorizationLoss(',
          ),
          extract(
            main,
            "ipcMain.handle('mcp:approval'",
            "ipcMain.handle('workspace:update-node-web-settings'",
          ),
        ].join('\n'),
      ),
      {
        authSession,
        ipcMain: {
          handle: (name: string, handler: (event: unknown, value: unknown) => Promise<unknown>) =>
            handlers.set(name, handler),
        },
        serializeAuthOperation: (operation: () => Promise<unknown>) => operation(),
        requireWorkspaceAuth: async () => {},
        sshBackend: {
          respondMcpApproval: async () => {
            entered.resolve();
            await reply.promise;
          },
        },
        mcpApprovalWindowCoordinator: { finishApproval: (id: string) => finished.push(id) },
      },
    );
    const pending = handlers.get('mcp:approval')!(null, { requestId: 'open', approved: true });
    await entered.promise;
    if (outcome === 'locked' || outcome === 'reunlocked') {
      authSession.isAccessAllowed = outcome === 'reunlocked';
      authSession.authorizationEpoch++;
    }
    if (outcome === 'rejected') reply.reject(Error('Request cancelled'));
    else reply.resolve();
    if (outcome === 'approved') await pending;
    else await assert.rejects(pending, outcome === 'rejected' ? /cancelled/ : /Authentication/);
    assert.deepEqual(finished, ['open']);
  }
});

test('MCP renderer queues every manual action and opens full-access requests without a popup', () => {
  const pending: Array<Record<string, unknown>> = [];
  const automaticallyOpened: unknown[] = [];
  let listener: (event: Record<string, unknown>) => void = () => {};
  runInNewContext(
    stripTypeScriptTypes(extract(app, 'const unsubscribeMcp =', 'const unsubscribeBackend =')),
    {
      window: {
        wormhole: {
          onMcpApproval: (callback: typeof listener) => {
            listener = callback;
          },
        },
      },
      settleAuthConfirmation: () => {},
      openAuthorizedMcpConnection: (event: unknown) => automaticallyOpened.push(event),
      setMcpApprovals: (update: (current: typeof pending) => typeof pending) => {
        const next = update(pending);
        pending.splice(0, pending.length, ...next);
      },
    },
  );
  const manual = {
    type: 'mcp.approval',
    requestId: 'one',
    approvalKind: 'session_control',
    approvalMode: 'always-ask',
  };
  listener(manual);
  listener(manual);
  listener({ ...manual, requestId: 'two' });
  assert.equal(pending.length, 2);
  const automatic = {
    ...manual,
    requestId: 'three',
    approvalKind: 'open_connection',
    approvalMode: 'full-access',
  };
  listener(automatic);
  assert.deepEqual(automaticallyOpened, [automatic]);
  assert.equal(pending.length, 2);
  listener({ type: 'mcp.approval-cancelled', requestId: 'one' });
  assert.equal(pending.length, 1);
  assert.equal(pending[0].requestId, 'two');
});

test('Electron routes automatic opens to one main window without presenting an approval', async () => {
  const sent: unknown[] = [];
  const presentations: string[] = [];
  const windows = [0, 1].map((index) => ({
    isDestroyed: () => false,
    webContents: {
      send: (channel: string, message: unknown) => sent.push([index, channel, message]),
    },
  }));
  const authSession = { isAccessAllowed: true };
  const handle = runInNewContext(
    stripTypeScriptTypes(`
    (function(mcpMessage) {
      ${extract(main, "if (mcpMessage?.type === 'mcp.approval')", 'const event = parseSshBackendEvent(line);')}
    })
  `),
    {
      authSession,
      BrowserWindow: { getAllWindows: () => windows, getFocusedWindow: () => windows[1] },
      windowCloseCoordinators: new Set(windows),
      selectMcpApprovalWindow: (_windows: unknown, focused: unknown) => focused,
      bringMcpApprovalWindowToFront: () => presentations.push('foreground'),
      webSurfaces: { closeBitwardenFloatingWindows: () => presentations.push('close-floating') },
      mcpApprovalWindowCoordinator: {
        beginApproval: async () => {
          presentations.push('approval');
        },
        presentApprovalWhenNativeDialogsClose: (_id: string, present: () => void) => present(),
      },
    },
  ) as (message: unknown) => void;
  const automatic = parser(JSON.stringify({ ...openApproval, approval_mode: 'full-access' }));
  handle(automatic);
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0], [1, 'mcp:approval', automatic]);
  assert.deepEqual(presentations, []);
  sent.length = 0;
  handle(parser(JSON.stringify({ ...sessionApproval, approval_mode: 'always-ask' })));
  await Promise.resolve();
  assert.equal(sent.length, 2);
  assert.deepEqual(presentations, ['approval', 'close-floating', 'foreground']);
  sent.length = 0;
  authSession.isAccessAllowed = false;
  handle(automatic);
  assert.equal(sent.length, 0);
});

test('full-access opening waits for backend validation and refuses changed or rejected targets', async () => {
  for (const outcome of ['valid', 'changed', 'rejected']) {
    const calls: unknown[] = [];
    const connection = {
      id: 'saved',
      kind: 'connection',
      persisted: true,
      protocol: 'ssh',
      name: outcome === 'changed' ? 'Changed' : 'Shell',
    };
    const approval = {
      requestId: 'open',
      approvalKind: 'open_connection',
      approvalMode: 'full-access',
      connectionId: 'saved',
      title: 'Shell',
      protocol: 'ssh',
    };
    let finish: (() => void) | undefined;
    const waiting = new Promise<void>((resolve) => {
      finish = resolve;
    });
    const resolveApproval = runInNewContext(
      stripTypeScriptTypes(
        [
          extract(app, 'function matchesMcpOpenConnectionApproval(', 'function containsTreeNode('),
          extract(app, 'async function resolveMcpApproval(', 'const openAuthorizedMcpConnection ='),
          'resolveMcpApproval;',
        ].join('\n'),
      ),
      {
        mcpApprovals: [],
        tree: [],
        findTreeNode: () => connection,
        window: {
          wormhole: {
            respondMcpApproval: async (id: string, approved: boolean) => {
              calls.push([id, approved]);
              await waiting;
              if (outcome === 'rejected') throw Error('Request is no longer pending');
            },
          },
        },
        openConnection: (node: unknown) => calls.push(node),
        setMcpApprovals: () => {},
      },
    ) as (approved: boolean, event: unknown) => Promise<void>;
    const result = resolveApproval(true, approval);
    assert.deepEqual(calls, [['open', outcome !== 'changed']]);
    finish!();
    await result;
    assert.equal(calls.length, outcome === 'valid' ? 2 : 1);
    if (outcome === 'valid') assert.equal(calls[1], connection);
  }
});

test('approval mode UI saves successful choices and retains the previous selection on failure', async () => {
  for (const outcome of ['success', 'failure', 'busy', 'unchanged']) {
    const state = { approvalMode: 'first-access' };
    const saved: unknown[] = [];
    const busy: boolean[] = [];
    const errors: string[] = [];
    const handler = runInNewContext(
      stripTypeScriptTypes(
        [
          extract(app, 'async function handleMcpApprovalMode(', 'async function revealMcpToken('),
          'handleMcpApprovalMode;',
        ].join('\n'),
      ),
      {
        mcpBusy: outcome === 'busy',
        mcpState: state,
        window: {
          wormhole: {
            setMcpApprovalMode: async (approvalMode: string) => {
              if (outcome === 'failure') throw Error('Cannot save');
              return { approvalMode };
            },
          },
        },
        setMcpBusy: (value: boolean) => busy.push(value),
        setMcpError: (value: string) => errors.push(value),
        setMcpMessage: () => {},
        setMcpState: (value: unknown) => saved.push(value),
        authSettingsErrorMessage: (error: Error) => error.message,
      },
    ) as (mode: string) => Promise<void>;
    await handler(outcome === 'unchanged' ? 'first-access' : 'always-ask');
    assert.equal(saved.length, outcome === 'success' ? 1 : 0);
    assert.deepEqual(busy, outcome === 'busy' || outcome === 'unchanged' ? [] : [true, false]);
    if (outcome === 'failure') assert.equal(errors.at(-1), 'Cannot save');
  }
});

test('concurrent automatic opens reuse the new SSH tab before React has rendered it', () => {
  let sessions: Array<Record<string, unknown>> = [];
  const sessionsRef = { current: sessions };
  const started: unknown[] = [];
  const open = runInNewContext(
    stripTypeScriptTypes(
      [
        extract(app, 'function openConnection(', 'async function releaseSessionResources('),
        'openConnection;',
      ].join('\n'),
    ),
    {
      sessions: [],
      sessionsRef,
      webSessionOpenInFlight: { current: new Set() },
      setSelectedSessionId: () => {},
      setActivePage: () => {},
      newSessionToken: () => `backend-${started.length}`,
      savedConnectionAddressForEditor: (_protocol: string, host: string) => host,
      sessionResourceReleaseGate: { current: { reset: () => {} } },
      setSessions: (update: (current: typeof sessions) => typeof sessions) => {
        sessions = update(sessions);
      },
      startSshSession: (request: unknown) => started.push(request),
    },
  ) as (node: unknown) => void;
  const node = {
    id: 'saved',
    kind: 'connection',
    protocol: 'ssh',
    name: 'Shell',
    host: 'host.example',
    port: 22,
  };
  open(node);
  open(node);
  assert.equal(sessions.length, 1);
  assert.equal(started.length, 1);
  assert.equal(sessionsRef.current[0], sessions[0]);
});
