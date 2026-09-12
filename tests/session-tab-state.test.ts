import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import * as React from 'react';
import { transformWithOxc } from 'vite';
import {
  applySessionMcpAccess,
  canDisconnectSessionAiAgent,
  sessionTabPresentation,
} from '../src/session-tab-state.ts';

test('MCP access affects only the approved backend session and can be withdrawn', () => {
  const sessions = [
    { backendSessionId: 'one', protocol: 'ssh', status: 'connected' },
    { backendSessionId: 'two', protocol: 'ssh', status: 'connected' },
  ];
  const granted = applySessionMcpAccess(sessions, { sessionId: 'one', accessible: true });
  assert.equal(granted[0].mcpAccessible, true);
  assert.equal(granted[1], sessions[1]);
  assert.equal(sessionTabPresentation(sessions[0], true).aiAccessible, false);
  for (const active of [true, false]) {
    const view = sessionTabPresentation(granted[0], active);
    assert.equal(view.aiAccessible, true);
    assert.match(view.className, /bg-yellow-/);
    assert.match(view.className, /dark:bg-yellow-/);
    assert.match(view.accessLabel, /AI agent access via MCP/);
  }
  const revoked = applySessionMcpAccess(granted, { sessionId: 'one', accessible: false });
  for (const active of [true, false]) {
    assert.equal(sessionTabPresentation(revoked[0], active).aiAccessible, false);
    assert.doesNotMatch(sessionTabPresentation(revoked[0], active).className, /yellow/);
    assert.equal(sessionTabPresentation(revoked[0], active).accessLabel, '');
  }
  assert.deepEqual(
    applySessionMcpAccess(sessions, { sessionId: 'old', accessible: true }),
    sessions,
  );
});

test('disconnected and unsupported sessions never show AI access', () => {
  for (const status of ['connecting', 'failed', 'closed', 'placeholder']) {
    assert.equal(
      sessionTabPresentation({ protocol: 'ssh', status, mcpAccessible: true }, true).aiAccessible,
      false,
    );
  }
  for (const protocol of ['rdp', 'vnc', 'serial', 'http', 'https', 'future']) {
    assert.equal(
      sessionTabPresentation({ protocol, status: 'connected', mcpAccessible: true }, true)
        .aiAccessible,
      false,
    );
  }
});

test('Electron validates MCP access metadata before forwarding it', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const extract = (start: string, end: string) =>
    main.slice(main.indexOf(start), main.indexOf(end, main.indexOf(start)));
  // Use the production parser with the same plain-record and session-id validators.
  const parserSource = [
    'const sshMaxSessionIdLength = 128;',
    main.slice(
      main.indexOf('function isRecord('),
      main.indexOf('\n}', main.indexOf('function isRecord(')) + 2,
    ),
    extract('function isSshSessionId(', 'function isUuid('),
    extract('function parseSshBackendEvent(', 'function parseMcpBackendMessage('),
    'parseSshBackendEvent;',
  ].join('\n');
  const parse = runInNewContext(stripTypeScriptTypes(parserSource)) as (
    line: string,
  ) => { accessible: boolean; sessionId: string } | undefined;
  for (const accessible of [true, false]) {
    const parsed = parse(
      JSON.stringify({ type: 'mcp.access', session_id: 'session', mcp_accessible: accessible }),
    );
    assert.equal(parsed?.accessible, accessible);
    assert.equal(parsed?.sessionId, 'session');
  }
  for (const value of [null, 'true', 1, undefined]) {
    assert.equal(
      parse(JSON.stringify({ type: 'mcp.access', session_id: 'session', mcp_accessible: value })),
      undefined,
    );
  }
  for (const id of ['', ' leading', 'x'.repeat(129), 1]) {
    assert.equal(
      parse(JSON.stringify({ type: 'mcp.access', session_id: id, mcp_accessible: true })),
      undefined,
    );
  }
});

test('shared pane tabs render MCP presentation and new connections discard old grants', () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const tabs = app.slice(
    app.indexOf('{pane.tabs.map('),
    app.indexOf('{sessions.map((session) => {', app.indexOf('{pane.tabs.map(')),
  );
  assert.match(tabs, /sessionTabPresentation\(session, active\)/);
  assert.match(tabs, /tabPresentation\.className/);
  assert.match(tabs, /tabPresentation\.aiAccessible \? \([\s\S]*<Bot/);
  assert.match(tabs, /<ProtocolIcon protocol=\{session\.protocol\}/);
  assert.match(tabs, /aria-label=\{`[^`]*tabPresentation\.accessLabel/);
  assert.match(app, /applySessionMcpAccess\(current, event\)/);
  assert.match(tabs, /onDisconnectAiAgent=\{\(\) => onDisconnectAiAgent\(session.id\)\}/);
  assert.match(app, /onDisconnectAiAgent=\{disconnectSessionAiAgent\}/);
  const reconnect = app.slice(
    app.indexOf('function reconnectSession('),
    app.indexOf('function duplicateSession('),
  );
  assert.equal((reconnect.match(/mcpAccessible: false/g) ?? []).length, 3);
  const duplicate = app.slice(
    app.indexOf('function duplicateSession('),
    app.indexOf('function openFileTransfer('),
  );
  assert.match(duplicate, /mcpAccessible: false/);
  const quickConnect = app.slice(
    app.indexOf('function startQuickSshSession('),
    app.indexOf('\n  function ', app.indexOf('function startQuickSshSession(') + 1),
  );
  assert.match(quickConnect, /backendSessionId,\s+mcpAccessible: false/);
  assert.match(app, /nodeId: editingId,\s+backendSessionId,\s+mcpAccessible: false/);
});

test('the tab menu disconnects the AI agent only for a live approved SSH session', async () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const source = app.slice(
    app.indexOf('function SessionTabContextMenu('),
    app.indexOf('const nodeTooltipDelayMs'),
  );
  const transformed = await transformWithOxc(source, 'session-menu.tsx', {
    jsx: { runtime: 'classic' },
  });
  type Element = React.ReactElement<{ children?: React.ReactNode; onSelect?: () => void }>;
  const menu = runInNewContext(`${transformed.code}\nSessionTabContextMenu;`, {
    React,
    canDisconnectSessionAiAgent,
    canDisconnectRemoteDesktopSession: () => false,
    canOpenRdpSystemClient: () => false,
    ...Object.fromEntries(
      [
        'ContextMenu',
        'ContextMenuTrigger',
        'ContextMenuContent',
        'ContextMenuItem',
        'ContextMenuSeparator',
        'Copy',
        'RefreshCcw',
        'Maximize2',
        'Power',
        'Bot',
        'Monitor',
        'FolderOpen',
        'X',
      ].map((name) => [name, name]),
    ),
  }) as (props: Record<string, unknown>) => Element;
  const items = (element: Element): Element[] => [
    ...(element.type === 'ContextMenuItem' ? [element] : []),
    ...React.Children.toArray(element.props.children).flatMap((child) =>
      React.isValidElement(child) ? items(child as Element) : [],
    ),
  ];
  const connected = {
    backendSessionId: 'backend',
    protocol: 'ssh',
    status: 'connected',
    mcpAccessible: true,
  };
  const cases = [
    connected,
    ...[false, undefined].map((mcpAccessible) => ({ ...connected, mcpAccessible })),
    ...['', undefined].map((backendSessionId) => ({ ...connected, backendSessionId })),
    ...['connecting', 'closed', 'failed', 'placeholder'].map((status) => ({
      ...connected,
      status,
    })),
    ...['rdp', 'vnc', 'serial', 'http', 'https', 'future'].map((protocol) => ({
      ...connected,
      protocol,
    })),
  ];
  let disconnections = 0;
  for (const session of cases) {
    const tree = menu({
      session,
      children: React.createElement('button', null, 'Tab'),
      onDisconnectAiAgent: () => {
        disconnections++;
      },
    });
    const action = items(tree).find((item) =>
      React.Children.toArray(item.props.children).includes('Disconnect AI Agent'),
    );
    assert.equal(Boolean(action), session === connected);
    action?.props.onSelect?.();
  }
  assert.equal(disconnections, 1);
});

test('AI disconnect targets the current backend session and waits for authoritative access events', async () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const source = app.slice(
    app.indexOf('async function disconnectSessionAiAgent('),
    app.indexOf('async function disconnectRemoteDesktopSession('),
  );
  const connected = {
    id: 'tab',
    backendSessionId: 'backend',
    protocol: 'ssh',
    status: 'connected',
    mcpAccessible: true,
  };
  type Session = typeof connected & { mcpAccessError?: string };
  const other: Session = { ...connected, id: 'other', backendSessionId: 'other-backend' };
  const sessionsRef = { current: [connected, other] as Session[] };
  const calls: string[] = [];
  const window: { wormhole?: { revokeMcpSessionAccess: (id: string) => Promise<void> } } = {
    wormhole: {
      revokeMcpSessionAccess: async (id) => {
        calls.push(id);
      },
    },
  };
  const disconnect = runInNewContext(`${stripTypeScriptTypes(source)}\ndisconnectSessionAiAgent;`, {
    window,
    sessionsRef,
    canDisconnectSessionAiAgent,
    setSessions: (update: (sessions: Session[]) => Session[]) => {
      sessionsRef.current = update(sessionsRef.current);
    },
  }) as (id: string) => Promise<void>;
  await disconnect('missing');
  assert.deepEqual(calls, []);
  await disconnect('tab');
  assert.deepEqual(calls, ['backend']);
  assert.equal(sessionsRef.current[0], connected, 'only access events update the grant');
  assert.equal(sessionsRef.current[1], other);

  sessionsRef.current = applySessionMcpAccess(sessionsRef.current, {
    sessionId: 'backend',
    accessible: false,
  });
  await disconnect('tab');
  assert.deepEqual(calls, ['backend'], 'a stale menu cannot revoke an unapproved session');
  sessionsRef.current = [connected, other];
  window.wormhole = undefined;
  await disconnect('tab');
  assert.equal(
    sessionsRef.current[0].mcpAccessError,
    'Could not disconnect the AI agent. Try again.',
  );
  assert.equal(sessionsRef.current[0].mcpAccessible, true);
  assert.equal(sessionsRef.current[0].status, 'connected');
  assert.equal(sessionsRef.current[1], other);
  const refreshed = applySessionMcpAccess(sessionsRef.current, {
    sessionId: 'backend',
    accessible: false,
  });
  assert.equal(refreshed[0].mcpAccessError, undefined, 'access events clear old action errors');
  assert.match(app, /session\.mcpAccessible && session\.mcpAccessError[\s\S]*?role="alert"/);

  window.wormhole = {
    revokeMcpSessionAccess: async () => {
      sessionsRef.current = [{ ...connected, backendSessionId: 'reconnected' }, other];
      throw new Error('backend failure');
    },
  };
  await disconnect('tab');
  assert.equal(
    sessionsRef.current[0].mcpAccessError,
    undefined,
    'late errors do not affect a new session',
  );
});

test('AI disconnect crosses the preload and authenticated IPC bridge with a validated session id', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const extract = (text: string, start: string, end: string) =>
    text.slice(text.indexOf(start), text.indexOf(end, text.indexOf(start)));
  const commands: Record<string, unknown>[] = [];
  let authorized = true;
  let authChecks = 0;
  const handlers = new Map<string, (_event: unknown, value: unknown) => Promise<void>>();
  const code = [
    'const sshMaxSessionIdLength = 128;',
    extract(main, 'function isSshSessionId(', 'function isUuid('),
    'const sshBackend = {',
    extract(main, 'async revokeMcpSessionAccess(', 'async setMcpLocked(').trim() + ',',
    'sendMcpControl: async (command) => send(command) };',
    extract(
      main,
      "ipcMain.handle('mcp:revoke-session'",
      "ipcMain.handle('workspace:update-node-web-settings'",
    ),
    'const bridge = {',
    extract(preload, 'revokeMcpSessionAccess:', 'onMcpApproval:'),
    '}; bridge.revokeMcpSessionAccess;',
  ].join('\n');
  const revoke = runInNewContext(stripTypeScriptTypes(code), {
    send: (command: Record<string, unknown>) => {
      commands.push(command);
    },
    serializeAuthOperation: async (action: () => Promise<void>) => action(),
    requireWorkspaceAuth: async () => {
      authChecks++;
      if (!authorized) throw new Error('locked');
    },
    ipcMain: {
      handle: (name: string, callback: (_event: unknown, value: unknown) => Promise<void>) => {
        handlers.set(name, callback);
      },
    },
    ipcRenderer: { invoke: (name: string, value: unknown) => handlers.get(name)!(null, value) },
  }) as (value: unknown) => Promise<void>;
  for (const id of ['', ' leading', 'trailing ', 'x'.repeat(129), null, 1, {}]) {
    await assert.rejects(revoke(id), /session id is invalid/);
  }
  assert.equal(authChecks, 0);
  assert.equal(commands.length, 0);
  authorized = false;
  await assert.rejects(revoke('backend'), /locked/);
  assert.equal(commands.length, 0);
  authorized = true;
  await revoke('backend');
  assert.equal(commands.length, 1);
  assert.equal(commands[0].type, 'mcp.revoke-session');
  assert.equal(commands[0].session_id, 'backend');
});
