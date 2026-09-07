import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { applySessionMcpAccess, sessionTabPresentation } from '../src/session-tab-state.ts';

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
