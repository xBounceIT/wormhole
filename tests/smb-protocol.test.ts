import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Session } from 'node:inspector/promises';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import * as React from 'react';
import * as icons from 'lucide-react';
import { transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { SftpConnectionIcon } from '../src/components/SftpConnectionIcon.ts';
import { fileSessionMode, isFileBrowserProtocol } from '../src/file-protocol.ts';
import {
  connectionProtocolForType,
  connectionTypeForProtocol,
  connectionProtocolSupportsTunnel,
  quickConnectStartsImmediately,
  quickConnectTunnelId,
} from '../src/quick-connect-state.ts';
import {
  connectionInlinePasswordAction,
  credentialCanUseProtocol,
  isCredentialProtocol,
} from '../src/credential-state.ts';
import { sshOpenCredentialFields } from '../electron/ssh-open-credentials.ts';
import { sshCredentialPromptTarget } from '../src/runtime-credential-errors.ts';

const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8').replace(
  /\r\n/g,
  '\n',
);
const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
function between(source: string, start: string, end: string) {
  const offset = source.indexOf(start);
  const limit = source.indexOf(end, offset);
  assert.ok(offset >= 0 && limit > offset);
  return source.slice(offset, limit);
}

test('connected events accept omitted SMB fingerprints, validate metadata and use the network folder icon', async (context) => {
  // Measure the changed event arm and icon in the process entrypoints directly,
  // following the repository's V8 handler coverage gate. Node owns the profiler
  // during the aggregate coverage run.
  const profiler = new Session();
  const measure =
    !process.execArgv.includes('--experimental-test-coverage') && !process.env.NODE_V8_COVERAGE;
  if (measure) {
    profiler.connect();
    context.after(() => profiler.disconnect());
    await profiler.post('Profiler.enable');
    await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  }
  const connectedArm = between(
    main,
    "  if (\n    value.type === 'connected'",
    "  if (value.type === 'terminal-output')",
  );
  const icon = between(app, 'function ProtocolIcon(', 'function protocolTone(');
  const transformed = await transformWithOxc(icon, 'smb-icons.tsx', {
    jsx: { runtime: 'classic' },
  });
  const { parseConnected, ProtocolIcon } = runInNewContext(
    `${stripTypeScriptTypes(`function parseConnected(value) { ${connectedArm} }`)}\n${transformed.code}\n({ parseConnected, ProtocolIcon });`,
    { React, ...icons, SftpConnectionIcon },
    { filename: 'wormhole-smb-contract.js' },
  );
  const wire = {
    type: 'connected',
    session_id: 'smb',
    host: 'smb://nas/share',
    port: 445,
    username: 'user',
  };
  for (const fingerprint of [undefined, '', 'SHA256:server-key']) {
    const event = parseConnected({ ...wire, fingerprint });
    assert.equal(event.sessionId, 'smb');
    assert.equal(event.host, wire.host);
    assert.equal(event.port, 445);
    assert.equal(event.username, 'user');
    assert.equal(event.fingerprint, fingerprint ?? '');
  }
  for (const invalid of [
    { type: 'other' },
    { host: undefined },
    { host: 1 },
    { port: '445' },
    { port: 0 },
    { port: 65536 },
    { port: 1.5 },
    { username: undefined },
    { username: 1 },
    ...[null, false, 1, {}, []].map((fingerprint) => ({ fingerprint })),
  ])
    assert.equal(parseConnected({ ...wire, ...invalid }), undefined, JSON.stringify(invalid));
  for (const port of [1, 65535]) assert.equal(parseConnected({ ...wire, port }).port, port);

  for (const [protocol, expected] of [
    ['smb', SftpConnectionIcon],
    ['sftp', SftpConnectionIcon],
    ['ssh', icons.Terminal],
    ['rdp', icons.Monitor],
    ['http', icons.Globe],
    ['https', icons.Globe],
    ['vnc', icons.Monitor],
    ['serial', icons.Radio],
  ] as const) {
    for (const size of [undefined, 19]) {
      const rendered = ProtocolIcon({ protocol, size });
      assert.equal(rendered.type, expected, protocol);
      assert.equal(rendered.props.size, size ?? 15);
    }
  }
  const tabs = between(app, '{pane.tabs.map(', '{sessions.map((session) => {');
  assert.match(tabs, /<ProtocolIcon protocol=\{session\.protocol\}/);

  if (measure) {
    const coverage = await profiler.post('Profiler.takePreciseCoverage');
    await profiler.post('Profiler.stopPreciseCoverage');
    const script = coverage.result.find((item) => item.url === 'wormhole-smb-contract.js');
    assert.ok(script);
    for (const name of ['parseConnected', 'ProtocolIcon']) {
      const fn = script.functions.find((item) => item.functionName === name);
      assert.ok(fn);
      const percent =
        (100 * fn.ranges.filter((range) => range.count > 0).length) / fn.ranges.length;
      context.diagnostic(`${name}: V8 block coverage ${percent.toFixed(2)}%`);
      assert.ok(percent >= coverageThreshold);
    }
  }
});

test('an SMB wire connection settles the open request and starts the file browser while retaining its VPN', () => {
  const parser = runInNewContext(
    stripTypeScriptTypes(
      [
        'const sshMaxSessionIdLength = 128;',
        between(main, 'function isRecord(', '\nfunction '),
        between(main, 'function isSshSessionId(', 'function isUuid('),
        between(main, 'function parseSshBackendEvent(', 'function parseMcpBackendMessage('),
        'parseSshBackendEvent;',
      ].join('\n'),
    ),
  );
  let listener: (event: unknown) => void = () => {
    throw new Error('missing listener');
  };
  const sessionsRef = {
    current: [
      {
        id: 'files',
        backendSessionId: 'smb',
        protocol: 'smb',
        status: 'connecting',
        tunnelProgress: { phase: 'connected' },
      },
      {
        id: 'other',
        backendSessionId: 'other',
        protocol: 'ssh',
        status: 'connected',
        tunnelProgress: null,
      },
    ],
  };
  const other = sessionsRef.current[1];
  const initialized: string[] = [];
  const scheduled: (() => void)[] = [];
  runInNewContext(
    stripTypeScriptTypes(
      between(app, 'const unsubscribe = window.wormhole?.onSshEvent((event) => {', '\n    });') +
        '\n    });',
    ),
    {
      window: {
        wormhole: {
          onSshEvent: (callback: typeof listener) => {
            listener = callback;
          },
        },
        setTimeout: (callback: () => void) => {
          scheduled.push(callback);
        },
      },
      settlesSshHostKeyTrustAttempt: () => true,
      sshHostKeyTrustInFlight: { current: new Set(['smb']) },
      sessionsRef,
      isFileBrowserProtocol,
      initializeFileTransfer: (id: string) => {
        initialized.push(id);
      },
      setSessions: (
        update: (current: typeof sessionsRef.current) => typeof sessionsRef.current,
      ) => {
        sessionsRef.current = update(sessionsRef.current);
      },
    },
  );
  const body = between(
    main,
    '    const event = parseSshBackendEvent(line);',
    '  private broadcast(event: SshBackendEvent): void {',
  );
  const backend = runInNewContext(
    stripTypeScriptTypes(`new (class {
    terminalDelivery = { remove() {} };
    activeSessions = new Set(); retainedMismatchSessions = new Set();
    pendingConnections = new Map([['smb', 1]]); openWaiters = new Map();
    releases = [];
    releaseTunnel(id) { this.releases.push(id); return Promise.resolve(); }
    broadcast(event) { listener(event); }
    handleLine(line) { ${body}
  })()`),
    { parseSshBackendEvent: parser, listener, clearTimeout },
  );
  let settled = false;
  backend.openWaiters.set('smb', {
    resolve: () => {
      settled = true;
    },
  });
  // This is Go's actual json omitempty contract: SMB has no fingerprint field.
  backend.handleLine(
    JSON.stringify({
      type: 'connected',
      session_id: 'smb',
      host: 'nas/share',
      port: 445,
      username: 'user',
    }),
  );
  assert.equal(settled, true, 'the open request must resolve before its timeout');
  assert.equal(backend.openWaiters.size, 0);
  assert.equal(backend.pendingConnections.size, 0);
  assert.equal(backend.activeSessions.has('smb'), true);
  assert.equal(backend.releases.length, 0, 'a successful SMB connection retains its VPN lease');
  assert.equal(sessionsRef.current[0].status, 'connected');
  assert.equal(sessionsRef.current[0].tunnelProgress, null);
  assert.equal(sessionsRef.current[1], other);
  assert.equal(scheduled.length, 1);
  scheduled[0]();
  assert.deepEqual(initialized, ['files']);
});

test('SMB shares the internal file lifecycle and keeps its native transport mode', () => {
  for (const protocol of ['smb', 'sftp']) assert.equal(isFileBrowserProtocol(protocol), true);
  for (const protocol of ['ssh', 'rdp', 'serial', undefined, 'unknown'])
    assert.equal(isFileBrowserProtocol(protocol), false);
  assert.equal(fileSessionMode('smb'), 'smb');
  assert.equal(fileSessionMode('sftp'), 'sftp');
  assert.equal(fileSessionMode('ssh'), 'terminal');
  assert.equal(fileSessionMode(undefined), 'terminal');
  assert.equal(connectionTypeForProtocol('smb'), 'smb');
  assert.equal(connectionProtocolForType('smb', 'ssh'), 'smb');
  assert.equal(connectionProtocolSupportsTunnel('smb'), true);
  assert.equal(quickConnectTunnelId('smb', 'route'), 'route');
  assert.equal(quickConnectTunnelId('smb', 'off'), undefined);
  assert.equal(quickConnectStartsImmediately('smb', true, undefined), false);
  assert.equal(quickConnectStartsImmediately('smb', true, 'credential'), true);
  assert.equal(quickConnectStartsImmediately('smb', false, undefined), true);
});

test('SMB accepts password credentials, preserves inline secrets and requests replacement credentials on authentication failure', () => {
  assert.equal(isCredentialProtocol('smb'), true);
  assert.equal(credentialCanUseProtocol('password', 'smb'), true);
  assert.equal(credentialCanUseProtocol('sshKey', 'smb'), false);
  assert.equal(credentialCanUseProtocol('unsupported', 'smb'), false);
  assert.equal(connectionInlinePasswordAction(false, 'smb', 'secret', false, false), 'set');
  assert.equal(connectionInlinePasswordAction(false, 'smb', '', true, false), 'preserve');
  assert.equal(connectionInlinePasswordAction(false, 'smb', '', true, true), 'clear');
  assert.equal(connectionInlinePasswordAction(true, 'smb', 'secret', true, false), 'clear');
  assert.equal(
    sshCredentialPromptTarget(
      { nodeId: 'saved' },
      'SMB authentication or negotiation failed; check username and password',
    ),
    'saved',
  );
  assert.equal(
    sshCredentialPromptTarget(
      { credentialId: 'saved' },
      'SMB authentication or negotiation failed; check username and password',
    ),
    'quick',
  );
  assert.equal(
    sshCredentialPromptTarget({ nodeId: 'saved' }, 'could not connect to the SMB server'),
    null,
  );
  for (const message of [
    'the selected credential is not an SMB credential',
    'the selected credential is not an SSH credential',
  ]) {
    assert.equal(sshCredentialPromptTarget({ nodeId: 'saved' }, message), 'saved');
    assert.equal(sshCredentialPromptTarget({ credentialId: 'profile' }, message), 'quick');
    assert.equal(
      sshCredentialPromptTarget({ nodeId: 'saved', manualCredentials: true }, message),
      null,
    );
  }
});

test('SMB forwards a vault domain only through native one-shot credentials', () => {
  const vault = { bitwarden: true, username: 'user', domain: 'CORP', password: 'secret' };
  assert.equal(sshOpenCredentialFields({ mode: 'smb' }, vault).username, 'CORP\\user');
  const fields = sshOpenCredentialFields({ mode: 'smb', nodeId: 'node' }, vault);
  assert.equal(fields.username_override, 'CORP\\user');
  assert.equal(fields.password_override, 'secret');
  assert.equal(fields.credential_override, true);
  assert.equal(
    sshOpenCredentialFields({ mode: 'smb' }, { ...vault, username: 'OTHER\\user' }).username,
    'OTHER\\user',
  );
  assert.equal(
    sshOpenCredentialFields({ mode: 'smb' }, { ...vault, username: 'user@example.test' }).username,
    'user@example.test',
  );
  assert.equal(sshOpenCredentialFields({ mode: 'sftp' }, vault).username, 'user');
  assert.equal(
    sshOpenCredentialFields(
      { mode: 'smb', username: 'manual', password: 'manual-secret' },
      { bitwarden: false },
    ).username,
    'manual',
  );
});
