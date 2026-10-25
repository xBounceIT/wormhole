import { isTunnelIdentifier } from '../electron/tunnel-test-contract.ts';
import { hasValidCredentialSecretLength } from '../electron/credential-secret-length.ts';
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stripTypeScriptTypes } from 'node:module';
import { parseWorkspaceNotes } from '../electron/workspace-notes.ts';
import { parseWorkspaceRdpSettings } from '../electron/workspace-rdp-contract.ts';

import {
  isLocalSftpPath,
  isSftpName,
  sshMaxSftpEntryNameLength,
  sshMaxSftpPathLength,
  isSftpEditRequest,
  parseSftpEditEvent,
} from '../electron/sftp-contract.ts';

test('editor snapshots and watcher updates leave the owning session and file browser connected', () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const marker = 'const unsubscribe = window.wormhole?.onSshEvent((event) => {';
  const start = source.indexOf(marker);
  const end = source.indexOf('\n    });', start);
  assert.ok(start > 0 && end > start);
  let listener: (event: unknown) => void = () => {
    throw new Error('listener was not installed');
  };
  const sessions = [
    {
      id: 'file-tab',
      backendSessionId: 'backend',
      protocol: 'sftp',
      status: 'connected',
      sftp: { status: 'ready', path: '/remote', entries: [] },
    },
  ];
  let current = sessions;
  let sessionUpdates = 0;
  new Function(
    'window',
    'setSessions',
    'settlesSshHostKeyTrustAttempt',
    stripTypeScriptTypes(source.slice(start, end + '\n    });'.length)),
  )(
    {
      wormhole: {
        onSshEvent: (callback: typeof listener) => {
          listener = callback;
        },
      },
    },
    (update: (value: typeof sessions) => typeof sessions) => {
      sessionUpdates++;
      current = update(current);
    },
    () => false,
  );
  for (const state of ['Opening', 'Watching', 'Uploading', 'Uploaded', 'Failed']) {
    listener({
      type: 'sftp.edit',
      sessionId: 'backend',
      requestId: 'edit-response',
      edits: [{ id: 'edit', state }],
    });
    listener({ type: 'sftp.edit', sessionId: 'backend', edits: [{ id: 'edit', state }] });
    assert.equal(current, sessions, `editor state ${state} retired the file-transfer tab`);
  }
  listener({ type: 'sftp.edit', sessionId: 'backend', requestId: 'empty-list', edits: [] });
  assert.equal(current, sessions, 'an empty edit inventory retired the file-transfer tab');
  assert.equal(sessionUpdates, 0, 'edit-only events must not enter the lifecycle mapper');
});

test('SFTP bridge declarations preserve the renderer Vite ambient type reference', () => {
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vite-types-'));
  try {
    const declaration = fileURLToPath(new URL('../src/vite-env.d.ts', import.meta.url)).replaceAll(
      '\\',
      '/',
    );
    const source = join(directory, 'ambient.mts');
    writeFileSync(
      source,
      `/// <reference path="${declaration}" />\nconst development: boolean = import.meta.env.DEV;\n`,
    );
    execFileSync(
      process.execPath,
      [
        fileURLToPath(new URL('../node_modules/typescript/bin/tsc', import.meta.url)),
        '--noEmit',
        '--skipLibCheck',
        '--target',
        'es2022',
        '--module',
        'esnext',
        '--moduleResolution',
        'bundler',
        source,
      ],
      { cwd: directory, windowsHide: true, timeout: 30000, stdio: 'pipe' },
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('failed edit finalization still disconnects SSH and releases its route', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = source.indexOf(
    '  async close(sessionId: string): Promise<void> {',
    source.indexOf('class NativeSshBackend'),
  );
  const end = source.indexOf('\n  cancelPendingConnections()', start);
  assert.ok(start > 0 && end > start);
  const { close } = new Function(
    stripTypeScriptTypes(`function makeClose() { return { ${source.slice(start, end)} }; }`) +
      ';return makeClose();',
  )();
  const calls: string[] = [];
  const originalWarn = console.warn;
  console.warn = () => undefined;
  try {
    await close.call(
      {
        finishEditClose: async () => {
          throw new Error('journal write failed');
        },
        terminalDelivery: { remove: () => calls.push('delivery') },
        terminalOwners: new Map(),
        connectionAttempts: { cancel: () => calls.push('cancel') },
        openWaiters: new Map(),
        child: { killed: false },
        write: (command: { type: string }) => calls.push(command.type),
        releaseTunnel: async () => calls.push('release'),
      },
      'session',
    );
    assert.deepEqual(calls, ['delivery', 'cancel', 'close', 'release']);
  } finally {
    console.warn = originalWarn;
  }
});

test('SFTP reconnect waits for edit confirmation and close, rejecting duplicates and stale tabs', async () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('  async function reconnectSession(');
  const end = source.indexOf('\n  function restartSession(', start);
  assert.ok(start > 0 && end > start);
  const calls: string[] = [];
  const session = { id: 'tab', protocol: 'sftp', backendSessionId: 'backend', error: '' };
  const sessionsRef = { current: [session] };
  const pending = { current: new Set<string>() };
  let answer!: (value: boolean) => void;
  let failClose = false;
  const reconnect = new Function(
    'sessionsRef',
    'sftpReconnectPending',
    'restartSession',
    'setSessions',
    'window',
    stripTypeScriptTypes(source.slice(start, end)) + ';return reconnectSession;',
  )(
    sessionsRef,
    pending,
    () => calls.push('restart'),
    (update: (current: (typeof session)[]) => (typeof session)[]) => {
      sessionsRef.current = update(sessionsRef.current);
    },
    {
      wormhole: {
        prepareSftpEditClose: () =>
          new Promise<boolean>((resolve) => {
            calls.push('prepare');
            answer = resolve;
          }),
        closeSshSession: async () => {
          calls.push('close');
          if (failClose) throw new Error('close failed');
        },
      },
    },
  );
  let result = reconnect('tab');
  await reconnect('tab');
  assert.deepEqual(calls, ['prepare']);
  answer(false);
  await result;
  assert.deepEqual(calls, ['prepare']);
  result = reconnect('tab');
  answer(true);
  await result;
  assert.deepEqual(calls.slice(-3), ['prepare', 'close', 'restart']);
  failClose = true;
  result = reconnect('tab');
  answer(true);
  await result;
  assert.equal(sessionsRef.current[0].error, 'close failed');
  assert.equal(calls.at(-1), 'close');
  failClose = false;
  result = reconnect('tab');
  sessionsRef.current = [];
  answer(true);
  await result;
  assert.equal(calls.at(-1), 'prepare');
  assert.equal(pending.current.size, 0);
});

test('Electron accepts SFTP connection creation, editing and subsystem-only open requests', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const extract = (name: string) => {
    const start = main.indexOf(`function ${name}(`);
    assert.ok(start >= 0);
    const body = main.indexOf('{', start);
    let depth = 0;
    for (let end = body; end < main.length; end++) {
      if (main[end] === '{') depth++;
      if (main[end] === '}' && --depth === 0) return main.slice(start, end + 1);
    }
    throw new Error(`Missing function body: ${name}`);
  };
  const code = [
    'isRecord',
    'isSshSessionId',
    'isUuid',
    'isTunnelID',
    'hasValidSshKeyPassphraseOverride',
    'isSshOpenRequest',
    'parseWorkspaceNodeWriteRequest',
  ]
    .map(extract)
    .join('\n');
  const validators = new Function(
    'parseWorkspaceNotes',
    'parseWorkspaceRdpSettings',
    'isTunnelIdentifier',
    'hasValidCredentialSecretLength',
    stripTypeScriptTypes(
      `const credentialMaxUsernameLength=512,credentialMaxPasswordLength=4096,sshMaxSessionIdLength=128,webMaxAddressLength=4096;${code}`,
    ) + ';return {parseWorkspaceNodeWriteRequest,isSshOpenRequest};',
  )(
    parseWorkspaceNotes,
    parseWorkspaceRdpSettings,
    isTunnelIdentifier,
    hasValidCredentialSecretLength,
  );
  const draft = {
    name: 'File transfer',
    parentId: 'folder',
    kind: 'connection',
    protocol: 'sftp',
    host: 'sftp.example',
    port: 22,
    username: 'operator',
    inlinePasswordAction: 'set',
    inlinePassword: 'one-time password',
    credentialMode: 1,
    credentialId: '',
    sshAutoSudo: null,
    httpIgnoreCertErrors: null,
    tunnelEnabled: true,
    tunnelConfigId: 'tunnel',
    serialBaudRate: 0,
    serialDataBits: 0,
    serialStopBits: 0,
    serialParity: 0,
    serialFlowControl: 0,
  };
  assert.equal(validators.parseWorkspaceNodeWriteRequest(draft, false).protocol, 'sftp');
  assert.equal(
    validators.parseWorkspaceNodeWriteRequest(
      { ...draft, id: 'node', inlinePasswordAction: 'preserve', inlinePassword: '' },
      true,
    ).inlinePasswordAction,
    'preserve',
  );
  assert.equal(
    validators.parseWorkspaceNodeWriteRequest(
      {
        ...draft,
        credentialMode: 2,
        credentialId: 'ssh-credential',
        inlinePasswordAction: 'clear',
        inlinePassword: '',
      },
      false,
    ).credentialId,
    'ssh-credential',
  );
  assert.throws(() =>
    validators.parseWorkspaceNodeWriteRequest({ ...draft, protocol: 'ftp' }, false),
  );
  const direct = {
    sessionId: 'sftp',
    mode: 'sftp',
    host: 'sftp.example',
    username: 'operator',
    password: 'one-time password',
    columns: 80,
    rows: 24,
  };
  assert.equal(validators.isSshOpenRequest(direct), true);
  assert.equal(validators.isSshOpenRequest({ ...direct, mode: 'terminal' }), true);
  assert.equal(validators.isSshOpenRequest({ ...direct, mode: 'shell-command' }), false);
  assert.equal(
    validators.isSshOpenRequest({
      sessionId: 'saved',
      nodeId: 'node',
      mode: 'sftp',
      columns: 0,
      rows: 0,
    }),
    true,
  );
});

test('file edit IPC bounds paths and selects configured editor IDs without accepting executable requests', () => {
  const id = '12345678-1234-1234-1234-123456789abc';
  for (const operation of ['list', 'prepare-close', 'finish-close'])
    assert.equal(isSftpEditRequest({ operation }), true);
  for (const operation of ['upload', 'stop', 'reload', 'reveal', 'recover', 'discard']) {
    assert.equal(isSftpEditRequest({ operation, editId: id }), true);
    assert.equal(isSftpEditRequest({ operation, editId: '../../etc/passwd' }), false);
  }
  for (const value of [
    null,
    'start',
    {},
    { operation: 'exec' },
    { operation: 'start', pane: 'bad' },
    { operation: 'list', allowBinary: 'yes' },
    { operation: 'list', editorId: 'x'.repeat(129) },
    { operation: 'upload', editId: id, decision: 'yes' },
    { operation: 'upload', editId: id, destinationPath: 'relative' },
    { operation: 'upload', editId: id, destinationPath: '/nul\u0000' },
  ])
    assert.equal(isSftpEditRequest(value), false);
  assert.equal(
    isSftpEditRequest({
      operation: 'start',
      pane: 'remote',
      path: '/etc/my file.conf',
      editorId: 'code',
      allowBinary: true,
    }),
    true,
  );
  assert.equal(
    isSftpEditRequest({ operation: 'start', pane: 'remote', path: `/${'a'.repeat(16384)}` }),
    false,
  );
  assert.equal(
    isSftpEditRequest(
      { operation: 'start', pane: 'local', path: 'C:\\Users\\me\\file.conf' },
      'win32',
    ),
    true,
  );
  assert.equal(
    isSftpEditRequest({ operation: 'start', pane: 'local', path: '/home/me/file.conf' }, 'linux'),
    true,
  );
  assert.equal(
    isSftpEditRequest({ operation: 'start', pane: 'local', path: 'relative' }, 'linux'),
    false,
  );
  assert.equal(
    isSftpEditRequest({
      operation: 'upload',
      editId: id,
      destinationPath: '/copy.conf',
      decision: 'overwrite',
    }),
    true,
  );
});

test('edit event parsing validates bounded metadata and never requires working-copy contents or paths', () => {
  const entry = {
    id: 'id',
    sessionId: 'session',
    nodeId: 'node',
    name: 'server.conf',
    remotePath: '/etc/server.conf',
    editor: 'Code',
    state: 'Watching',
    pending: false,
    recovered: false,
  };
  const event = { type: 'sftp.edit', session_id: 'session', request_id: 'request', edits: [entry] };
  assert.deepEqual(parseSftpEditEvent(event), {
    type: 'sftp.edit',
    sessionId: 'session',
    requestId: 'request',
    edits: [entry],
    error: undefined,
  });
  assert.equal(parseSftpEditEvent({ ...event, edits: undefined })?.edits.length, 0);
  assert.equal(
    parseSftpEditEvent({
      ...event,
      edits: [{ ...entry, error: 'Upload failed', uploadedAt: '2026-10-25T12:00:00Z' }],
    })?.edits[0].error,
    'Upload failed',
  );
  for (const value of [
    { ...event, type: 'other' },
    { ...event, session_id: '' },
    { ...event, request_id: 123 },
    { ...event, error: 'x'.repeat(8193) },
    { ...event, edits: {} },
    { ...event, edits: Array(257).fill(entry) },
    { ...event, edits: [null] },
    { ...event, edits: [{ ...entry, pending: 'yes' }] },
    { ...event, edits: [{ ...entry, name: 'nul\u0000' }] },
    { ...event, edits: [{ ...entry, error: 123 }] },
    { ...event, edits: [{ ...entry, uploadedAt: 123 }] },
  ])
    assert.equal(parseSftpEditEvent(value), undefined);
});

test('local SFTP paths accept native POSIX roots on Linux and macOS', () => {
  for (const platform of ['linux', 'darwin'] as const) {
    assert.equal(isLocalSftpPath('/', false, platform), true);
    assert.equal(isLocalSftpPath('/home/operator', false, platform), true);
    assert.equal(isLocalSftpPath('/Users/operator', false, platform), true);
    assert.equal(isLocalSftpPath('relative/path', false, platform), false);
    assert.equal(isLocalSftpPath('C:\\Users\\operator', false, platform), false);
  }
});

test('local SFTP paths preserve Windows drive and UNC validation', () => {
  assert.equal(isLocalSftpPath('C:\\Users\\operator', false, 'win32'), true);
  assert.equal(isLocalSftpPath('C:/Users/operator', false, 'win32'), true);
  assert.equal(isLocalSftpPath('\\\\server\\share', false, 'win32'), true);
  assert.equal(isLocalSftpPath('/home/operator', false, 'win32'), false);
  assert.equal(isLocalSftpPath('relative\\path', false, 'win32'), false);
});

test('local SFTP paths allow only the explicit empty home request', () => {
  for (const platform of ['linux', 'darwin', 'win32'] as const) {
    assert.equal(isLocalSftpPath('', true, platform), true);
    assert.equal(isLocalSftpPath('', false, platform), false);
  }
  assert.equal(isLocalSftpPath('/home/operator\u0000/file', false, 'linux'), false);
  assert.equal(isLocalSftpPath('C:\\Users\\operator\u0000file', false, 'win32'), false);
});

test('local SFTP path limits are measured in UTF-8 bytes on every platform', () => {
  const maxPosixPath = `/${'a'.repeat(sshMaxSftpPathLength - 1)}`;
  const maxWindowsPath = `C:\\${'a'.repeat(sshMaxSftpPathLength - 3)}`;
  assert.equal(isLocalSftpPath(maxPosixPath, false, 'linux'), true);
  assert.equal(isLocalSftpPath(`${maxPosixPath}a`, false, 'linux'), false);
  assert.equal(isLocalSftpPath(maxWindowsPath, false, 'win32'), true);
  assert.equal(isLocalSftpPath(`${maxWindowsPath}a`, false, 'win32'), false);
  assert.equal(isLocalSftpPath(`/${'é'.repeat(sshMaxSftpPathLength / 2)}`, false, 'linux'), false);
});

test('local SFTP names follow the destination host filesystem', () => {
  for (const platform of ['linux', 'darwin'] as const) {
    assert.equal(isSftpName('report:2026.txt', 'local', platform), true);
    assert.equal(isSftpName('report\\2026.txt', 'local', platform), true);
  }
  assert.equal(isSftpName('report:2026.txt', 'local', 'win32'), false);
  assert.equal(isSftpName('report\\2026.txt', 'local', 'win32'), false);
  assert.equal(isSftpName('nested/report.txt', 'local', 'linux'), false);
  assert.equal(isSftpName('bad\u0000name', 'local', 'linux'), false);
});

test('remote SFTP names allow colons without treating backslashes as separators', () => {
  assert.equal(isSftpName('report:2026.txt', 'remote', 'win32'), true);
  assert.equal(isSftpName('report\\2026.txt', 'remote', 'linux'), false);
  assert.equal(isSftpName('.', 'remote', 'linux'), false);
  assert.equal(isSftpName('..', 'remote', 'linux'), false);
  assert.equal(isSftpName('é'.repeat(sshMaxSftpEntryNameLength / 2), 'remote', 'linux'), true);
  assert.equal(
    isSftpName(`${'é'.repeat(sshMaxSftpEntryNameLength / 2)}a`, 'remote', 'linux'),
    false,
  );
});
