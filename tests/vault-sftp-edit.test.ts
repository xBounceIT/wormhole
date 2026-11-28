import {
  parseVaultRecoveryRequest,
  parseVaultRecoveryRecords,
} from '../electron/vault-sftp-recovery.ts';
import { parseVaultRecoveryScopes } from '../electron/vault-sftp-recovery.ts';
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { sealedSftpEditCommand, parseVaultFileEditSettings } from '../electron/vault-sftp-edit.ts';

const defaults = () => ({
  editors: [],
  defaultEditor: 'auto',
  maxFileSize: 1024,
  swapPanels: false,
});
test('settings require the same unlocked host and invalid requests never spawn a process', async () => {
  const client = new VaultBackendClient({ executable: '/unused', databasePath: '/unused' }, () => {
    throw Error('unexpected spawn');
  });
  await assert.rejects(client.fileEditSettings({ password: 'hidden' }), /Invalid/);
  await assert.rejects(client.sftpRecoveryScopes('../bad'), /Invalid/);
  await assert.rejects(client.sftpRecoveryRecords({}), /Invalid/);
  const method = VaultBackendHost.prototype.fileEditSettings;
  await assert.rejects(method.call({ client: undefined } as any), /locked/);
  let finish!: (value: unknown) => void;
  const state: any = {
    unlockedWorkspaceId: 'one',
    client: {
      fileEditSettings: () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    },
  };
  let response = method.call(state);
  state.unlockedWorkspaceId = 'two';
  finish(defaults());
  await assert.rejects(response, /locked/);
  response = method.call(state);
  state.client = {};
  finish(defaults());
  await assert.rejects(response, /locked/);
});

test('offline queries reject locked and replaced native owners', async () => {
  for (const [method, arg] of [
    [VaultBackendHost.prototype.sftpRecoveryScopes, ''],
    [VaultBackendHost.prototype.sftpRecoveryRecords, { nodeId: randomUUID(), operation: 'list' }],
  ] as const) {
    await assert.rejects(method.call({ client: undefined } as any, arg as any), /locked/);
    let finish!: (value: unknown) => void;
    const deferred = () =>
      new Promise((resolve) => {
        finish = resolve;
      });
    const state: any = {
      unlockedWorkspaceId: 'one',
      client: { sftpRecoveryScopes: deferred, sftpRecoveryRecords: deferred },
    };
    let p = method.call(state, arg as any);
    state.unlockedWorkspaceId = 'two';
    finish({});
    await assert.rejects(p, /locked/);
    p = method.call(state, arg as any);
    state.client = {};
    finish({});
    await assert.rejects(p, /locked/);
  }
});

test('offline reveal uses the authenticated edit scope and a dedicated native acknowledgement', async () => {
  const workspace = randomUUID();
  const nodeId = randomUUID();
  const editId = randomUUID();
  const request = { nodeId, editId, operation: 'reveal' } as const;
  const result = { edits: [], after: '', busy: false };
  const root = process.cwd();
  const folder = join(root, 'vault-sftp-edit', workspace, nodeId, 'sftp-edit', editId, 'files');
  const state = {
    options: { userDataPath: root },
    metadata: (
      _operation: string,
      parse: (value: unknown) => unknown,
      _timeout: undefined,
      q: unknown,
    ) => {
      assert.deepEqual(q, request);
      return parse({ ...result, revealReady: true });
    },
  };
  const reveal = VaultBackendClient.prototype.sftpRecoveryRecords;
  assert.deepEqual(await reveal.call(state as any, request, workspace), {
    ...result,
    revealPath: folder,
  });
  await assert.rejects(reveal.call(state as any, request, '../outside'), /unavailable/);
  state.options.userDataPath = 'relative';
  await assert.rejects(reveal.call(state as any, request, workspace), /unavailable/);
  for (const bad of [
    result,
    { ...result, revealReady: false },
    { ...result, revealReady: true, revealPath: folder },
    { ...result, revealReady: true, busy: true },
  ])
    assert.equal(parseVaultRecoveryRecords(bad, request, folder), undefined);
  assert.equal(parseVaultRecoveryRecords({ ...result, revealReady: true }, request), undefined);
  assert.deepEqual(parseVaultRecoveryRecords({ ...result, busy: true }, request, folder), {
    ...result,
    busy: true,
  });
  assert.equal(
    parseVaultRecoveryRecords({ ...result, revealReady: true }, { nodeId, operation: 'list' }),
    undefined,
  );
});

test('file editor settings IPC selects the unlocked owner and validates the current document', async () => {
  const source = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const selected = source.slice(
    source.indexOf("  ipcMain.handle('settings:file-transfer-read'"),
    source.indexOf("  ipcMain.handle('ssh:sftp-edit'"),
  );
  const handlers = new Map<string, any>(),
    calls: any[] = [];
  let trusted = true;
  const vaultBackend = {
    isVaultWorkspace: true,
    fileEditSettings: async (value?: unknown) => {
      calls.push(['vault', value]);
      return defaults();
    },
  };
  runInNewContext(stripTypeScriptTypes(selected), {
    ipcMain: { handle: (name: string, fn: any) => handlers.set(name, fn) },
    vaultBackend,
    serializeAuthOperation: (fn: any) => fn(),
    requireWorkspaceAuth: async () => {},
    isTrustedVaultSender: () => trusted,
    isRecord: (v: unknown) => typeof v === 'object' && v !== null && !Array.isArray(v),
    runBackend: async (...args: any[]) => {
      calls.push(args);
      return defaults();
    },
  });
  const read = handlers.get('settings:file-transfer-read'),
    write = handlers.get('settings:file-transfer-write');
  await read({});
  await write({}, defaults());
  assert.equal(calls.length, 2);
  assert.equal(calls[0][0], 'vault');
  trusted = false;
  await assert.rejects(read({}), /owner/);
  await assert.rejects(write({}, defaults()), /owner/);
  assert.equal(calls.length, 2);
  await assert.rejects(write({}, null), /Invalid/);
  await assert.rejects(write({}, { large: 'x'.repeat(65536) }), /Invalid/);
  vaultBackend.isVaultWorkspace = false;
  await read({});
  await write({}, defaults());
  assert.equal(calls[2][0], 'settings-file-transfer-read');
  assert.equal(calls[3][0], 'settings-file-transfer-write');
});

test('sealed editor commands reject injected authority and invalid per-operation fields', () => {
  const common = { type: 'sftp-edit', session_id: randomUUID(), request_id: 'request' };
  const edit = randomUUID();
  for (const request of [
    { operation: 'list' },
    { operation: 'prepare-close' },
    { operation: 'finish-close', decision: 'keep' },
    { operation: 'start', pane: 'remote', path: '/file', editor_id: 'auto', allow_binary: false },
    { operation: 'start', pane: 'local', path: process.cwd(), editor_id: '', allow_binary: true },
    ...['reveal', 'recover', 'upload', 'stop'].map((operation) => ({ operation, edit_id: edit })),
    ...['reload', 'discard'].map((operation) => ({
      operation,
      edit_id: edit,
      decision: 'discard',
    })),
    { operation: 'upload', edit_id: edit, decision: 'overwrite', destination_path: '/new' },
    { operation: 'stop', edit_id: edit, destination_path: '' },
  ]) {
    const q = { ...common, ...request };
    assert.deepEqual(sealedSftpEditCommand({ ...q, unknown: undefined }), q);
    for (const field of ['executable', 'password', 'route', 'nodeId', 'settingsPath', 'publicKey'])
      assert.throws(() => sealedSftpEditCommand({ ...q, [field]: 'injected' }), /Invalid/);
    for (const field of Object.keys(q))
      assert.throws(() => sealedSftpEditCommand({ ...q, [field]: null }), /Invalid/);
  }
  for (const request of [
    { operation: '__proto__' },
    { operation: 1 },
    { operation: 'start', pane: 'remote', path: 'relative' },
    { operation: 'list', path: '/other' },
    { operation: 'list', session_id: '' },
    { operation: 'list', request_id: '' },
    { operation: 'list', request_id: 'x\n' },
    { operation: 'list', request_id: 'x'.repeat(129) },
    { operation: 'finish-close' },
    { operation: 'finish-close', decision: 'discard' },
    { operation: 'recover', edit_id: '../outside' },
    { operation: 'reload', edit_id: edit, decision: 'overwrite' },
    { operation: 'stop', edit_id: edit, decision: 'keep' },
    { operation: 'upload', edit_id: edit, destination_path: 'relative' },
    { operation: 'start', pane: 'remote', path: '/file', editor_id: 'bad\t' },
    { operation: 'list', type: 'open' },
  ])
    assert.throws(() => sealedSftpEditCommand({ ...common, ...request }), /Invalid/);
});

test('editor settings project only bounded native public fields and own their arrays', () => {
  assert.deepEqual(parseVaultFileEditSettings(defaults()), defaults());
  const editor = {
    id: 'custom',
    name: 'Editor',
    executable: 'editor',
    arguments: ['{file}'],
    patterns: '*.txt',
  };
  const input = { ...defaults(), editors: [editor], defaultEditor: editor.id };
  const got = parseVaultFileEditSettings(input)!;
  assert.deepEqual(got, input);
  got.editors[0].arguments.push('changed');
  assert.deepEqual(editor.arguments, ['{file}']);
  for (const bad of [
    null,
    [],
    {},
    { ...defaults(), secret: 'hidden' },
    { ...defaults(), editors: null },
    { ...defaults(), defaultEditor: 'missing' },
    { ...defaults(), maxFileSize: 0 },
    { ...defaults(), maxFileSize: 1024 ** 3 + 1 },
    { ...defaults(), maxFileSize: 1.2 },
    { ...defaults(), swapPanels: 1 },
    { ...defaults(), editors: Array(33).fill(editor) },
    { ...defaults(), editors: [editor, editor] },
    ...[
      null,
      {},
      { ...editor, id: 'system' },
      { ...editor, id: '' },
      { ...editor, name: ' ' },
      { ...editor, executable: '' },
      { ...editor, patterns: '\0' },
      { ...editor, name: 'x\n' },
      { ...editor, arguments: [null] },
      { ...editor, arguments: Array(65).fill('x') },
      { ...editor, password: 'hidden' },
      { ...editor, arguments: ['x'.repeat(4097)] },
      { ...editor, arguments: Array(64).fill('x'.repeat(4096)) },
    ].map((value) => ({ ...defaults(), editors: [value] })),
  ])
    assert.equal(parseVaultFileEditSettings(bad), undefined);
});

test('offline recovery scope pages reject replay, unsorted identities and invalid continuations', () => {
  const ids = Array.from({ length: 65 }, () => randomUUID()).sort();
  const q = { nodeIds: ids.slice(0, 64), after: ids[63] };
  const got = parseVaultRecoveryScopes(q)!;
  assert.deepEqual(got, q);
  got.nodeIds.pop();
  assert.equal(q.nodeIds.length, 64);
  assert.deepEqual(parseVaultRecoveryScopes({ nodeIds: [], after: '' }), {
    nodeIds: [],
    after: '',
  });
  assert.ok(parseVaultRecoveryScopes({ nodeIds: [ids[64]], after: '' }, ids[63]));
  for (const v of [
    null,
    {},
    { ...q, secret: 'hidden' },
    { ...q, nodeIds: ids },
    { ...q, nodeIds: [ids[0], ids[0]] },
    { ...q, nodeIds: ['bad'] },
    { ...q, after: ids[0] },
    { nodeIds: [], after: ids[0] },
    { nodeIds: [], after: null },
    { nodeIds: null, after: '' },
  ])
    assert.equal(parseVaultRecoveryScopes(v), undefined);
  assert.equal(parseVaultRecoveryScopes({ nodeIds: [ids[0]], after: '' }, ids[0]), undefined);
});

test('offline record actions bind exact fields and public pages to their selected node', () => {
  const nodeId = randomUUID(),
    id = randomUUID();
  const q = { nodeId, operation: 'list' as const };
  const edit = {
    id,
    nodeId,
    sessionId: randomUUID(),
    name: 'file',
    remotePath: '/file',
    editor: 'fixture',
    state: 'Recovered',
    pending: false,
    recovered: true,
  };
  for (const v of [
    q,
    { ...q, after: '' },
    { nodeId, operation: 'reveal', editId: id },
    { nodeId, operation: 'discard', editId: id, decision: 'discard' },
  ])
    assert.deepEqual(parseVaultRecoveryRequest(v), v);
  for (const v of [
    null,
    {},
    { ...q, nodeId: 'bad' },
    { ...q, after: 'bad' },
    { ...q, path: 'injected' },
    { nodeId, operation: 'reveal', editId: 'bad' },
    { nodeId, operation: 'discard', editId: id },
    { nodeId, operation: 'upload', editId: id },
  ])
    assert.equal(parseVaultRecoveryRequest(v), undefined);
  const raw = { edits: [edit], after: id, busy: false };
  const got = parseVaultRecoveryRecords(raw, q)!;
  assert.deepEqual(got, raw);
  got.edits[0].name = 'changed';
  assert.equal(edit.name, 'file');
  assert.ok(parseVaultRecoveryRecords({ edits: [], after: '', busy: true }, q));
  for (const v of [
    null,
    {},
    { ...raw, password: 'hidden' },
    { ...raw, busy: 1 },
    { ...raw, after: null },
    { ...raw, after: randomUUID() },
    { ...raw, edits: [{ ...edit, nodeId: randomUUID() }] },
    { ...raw, edits: [{ ...edit, recovered: false }] },
    { ...raw, edits: [{ ...edit, state: 'Watching' }] },
    { ...raw, edits: [{ ...edit, password: 'hidden' }] },
    { ...raw, edits: Array(33).fill(edit) },
    { ...raw, edits: [edit, edit] },
    { ...raw, edits: [{}] },
    { ...raw, busy: true },
  ])
    assert.equal(parseVaultRecoveryRecords(v, q), undefined);
  assert.equal(parseVaultRecoveryRecords(raw, { ...q, after: id }), undefined);
  assert.equal(
    parseVaultRecoveryRecords(raw, { nodeId, operation: 'reveal', editId: id }),
    undefined,
  );
  assert.ok(
    parseVaultRecoveryRecords(
      { edits: [], after: '', busy: false },
      { nodeId, operation: 'discard', editId: id, decision: 'discard' },
    ),
  );
});
