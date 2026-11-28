import assert from 'node:assert/strict';
import test from 'node:test';
import {
  consumeVaultTunnelInput,
  parseVaultTunnelSelection,
  parseVaultTunnelResult,
  parseVaultTunnelDeleteResult,
  parseVaultTunnelEditorContext,
  parseVaultTunnelEditorRequest,
  parseVaultTunnelEditorDisplay,
  tunnelEditorCiphertext,
} from '../electron/vault-tunnel.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';

const id = '11111111-1111-4111-8111-111111111111';
const second = '22222222-2222-4222-8222-222222222222';
const third = '33333333-3333-4333-8333-333333333333';
const context = { workspaceId: id, tunnelId: second, requestId: third, rowVersion: '1' };
const publicKey = Buffer.alloc(32, 1).toString('base64');
const response = {
  ...context,
  bundle: {
    formatVersion: 1,
    suiteId: 2,
    enc: publicKey,
    ciphertext: Buffer.alloc(32).toString('base64'),
  },
};
const selection = { id: second, rowVersion: '1' };
const saved = { id: second, rowVersion: '2', updated: true };
const deleted = { id: second, rowVersion: '2', deleted: true };
const tick = () => new Promise(setImmediate);
const factor = () => ({
  vaultId: id,
  slotId: third,
  kind: 'password' as const,
  factor: new Uint8Array([65]),
});
function input(): any {
  return {
    metadata: { id: second, name: 'Tunnel', kind: 1 },
    rowVersion: '1',
    forgetHostKey: false,
    patch: new TextEncoder().encode('{"Password":"secret"}'),
  };
}

test('tunnel edits consume bounded mutable bytes and snapshot only known metadata', () => {
  for (const kind of [0, 1, 2, 3, 4, 5, 6, 7, 8]) {
    const value = input();
    value.metadata.kind = kind;
    const before = structuredClone(value),
      owned = consumeVaultTunnelInput(value);
    assert.deepEqual(owned, before);
    assert.ok(value.patch.every((v: number) => v === 0));
    value.metadata.name = 'Changed';
    value.rowVersion = '9';
    assert.equal(owned.metadata.name, 'Tunnel');
    assert.equal(owned.rowVersion, '1');
    owned.patch.fill(0);
  }
  const draft = input();
  draft.metadata.id = '';
  draft.rowVersion = '0';
  assert.equal(consumeVaultTunnelInput(draft).rowVersion, '0');
  const max = input();
  max.patch = new Uint8Array(4 * 1024 * 1024).fill(32);
  max.metadata.name = '😀'.repeat(128);
  assert.equal(consumeVaultTunnelInput(max).patch.length, 4 * 1024 * 1024);
  const padded = input();
  padded.metadata.name = '\u0085' + 'x'.repeat(128) + '\u0085';
  assert.equal(consumeVaultTunnelInput(padded).metadata.name, padded.metadata.name);
  for (const bad of [null, [], {}]) assert.throws(() => consumeVaultTunnelInput(bad), /Invalid/);
  for (const mutate of [
    (v: any) => (v.extra = 1),
    (v: any) => (v.metadata = null),
    (v: any) => (v.metadata.extra = 1),
    (v: any) => (v.metadata.id = 'bad'),
    (v: any) => (v.rowVersion = '0'),
    (v: any) => (v.rowVersion = '01'),
    (v: any) => (v.rowVersion = '9223372036854775807'),
    (v: any) => (v.metadata.name = ''),
    (v: any) => (v.metadata.name = ' '),
    (v: any) => (v.metadata.name = 'x'.repeat(129)),
    (v: any) => (v.metadata.name = '😀'.repeat(129)),
    (v: any) => (v.metadata.name = '\ud800'),
    (v: any) => (v.metadata.name = '\ufeff' + 'x'.repeat(128)),
    (v: any) => (v.metadata.kind = -1),
    (v: any) => (v.metadata.kind = 10),
    (v: any) => (v.metadata.kind = 0.5),
    (v: any) => (v.metadata.kind = '1'),
    (v: any) => (v.metadata.kind = NaN),
    (v: any) => (v.forgetHostKey = null),
    (v: any) => (v.patch = []),
    (v: any) => (v.patch = new Uint8Array(1).fill(1)),
    (v: any) => (v.patch = new Uint8Array(4 * 1024 * 1024 + 1).fill(1)),
    (v: any) => (v.patch = new Uint8Array(new SharedArrayBuffer(2)).fill(1)),
  ]) {
    const bad = input();
    mutate(bad);
    assert.throws(() => consumeVaultTunnelInput(bad), /Invalid/, String(mutate));
    if (bad.patch instanceof Uint8Array) assert.ok(bad.patch.every((v: number) => v === 0));
  }
});

test('tunnel selections and results enforce canonical identifiers, revisions and minimal responses', () => {
  for (const [parse, value, flag] of [
    [parseVaultTunnelSelection, selection, ''],
    [parseVaultTunnelResult, saved, 'updated'],
    [parseVaultTunnelDeleteResult, deleted, 'deleted'],
  ] as const) {
    assert.deepEqual(parse(value), value);
    for (const bad of [
      null,
      {},
      { ...value, extra: 1 },
      { ...value, id: 'bad' },
      ...['0', '01', '-1', '9223372036854775808', 1].map((rowVersion) => ({
        ...value,
        rowVersion,
      })),
      ...(flag ? [{ ...value, [flag]: false }] : []),
    ])
      assert.equal(parse(bad), undefined);
  }
  assert.equal(
    parseVaultTunnelSelection({ ...selection, rowVersion: '9223372036854775807' }),
    undefined,
  );
  assert.ok(parseVaultTunnelResult({ ...saved, rowVersion: '9223372036854775807' }));
});

test('tunnel display contracts bind workspace, request, item and revision and bound sealed payloads', () => {
  assert.deepEqual(parseVaultTunnelEditorContext(context), context);
  assert.deepEqual(parseVaultTunnelEditorRequest({ ...context, publicKey }), {
    ...context,
    publicKey,
  });
  assert.deepEqual(parseVaultTunnelEditorDisplay(response, context), response);
  for (const bad of [
    null,
    [],
    {},
    { ...context, extra: true },
    ...Object.keys(context).map((key) => ({ ...context, [key]: 'bad' })),
  ])
    assert.equal(parseVaultTunnelEditorContext(bad), undefined);
  for (const bad of [
    null,
    context,
    { ...context, publicKey: 'bad' },
    { ...context, publicKey, extra: 1 },
    { ...context, publicKey, rowVersion: '0' },
  ])
    assert.equal(parseVaultTunnelEditorRequest(bad), undefined);
  for (const bad of [
    null,
    { ...response, extra: 1 },
    ...Object.keys(context).map((key) => ({ ...response, [key]: 'bad' })),
    ...['formatVersion', 'suiteId', 'enc', 'ciphertext'].map((key) => ({
      ...response,
      bundle: { ...response.bundle, [key]: 'bad' },
    })),
    { ...response, bundle: null },
    { ...response, bundle: { ...response.bundle, Password: 'secret' } },
  ])
    assert.equal(parseVaultTunnelEditorDisplay(bad, context), undefined);
  for (const size of [16, 17, 18, 524304])
    assert.equal(tunnelEditorCiphertext(Buffer.alloc(size).toString('base64'))?.length, size);
  for (const bad of [
    null,
    '',
    '!'.repeat(24),
    Buffer.alloc(15).toString('base64'),
    Buffer.alloc(524305).toString('base64'),
    'A'.repeat(699073),
  ])
    assert.equal(tunnelEditorCiphertext(bad), undefined);
});

function fixture(standard = false) {
  const calls: any[] = [],
    attempts: any[] = [];
  let complete!: () => void,
    delayed = false,
    fail = false,
    accepted = true;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    lock: async () => {},
    security: async () => ({ effective: standard ? 'standard' : 'default' }),
    describe: async () => ({ vaultId: id, slots: [{ id: third, kind: 'password' }] }),
    editTunnel: async (value: any, auth: any) => {
      calls.push('edit');
      attempts.push(value);
      assert.equal(new TextDecoder().decode(value.patch), '{"Password":"secret"}');
      assert.equal(value.metadata.name, 'Tunnel');
      if (standard) assert.deepEqual([...auth.factor], [65]);
      if (delayed) await new Promise<void>((r) => (complete = r));
      if (fail) {
        fail = false;
        throw Error('Vault operation failed.');
      }
      return saved;
    },
    deleteTunnel: async (value: any, auth: any) => {
      calls.push('delete');
      assert.deepEqual(value, selection);
      if (standard) assert.deepEqual([...auth.factor], [65]);
      if (delayed) await new Promise<void>((r) => (complete = r));
      return deleted;
    },
    displayTunnelEditor: async (request: any) => {
      calls.push('display');
      assert.deepEqual(request, { ...context, publicKey });
      if (delayed) await new Promise<void>((r) => (complete = r));
      return response;
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  return {
    host,
    calls,
    attempts,
    client,
    accepted: () => accepted,
    delay: () => {
      delayed = true;
    },
    complete: () => complete(),
    fail: () => {
      fail = true;
    },
    deny: () => {
      accepted = false;
    },
  };
}

test('main tunnel host rejects locked, foreign and stale owners without exposing generic IPC', async () => {
  const f = fixture();
  const methods = [
    () => f.host.editTunnel(input()),
    () => f.host.deleteTunnel(selection),
    () => f.host.displayTunnelEditor({ ...context, publicKey }),
  ];
  await assert.rejects(f.host.editTunnel(null), /Invalid/);
  await assert.rejects(f.host.deleteTunnel(null), /Invalid/);
  await assert.rejects(f.host.displayTunnelEditor(null), /Invalid/);
  for (const invoke of methods) await assert.rejects(invoke(), /locked/);
  await f.host.unlock(factor());
  await assert.rejects(
    f.host.displayTunnelEditor({ ...context, workspaceId: third, publicKey }),
    /locked/,
  );
  assert.deepEqual(await methods[0](), saved);
  assert.deepEqual(await methods[1](), deleted);
  assert.deepEqual(await methods[2](), response);
  const channels: string[] = [];
  registerVaultIpc({ handle: (name: string) => channels.push(name) } as any, f.host, () => true);
  assert.deepEqual(
    channels.filter((c) => c.includes('tunnel')),
    ['vault:delete-tunnel'],
  );
  f.delay();
  for (const invoke of methods) {
    const pending = invoke();
    await tick();
    await f.host.stop();
    f.complete();
    await assert.rejects(pending, /locked/);
    await f.host.unlock(factor());
  }
  assert.ok(f.attempts.every((v) => v.patch.every((b: number) => b === 0)));
  await f.host.stop();
});

test('Standard tunnel retries preserve owned patch until completion and bind confirmation to operation', async () => {
  const f = fixture(true);
  await f.host.unlock(factor());
  const denied = input();
  await assert.rejects(f.host.editTunnel(denied), /Fresh authentication/);
  assert.ok(denied.patch.every((b: number) => b === 0));
  f.fail();
  const value = input();
  const pending = f.host.editTunnel(value, async (operation, _descriptor, invoke) => {
    assert.equal(operation, 'tunnel-edit');
    await assert.rejects(invoke(factor()), /operation failed/);
    assert.ok(f.attempts[0].patch.every((b: number) => b === 0));
    return invoke(factor());
  });
  value.metadata.name = 'Changed';
  assert.deepEqual(await pending, saved);
  assert.ok(value.patch.every((b: number) => b === 0));
  assert.ok(f.attempts.every((v) => v.patch.every((b: number) => b === 0)));
  assert.deepEqual(
    await f.host.deleteTunnel(selection, async (operation, _descriptor, invoke) => {
      assert.equal(operation, 'tunnel-delete');
      return invoke(factor());
    }),
    deleted,
  );
  await f.host.stop();
});

test('tunnel host revokes in-flight default mutations when their window loses authority', async () => {
  for (const edit of [false, true]) {
    const f = fixture();
    await f.host.unlock(factor());
    f.delay();
    const pending = edit
      ? f.host.editTunnel(input(), undefined, f.accepted)
      : f.host.deleteTunnel(selection, undefined, f.accepted);
    await tick();
    f.deny();
    f.complete();
    await assert.rejects(pending, /locked/);
    assert.ok(f.attempts.every((v) => v.patch.every((b: number) => b === 0)));
    await f.host.stop();
  }
});
