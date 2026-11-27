import assert from 'node:assert/strict';
import test from 'node:test';
import {
  consumeVaultCredentialInput,
  consumeVaultCredentialRequest,
  parseVaultCredentialSelection,
  parseVaultCredentialResult,
  parseVaultCredentialDeleteResult,
} from '../electron/vault-credential.ts';
import { prepareVaultCredentialSelections } from '../electron/vault-credential-selection.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';

const id = '11111111-1111-4111-8111-111111111111';
const second = '22222222-2222-4222-8222-222222222222';
function input(native = false, key = false): any {
  return {
    metadata: {
      id: '',
      name: 'Account',
      protocol: 'ssh',
      kind: key ? 'sshKey' : 'password',
      username: 'user',
      domain: '',
      provider: 'Local',
      bitwardenItemId: '',
      bitwardenItemName: '',
      clearPassphrase: false,
      clearCertificate: false,
      ...(native
        ? { privateKeyPath: '', certificatePath: '' }
        : { privateKeySelectionId: '', certificateSelectionId: '' }),
    },
    rowVersion: '0',
    password: new Uint8Array(key ? [] : [65, 66]),
    passphrase: new Uint8Array(key ? [67, 68] : []),
  };
}
const selection = { id, rowVersion: '1' };
const saved = { id, rowVersion: '1', updated: true } as const;
const deleted = { id, rowVersion: '2', deleted: true } as const;
const factor = () => ({
  vaultId: id,
  slotId: second,
  kind: 'password' as const,
  factor: new Uint8Array([3]),
});

test('credential boundary copies owned bytes, rejects shape/path/secret confusion and wipes all rejected inputs', () => {
  for (const native of [false, true])
    for (const key of [false, true]) {
      const consume = native ? consumeVaultCredentialInput : consumeVaultCredentialRequest;
      const value = input(native, key),
        before = structuredClone(value),
        owned = consume(value);
      assert.deepEqual(
        { ...owned, password: [...owned.password], passphrase: [...owned.passphrase] },
        { ...before, password: [...before.password], passphrase: [...before.passphrase] },
      );
      value.metadata.name = 'Changed';
      assert.equal(owned.metadata.name, 'Account');
      assert.ok(value.password.every((x: number) => x === 0));
      assert.ok(value.passphrase.every((x: number) => x === 0));
      owned.password.fill(0);
      owned.passphrase.fill(0);
      for (const value of [null, [], {}, { ...input(native, key), extra: 1 }])
        assert.throws(() => consume(value), /Invalid/);
      const mutations: Array<(v: any) => void> = [
        (v) => (v.metadata = null),
        (v) => (v.metadata.extra = 1),
        (v) => (v.metadata.id = 'bad'),
        (v) => (v.metadata.id = id),
        (v) => (v.rowVersion = '1'),
        (v) => (v.rowVersion = '01'),
        (v) => (v.metadata.name = ''),
        (v) => (v.metadata.name = 'x'.repeat(1025)),
        (v) => (v.metadata.username = '\ud800'),
        (v) => (v.metadata.domain = null),
        (v) => (v.metadata.bitwardenItemId = null),
        (v) => (v.metadata.bitwardenItemName = 'x'.repeat(4097)),
        (v) => (v.metadata.protocol = 'other'),
        (v) => (v.metadata.kind = 'other'),
        (v) => (v.metadata.provider = 'other'),
        (v) => (v.metadata.clearPassphrase = 1),
        (v) => (v.metadata.clearCertificate = null),
        (v) => (v.password = []),
        (v) => (v.passphrase = []),
        (v) => (v.password = new Uint8Array(16385).fill(1)),
        (v) => (v.passphrase = new Uint8Array(16385).fill(1)),
        (v) => (v.password = new Uint8Array(new SharedArrayBuffer(1)).fill(1)),
        (v) => (v.passphrase = new Uint8Array(new SharedArrayBuffer(1)).fill(1)),
        (v) =>
          (v.metadata[native ? 'privateKeyPath' : 'privateKeySelectionId'] = native
            ? 'x'.repeat(32769)
            : 'arbitrary-path'),
        (v) =>
          (v.metadata[native ? 'certificatePath' : 'certificateSelectionId'] = native
            ? null
            : 'arbitrary-path'),
        (v) => (v.metadata[native ? 'privateKeySelectionId' : 'privateKeyPath'] = 'injected'),
        ...(key
          ? [
              (v) => (v.metadata.protocol = 'rdp'),
              (v) => (v.metadata.provider = 'Bitwarden'),
              (v) => (v.password = new Uint8Array([1])),
              (v) => (v.metadata.clearPassphrase = true),
              (v) => {
                v.metadata.clearCertificate = true;
                v.metadata[native ? 'certificatePath' : 'certificateSelectionId'] = native
                  ? 'file'
                  : id;
              },
            ]
          : [
              (v) => (v.passphrase = new Uint8Array([1])),
              (v) => (v.metadata.clearPassphrase = true),
              (v) => (v.metadata.clearCertificate = true),
              (v) =>
                (v.metadata[native ? 'privateKeyPath' : 'privateKeySelectionId'] = native
                  ? 'file'
                  : id),
            ]),
      ];
      for (const mutate of mutations) {
        const bad = input(native, key);
        mutate(bad);
        assert.throws(() => consume(bad), /Invalid/, `${native}/${key}: ${mutate}`);
        for (const field of ['password', 'passphrase'])
          if (bad[field] instanceof Uint8Array) assert.ok(bad[field].every((x: number) => x === 0));
      }
      const edit = input(native, key);
      edit.metadata.id = id;
      edit.rowVersion = '2';
      assert.equal(consume(edit).rowVersion, '2');
    }
});

test('credential results and deletion bind canonical revision and exact fields', () => {
  assert.deepEqual(parseVaultCredentialSelection(selection), selection);
  assert.deepEqual(parseVaultCredentialResult(saved), saved);
  assert.deepEqual(parseVaultCredentialDeleteResult(deleted), deleted);
  for (const [parse, value, flag] of [
    [parseVaultCredentialSelection, selection, ''],
    [parseVaultCredentialResult, saved, 'updated'],
    [parseVaultCredentialDeleteResult, deleted, 'deleted'],
  ] as const) {
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
  assert.equal(parseVaultCredentialSelection({ id, rowVersion: '9223372036854775807' }), undefined);
  assert.ok(parseVaultCredentialResult({ ...saved, rowVersion: '9223372036854775807' }));
});

test('picker selection is sender and epoch bound, atomic and consumed once', () => {
  const sender = {},
    other = {},
    keys = new WeakMap(),
    certificates = new WeakMap();
  const key = { id, path: 'native-key', authorizationEpoch: 1 },
    certificate = { id: second, path: 'native-cert', authorizationEpoch: 2 };
  for (const useKey of [false, true])
    for (const useCert of [false, true]) {
      keys.set(sender, key);
      certificates.set(sender, certificate);
      const value = input(false, true);
      value.metadata.privateKeySelectionId = useKey ? id : '';
      value.metadata.certificateSelectionId = useCert ? second : '';
      const epochs: number[] = [];
      const prepared = prepareVaultCredentialSelections(value, sender, keys, certificates, (e) =>
        epochs.push(e),
      );
      assert.equal(prepared.metadata.privateKeyPath, useKey ? key.path : '');
      assert.equal(prepared.metadata.certificatePath, useCert ? certificate.path : '');
      assert.equal('privateKeySelectionId' in prepared.metadata, false);
      assert.deepEqual(epochs, [...(useKey ? [1] : []), ...(useCert ? [2] : [])]);
      assert.equal(keys.has(sender), !useKey);
      assert.equal(certificates.has(sender), !useCert);
      if (useKey || useCert)
        assert.throws(
          () => prepareVaultCredentialSelections(value, sender, keys, certificates, () => {}),
          /again/,
        );
    }
  keys.set(sender, key);
  certificates.set(sender, certificate);
  const value = input(false, true);
  value.metadata.privateKeySelectionId = id;
  value.metadata.certificateSelectionId = second;
  assert.throws(
    () => prepareVaultCredentialSelections(value, other, keys, certificates, () => {}),
    /again/,
  );
  assert.throws(
    () =>
      prepareVaultCredentialSelections(value, sender, keys, certificates, (e) => {
        if (e === 2) throw Error('epoch');
      }),
    /epoch/,
  );
  assert.ok(keys.has(sender) && certificates.has(sender));
  value.metadata.certificateSelectionId = id;
  assert.throws(
    () => prepareVaultCredentialSelections(value, sender, keys, certificates, () => {}),
    /again/,
  );
  assert.ok(keys.has(sender));
});

test('credential IPC validates trusted owners, consumes factors and rejects completion after lock or owner change', async () => {
  let trusted = true,
    delayed = false,
    complete!: () => void,
    calls = 0,
    submitted: any;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    lock: async () => {},
    security: async () => ({ effective: 'default' }),
    editCredential: async (value: any) => {
      calls++;
      submitted = value;
      if (delayed) await new Promise<void>((r) => (complete = r));
      return saved;
    },
    deleteCredential: async (value: any) => {
      calls++;
      submitted = value;
      if (delayed) await new Promise<void>((r) => (complete = r));
      return deleted;
    },
  };
  const host = new VaultBackendHost(
      () => client,
      () => true,
    ),
    handlers = new Map<string, any>();
  registerVaultIpc(
    { handle: (name: string, fn: any) => handlers.set(name, fn) } as any,
    host,
    () => trusted,
    undefined,
    undefined,
    (_event, value) =>
      prepareVaultCredentialSelections(value, {}, new WeakMap(), new WeakMap(), () => {}),
  );
  const edit = (...args: any[]) => handlers.get('vault:edit-credential')({}, ...args),
    remove = (...args: any[]) => handlers.get('vault:delete-credential')({}, ...args);
  await assert.rejects(host.editCredential(null), /Invalid/);
  await assert.rejects(host.deleteCredential(null), /Invalid/);
  await assert.rejects(edit(input()), /locked/);
  await assert.rejects(remove(selection), /locked/);
  await host.unlock(factor());
  for (const invoke of [edit, remove]) {
    await assert.rejects(invoke(), /Invalid/);
    await assert.rejects(invoke(invoke === edit ? input() : selection, {}), /Invalid/);
    trusted = false;
    await assert.rejects(invoke(invoke === edit ? input() : selection), /Invalid/);
    trusted = true;
  }
  await assert.rejects(edit(input(true)), /Invalid/);
  const request = input();
  assert.deepEqual(await edit(request), saved);
  assert.ok(request.password.every((x: number) => x === 0));
  assert.ok(submitted.password.every((x: number) => x === 0));
  assert.deepEqual(await remove(selection), deleted);
  delayed = true;
  for (const invoke of [edit, remove]) {
    const pending = invoke(invoke === edit ? input() : selection);
    await new Promise(setImmediate);
    trusted = false;
    complete();
    await assert.rejects(pending, /owner/);
    trusted = true;
  }
  const pending = edit(input());
  await new Promise(setImmediate);
  await host.stop();
  complete();
  await assert.rejects(pending, /locked/);
  assert.ok(submitted.password.every((x: number) => x === 0));
  assert.equal(calls, 5);
  const noPrepare = new Map<string, any>();
  registerVaultIpc({ handle: (n: string, f: any) => noPrepare.set(n, f) } as any, host, () => true);
  await assert.rejects(noPrepare.get('vault:edit-credential')({}, input()), /Invalid/);
});

test('Standard credential retries retain owned factors only until the bound action finishes', async () => {
  let calls = 0;
  const attempts: any[] = [];
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    lock: async () => {},
    security: async () => ({ effective: 'standard' }),
    describe: async () => ({ vaultId: id, slots: [{ id: second, kind: 'password' }] }),
    editCredential: async (value: any, auth: any) => {
      attempts.push(value);
      assert.deepEqual([...value.passphrase], [67, 68]);
      assert.deepEqual([...auth.factor], [3]);
      if (++calls === 1) throw Error('Vault operation failed.');
      return saved;
    },
    deleteCredential: async (value: any, auth: any) => {
      assert.deepEqual(value, selection);
      assert.deepEqual([...auth.factor], [3]);
      return deleted;
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  await host.unlock(factor());
  await assert.rejects(host.editCredential(input(true)), /Fresh authentication/);
  const value = input(true, true);
  const result = await host.editCredential(value, async (operation, _descriptor, invoke) => {
    assert.equal(operation, 'credential-edit');
    await assert.rejects(invoke(factor()), /operation failed/);
    assert.ok(attempts[0].passphrase.every((x: number) => x === 0));
    return invoke(factor());
  });
  assert.deepEqual(result, saved);
  assert.ok(value.passphrase.every((x: number) => x === 0));
  assert.ok(attempts[1].passphrase.every((x: number) => x === 0));
  assert.deepEqual(
    await host.deleteCredential(selection, async (operation, _descriptor, invoke) => {
      assert.equal(operation, 'credential-delete');
      return invoke(factor());
    }),
    deleted,
  );
  await host.stop();
});
