import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVaultFolder, parseVaultFolderResult } from '../electron/vault-folder.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';

const id = '11111111-1111-4111-8111-111111111111';
const request = () => ({
  id: '',
  rowVersion: '0',
  parentId: '',
  name: 'Folder 🐛',
  sshAutoSudo: null,
  tunnelEnabled: null,
  tunnelConfigId: '',
  credentialMode: 0,
  credentialId: '',
});
const result = { nodeId: id, rowVersion: '1', updated: true } as const;

test('folder editor accepts only bounded public fields, nullable inheritance and canonical revisions', () => {
  const input = request(),
    snapshot = parseVaultFolder(input);
  assert.deepEqual(snapshot, input);
  input.name = 'Changed after queue';
  assert.equal(snapshot?.name, 'Folder 🐛');
  for (const bad of [null, [], {}, { ...request(), notes: 'secret' }])
    assert.equal(parseVaultFolder(bad), undefined);
  for (const [key, values] of Object.entries({
    id: [null, 1, 'bad', id],
    rowVersion: [null, 0, '01', '1', '9223372036854775807'],
    parentId: [null, 'bad'],
    name: [null, '', '  ', 'line\nfeed', '\ud800', 'a'.repeat(257)],
    sshAutoSudo: [0, 'true'],
    tunnelEnabled: [1, 'false'],
    tunnelConfigId: [null, 'bad'],
    credentialMode: [null, -1, 3, '0', 2],
    credentialId: [null, 'bad', id],
  }))
    for (const value of values)
      assert.equal(parseVaultFolder({ ...request(), [key]: value }), undefined, key);
  assert.ok(
    parseVaultFolder({
      ...request(),
      id,
      rowVersion: '7',
      parentId: id,
      sshAutoSudo: true,
      tunnelEnabled: false,
      tunnelConfigId: id,
      credentialMode: 2,
      credentialId: id,
    }),
  );
  assert.ok(parseVaultFolder({ ...request(), credentialMode: 1 }));
  assert.equal(
    parseVaultFolder({ ...request(), id, rowVersion: '9223372036854775807' }),
    undefined,
  );
  assert.deepEqual(parseVaultFolderResult(result), result);
  for (const bad of [
    null,
    {},
    { ...result, secret: 'bad' },
    { ...result, nodeId: 'bad' },
    { ...result, rowVersion: '0' },
    { ...result, updated: false },
  ])
    assert.equal(parseVaultFolderResult(bad), undefined);
});

test('folder IPC requires current trusted unlocked owner and snapshots input before waiting', async () => {
  let trusted = true,
    calls = 0,
    delayed = false,
    complete!: () => void,
    submitted: any;
  const host = new VaultBackendHost(
    () =>
      ({
        unlock: async () => ({ unlocked: true, lockedMemory: true }),
        security: async () => ({
          sequence: '1',
          workspace: 'default',
          user: 'default',
          os: 'default',
          effective: 'default',
          source: 'workspace',
        }),
        lock: async () => {},
        saveFolder: async (input: unknown) => {
          calls++;
          submitted = input;
          if (delayed)
            await new Promise<void>((resolve) => {
              complete = resolve;
            });
          return result;
        },
      }) as any,
    () => true,
  );
  const handlers = new Map<string, any>();
  registerVaultIpc(
    {
      handle: (name: string, fn: any) => {
        handlers.set(name, fn);
      },
    } as any,
    host,
    () => trusted,
  );
  const invoke = (...args: any[]) => handlers.get('vault:save-folder')({}, ...args);
  await assert.rejects(host.saveFolder(null), /Invalid/);
  await assert.rejects(invoke(request()), /locked/);
  assert.equal(calls, 0);
  await host.unlock({ vaultId: id, slotId: id, kind: 'password', factor: new Uint8Array([1]) });
  await assert.rejects(invoke(), /Invalid/);
  await assert.rejects(invoke(request(), {}), /Invalid/);
  trusted = false;
  await assert.rejects(invoke(request()), /Invalid/);
  trusted = true;
  assert.deepEqual(await invoke(request()), result);
  delayed = true;
  const input = request(),
    late = invoke(input);
  await new Promise(setImmediate);
  input.name = 'Changed';
  assert.equal(submitted.name, 'Folder 🐛');
  trusted = false;
  complete();
  await assert.rejects(late, /owner/);
  trusted = true;
  const locked = invoke(request());
  await new Promise(setImmediate);
  await host.stop();
  complete();
  await assert.rejects(locked, /locked/);
});
