import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVaultNodeDelete, parseVaultNodeDeleteResult } from '../electron/vault-node-delete.ts';
import { vaultDeleteSelection } from '../src/vault-delete-selection.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
import { parseVaultWorkspace } from '../electron/vault-workspace.ts';

const id = '11111111-1111-4111-8111-111111111111',
  child = '22222222-2222-4222-8222-222222222222';
const request = () => ({ nodes: [{ id, rowVersion: '1' }] });
const result = { deleted: true, deletedCount: '2' } as const;

test('deletion contracts require bounded exact versioned selections and fixed results', () => {
  const input = request(),
    snapshot = parseVaultNodeDelete(input)!;
  input.nodes[0].rowVersion = '2';
  assert.equal(snapshot.nodes[0].rowVersion, '1');
  for (const bad of [
    null,
    {},
    { nodes: null },
    { nodes: [] },
    { nodes: Array(4097).fill({ id, rowVersion: '1' }) },
    { ...request(), extra: 1 },
    { nodes: [...request().nodes, ...request().nodes] },
    { nodes: [{ id: 'bad', rowVersion: '1' }] },
    { nodes: [{ id, rowVersion: '0' }] },
    { nodes: [{ id, rowVersion: 1 }] },
    { nodes: [{ id, rowVersion: '01' }] },
    { nodes: [{ id, rowVersion: '9223372036854775807' }] },
    { nodes: [{ id, rowVersion: '1', secret: 'bad' }] },
  ])
    assert.equal(parseVaultNodeDelete(bad), undefined);
  assert.deepEqual(parseVaultNodeDeleteResult(result), result);
  for (const bad of [
    null,
    {},
    { ...result, deleted: false },
    { ...result, deletedCount: '0' },
    { ...result, deletedCount: '01' },
    { ...result, secret: 'bad' },
  ])
    assert.equal(parseVaultNodeDeleteResult(bad), undefined);
});

test('selection preserves confirmation revisions and rejects missing or ambiguous nodes', () => {
  const tree = [{ id, rowVersion: '7', children: [{ id: child, rowVersion: '9' }] }];
  assert.deepEqual(vaultDeleteSelection(tree, [child, id]), {
    nodes: [
      { id: child, rowVersion: '9' },
      { id, rowVersion: '7' },
    ],
  });
  for (const [nodes, ids] of [
    [tree, ['missing']],
    [[{ id }], [id]],
    [tree, [id, id]],
    [[tree[0], tree[0]], [id]],
    [Array.from({ length: 50_001 }, (_, i) => ({ id: String(i), rowVersion: '1' })), [id]],
  ] as const)
    assert.throws(() => vaultDeleteSelection(nodes, ids));
  const value = {
    tree: [
      { id, name: 'Folder', kind: 'folder', persisted: true, rowVersion: '9223372036854775807' },
    ],
    credentials: [],
    credentialOptions: { ssh: [], rdp: [], vnc: [] },
    tunnels: [],
  };
  assert.ok(parseVaultWorkspace(value));
  value.tree[0].rowVersion = '01';
  assert.equal(parseVaultWorkspace(value), undefined);
});

test('host and IPC require an unlocked owner and current trusted document for deletion', async () => {
  let trusted = true,
    calls = 0,
    complete!: () => void,
    delayed = false;
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
        deleteNodes: async () => {
          calls++;
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
  const invoke = (...args: any[]) => handlers.get('vault:delete-nodes')({}, ...args);
  await assert.rejects(host.deleteNodes(null), /Invalid/);
  await assert.rejects(invoke(request()), /locked/);
  assert.equal(calls, 0);
  const unlock = () =>
    host.unlock({ vaultId: id, slotId: child, kind: 'password', factor: new Uint8Array([1]) });
  await unlock();
  await assert.rejects(invoke(request(), {}), /Invalid/);
  trusted = false;
  await assert.rejects(invoke(request()), /Invalid/);
  trusted = true;
  assert.deepEqual(await invoke(request()), result);
  delayed = true;
  const late = invoke(request());
  await new Promise(setImmediate);
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
