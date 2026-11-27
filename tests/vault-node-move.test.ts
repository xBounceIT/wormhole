import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session as InspectorSession } from 'node:inspector/promises';
import { vaultDeleteSelection } from '../src/vault-delete-selection.ts';
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVaultNodeMove, parseVaultNodeMoveResult } from '../electron/vault-node-move.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
const id = '11111111-1111-4111-8111-111111111111',
  child = '22222222-2222-4222-8222-222222222222';
const request = () => ({
  nodes: [{ id, rowVersion: '1' }],
  target: { id: child, rowVersion: '7' },
  placement: 'inside',
});
const result = { moved: true, updatedCount: '2' } as const;
test('move validates independent target revision, placement, bounds and snapshots', () => {
  for (const placement of ['inside', 'before', 'after'])
    assert.ok(parseVaultNodeMove({ ...request(), placement }));
  const input = request(),
    snapshot = parseVaultNodeMove(input)!;
  input.nodes[0].rowVersion = '99';
  input.target.rowVersion = '99';
  input.placement = 'after';
  assert.deepEqual(snapshot, request());
  for (const bad of [
    null,
    {},
    { ...request(), extra: 1 },
    { ...request(), nodes: [] },
    { ...request(), nodes: null },
    { ...request(), nodes: Array(1001).fill(request().nodes[0]) },
    { ...request(), placement: 'around' },
    { ...request(), target: null },
    { ...request(), target: request().nodes[0] },
    { ...request(), target: { id: child, rowVersion: '0' } },
    { ...request(), target: { id: child, rowVersion: '01' } },
    { ...request(), target: { id: child, rowVersion: '9223372036854775807' } },
    { ...request(), nodes: [...request().nodes, ...request().nodes] },
  ])
    assert.equal(parseVaultNodeMove(bad), undefined);
  for (const updatedCount of ['0', '2'])
    assert.deepEqual(parseVaultNodeMoveResult({ ...result, updatedCount }), {
      ...result,
      updatedCount,
    });
  for (const bad of [
    null,
    {},
    { ...result, moved: false },
    { ...result, extra: 1 },
    { ...result, updatedCount: '01' },
    { ...result, updatedCount: -1 },
  ])
    assert.equal(parseVaultNodeMoveResult(bad), undefined);
});
test('host and IPC require an unlocked owner and current trusted document for movement', async () => {
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
        moveNodes: async () => {
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
  const invoke = (...args: any[]) => handlers.get('vault:move-nodes')({}, ...args);
  await assert.rejects(host.moveNodes(null), /Invalid/);
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

test('Standard move binds fresh authentication to the captured intent', async () => {
  let calls = 0,
    submitted: any,
    auth: any;
  const input = request();
  const host = new VaultBackendHost(
    () =>
      ({
        unlock: async () => ({ unlocked: true, lockedMemory: true }),
        lock: async () => {},
        security: async () => ({ effective: 'standard' }),
        describe: async () => ({ vaultId: id, slots: [{ id: child, kind: 'password' }] }),
        moveNodes: async (q: any, factor: any) => {
          calls++;
          submitted = q;
          auth = factor;
          return result;
        },
      }) as any,
    () => true,
  );
  const factor = () => ({
    vaultId: id,
    slotId: child,
    kind: 'password',
    factor: new Uint8Array([7]),
  });
  await host.unlock(factor());
  await assert.rejects(host.moveNodes(input), /Fresh authentication/);
  assert.equal(calls, 0);
  assert.deepEqual(
    await host.moveNodes(input, async (operation, descriptor, submit) => {
      assert.equal(operation, 'node-move');
      assert.equal(descriptor.vaultId, id);
      input.target.rowVersion = '99';
      input.nodes[0].rowVersion = '99';
      return submit(factor());
    }),
    result,
  );
  assert.deepEqual(submitted, request());
  assert.ok(auth.factor.every((b: number) => b === 0));
  let accepted = true;
  await assert.rejects(
    host.moveNodes(
      request(),
      async (_op, _descriptor, submit) => {
        accepted = false;
        return submit(factor());
      },
      () => accepted,
    ),
    /locked/,
  );
  assert.equal(calls, 1);
  await host.stop();
});

test('actual tree drop dispatches captured revisions to the vault and keeps legacy behavior', async (t) => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('  async function handleTreeDrop('),
    end = source.indexOf('\n  function ', start + 30);
  assert.ok(start > 0 && end > start);
  const script = stripTypeScriptTypes(source.slice(start, end)) + ';handleTreeDrop';
  const inspector = new InspectorSession();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const mode of ['vault', 'legacy'])
    for (const outcome of ['ok', 'refresh-fail', 'reject']) {
      const tree = [
        { id, rowVersion: '3', persisted: true },
        { id: child, rowVersion: '7', persisted: true },
      ];
      const calls: any[] = [],
        errors: string[] = [];
      let selectionReads = 0;
      let selected = '',
        refreshed = 0;
      const pending = { current: false };
      const save = async (q: any) => {
        calls.push(q);
        if (outcome === 'reject') throw Error('stale revision');
        return { moved: true };
      };
      const context = {
        Error,
        treeMovePending: pending,
        draggedNodeIds: [id],
        searchText: '',
        treeRef: { current: tree },
        authState: { mode },
        getTreeDropPlacement: () => 'after',
        canDropTreeNodes: () => true,
        findTreeNode: (nodes: any[], key: string) => nodes.find((n) => n.id === key),
        vaultDeleteSelection: (...args: Parameters<typeof vaultDeleteSelection>) => {
          selectionReads++;
          return vaultDeleteSelection(...args);
        },
        window: {
          wormhole: {
            moveVaultNodes: mode === 'vault' ? save : () => assert.fail('vault on legacy'),
            moveWorkspaceNodes: mode === 'legacy' ? save : () => assert.fail('legacy on vault'),
          },
        },
        refreshWorkspace: async () => {
          refreshed++;
          if (outcome === 'refresh-fail') throw Error('refresh unavailable');
        },
        setTreeMoveError: (s: string) => errors.push(s),
        setTree: (update: any) => update(tree),
        moveTreeNodes: () => tree,
        setDraggedNodeIds: () => {},
        setDropTarget: () => {},
        setSelectedNodeId: (v: string) => {
          selected = v;
        },
        toggleFolder: () => {},
      };
      await runInNewContext(script, context, { filename: 'vault-tree-move-ui.js' })(
        { preventDefault: () => {} },
        tree[1],
      );
      assert.equal(calls.length, 1);
      assert.equal(selectionReads, mode === 'vault' ? 1 : 0);
      assert.equal(pending.current, false);
      assert.deepEqual(
        JSON.parse(JSON.stringify(calls[0])),
        mode === 'vault'
          ? {
              nodes: [{ id, rowVersion: '3' }],
              target: { id: child, rowVersion: '7' },
              placement: 'after',
            }
          : { nodeIds: [id], targetId: child, placement: 'after' },
      );
      assert.equal(refreshed, outcome === 'reject' ? 0 : 1);
      assert.equal(selected, outcome === 'reject' ? '' : id);
      if (outcome === 'refresh-fail') assert.match(errors.at(-1)!, /Move saved/);
      if (outcome === 'reject') assert.equal(errors.at(-1), 'stale revision');
    }
  const coverage = await inspector.post('Profiler.takePreciseCoverage');
  await inspector.post('Profiler.stopPreciseCoverage');
  for (const needle of [
    'window.wormhole.moveVaultNodes',
    'vaultDeleteSelection(currentTree, [...sourceIds, node.id])',
    'target: selection.at(-1)',
    'window.wormhole.moveWorkspaceNodes',
  ]) {
    const offset = script.indexOf(needle);
    assert.ok(offset > 0);
    const ranges = coverage.result
      .filter((e) => e.url === 'vault-tree-move-ui.js')
      .flatMap((e) => e.functions.flatMap((f) => f.ranges))
      .filter((r) => r.startOffset <= offset && r.endOffset > offset);
    const smallest = Math.min(...ranges.map((r) => r.endOffset - r.startOffset));
    assert.ok(ranges.some((r) => r.endOffset - r.startOffset === smallest && r.count > 0));
  }
  t.diagnostic('V8 executed all changed tree move dispatch statements in both workspace modes.');
});
