import assert from 'node:assert/strict';
import test from 'node:test';
import { findParentFolderId } from '../src/tree-parent.ts';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { Session as InspectorSession } from 'node:inspector/promises';
import {
  parseVaultNodeDuplicate,
  parseVaultNodeDuplicateResult,
} from '../electron/vault-node-duplicate.ts';
import { VaultBackendHost, registerVaultIpc } from '../electron/vault-host.ts';
const id = '11111111-1111-4111-8111-111111111111',
  child = '22222222-2222-4222-8222-222222222222';
const request = () => ({ id, rowVersion: '1' });
const result = { nodeId: child, name: 'Source (copy)', rowVersion: '1' } as const;
test('duplicate contracts bind a source revision and return only bounded public metadata', () => {
  const input = request(),
    captured = parseVaultNodeDuplicate(input);
  input.rowVersion = '9';
  assert.deepEqual(captured, request());
  for (const bad of [
    null,
    {},
    { ...request(), secret: 'bad' },
    { ...request(), id: 'bad' },
    { ...request(), rowVersion: '0' },
    { ...request(), rowVersion: '01' },
    { ...request(), rowVersion: 1 },
    { ...request(), rowVersion: '9223372036854775807' },
  ])
    assert.equal(parseVaultNodeDuplicate(bad), undefined);
  for (const name of ['Source (copy)', '🪱'.repeat(249) + ' (copy)'])
    assert.deepEqual(parseVaultNodeDuplicateResult({ ...result, name }), { ...result, name });
  for (const bad of [
    null,
    {},
    { ...result, extra: 1 },
    { ...result, nodeId: id.toUpperCase().replace('1', 'G') },
    { ...result, name: '' },
    { ...result, name: ' ' },
    { ...result, name: 'a'.repeat(257) },
    { ...result, name: 'a\n' },
    { ...result, name: '\ud800' },
    { ...result, rowVersion: '2' },
  ])
    assert.equal(parseVaultNodeDuplicateResult(bad), undefined);
});
test('host and IPC require an unlocked owner and current trusted document for duplication', async () => {
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
        duplicateConnection: async () => {
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
  const invoke = (...args: any[]) => handlers.get('vault:duplicate-connection')({}, ...args);
  await assert.rejects(host.duplicateConnection(null), /Invalid/);
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

test('Standard duplication binds fresh authentication to the captured intent', async () => {
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
        duplicateConnection: async (q: any, factor: any) => {
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
  await assert.rejects(host.duplicateConnection(input), /Fresh authentication/);
  assert.equal(calls, 0);
  assert.deepEqual(
    await host.duplicateConnection(input, async (operation, descriptor, submit) => {
      assert.equal(operation, 'node-duplicate');
      assert.equal(descriptor.vaultId, id);
      input.rowVersion = '99';
      return submit(factor());
    }),
    result,
  );
  assert.deepEqual(submitted, request());
  assert.ok(auth.factor.every((b: number) => b === 0));
  let accepted = true;
  await assert.rejects(
    host.duplicateConnection(
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

test('actual duplication callback routes vault revisions and repairs the fallback revision', async (t) => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('  function duplicateConnection('),
    end = source.indexOf('\n  function ', start + 30);
  assert.ok(start > 0 && end > start);
  const helper = (name: string) => {
    const begin = source.indexOf('function ' + name + '('),
      finish = source.indexOf('\nfunction ', begin + 20);
    assert.ok(begin > 0 && finish > begin);
    return stripTypeScriptTypes(source.slice(begin, finish));
  };
  const script =
    helper('insertIntoTreeFolder') +
    helper('insertRelativeToTreeNode') +
    stripTypeScriptTypes(source.slice(start, end)) +
    ';duplicateConnection';
  const inspector = new InspectorSession();
  inspector.connect();
  t.after(() => inspector.disconnect());
  await inspector.post('Profiler.enable');
  await inspector.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
  for (const mode of ['vault', 'legacy'])
    for (const outcome of ['ok', 'refresh-fail', 'changed-tree', 'reject'])
      for (const nested of [true, false]) {
        const calls: any[] = [],
          errors: string[] = [];
        let fallback: any,
          selected = '';
        const sourceNode = {
          id,
          name: 'Source',
          kind: 'connection',
          persisted: true,
          rowVersion: '7',
        };
        const sibling = { id: 'sibling', name: 'Sibling', kind: 'connection', persisted: true };
        const folder = {
          id: 'folder',
          name: 'Folder',
          kind: 'folder',
          children: [sourceNode, sibling],
        };
        let tree: any[] = nested ? [folder] : [sourceNode, sibling];
        const find = (nodes: any[], key: string): any => {
          for (const item of nodes) {
            if (item.id === key) return item;
            const child = item.children && find(item.children, key);
            if (child) return child;
          }
        };
        const invoke = async (q: any) => {
          calls.push(q);
          if (outcome === 'reject') throw Error('stale source');
          return mode === 'vault' ? result : { nodeId: child, name: result.name };
        };
        const context = {
          Error,
          treeRef: { current: tree },
          findParentFolderId,
          authState: { mode },
          window: {
            wormhole: {
              duplicateVaultConnection:
                mode === 'vault' ? invoke : () => assert.fail('vault on legacy'),
              duplicateWorkspaceNode:
                mode === 'legacy' ? invoke : () => assert.fail('legacy on vault'),
            },
          },
          refreshWorkspace: async () => {
            if (outcome === 'changed-tree') tree = [...tree];
            if (outcome === 'refresh-fail' || outcome === 'changed-tree')
              throw Error('refresh unavailable');
          },
          setEditorError: (message: string) => errors.push(message),
          setTree: (update: any) => {
            tree = update(tree);
            fallback = find(tree, child);
          },
          findTreeNode: find,
          setSelectedNodeId: (value: string) => {
            selected = value;
          },
          setSelectedTreeNodeIds: () => {},
        };
        runInNewContext(script, context, { filename: 'vault-duplicate-ui.js' })(sourceNode);
        await new Promise(setImmediate);
        await new Promise(setImmediate);
        assert.deepEqual(JSON.parse(JSON.stringify(calls)), [
          mode === 'vault' ? { id, rowVersion: '7' } : { nodeId: id },
        ]);
        assert.equal(selected, outcome === 'reject' ? '' : child);
        if (outcome === 'refresh-fail' || (outcome === 'changed-tree' && mode === 'legacy')) {
          assert.equal(fallback.rowVersion, mode === 'vault' ? '1' : undefined);
          assert.equal(fallback.id, child);
          const siblings = nested ? tree[0].children : tree;
          assert.equal(siblings[mode === 'vault' ? 2 : 1].id, child);
          assert.match(errors.at(-1)!, /duplicated/);
        }
        if (outcome === 'changed-tree' && mode === 'vault') assert.equal(fallback, undefined);
        if (outcome === 'reject') {
          assert.equal(fallback, undefined);
          assert.equal(errors.at(-1), 'stale source');
        }
      }
  const coverage = await inspector.post('Profiler.takePreciseCoverage');
  await inspector.post('Profiler.stopPreciseCoverage');
  for (const needle of [
    'api.duplicateVaultConnection',
    'api.duplicateWorkspaceNode',
    'const { nodeId, name } = result',
    'rowVersion:',
  ]) {
    const offset = script.indexOf(needle);
    assert.ok(offset > 0);
    const ranges = coverage.result
      .filter((e) => e.url === 'vault-duplicate-ui.js')
      .flatMap((e) => e.functions.flatMap((f) => f.ranges))
      .filter((r) => r.startOffset <= offset && r.endOffset > offset);
    const smallest = Math.min(...ranges.map((r) => r.endOffset - r.startOffset));
    assert.ok(ranges.some((r) => r.endOffset - r.startOffset === smallest && r.count > 0));
  }
  t.diagnostic(
    'V8 executed every changed duplication dispatch/fallback statement in both workspace modes.',
  );
});
