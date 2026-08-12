import assert from 'node:assert/strict';
import test from 'node:test';
import {
  maxConnectionTreeExpansionFolderIdBytes,
  maxConnectionTreeExpansionFolderIds,
  parseConnectionTreeExpansionSetting,
} from '../electron/connection-tree-settings.ts';
import {
  createConnectionTreeExpansionWriter,
  indexConnectionTree,
  reconcileExpandedFolderIds,
  restoreExpandedFolderIds,
  serializeConnectionTreeExpansion,
  shouldRenderConnectionTreeChildren,
  type ConnectionTreeStateNode,
} from '../src/connection-tree-state.ts';

const tree: ConnectionTreeStateNode[] = [
  { id: 'root-connection', kind: 'connection' },
  {
    id: 'first-folder',
    kind: 'folder',
    children: [
      { id: 'nested-connection', kind: 'connection' },
      { id: 'nested-folder', kind: 'folder', children: [] },
    ],
  },
];

test('tree index collects folders and parents in one traversal', () => {
  const index = indexConnectionTree(tree);

  assert.deepEqual(index.folderIds, ['first-folder', 'nested-folder']);
  assert.equal(index.parentFolderIdByNodeId.get('nested-connection'), 'first-folder');
  assert.equal(index.parentFolderIdByNodeId.get('nested-folder'), 'first-folder');
  assert.equal(index.parentFolderIdByNodeId.has('root-connection'), false);
});

test('tree index handles deeply nested imports without recursive stack growth', () => {
  let nested: ConnectionTreeStateNode = { id: 'leaf', kind: 'connection' };
  for (let depth = 0; depth < 10_000; depth++) {
    nested = { id: `folder-${depth}`, kind: 'folder', children: [nested] };
  }

  const index = indexConnectionTree([nested]);
  assert.equal(index.folderIds.length, 10_000);
  assert.equal(index.parentFolderIdByNodeId.get('leaf'), 'folder-0');
});

test('restored expansion distinguishes missing state from an explicit collapse-all', () => {
  const folderIds = indexConnectionTree(tree).folderIds;

  assert.deepEqual([...restoreExpandedFolderIds(folderIds, null)], folderIds);
  assert.deepEqual(
    [...restoreExpandedFolderIds(folderIds, { defaultExpanded: false, folderIds: [] })],
    [],
  );
  assert.deepEqual(
    [
      ...restoreExpandedFolderIds(folderIds, {
        defaultExpanded: false,
        folderIds: ['nested-folder', 'deleted-folder'],
      }),
    ],
    ['nested-folder'],
  );
  assert.deepEqual(
    [
      ...restoreExpandedFolderIds(folderIds, {
        defaultExpanded: true,
        folderIds: ['nested-folder', 'deleted-folder'],
      }),
    ],
    ['first-folder'],
  );
});

test('serialized expansion stores the smaller side of a large tree', () => {
  const folderIds = ['a', 'b', 'c', 'd'];
  assert.deepEqual(serializeConnectionTreeExpansion(folderIds, new Set(folderIds)), {
    defaultExpanded: true,
    folderIds: [],
  });
  assert.deepEqual(serializeConnectionTreeExpansion(folderIds, new Set(['a'])), {
    defaultExpanded: false,
    folderIds: ['a'],
  });
  assert.deepEqual(serializeConnectionTreeExpansion(folderIds, new Set(['a', 'b', 'c'])), {
    defaultExpanded: true,
    folderIds: ['d'],
  });
});

test('collapsed tree branches do not render their descendants', () => {
  assert.equal(shouldRenderConnectionTreeChildren(true, true), true);
  assert.equal(shouldRenderConnectionTreeChildren(true, false), false);
  assert.equal(shouldRenderConnectionTreeChildren(false, true), false);
});

test('expansion reconciliation prunes deleted folders and preserves stable sets', () => {
  const current = new Set(['first-folder']);
  assert.equal(reconcileExpandedFolderIds(['first-folder', 'nested-folder'], current), current);
  assert.deepEqual([...reconcileExpandedFolderIds(['nested-folder'], current)], []);
});

test('expansion writes debounce, compact, and skip unchanged state', async () => {
  const callbacks: Array<() => void> = [];
  const writes: Array<{ defaultExpanded: boolean; folderIds: string[] }> = [];
  const writer = createConnectionTreeExpansionWriter((state) => writes.push(state), {
    delayMs: 250,
    initialState: { defaultExpanded: false, folderIds: ['first-folder'] },
    scheduler: {
      set(callback) {
        callbacks.push(callback);
        return callbacks.length - 1;
      },
      clear(handle) {
        callbacks[handle as number] = () => undefined;
      },
    },
  });

  const folderIds = ['first-folder', 'nested-folder'];
  writer.schedule(folderIds, new Set(['first-folder']));
  writer.schedule(folderIds, new Set(['nested-folder', 'first-folder']));
  for (const callback of callbacks) callback();
  await writer.flush();
  assert.deepEqual(writes, [{ defaultExpanded: true, folderIds: [] }]);

  writer.schedule(folderIds, new Set());
  await writer.flush();
  assert.deepEqual(writes, [
    { defaultExpanded: true, folderIds: [] },
    { defaultExpanded: false, folderIds: [] },
  ]);
});

test('failed debounced persistence remains pending for a later flush', async () => {
  let attempts = 0;
  let callback = () => undefined;
  const writer = createConnectionTreeExpansionWriter(
    async () => {
      attempts++;
      if (attempts === 1) throw new Error('backend unavailable');
    },
    {
      scheduler: {
        set(next) {
          callback = next;
          return 1;
        },
        clear() {},
      },
    },
  );

  writer.schedule(['first-folder'], new Set(['first-folder']));
  callback();
  await new Promise((resolve) => setImmediate(resolve));
  await writer.flush();
  assert.equal(attempts, 2);
});

test('an expansion change queued during a write is persisted afterwards', async () => {
  let finishFirstWrite = () => undefined;
  const writes: Array<{ defaultExpanded: boolean; folderIds: string[] }> = [];
  const writer = createConnectionTreeExpansionWriter(async (state) => {
    writes.push(state);
    if (writes.length === 1) {
      await new Promise<void>((resolve) => {
        finishFirstWrite = resolve;
      });
    }
  });

  const folderIds = ['first-folder', 'nested-folder'];
  writer.schedule(folderIds, new Set(['first-folder']));
  const firstFlush = writer.flush();
  await new Promise((resolve) => setImmediate(resolve));
  writer.schedule(folderIds, new Set(['nested-folder']));
  finishFirstWrite();
  await firstFlush;
  await writer.flush();

  assert.deepEqual(writes, [
    { defaultExpanded: false, folderIds: ['first-folder'] },
    { defaultExpanded: false, folderIds: ['nested-folder'] },
  ]);
});

test('Electron validates bounded connection tree expansion settings', () => {
  assert.deepEqual(
    parseConnectionTreeExpansionSetting({
      defaultExpanded: true,
      folderIds: ['folder-a', 'folder-a'],
    }),
    { defaultExpanded: true, folderIds: ['folder-a'] },
  );
  assert.throws(() => parseConnectionTreeExpansionSetting(null));
  assert.throws(() =>
    parseConnectionTreeExpansionSetting({ defaultExpanded: 'yes', folderIds: [] }),
  );
  assert.throws(() =>
    parseConnectionTreeExpansionSetting({ defaultExpanded: false, folderIds: [''] }),
  );
  assert.throws(() =>
    parseConnectionTreeExpansionSetting({
      defaultExpanded: false,
      folderIds: ['x'.repeat(maxConnectionTreeExpansionFolderIdBytes + 1)],
    }),
  );
  assert.throws(() =>
    parseConnectionTreeExpansionSetting({
      defaultExpanded: false,
      folderIds: new Array(maxConnectionTreeExpansionFolderIds + 1),
    }),
  );
  for (const folderIds of [new Array(1), [' folder'], ['folder\n']]) {
    assert.throws(() => parseConnectionTreeExpansionSetting({ defaultExpanded: false, folderIds }));
  }
});
