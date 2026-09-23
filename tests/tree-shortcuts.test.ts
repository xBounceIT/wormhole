import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { stripTypeScriptTypes } from 'node:module';
import { WorkspaceRefreshCoordinator } from '../src/workspace-refresh.ts';

import {
  canonicalizeConnectionTreeNodeIds,
  isEditableConnectionTreeShortcutTarget,
  resolveConnectionTreeShortcut,
  resolveVisibleConnectionTreeSelection,
  type ConnectionTreeShortcutContext,
  type ConnectionTreeShortcutEvent,
  type ConnectionTreeShortcutNode,
} from '../src/tree-shortcuts.ts';
import {
  isWormholeShortcutSuppressed,
  markWormholeShortcutSuppressed,
} from '../src/app-shortcuts.ts';
import {
  parseWorkspaceNodesRequest,
  parseWorkspaceMoveNodesRequest,
  workspaceDeleteNodesMaxRequestBytes,
} from '../electron/workspace-delete-contract.ts';

const tree: ConnectionTreeShortcutNode[] = [
  {
    id: 'folder',
    kind: 'folder',
    children: [
      { id: 'nested-connection', kind: 'connection' },
      { id: 'nested-folder', kind: 'folder' },
    ],
  },
  { id: 'root-connection', kind: 'connection' },
];

const baseEvent: ConnectionTreeShortcutEvent = {
  key: '',
  ctrlKey: false,
  metaKey: false,
  shiftKey: false,
  altKey: false,
};

const baseContext: ConnectionTreeShortcutContext = {
  unlocked: true,
  dialogOpen: false,
  editableTarget: false,
  portaledWidgetOpen: false,
  withinTree: true,
  deleteBusy: false,
  tree,
  visibleTree: tree,
  selectedNodeId: 'root-connection',
  selectedNodeIds: [],
};

function shortcutEvent(
  key: string,
  overrides: Partial<ConnectionTreeShortcutEvent> = {},
): ConnectionTreeShortcutEvent {
  return { ...baseEvent, key, ...overrides };
}

function shortcutContext(
  overrides: Partial<ConnectionTreeShortcutContext> = {},
): ConnectionTreeShortcutContext {
  return { ...baseContext, ...overrides };
}

test('creation accelerators always target the explicit root on Windows and macOS', () => {
  assert.deepEqual(
    resolveConnectionTreeShortcut(
      shortcutEvent('N', { ctrlKey: true, shiftKey: true }),
      shortcutContext({ selectedNodeId: 'folder', selectedNodeIds: ['folder'] }),
    ),
    { kind: 'new-folder', parentFolderId: null },
  );
  assert.deepEqual(
    resolveConnectionTreeShortcut(
      shortcutEvent('n', { metaKey: true }),
      shortcutContext({ selectedNodeId: 'folder' }),
    ),
    { kind: 'new-connection', parentFolderId: null },
  );
  assert.deepEqual(
    resolveConnectionTreeShortcut(
      shortcutEvent('n', { metaKey: true, shiftKey: true }),
      baseContext,
    ),
    { kind: 'new-folder', parentFolderId: null },
  );
  for (const modifiers of [
    { ctrlKey: true, altKey: true },
    { metaKey: true, altKey: true },
    { ctrlKey: true, metaKey: true },
    { ctrlKey: true, getModifierState: (key: string) => key === 'AltGraph' },
  ]) {
    assert.equal(resolveConnectionTreeShortcut(shortcutEvent('n', modifiers), baseContext), null);
  }
});

test('single-target accelerators prefer checked selection and reject multiple targets', () => {
  assert.deepEqual(
    resolveConnectionTreeShortcut(
      shortcutEvent('F2'),
      shortcutContext({
        selectedNodeId: 'root-connection',
        selectedNodeIds: ['nested-folder'],
      }),
    ),
    { kind: 'edit', nodeId: 'nested-folder' },
  );
  assert.deepEqual(resolveConnectionTreeShortcut(shortcutEvent('Enter'), baseContext), {
    kind: 'open',
    nodeId: 'root-connection',
  });
  assert.equal(
    resolveConnectionTreeShortcut(
      shortcutEvent('Enter'),
      shortcutContext({ selectedNodeId: 'folder' }),
    ),
    null,
  );
  assert.equal(
    resolveConnectionTreeShortcut(
      shortcutEvent('F2'),
      shortcutContext({ selectedNodeIds: ['nested-connection', 'root-connection'] }),
    ),
    null,
  );
});

test('delete canonicalizes multi-selection in tree order', () => {
  assert.deepEqual(
    canonicalizeConnectionTreeNodeIds(tree, [
      'root-connection',
      'nested-connection',
      'folder',
      'missing',
    ]),
    ['folder', 'root-connection'],
  );
  assert.deepEqual(canonicalizeConnectionTreeNodeIds(tree, ['folder', 'folder']), ['folder']);
  assert.deepEqual(
    resolveConnectionTreeShortcut(
      shortcutEvent('Delete'),
      shortcutContext({
        selectedNodeIds: ['root-connection', 'nested-connection', 'folder'],
      }),
    ),
    { kind: 'delete', nodeIds: ['folder', 'root-connection'] },
  );
  assert.equal(
    resolveConnectionTreeShortcut(shortcutEvent('Delete'), shortcutContext({ deleteBusy: true })),
    null,
  );
  assert.equal(
    resolveConnectionTreeShortcut(
      shortcutEvent('Delete'),
      shortcutContext({ selectedNodeId: '', selectedNodeIds: [] }),
    ),
    null,
  );
});

test('search projection excludes hidden selections and stale primary targets', () => {
  const visibleTree = [
    {
      id: 'folder',
      kind: 'folder' as const,
      children: [{ id: 'nested-connection', kind: 'connection' as const }],
    },
  ];
  assert.deepEqual(
    resolveConnectionTreeShortcut(
      shortcutEvent('F2'),
      shortcutContext({
        visibleTree,
        selectedNodeId: 'root-connection',
        selectedNodeIds: ['root-connection', 'nested-connection'],
      }),
    ),
    { kind: 'edit', nodeId: 'nested-connection' },
  );
  assert.equal(
    resolveConnectionTreeShortcut(
      shortcutEvent('Delete'),
      shortcutContext({ visibleTree, selectedNodeId: 'root-connection' }),
    ),
    null,
  );
  assert.deepEqual(
    resolveVisibleConnectionTreeSelection(visibleTree, 'nested-connection', [
      'root-connection',
      'nested-connection',
    ]),
    ['nested-connection'],
  );
});

test('guards block shortcuts while typing, in dialogs, outside the tree, or locked', () => {
  for (const context of [
    shortcutContext({ editableTarget: true }),
    shortcutContext({ dialogOpen: true }),
    shortcutContext({ portaledWidgetOpen: true }),
    shortcutContext({ unlocked: false }),
  ]) {
    assert.equal(
      resolveConnectionTreeShortcut(shortcutEvent('n', { ctrlKey: true }), context),
      null,
    );
  }

  assert.equal(
    resolveConnectionTreeShortcut(shortcutEvent('F2'), shortcutContext({ withinTree: false })),
    null,
  );
  assert.equal(
    resolveConnectionTreeShortcut(shortcutEvent('Delete', { isComposing: true }), baseContext),
    null,
  );
  assert.equal(
    resolveConnectionTreeShortcut(shortcutEvent('Delete', { repeat: true }), baseContext),
    null,
  );
  assert.equal(
    resolveConnectionTreeShortcut(
      shortcutEvent('n', { ctrlKey: true, isComposing: true }),
      baseContext,
    ),
    null,
  );
  assert.equal(
    resolveConnectionTreeShortcut(shortcutEvent('k', { metaKey: true, repeat: true }), baseContext),
    null,
  );
  assert.deepEqual(
    resolveConnectionTreeShortcut(
      shortcutEvent('k', { metaKey: true }),
      shortcutContext({ withinTree: false }),
    ),
    { kind: 'quick-connect' },
  );
});

test('Wormhole window handlers honor session shortcut suppression', () => {
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const sidebarSource = readFileSync(
    new URL('../src/components/ui/sidebar.tsx', import.meta.url),
    'utf8',
  );
  let receivedSelector = '';
  const sessionTarget = {
    closest(selector: string) {
      receivedSelector = selector;
      return {};
    },
  } as unknown as EventTarget;
  const ordinaryTarget = { closest: () => null } as unknown as EventTarget;
  const eventFor = (target: EventTarget | null) => ({ target }) as Event;

  assert.equal(isWormholeShortcutSuppressed(eventFor(sessionTarget)), true);
  assert.equal(receivedSelector, '[data-wormhole-shortcuts-disabled]');
  assert.equal(isWormholeShortcutSuppressed(eventFor(ordinaryTarget)), false);
  assert.equal(isWormholeShortcutSuppressed(eventFor(null)), false);

  const portaledSessionEvent = eventFor(ordinaryTarget);
  markWormholeShortcutSuppressed(portaledSessionEvent);
  assert.equal(isWormholeShortcutSuppressed(portaledSessionEvent), true);
  assert.equal(isWormholeShortcutSuppressed(eventFor(ordinaryTarget)), false);

  for (const source of [appSource, sidebarSource]) {
    assert.match(
      source,
      /const handleKeyDown = \(event: KeyboardEvent\) => \{\s*if \(isWormholeShortcutSuppressed\(event\)\) return;/,
    );
  }
});

test('editable-target classification covers form controls and contenteditable surfaces', () => {
  for (const tagName of ['INPUT', 'textarea', 'Select']) {
    assert.equal(isEditableConnectionTreeShortcutTarget({ tagName }), true);
  }
  assert.equal(isEditableConnectionTreeShortcutTarget({ isContentEditable: true }), true);
  assert.equal(isEditableConnectionTreeShortcutTarget({ isContentEditable: false }), false);
  assert.equal(isEditableConnectionTreeShortcutTarget({ tagName: 'button' }), false);
});

test('irrelevant tree keys do not traverse the tree selection', () => {
  const poisonNode = { id: 'poison', kind: 'folder' as const } as ConnectionTreeShortcutNode;
  Object.defineProperty(poisonNode, 'children', {
    get() {
      throw new Error('tree traversal was not expected');
    },
  });

  assert.equal(
    resolveConnectionTreeShortcut(
      shortcutEvent('ArrowDown'),
      shortcutContext({ tree: [poisonNode], visibleTree: [poisonNode] }),
    ),
    null,
  );
});

test('workspace deletion closes current sessions and preserves concurrent session changes', () => {
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = appSource.indexOf('async function closeSessionsForNodeIds(');
  const end = appSource.indexOf('const releaseSessionResourcesRef', start);
  assert.ok(start >= 0 && end > start, 'missing workspace session cleanup');
  const cleanupSource = appSource.slice(start, end);

  // Backend deletion and resource release can finish after session state changes.
  assert.match(
    cleanupSource,
    /const closing = sessionsRef\.current\.filter\(\s*\(session\) => session\.nodeId && nodeIds\.has\(session\.nodeId\)/,
  );
  assert.match(
    cleanupSource,
    /setSessions\(\(current\) => current\.filter\(\(session\) => !closingIds\.has\(session\.id\)\)\)/,
  );
});

test('workspace deletion rereads the tree across backend and session cleanup awaits', () => {
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = appSource.indexOf('async function confirmDeleteNodes()');
  const end = appSource.indexOf('function duplicateConnection(', start);
  assert.ok(start >= 0 && end > start, 'missing workspace deletion handler');
  const deletion = appSource.slice(start, end);

  assert.match(deletion, /const currentTree = treeRef\.current/);
  assert.match(deletion, /canonicalizeConnectionTreeNodeIds\(currentTree, requestedNodeIds\)/);
  assert.match(
    deletion,
    /const reconcileDeletedNodes = async \(\) => \{\s*const latestTree = treeRef\.current;[\s\S]*?findTreeNode\(latestTree, nodeId\)/,
  );
  assert.match(
    deletion,
    /await closeSessionsForNodeIds\(latestDeletedNodeIds\);\s*const treeAfterSessionClose = treeRef\.current;\s*applyDeletedTreeState\(\s*extractTreeNodes\(treeAfterSessionClose,/,
  );
  assert.match(
    deletion,
    /await api\.deleteWorkspaceNodes\([\s\S]*?await reconcileDeletedNodes\(\)/,
  );
});

test('workspace batch deletion IPC accepts one or many IDs and deduplicates in request order', () => {
  assert.deepEqual(parseWorkspaceNodesRequest({ nodeIds: ['one'] }), { nodeIds: ['one'] });
  assert.deepEqual(parseWorkspaceNodesRequest({ nodeIds: ['two', 'one', 'two'] }), {
    nodeIds: ['two', 'one'],
  });
});

test('workspace batch deletion IPC rejects empty, sparse, malformed, and oversized arrays', () => {
  const sparse = new Array<string>(1);
  for (const nodeIds of [
    [],
    sparse,
    [''],
    [' spaced '],
    ['line\nbreak'],
    [42],
    ['x'.repeat(129)],
    Array.from({ length: 1_001 }, (_, index) => `node-${index}`),
  ]) {
    assert.throws(() => parseWorkspaceNodesRequest({ nodeIds }));
  }
});

test('workspace batch deletion IPC uses the backend UTF-8 ID boundary', () => {
  assert.deepEqual(parseWorkspaceNodesRequest({ nodeIds: ['é'.repeat(64)] }), {
    nodeIds: ['é'.repeat(64)],
  });
  assert.throws(() => parseWorkspaceNodesRequest({ nodeIds: ['é'.repeat(65)] }));
});

test('maximum valid workspace batch fits its dedicated Electron backend wire limit', () => {
  const request = parseWorkspaceNodesRequest({
    nodeIds: Array.from(
      { length: 1_000 },
      (_, index) => `${'\\'.repeat(120)}${String(index).padStart(8, '0')}`,
    ),
  });
  const payloadBytes = Buffer.byteLength(JSON.stringify(request), 'utf8');
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');

  assert.ok(payloadBytes > 64 * 1024);
  assert.ok(payloadBytes <= workspaceDeleteNodesMaxRequestBytes);
  assert.match(mainSource, /operation === 'workspace-delete-nodes'/);
});

test('workspace moves validate bounded source and target IDs and placement', () => {
  for (const placement of ['inside', 'before', 'after'] as const) {
    assert.deepEqual(
      parseWorkspaceMoveNodesRequest({
        nodeIds: ['one', 'one', 'two'],
        targetId: 'folder',
        placement,
      }),
      { nodeIds: ['one', 'two'], targetId: 'folder', placement },
    );
  }
  for (const value of [
    null,
    {},
    { nodeIds: [] },
    { nodeIds: new Array(1) },
    { nodeIds: ['one'], targetId: '', placement: 'inside' },
    { nodeIds: ['one'], targetId: 'folder', placement: 'sideways' },
    { nodeIds: ['one'], targetId: 'x'.repeat(129), placement: 'inside' },
    { nodeIds: ['one'], targetId: 'folder\n', placement: 'inside' },
  ]) {
    assert.throws(() => parseWorkspaceMoveNodesRequest(value));
  }
});

// Exercise the actual TSX event handler with a controlled bridge. The application
// entrypoint is excluded from Node's loaded-module coverage by test-coverage.ts.
test('tree drop commits before refreshing and leaves the tree intact on save failures', async () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('  async function handleTreeDrop(');
  const end = source.indexOf('  function handleTreeDragEnd', start);
  assert.ok(start >= 0 && end > start);
  const refreshStart = source.indexOf('  async function refreshWorkspace(');
  const refreshEnd = source.indexOf(
    '  async function saveRuntimeConnectionCredential(',
    refreshStart,
  );
  const handler = stripTypeScriptTypes(
    source.slice(start, end) + source.slice(refreshStart, refreshEnd),
  );
  for (const scenario of [
    'saved',
    'local',
    'unavailable',
    'mixed',
    'local-target',
    'rejected',
    'error',
    'reload-error',
  ]) {
    const calls: string[] = [];
    const persisted = scenario !== 'local';
    const nodes = [
      { id: 'source', persisted },
      { id: 'other', persisted: scenario !== 'mixed' && persisted },
    ];
    let releaseSave: () => void = () => {};
    const saving = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    const api = {
      async moveWorkspaceNodes(request: unknown) {
        assert.deepEqual(request, {
          nodeIds: ['source', 'other'],
          targetId: 'deep',
          placement: 'inside',
        });
        calls.push('save');
        await saving;
        if (scenario === 'error') throw new Error('save failed');
        return { moved: scenario !== 'rejected' };
      },
      async loadWorkspace() {
        calls.push('load');
        if (scenario === 'reload-error') throw new Error('reload failed');
        return { tree: 'persisted tree' };
      },
    };
    const bindings = {
      draggedNodeIds: ['source', 'other'],
      searchText: '',
      tree: nodes,
      workspaceRefresh: new WorkspaceRefreshCoordinator(),
      treeMovePending: { current: false },
      treeRef: { current: nodes },
      window: { wormhole: scenario === 'unavailable' ? undefined : api },
      getTreeDropPlacement: () => 'inside',
      canDropTreeNodes: () => true,
      findTreeNode: (_tree: unknown, id: string) => nodes.find((node) => node.id === id),
      applyWorkspaceSnapshot: (snapshot: unknown) => {
        assert.deepEqual(snapshot, { tree: 'persisted tree' });
        calls.push('apply');
      },
      setTree: (update: (value: unknown) => unknown) => {
        update(nodes);
        calls.push('local');
      },
      moveTreeNodes: () => nodes,
      setTreeMoveError: (message: string) => {
        if (!message) return;
        if (scenario === 'reload-error') assert.match(message, /^Move saved, but/);
        calls.push('error');
      },
      setDraggedNodeIds: () => {},
      setDropTarget: () => {},
      setSelectedNodeId: () => {
        calls.push('select');
      },
      toggleFolder: () => {},
    };
    const drop = new Function(...Object.keys(bindings), `${handler}; return handleTreeDrop;`)(
      ...Object.values(bindings),
    );
    const pending = drop(
      { preventDefault() {} },
      { id: 'deep', persisted: scenario !== 'local-target' && persisted },
    );
    assert.ok(!calls.includes('load') && !calls.includes('apply'), 'must wait for persistence');
    releaseSave();
    await pending;
    const expected =
      scenario === 'saved'
        ? ['save', 'load', 'apply', 'select']
        : scenario === 'local'
          ? ['local', 'select']
          : scenario === 'rejected' || scenario === 'error'
            ? ['save', 'error']
            : scenario === 'reload-error'
              ? ['save', 'load', 'local', 'error', 'select']
              : ['error'];
    assert.deepEqual(calls, expected, scenario);
    assert.equal(bindings.treeMovePending.current, false, scenario);
  }
});

test('a pending tree move blocks a second drop until its refresh completes', async () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('  async function handleTreeDrop(');
  const end = source.indexOf('  function handleTreeDragEnd', start);
  let saveCount = 0;
  let signalLoading = () => {};
  let finishLoading = () => {};
  const loadingStarted = new Promise<void>((resolve) => {
    signalLoading = resolve;
  });
  const loading = new Promise<void>((resolve) => {
    finishLoading = resolve;
  });
  const tree = [{ id: 'source', persisted: true }];
  const bindings = {
    draggedNodeIds: ['source'],
    searchText: '',
    tree,
    workspaceRefresh: new WorkspaceRefreshCoordinator(),
    treeMovePending: { current: false },
    treeRef: { current: tree },
    window: {
      wormhole: {
        async moveWorkspaceNodes() {
          saveCount++;
          return { moved: true };
        },
        async loadWorkspace() {
          signalLoading();
          await loading;
          return { tree };
        },
      },
    },
    getTreeDropPlacement: () => 'inside',
    canDropTreeNodes: () => true,
    findTreeNode: () => tree[0],
    applyWorkspaceSnapshot: () => {},
    setTreeMoveError: () => {},
    setEditorError: () => {},
    setDraggedNodeIds: () => {},
    setDropTarget: () => {},
    setSelectedNodeId: () => {},
    toggleFolder: () => {},
  };
  const refreshStart = source.indexOf('  async function refreshWorkspace(');
  const refreshEnd = source.indexOf(
    '  async function saveRuntimeConnectionCredential(',
    refreshStart,
  );
  const drop = new Function(
    ...Object.keys(bindings),
    `${stripTypeScriptTypes(source.slice(start, end) + source.slice(refreshStart, refreshEnd))}; return handleTreeDrop;`,
  )(...Object.values(bindings));
  const first = drop({ preventDefault() {} }, { id: 'deep', persisted: true });
  await loadingStarted;
  const second = drop({ preventDefault() {} }, { id: 'deep', persisted: true });
  finishLoading();
  await Promise.all([first, second]);
  assert.equal(saveCount, 1, 'the second drop must not start another save or stale refresh');
  assert.equal(bindings.treeMovePending.current, false);
  await drop({ preventDefault() {} }, { id: 'deep', persisted: true });
  assert.equal(saveCount, 2, 'a completed move must release the guard');
});

test('tree move errors are rendered in the visible connection sidebar', () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('<SidebarContent');
  const sidebar = source.slice(start, source.indexOf('</SidebarContent>', start));
  assert.match(sidebar, /role="alert"[\s\S]*?\{treeMoveError\}/);
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

test('workspace refresh ignores an older success or failure even when it completes last', async () => {
  for (const staleFails of [false, true]) {
    const coordinator = new WorkspaceRefreshCoordinator();
    const old = deferred<string>();
    const applied: string[] = [];
    const first = coordinator.refresh(
      () => old.promise,
      (value) => applied.push(value),
    );
    assert.equal(
      await coordinator.refresh(
        async () => 'after move',
        (value) => applied.push(value),
      ),
      true,
    );
    if (staleFails) old.reject(new Error('stale failure'));
    else old.resolve('before move');
    assert.equal(await first, false);
    assert.deepEqual(applied, ['after move']);
  }
});

test('workspace invalidation and a failed newest refresh never resurrect an older snapshot', async () => {
  for (const failNewest of [false, true]) {
    const coordinator = new WorkspaceRefreshCoordinator();
    const old = deferred<string>();
    const applied: string[] = [];
    const pending = coordinator.refresh(
      () => old.promise,
      (value) => applied.push(value),
    );
    if (failNewest) {
      await assert.rejects(
        coordinator.refresh(
          async () => {
            throw new Error('latest failed');
          },
          () => {},
        ),
        /latest failed/,
      );
    } else coordinator.invalidate();
    old.resolve('stale');
    assert.equal(await pending, false);
    assert.deepEqual(applied, []);
    assert.equal(
      await coordinator.refresh(
        async () => 'recovered',
        (value) => applied.push(value),
      ),
      true,
    );
    assert.deepEqual(applied, ['recovered']);
  }
});

test('a duplicate refresh completing after a committed move cannot revert the tree', async () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const extract = (start: string, end: string) => {
    const from = source.indexOf(start);
    const to = source.indexOf(end, from);
    assert.ok(from >= 0 && to > from);
    return source.slice(from, to);
  };
  const code = stripTypeScriptTypes(
    extract('  async function handleTreeDrop(', '  function handleTreeDragEnd') +
      extract('  function duplicateConnection(', '  function openEditConnection') +
      extract(
        '  async function refreshWorkspace(',
        '  async function saveRuntimeConnectionCredential',
      ),
  );
  const old = deferred<{ revision: number }>();
  const started = deferred<void>();
  const node = { id: 'source', kind: 'connection', persisted: true };
  const applied: number[] = [];
  let loads = 0;
  const bindings = {
    workspaceRefresh: new WorkspaceRefreshCoordinator(),
    treeMovePending: { current: false },
    treeRef: { current: [node] },
    draggedNodeIds: ['source'],
    searchText: '',
    window: {
      wormhole: {
        async duplicateWorkspaceNode() {
          return { nodeId: 'copy', name: 'Copy' };
        },
        async moveWorkspaceNodes() {
          return { moved: true };
        },
        async loadWorkspace() {
          loads++;
          if (loads === 1) {
            started.resolve();
            return old.promise;
          }
          return { revision: 2 };
        },
      },
    },
    canDropTreeNodes: () => true,
    getTreeDropPlacement: () => 'inside',
    findTreeNode: () => node,
    applyWorkspaceSnapshot: (snapshot: { revision: number }) => applied.push(snapshot.revision),
    setTreeMoveError: () => {},
    setSelectedNodeId: () => {},
    setSelectedTreeNodeIds: () => {},
    setDraggedNodeIds: () => {},
    setDropTarget: () => {},
    toggleFolder: () => {},
    setTree: () => assert.fail('stale refresh must not trigger local fallback'),
    setEditorError: () => assert.fail('stale refresh must not report an error'),
  };
  const { drop, duplicate } = new Function(
    ...Object.keys(bindings),
    `${code};return {drop:handleTreeDrop,duplicate:duplicateConnection};`,
  )(...Object.values(bindings));
  duplicate(node);
  await started.promise;
  await drop({ preventDefault() {} }, { id: 'deep', persisted: true });
  assert.deepEqual(applied, [2]);
  old.resolve({ revision: 1 });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.deepEqual(applied, [2]);
});

test('all mounted-workspace snapshot loads use the shared refresh coordinator', () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const importer = readFileSync(
    new URL('../src/components/MRemoteImportDialog.tsx', import.meta.url),
    'utf8',
  );
  assert.equal(source.match(/\.loadWorkspace\(/g)?.length, 1);
  assert.doesNotMatch(importer, /\.loadWorkspace\(/);
  assert.match(source, /onBackupImported=\{\(\) => refreshWorkspace\(true\)\}/);
  assert.match(source, /onImported=\{refreshWorkspace\}/);
  assert.match(importer, /await onImported\(\)/);
});
