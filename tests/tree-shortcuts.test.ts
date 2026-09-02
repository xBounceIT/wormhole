import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  canonicalizeConnectionTreeNodeIds,
  isEditableConnectionTreeShortcutTarget,
  resolveConnectionTreeShortcut,
  resolveVisibleConnectionTreeSelection,
  type ConnectionTreeShortcutContext,
  type ConnectionTreeShortcutEvent,
  type ConnectionTreeShortcutNode,
} from '../src/tree-shortcuts.ts';
import { isWormholeShortcutSuppressed } from '../src/app-shortcuts.ts';
import {
  parseWorkspaceNodesRequest,
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
  assert.equal(
    resolveConnectionTreeShortcut(
      shortcutEvent('n', { ctrlKey: true, metaKey: true }),
      baseContext,
    ),
    null,
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

  assert.equal(isWormholeShortcutSuppressed(sessionTarget), true);
  assert.equal(receivedSelector, '[data-wormhole-shortcuts-disabled]');
  assert.equal(isWormholeShortcutSuppressed(ordinaryTarget), false);
  assert.equal(isWormholeShortcutSuppressed(null), false);

  for (const source of [appSource, sidebarSource]) {
    assert.match(
      source,
      /const handleKeyDown = \(event: KeyboardEvent\) => \{\s*if \(isWormholeShortcutSuppressed\(event\.target\)\) return;/,
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

test('async batch deletion reconciles against current tree and session state', () => {
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');

  assert.match(appSource, /const treeRef = useRef\(tree\)/);
  assert.match(appSource, /const currentTree = treeRef\.current/);
  assert.match(appSource, /const closing = sessionsRef\.current\.filter/);
  assert.match(appSource, /setSessions\(\(current\) => current\.filter/);
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
