import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canonicalizeConnectionTreeNodeIds,
  isEditableConnectionTreeShortcutTarget,
  resolveConnectionTreeShortcut,
  type ConnectionTreeShortcutContext,
  type ConnectionTreeShortcutEvent,
  type ConnectionTreeShortcutNode,
} from '../src/tree-shortcuts.ts';

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
});

test('guards block shortcuts while typing, in dialogs, outside the tree, or locked', () => {
  for (const context of [
    shortcutContext({ editableTarget: true }),
    shortcutContext({ dialogOpen: true }),
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
  assert.deepEqual(
    resolveConnectionTreeShortcut(
      shortcutEvent('k', { metaKey: true }),
      shortcutContext({ withinTree: false }),
    ),
    { kind: 'quick-connect' },
  );
});

test('editable-target classification covers form controls and contenteditable surfaces', () => {
  for (const tagName of ['INPUT', 'textarea', 'Select']) {
    assert.equal(isEditableConnectionTreeShortcutTarget({ tagName }), true);
  }
  assert.equal(isEditableConnectionTreeShortcutTarget({ isContentEditable: true }), true);
  assert.equal(isEditableConnectionTreeShortcutTarget({ tagName: 'button' }), false);
});
