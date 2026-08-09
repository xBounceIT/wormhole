import assert from 'node:assert/strict';
import test from 'node:test';
import { findParentFolderId, type TreeParentNode } from '../src/tree-parent.ts';

const tree: TreeParentNode[] = [
  { id: 'root-connection', kind: 'connection' },
  { id: 'first-folder', kind: 'folder', children: [] },
  {
    id: 'nested-folder',
    kind: 'folder',
    children: [{ id: 'nested-connection', kind: 'connection' }],
  },
];

test('root nodes do not resolve to the first available folder', () => {
  assert.equal(findParentFolderId(tree, 'root-connection'), undefined);
});

test('nested nodes resolve to their containing folder', () => {
  assert.equal(findParentFolderId(tree, 'nested-connection'), 'nested-folder');
});
