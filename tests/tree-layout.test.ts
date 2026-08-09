import assert from 'node:assert/strict';
import test from 'node:test';
import {
  getTreeRowGeometry,
  treeBranchRailWidth,
  treeSelectionSlotWidth,
  treeSlotGap,
} from '../src/tree-layout.ts';

test('root rows have no branch and share the root inset', () => {
  assert.deepEqual(getTreeRowGeometry(0), { paddingLeft: 8, branch: null });
});

test('child selection slots align with their parent disclosure slots', () => {
  const parent = getTreeRowGeometry(0);
  const child = getTreeRowGeometry(1);

  assert.equal(child.paddingLeft, parent.paddingLeft + treeSelectionSlotWidth + treeSlotGap);
});

test('branch rails center on the parent selection slot', () => {
  const parent = getTreeRowGeometry(1);
  const child = getTreeRowGeometry(2);

  assert.ok(child.branch);
  assert.equal(child.branch.left, parent.paddingLeft + treeSelectionSlotWidth / 2);
});

test('horizontal connectors start after the vertical rail', () => {
  const geometry = getTreeRowGeometry(1);

  assert.ok(geometry.branch);
  assert.equal(geometry.branch.connectorLeft, geometry.branch.left + treeBranchRailWidth);
  assert.equal(
    geometry.branch.connectorLeft + geometry.branch.connectorWidth,
    geometry.branch.left + geometry.branch.width,
  );
});

test('branch connectors end at the checkbox slot', () => {
  for (const depth of [1, 2, 3, 12]) {
    const geometry = getTreeRowGeometry(depth);
    assert.ok(geometry.branch);
    assert.equal(geometry.branch.left + geometry.branch.width, geometry.paddingLeft);
    assert.ok(geometry.branch.width > 0);
  }
});

test('connection branch connectors stop before the protocol icon rail', () => {
  const geometry = getTreeRowGeometry(2);
  assert.ok(geometry.branch);
  assert.equal(geometry.branch.left + geometry.branch.width, geometry.paddingLeft);
});

test('tree depth rejects invalid values', () => {
  assert.throws(() => getTreeRowGeometry(-1), RangeError);
  assert.throws(() => getTreeRowGeometry(1.5), RangeError);
});
