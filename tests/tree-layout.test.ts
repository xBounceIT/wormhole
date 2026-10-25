import assert from 'node:assert/strict';
import test from 'node:test';
import {
  getTreeRowGeometry,
  getTreeRowStyles,
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

test('tree depth rejects invalid values', () => {
  assert.throws(() => getTreeRowGeometry(-1), RangeError);
  assert.throws(() => getTreeRowGeometry(1.5), RangeError);
});

test('tree row styles reserve room for controls and labels without capping the depth', () => {
  assert.deepEqual(getTreeRowStyles(0), {
    paddingLeft: 'min(8px, calc(100% - 112px))',
    branch: null,
  });
  for (const [depth, requestedInset] of [
    [2, 52],
    [16, 360],
    [4096, 90120],
  ]) {
    const styles = getTreeRowStyles(depth);
    assert.equal(styles.paddingLeft, `min(${requestedInset}px, calc(100% - 112px))`);
    assert.ok(styles.branch);
    const parentInset = `min(${requestedInset - 22}px, calc(100% - 112px))`;
    assert.equal(styles.branch.left, `calc(${parentInset} + 8px)`);
  }
});

test('tree row styles keep connectors bounded in either direction', () => {
  const { paddingLeft, branch } = getTreeRowStyles(2);
  assert.ok(branch);
  assert.equal(branch.connectorLeft, `min(${paddingLeft}, calc(${branch.left} + 1px))`);
  assert.equal(
    branch.connectorWidth,
    `max(calc(${paddingLeft} - ${branch.left} - 1px), calc(${branch.left} - ${paddingLeft}))`,
  );
});

test('tree row styles reject invalid depths before producing CSS', () => {
  for (const depth of [-1, 0.5, NaN, Infinity])
    assert.throws(() => getTreeRowStyles(depth), RangeError);
});
