import assert from 'node:assert/strict';
import test from 'node:test';

import {
  virtualGridColumnCount,
  virtualGridHeight,
  virtualGridRange,
  virtualGridScrollAnchor,
} from '../src/virtual-grid.ts';

test('virtual grid derives responsive column counts', () => {
  assert.equal(virtualGridColumnCount(279, 280, 16), 1);
  assert.equal(virtualGridColumnCount(575, 280, 16), 1);
  assert.equal(virtualGridColumnCount(576, 280, 16), 2);
  assert.equal(virtualGridColumnCount(872, 280, 16), 3);
});

test('virtual grid height includes row gaps without a trailing gap', () => {
  assert.equal(virtualGridHeight(0, 3, 176, 16), 0);
  assert.equal(virtualGridHeight(1, 3, 176, 16), 176);
  assert.equal(virtualGridHeight(7, 3, 176, 16), 560);
});

test('virtual grid renders only visible and overscan rows', () => {
  assert.deepEqual(virtualGridRange(1_000, 4, 0, 400, 140, 12, 2), {
    startRow: 0,
    endRow: 5,
    startIndex: 0,
    endIndex: 20,
    totalRows: 250,
  });

  assert.deepEqual(virtualGridRange(1_000, 4, 1_520, 400, 140, 12, 2), {
    startRow: 8,
    endRow: 15,
    startIndex: 32,
    endIndex: 60,
    totalRows: 250,
  });
});

test('virtual grid clamps the final range to the item count', () => {
  assert.deepEqual(virtualGridRange(10, 3, 10_000, 300, 176, 16, 2), {
    startRow: 1,
    endRow: 4,
    startIndex: 3,
    endIndex: 10,
    totalRows: 4,
  });
});

test('virtual grid anchors scroll updates to row boundaries', () => {
  assert.equal(virtualGridScrollAnchor(0, 176, 16), 0);
  assert.equal(virtualGridScrollAnchor(191, 176, 16), 0);
  assert.equal(virtualGridScrollAnchor(192, 176, 16), 192);
});
