import assert from 'node:assert/strict';
import test from 'node:test';

import {
  filterListSearchIndex,
  listSearchResultsArePending,
  normalizeListSearch,
} from '../src/list-search.ts';

test('list search normalization matches case-insensitive filtered views', () => {
  assert.equal(normalizeListSearch('  Office VPN  '), 'office vpn');
});

test('bulk actions wait while deferred results belong to an older query', () => {
  assert.equal(listSearchResultsArePending('prod', ''), true);
  assert.equal(listSearchResultsArePending('production', 'prod'), true);
  assert.equal(listSearchResultsArePending(' Production ', 'production'), false);
});

test('indexed list search filters in one pass and preserves the unfiltered list', () => {
  const items = [{ id: 'one' }, { id: 'two' }, { id: 'three' }];
  const index = [
    { item: items[0], text: 'production ssh' },
    { item: items[1], text: 'office vpn' },
    { item: items[2], text: 'production rdp' },
  ];

  assert.equal(filterListSearchIndex(items, index, ''), items);
  assert.deepEqual(filterListSearchIndex(items, index, 'production'), [items[0], items[2]]);
});
