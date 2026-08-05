import assert from 'node:assert/strict';
import test from 'node:test';

import { mergeCredential } from '../src/credential-state.ts';

test('credential merge matches SQLite BINARY ordering for Unicode names', () => {
  const merged = mergeCredential(
    [
      { id: '3', name: 'ASCII' },
      { id: '1', name: '\u{e000}' },
    ],
    { id: '2', name: '\u{10000}' },
  );

  assert.deepEqual(
    merged.map((credential) => credential.id),
    ['3', '1', '2'],
  );
});

test('credential merge replaces an existing id without duplicating it', () => {
  const merged = mergeCredential(
    [
      { id: '1', name: 'Old name' },
      { id: '2', name: 'Second' },
    ],
    { id: '1', name: 'Updated' },
  );

  assert.deepEqual(merged, [
    { id: '2', name: 'Second' },
    { id: '1', name: 'Updated' },
  ]);
});
