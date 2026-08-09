import assert from 'node:assert/strict';
import test from 'node:test';

import { backupExportPasswordsMatch } from '../src/backup-state.ts';

test('plaintext export ignores a stale disabled confirmation', () => {
  assert.equal(backupExportPasswordsMatch('', 'previous encrypted password'), true);
});

test('encrypted export still requires an exact confirmation', () => {
  assert.equal(backupExportPasswordsMatch('secret', 'different'), false);
  assert.equal(backupExportPasswordsMatch('secret', 'secret'), true);
});

test('encrypted export confirmation follows the backend NFC password semantics', () => {
  assert.equal(backupExportPasswordsMatch('Cafe\u0301', 'Caf\u00e9'), true);
});
