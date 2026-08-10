import assert from 'node:assert/strict';
import test from 'node:test';

import {
  backupExportPasswordIsValid,
  backupExportPasswordsMatch,
  backupExportRequiresEncryption,
} from '../src/backup-state.ts';

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

test('backup export requires encryption only for local SSH key credentials', () => {
  assert.equal(
    backupExportRequiresEncryption([
      { kind: 'password', provider: 'Local' },
      { kind: 'sshKey', provider: 'Bitwarden' },
    ]),
    false,
  );
  assert.equal(backupExportRequiresEncryption([{ kind: 'sshKey', provider: 'Local' }]), true);
});

test('required backup encryption rejects a blank password before export', () => {
  assert.equal(backupExportPasswordIsValid('', '', true), false);
  assert.equal(backupExportPasswordIsValid('secret', 'different', true), false);
  assert.equal(backupExportPasswordIsValid('secret', 'secret', true), true);
  assert.equal(backupExportPasswordIsValid('', 'stale confirmation', false), true);
});
