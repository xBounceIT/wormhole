import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isBitwardenUnlockError,
  requiresSshCredentialPrompt,
} from '../src/runtime-credential-errors.ts';

test('locked Bitwarden errors preserve the vault unlock flow', () => {
  assert.equal(isBitwardenUnlockError('Bitwarden vault is locked or the session is invalid'), true);
  assert.equal(isBitwardenUnlockError('The linked Bitwarden item was not found'), false);
  assert.equal(isBitwardenUnlockError(undefined), false);
});

test('unavailable Bitwarden credentials fall back to the SSH credential prompt', () => {
  assert.equal(requiresSshCredentialPrompt('The linked Bitwarden item was not found'), true);
  assert.equal(requiresSshCredentialPrompt('Bitwarden credential is unavailable'), true);
});

test('pruned virtual Bitwarden references fall back to the SSH credential prompt', () => {
  assert.equal(requiresSshCredentialPrompt('SSH credential was not found'), true);
  assert.equal(requiresSshCredentialPrompt('Wormhole database has no SSH credentials'), true);
});

test('missing SSH account details and local secrets fall back to the credential prompt', () => {
  assert.equal(requiresSshCredentialPrompt('SSH connection has no username'), true);
  assert.equal(requiresSshCredentialPrompt('The connection has no usable SSH credential'), true);
  assert.equal(
    requiresSshCredentialPrompt('The selected credential is not an SSH credential'),
    true,
  );
  assert.equal(
    requiresSshCredentialPrompt('Could not read the SSH password: stored SSH secret is missing'),
    true,
  );
});

test('transport and saved-credential rejection errors do not open a fallback prompt', () => {
  assert.equal(requiresSshCredentialPrompt('SSH connection timed out.'), false);
  assert.equal(requiresSshCredentialPrompt('SSH authentication failed.'), false);
  assert.equal(
    requiresSshCredentialPrompt(
      'Bitwarden credential was rejected by the SSH server: Permission denied.',
    ),
    false,
  );
  assert.equal(requiresSshCredentialPrompt('Host key mismatch.'), false);
  assert.equal(
    requiresSshCredentialPrompt(
      'Could not read the SSH password: stored SSH secret could not be decrypted',
    ),
    false,
  );
});
