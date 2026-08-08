import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isBitwardenUnlockError,
  requiresRdpCredentialPrompt,
  requiresSshCredentialPrompt,
  sshCredentialPromptTarget,
} from '../src/runtime-credential-errors.ts';

test('locked Bitwarden errors preserve the vault unlock flow', () => {
  assert.equal(isBitwardenUnlockError('Bitwarden vault is locked or the session is invalid'), true);
  assert.equal(isBitwardenUnlockError('The linked Bitwarden item was not found'), false);
  assert.equal(isBitwardenUnlockError(undefined), false);
});

test('RDP gateway failures do not open the unrelated primary credential prompt', () => {
  assert.equal(requiresRdpCredentialPrompt('RDP credential was not found'), true);
  assert.equal(requiresRdpCredentialPrompt('Bitwarden credential is unavailable'), true);
  assert.equal(
    requiresRdpCredentialPrompt('RDP Gateway credential is unavailable: password missing'),
    false,
  );
});

test('RDP VPN failures do not open the unrelated primary credential prompt', () => {
  assert.equal(
    requiresRdpCredentialPrompt(
      'RDP VPN tunnel is unavailable: the VPN credential password was rejected',
    ),
    false,
  );
});

test('saved and Quick Connect SSH credentials select the correct manual fallback', () => {
  const missing = 'Stored SSH secret is missing';
  assert.equal(sshCredentialPromptTarget({ nodeId: 'node' }, missing), 'saved');
  assert.equal(sshCredentialPromptTarget({ credentialId: 'credential' }, missing), 'quick');
  assert.equal(
    sshCredentialPromptTarget({ credentialId: 'credential', manualCredentials: true }, missing),
    null,
  );
  assert.equal(sshCredentialPromptTarget({ credentialId: 'credential' }, 'SSH timed out'), null);
  assert.equal(sshCredentialPromptTarget({}, missing), null);
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
