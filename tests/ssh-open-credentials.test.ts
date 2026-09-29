import assert from 'node:assert/strict';
import test from 'node:test';
import { sshOpenCredentialFields } from '../electron/ssh-open-credentials.ts';

const vault = { bitwarden: true, username: 'vault-user', password: ' password\n🔑 ' };

test('Quick Connect forwards resolved Bitwarden credentials as a direct SSH target', () => {
  const fields = sshOpenCredentialFields({ credentialId: 'virtual-credential' }, vault);
  assert.equal(fields.username, vault.username);
  assert.equal(fields.password, vault.password);
  assert.equal(fields.credential_id, undefined);
  assert.equal(fields.username_override, undefined);
  assert.equal(fields.password_override, undefined);
  assert.equal(fields.credential_override, false);
});

test('saved Bitwarden connections use overrides without exposing a direct target', () => {
  const fields = sshOpenCredentialFields({ nodeId: 'node' }, vault);
  assert.equal(fields.username, undefined);
  assert.equal(fields.password, undefined);
  assert.equal(fields.username_override, vault.username);
  assert.equal(fields.password_override, vault.password);
  assert.equal(fields.credential_override, true);
  assert.equal(fields.username_override_authoritative, false);
  const selected = sshOpenCredentialFields({ nodeId: 'node', credentialId: 'selected' }, vault);
  assert.equal(selected.credential_id, undefined);
  assert.equal(selected.username_override_authoritative, true);
});

test('saved nodes delegate missing vault usernames to Go while selected credentials must own their identity', () => {
  for (const username of [undefined, '', '  ']) {
    const missing = { ...vault, username };
    const inherited = sshOpenCredentialFields({ nodeId: 'node' }, missing);
    assert.equal(inherited.username_override, username);
    assert.equal(inherited.password_override, vault.password);
    assert.equal(inherited.username_override_authoritative, false);
    for (const request of [
      { credentialId: 'selected' },
      { nodeId: 'node', credentialId: 'selected' },
      {},
    ]) {
      assert.throws(() => sshOpenCredentialFields(request, missing), /SSH username is missing/);
    }
  }
});

test('local and manual credentials preserve the existing direct and saved wire formats', () => {
  const local = { bitwarden: false };
  const selected = sshOpenCredentialFields({ credentialId: 'local-id' }, local);
  assert.equal(selected.credential_id, 'local-id');
  assert.equal(selected.username, undefined);
  assert.equal(selected.password, undefined);
  assert.equal(selected.credential_override, false);
  const direct = sshOpenCredentialFields(
    { username: 'manual-user', password: vault.password },
    local,
  );
  assert.equal(direct.username, 'manual-user');
  assert.equal(direct.password, vault.password);
  const manual = sshOpenCredentialFields(
    { nodeId: 'node', manualCredentials: true, username: ' manual-user ', password: '' },
    local,
  );
  assert.equal(manual.username_override, 'manual-user');
  assert.equal(manual.password_override, '');
  assert.equal(manual.username_override_authoritative, true);
  assert.equal(manual.credential_override, true);
  const saved = sshOpenCredentialFields({ nodeId: 'node', credentialId: 'local-id' }, local);
  assert.equal(saved.credential_id, 'local-id');
  assert.equal(saved.username_override, undefined);
  assert.equal(saved.password_override, undefined);
  assert.equal(saved.credential_override, false);
  assert.equal(saved.username_override_authoritative, true);
});
