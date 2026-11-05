import assert from 'node:assert/strict';
import test from 'node:test';
import { fileSessionMode, isFileBrowserProtocol } from '../src/file-protocol.ts';
import {
  connectionProtocolForType,
  connectionTypeForProtocol,
  connectionProtocolSupportsTunnel,
  quickConnectStartsImmediately,
  quickConnectTunnelId,
} from '../src/quick-connect-state.ts';
import {
  connectionInlinePasswordAction,
  credentialCanUseProtocol,
  isCredentialProtocol,
} from '../src/credential-state.ts';
import { sshOpenCredentialFields } from '../electron/ssh-open-credentials.ts';
import { sshCredentialPromptTarget } from '../src/runtime-credential-errors.ts';

test('SMB shares the internal file lifecycle and keeps its native transport mode', () => {
  for (const protocol of ['smb', 'sftp']) assert.equal(isFileBrowserProtocol(protocol), true);
  for (const protocol of ['ssh', 'rdp', 'serial', undefined, 'unknown'])
    assert.equal(isFileBrowserProtocol(protocol), false);
  assert.equal(fileSessionMode('smb'), 'smb');
  assert.equal(fileSessionMode('sftp'), 'sftp');
  assert.equal(fileSessionMode('ssh'), 'terminal');
  assert.equal(fileSessionMode(undefined), 'terminal');
  assert.equal(connectionTypeForProtocol('smb'), 'smb');
  assert.equal(connectionProtocolForType('smb', 'ssh'), 'smb');
  assert.equal(connectionProtocolSupportsTunnel('smb'), true);
  assert.equal(quickConnectTunnelId('smb', 'route'), 'route');
  assert.equal(quickConnectTunnelId('smb', 'off'), undefined);
  assert.equal(quickConnectStartsImmediately('smb', true, undefined), false);
  assert.equal(quickConnectStartsImmediately('smb', true, 'credential'), true);
  assert.equal(quickConnectStartsImmediately('smb', false, undefined), true);
});

test('SMB accepts password credentials, preserves inline secrets and requests replacement credentials on authentication failure', () => {
  assert.equal(isCredentialProtocol('smb'), true);
  assert.equal(credentialCanUseProtocol('password', 'smb'), true);
  assert.equal(credentialCanUseProtocol('sshKey', 'smb'), false);
  assert.equal(credentialCanUseProtocol('unsupported', 'smb'), false);
  assert.equal(connectionInlinePasswordAction(false, 'smb', 'secret', false, false), 'set');
  assert.equal(connectionInlinePasswordAction(false, 'smb', '', true, false), 'preserve');
  assert.equal(connectionInlinePasswordAction(false, 'smb', '', true, true), 'clear');
  assert.equal(connectionInlinePasswordAction(true, 'smb', 'secret', true, false), 'clear');
  assert.equal(
    sshCredentialPromptTarget(
      { nodeId: 'saved' },
      'SMB authentication or negotiation failed; check username and password',
    ),
    'saved',
  );
  assert.equal(
    sshCredentialPromptTarget(
      { credentialId: 'saved' },
      'SMB authentication or negotiation failed; check username and password',
    ),
    'quick',
  );
  assert.equal(
    sshCredentialPromptTarget({ nodeId: 'saved' }, 'could not connect to the SMB server'),
    null,
  );
});

test('SMB forwards a vault domain only through native one-shot credentials', () => {
  const vault = { bitwarden: true, username: 'user', domain: 'CORP', password: 'secret' };
  assert.equal(sshOpenCredentialFields({ mode: 'smb' }, vault).username, 'CORP\\user');
  const fields = sshOpenCredentialFields({ mode: 'smb', nodeId: 'node' }, vault);
  assert.equal(fields.username_override, 'CORP\\user');
  assert.equal(fields.password_override, 'secret');
  assert.equal(fields.credential_override, true);
  assert.equal(
    sshOpenCredentialFields({ mode: 'smb' }, { ...vault, username: 'OTHER\\user' }).username,
    'OTHER\\user',
  );
  assert.equal(
    sshOpenCredentialFields({ mode: 'smb' }, { ...vault, username: 'user@example.test' }).username,
    'user@example.test',
  );
  assert.equal(sshOpenCredentialFields({ mode: 'sftp' }, vault).username, 'user');
  assert.equal(
    sshOpenCredentialFields(
      { mode: 'smb', username: 'manual', password: 'manual-secret' },
      { bitwarden: false },
    ).username,
    'manual',
  );
});
