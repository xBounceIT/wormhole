import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildConnectionCredentialSelectionOptions,
  connectionCredentialSelectionAfterSavedToggle,
  connectionInlinePasswordAction,
  connectionInlinePasswordPlaceholder,
  connectionUsesSavedCredentials,
  credentialCanUseProtocol,
  effectiveSshAutoSudoMode,
  mergeCredential,
  sshAutoSudoAvailable,
} from '../src/credential-state.ts';
import {
  bitwardenCliIsLoggedIn,
  bitwardenCliServerRegionCode,
  formatBitwardenCurrentServerLabel,
  formatBitwardenLoginStatus,
  formatBitwardenSyncResult,
  formatBitwardenVaultStatus,
} from '../src/bitwarden-cli-view.ts';

test('connection credential choices expose inheritance and saved credentials only', () => {
  assert.deepEqual(
    buildConnectionCredentialSelectionOptions(
      [{ id: 'credential-1', name: 'Server account', provider: 'Bitwarden' }],
      true,
    ),
    [
      { value: 'inherit', label: 'Inherit from folder' },
      { value: 'credential-1', label: 'Server account · Bitwarden' },
    ],
  );
  assert.deepEqual(
    buildConnectionCredentialSelectionOptions(
      [{ id: 'credential-1', name: 'Server account', provider: 'Bitwarden' }],
      false,
    ),
    [{ value: 'credential-1', label: 'Server account · Bitwarden' }],
  );
});

test('connections without a saved or inline credential reopen with saved credentials disabled', () => {
  assert.equal(connectionUsesSavedCredentials(1, false), false);
  assert.equal(connectionUsesSavedCredentials(1, true), false);
  assert.equal(connectionUsesSavedCredentials(0, false), true);
  assert.equal(connectionUsesSavedCredentials(2, false), true);
  assert.equal(connectionUsesSavedCredentials(undefined, true), false);
});

test('enabling saved credentials replaces the removed connection-only none selection', () => {
  assert.equal(connectionCredentialSelectionAfterSavedToggle(true, 'saved', 'none'), 'inherit');
  assert.equal(connectionCredentialSelectionAfterSavedToggle(false, 'saved', 'none'), 'none');
  assert.equal(connectionCredentialSelectionAfterSavedToggle(true, 'quick', 'none'), 'none');
  assert.equal(
    connectionCredentialSelectionAfterSavedToggle(true, 'saved', 'credential-1'),
    'credential-1',
  );
});

test('manual password actions distinguish blank, preserved, replaced, and removed secrets', () => {
  assert.equal(connectionInlinePasswordAction(false, 'ssh', '', false, false), 'clear');
  assert.equal(connectionInlinePasswordAction(false, 'rdp', '', undefined, false), 'clear');
  assert.equal(connectionInlinePasswordAction(false, 'ssh', '', true, false), 'preserve');
  assert.equal(connectionInlinePasswordAction(false, 'rdp', 'secret', false, false), 'set');
  assert.equal(connectionInlinePasswordAction(false, 'ssh', '', true, true), 'clear');
  assert.equal(connectionInlinePasswordAction(true, 'ssh', 'ignored', true, false), 'clear');
  assert.equal(connectionInlinePasswordAction(false, 'vnc', 'ignored', true, false), 'clear');
});

test('blank password copy only promises preservation when an inline password exists', () => {
  assert.equal(connectionInlinePasswordPlaceholder(true), 'Leave blank to keep stored password');
  assert.equal(connectionInlinePasswordPlaceholder(false), '(optional)');
  assert.equal(connectionInlinePasswordPlaceholder(undefined), '(optional)');
});

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

test('SSH keys are accepted only by SSH password-capable controls', () => {
  assert.equal(credentialCanUseProtocol('sshKey', 'ssh'), true);
  assert.equal(credentialCanUseProtocol('sshKey', 'rdp'), false);
  assert.equal(credentialCanUseProtocol('sshKey', 'vnc'), false);
  assert.equal(credentialCanUseProtocol('password', 'rdp'), true);
  assert.equal(credentialCanUseProtocol('password', 'vnc'), true);
  assert.equal(credentialCanUseProtocol('unsupported', 'ssh'), false);
});

test('Auto sudo remains available for inline and inherited credentials but not a selected SSH key', () => {
  assert.equal(sshAutoSudoAvailable(false, 'sshKey'), true);
  assert.equal(sshAutoSudoAvailable(true, undefined), true);
  assert.equal(sshAutoSudoAvailable(true, 'password'), true);
  assert.equal(sshAutoSudoAvailable(true, 'sshKey'), false);
  assert.equal(sshAutoSudoAvailable(true, 'unsupported'), false);
});

test('hidden Auto sudo ignores stale quick-connect state and preserves only a loaded saved override', () => {
  assert.equal(effectiveSshAutoSudoMode('ssh', false, 'on', 'off'), 'off');
  assert.equal(effectiveSshAutoSudoMode('ssh', false, 'off', 'on'), 'on');
  assert.equal(effectiveSshAutoSudoMode('ssh', false, 'on', 'inherit'), 'inherit');
  assert.equal(effectiveSshAutoSudoMode('ssh', true, 'on', 'inherit'), 'on');
  assert.equal(effectiveSshAutoSudoMode('rdp', true, 'on', 'on'), 'inherit');
});

test('Bitwarden login and vault labels distinguish authentication from lock state', () => {
  assert.equal(formatBitwardenLoginStatus('Unauthenticated'), 'Not logged in');
  assert.equal(formatBitwardenVaultStatus('Unauthenticated'), 'Unavailable');
  assert.equal(bitwardenCliIsLoggedIn('Unauthenticated'), false);

  for (const status of ['Locked', 'Unlocked'] as const) {
    assert.equal(formatBitwardenLoginStatus(status), 'Logged in');
    assert.equal(formatBitwardenVaultStatus(status), status);
    assert.equal(bitwardenCliIsLoggedIn(status), true);
  }
});

test('Bitwarden current server location recognizes official US and EU hosts', () => {
  assert.equal(bitwardenCliServerRegionCode(null), 'US');
  assert.equal(bitwardenCliServerRegionCode('https://vault.bitwarden.com'), 'US');
  assert.equal(bitwardenCliServerRegionCode('https://vault.bitwarden.eu'), 'EU');
  assert.equal(bitwardenCliServerRegionCode('https://vault.example.com'), null);
  assert.equal(formatBitwardenCurrentServerLabel('US'), 'Current Server (US)');
  assert.equal(formatBitwardenCurrentServerLabel('EU'), 'Current Server (EU)');
});

test('Bitwarden cached sync is presented as a warning instead of a success', () => {
  assert.deepEqual(
    formatBitwardenSyncResult({
      availableCount: 12,
      lastSyncStatus: 'Bitwarden sync failed; using cached credentials.',
      usedCache: true,
      lastSyncError: 'The Bitwarden vault is locked.',
    }),
    {
      status: 'warning',
      message:
        'Bitwarden could not be synchronized. Wormhole will continue using 12 cached credentials. The Bitwarden vault is locked.',
    },
  );
});
