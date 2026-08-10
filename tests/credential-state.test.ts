import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
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

test('SSH key credential import keeps key paths and material behind the native boundary', () => {
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const preloadSource = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const backendSource = readFileSync(
    new URL('../tools/wormhole-backend/credentials.go', import.meta.url),
    'utf8',
  );

  assert.match(appSource, /<SelectItem value="sshKey">SSH private key<\/SelectItem>/);
  assert.match(appSource, /selectSshPrivateKey\(\)/);
  assert.match(appSource, /Key passphrase \(optional\)/);
  assert.doesNotMatch(appSource, /privateKeyPath/);

  assert.match(preloadSource, /credential:select-ssh-private-key/);
  assert.match(preloadSource, /credential:discard-ssh-private-key/);
  assert.doesNotMatch(preloadSource, /privateKeyPath/);

  assert.match(mainSource, /dialog\.showOpenDialog\(owner, options\)/);
  assert.match(mainSource, /sshPrivateKeySelections\.get\(event\.sender\)/);
  assert.match(mainSource, /privateKeyPath: selection\.path/);
  assert.match(mainSource, /sshPrivateKeySelections\.delete\(event\.sender\)/);
  assert.match(mainSource, /clearPassphrase/);
  assert.match(mainSource, /sshPrivateKeyDisplayName/);

  assert.match(backendSource, /ssh\.ParsePrivateKeyWithPassphrase/);
  assert.match(backendSource, /credentialPrivateKeyProtect/);
  assert.match(backendSource, /maxSshPrivateKeyBytes/);
  assert.match(backendSource, /ClearPassphrase/);
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
