import assert from 'node:assert/strict';
import test from 'node:test';

import { mergeCredential } from '../src/credential-state.ts';
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
