import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  buildConnectionCredentialSelectionOptions,
  connectionCredentialSelectionAfterSavedToggle,
  connectionInlinePasswordAction,
  connectionInlinePasswordPlaceholder,
  connectionUsesSavedCredentials,
  credentialCanUseProtocol,
  effectiveSshAutoSudoMode,
  filterCredentialsBySource,
  mergeCredential,
  sshAutoSudoAvailable,
} from '../src/credential-state.ts';
import { hasValidCredentialSecretLength } from '../electron/credential-secret-length.ts';
import {
  bitwardenCliIsLoggedIn,
  bitwardenCliServerRegionCode,
  formatBitwardenCurrentServerLabel,
  formatBitwardenLoginStatus,
  formatBitwardenSyncResult,
  formatBitwardenVaultStatus,
} from '../src/bitwarden-cli-view.ts';

const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');

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

test('connection password clear action is a button in the aligned field header', () => {
  const usernameInput = appSource.indexOf('id="connection-username"');
  const start = appSource.lastIndexOf('<div className="grid gap-4 sm:grid-cols-2">', usernameInput);
  const end = appSource.indexOf('{canConfigureConnectionSshAutoSudo ?', start);
  const manualCredentialFields = appSource.slice(start, end);
  const usernameHeaderStart = manualCredentialFields.indexOf(
    '<div className="flex h-6 items-center">',
  );
  const usernameHeaderEnd = manualCredentialFields.indexOf('</div>', usernameHeaderStart);
  const usernameHeader = manualCredentialFields.slice(usernameHeaderStart, usernameHeaderEnd + 6);
  const passwordHeaderStart = manualCredentialFields.indexOf(
    '<div className="flex h-6 items-center justify-between gap-2">',
  );
  const passwordHeaderEnd = manualCredentialFields.indexOf('</div>', passwordHeaderStart);
  const passwordHeader = manualCredentialFields.slice(passwordHeaderStart, passwordHeaderEnd + 6);

  assert.ok(
    usernameInput >= 0 &&
      start >= 0 &&
      end > start &&
      usernameHeaderStart >= 0 &&
      usernameHeaderEnd > usernameHeaderStart &&
      passwordHeaderStart >= 0 &&
      passwordHeaderEnd > passwordHeaderStart,
  );
  assert.match(
    usernameHeader,
    /<div className="flex h-6 items-center">\s*<Label htmlFor="connection-username">Username<\/Label>/,
  );
  assert.match(
    passwordHeader,
    /<div className="flex h-6 items-center justify-between gap-2">[\s\S]*?<Label htmlFor="connection-inline-password">Password<\/Label>[\s\S]*?<Button[\s\S]*?aria-pressed=\{newConnectionForm\.removeInlinePassword\}[\s\S]*?type="button"[\s\S]*?>\s*Clear password\s*<\/Button>/,
  );
  assert.match(
    passwordHeader,
    /inlinePassword: '',[\s\S]*?removeInlinePassword: !form\.removeInlinePassword/,
  );
  assert.doesNotMatch(usernameHeader, /<Input|<Button|<Checkbox/);
  assert.doesNotMatch(passwordHeader, /<Input|<Checkbox|Remove stored password/);
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

test('credential source filter separates local and Bitwarden credentials', () => {
  const credentials = [
    { id: 'local-password', provider: 'Local' },
    { id: 'vault-password', provider: 'Bitwarden' },
    { id: 'local-key', provider: 'Local' },
  ];

  assert.equal(filterCredentialsBySource(credentials, 'all'), credentials);
  assert.deepEqual(
    filterCredentialsBySource(credentials, 'all').map((credential) => credential.id),
    ['local-password', 'vault-password', 'local-key'],
  );
  assert.deepEqual(
    filterCredentialsBySource(credentials, 'Local').map((credential) => credential.id),
    ['local-password', 'local-key'],
  );
  assert.deepEqual(
    filterCredentialsBySource(credentials, 'Bitwarden').map((credential) => credential.id),
    ['vault-password'],
  );
});

test('credentials page exposes a source filter that also resets the virtual grid', () => {
  assert.match(appSource, /aria-label=\{`Filter credentials by source:/);
  assert.match(appSource, /\{ value: 'Local', label: 'Local' \}/);
  assert.match(appSource, /\{ value: 'Bitwarden', label: 'Bitwarden' \}/);
  assert.match(appSource, /filterCredentialsBySource\(credentials, credentialSourceFilter\)/);
  assert.match(
    appSource,
    /resetKey=\{`\$\{credentialSourceFilter\}\\u0000\$\{normalizedCredentialSearch\}`\}/,
  );
});

test('SSH keys are accepted only by SSH password-capable controls', () => {
  assert.equal(credentialCanUseProtocol('sshKey', 'ssh'), true);
  assert.equal(credentialCanUseProtocol('sshKey', 'rdp'), false);
  assert.equal(credentialCanUseProtocol('sshKey', 'vnc'), false);
  assert.equal(credentialCanUseProtocol('password', 'rdp'), true);
  assert.equal(credentialCanUseProtocol('password', 'vnc'), true);
  assert.equal(credentialCanUseProtocol('unsupported', 'ssh'), false);
});

test('credential cards omit the redundant password badge while retaining the SSH key badge', () => {
  const credentialGrid = appSource.match(
    /renderItem=\{\(credential\) => \([\s\S]*?resetKey=\{/,
  )?.[0];

  assert.ok(credentialGrid);
  assert.doesNotMatch(credentialGrid, />Password<|['"]Password['"]/);
  assert.match(
    credentialGrid,
    /credential\.kind === 'sshKey'[\s\S]*?<Badge variant="outline">SSH key<\/Badge>/,
  );
  assert.match(credentialGrid, /label=\{`Delete \$\{credential\.name\}`\}[\s\S]{0,160}<Trash2 \/>/);
});

test('Auto sudo remains available for password and SSH key credentials', () => {
  assert.equal(sshAutoSudoAvailable(false, 'sshKey'), true);
  assert.equal(sshAutoSudoAvailable(true, undefined), true);
  assert.equal(sshAutoSudoAvailable(true, 'password'), true);
  assert.equal(sshAutoSudoAvailable(true, 'sshKey'), true);
  assert.equal(sshAutoSudoAvailable(true, 'unsupported'), false);
});

test('SSH key passphrase limits count Unicode code points instead of encoded bytes', () => {
  assert.equal(hasValidCredentialSecretLength('é'.repeat(4096)), true);
  assert.equal(hasValidCredentialSecretLength('é'.repeat(4097)), false);
  assert.equal(hasValidCredentialSecretLength('🔐'.repeat(4096)), true);
  assert.equal(hasValidCredentialSecretLength('🔐'.repeat(4097)), false);
});

test('hidden Auto sudo ignores stale quick-connect state and preserves only a loaded saved override', () => {
  assert.equal(effectiveSshAutoSudoMode('ssh', false, 'on', 'off'), 'off');
  assert.equal(effectiveSshAutoSudoMode('ssh', false, 'off', 'on'), 'on');
  assert.equal(effectiveSshAutoSudoMode('ssh', false, 'on', 'inherit'), 'inherit');
  assert.equal(effectiveSshAutoSudoMode('ssh', true, 'on', 'inherit'), 'on');
  assert.equal(effectiveSshAutoSudoMode('rdp', true, 'on', 'on'), 'inherit');
});

test('SSH key credential import keeps key paths and material behind the native boundary', () => {
  const preloadSource = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const backendSource = readFileSync(
    new URL('../tools/wormhole-backend/credentials.go', import.meta.url),
    'utf8',
  );

  assert.match(appSource, /<SelectItem value="sshKey">SSH private key<\/SelectItem>/);
  assert.match(appSource, /selectSshPrivateKey\(\)/);
  assert.match(appSource, /Key passphrase \(optional\)/);
  assert.match(appSource, /id="credential-key-passphrase"[\s\S]*?maxLength=\{8192\}/);
  assert.doesNotMatch(appSource, /privateKeyPath/);

  const credentialDraft = appSource.match(/type CredentialDraft = \{[\s\S]*?\n\};/)?.[0];
  assert.ok(credentialDraft);
  assert.doesNotMatch(credentialDraft, /passphrase/);
  assert.match(appSource, /takeOneShotSecret\(credentialKeyPassphraseInput\.current\)/);
  assert.match(
    appSource,
    /failedSelectionId = request\.kind === 'sshKey' \? request\.privateKeySelectionId : ''[\s\S]*selectionMustBeRepeated = failedSelectionId\.length > 0[\s\S]*discardPrivateKeySelection\(failedSelectionId\)[\s\S]*privateKeySelectionId: ''[\s\S]*setPrivateKeySelectionRetryRequired\(true\)/,
  );
  assert.match(
    appSource,
    /const privateKeySelectionRequired = !editingCredential \|\| privateKeySelectionRetryRequired/,
  );
  assert.match(
    appSource,
    /privateKeyPassphraseRetryRequired && !draft\.clearPassphrase && !passphrase/,
  );
  assert.match(
    appSource,
    /passphraseMustBeRepeated = request\.kind === 'sshKey' && request\.passphrase\.length > 0/,
  );
  assert.match(appSource, /disabled=\{busy \|\| privateKeySelecting\}/);
  assert.match(appSource, /takeOneShotSecret\(sshKeyPassphraseInput\.current\)/);
  assert.match(appSource, /input\.value = '';/);
  assert.match(
    appSource,
    /clearSecretInput\(credentialKeyPassphraseInput\.current\);\s+setEditorOpen\(false\)/,
  );
  assert.match(
    appSource,
    /clearSecretInput\(sshKeyPassphraseInput\.current\);\s+setSshKeyPassphrasePrompt\(null\)/,
  );
  assert.doesNotMatch(appSource, /setSshKeyPassphrase\(/);
  assert.doesNotMatch(appSource, /credentialForm\.passphrase/);

  assert.match(preloadSource, /credential:select-ssh-private-key/);
  assert.match(preloadSource, /credential:discard-ssh-private-key/);
  assert.doesNotMatch(preloadSource, /privateKeyPath/);

  assert.match(mainSource, /dialog\.showOpenDialog\(owner, options\)/);
  assert.match(mainSource, /sshPrivateKeySelections\.get\(event\.sender\)/);
  assert.match(mainSource, /privateKeyPath: selection\.path/);
  assert.match(mainSource, /sshPrivateKeySelections\.delete\(event\.sender\)/);
  assert.match(mainSource, /clearPassphrase/);
  assert.match(mainSource, /sshPrivateKeyDisplayName/);
  assert.doesNotMatch(
    mainSource,
    /Buffer\.byteLength\((?:value\.keyPassphrase|passphrase), 'utf8'\)/,
  );

  assert.match(backendSource, /ssh\.ParsePrivateKeyWithPassphrase/);
  assert.match(backendSource, /credentialPrivateKeyStageProtect/);
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
