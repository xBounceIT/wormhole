import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  buildCredentialListProjection,
  buildConnectionCredentialSelectionOptions,
  connectionEditorCredentialSelectionIsComplete,
  connectionCredentialSelectionAfterSavedToggle,
  connectionInlinePasswordAction,
  connectionInlinePasswordPlaceholder,
  connectionUsesSavedCredentials,
  credentialSelectionAfterSelectAll,
  credentialCanUseProtocol,
  effectiveSshAutoSudoMode,
  filterCredentialsBySource,
  isCredentialProtocol,
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

test('credential protocol detection shares the saved-credential allowlist', () => {
  assert.equal(isCredentialProtocol('ssh'), true);
  assert.equal(isCredentialProtocol('rdp'), true);
  assert.equal(isCredentialProtocol('vnc'), true);
  assert.equal(isCredentialProtocol('https'), false);
  assert.equal(isCredentialProtocol(''), false);
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

test('saved connection forms require a selection without duplicating Go reference validation', () => {
  assert.equal(connectionEditorCredentialSelectionIsComplete('saved', true, true, 'inherit'), true);
  assert.equal(
    connectionEditorCredentialSelectionIsComplete('saved', true, true, ' credential-1 '),
    true,
  );
  assert.equal(connectionEditorCredentialSelectionIsComplete('saved', true, true, 'none'), false);
  assert.equal(
    connectionEditorCredentialSelectionIsComplete('saved', true, true, 'deleted-credential'),
    true,
  );
  assert.equal(connectionEditorCredentialSelectionIsComplete('saved', true, true, ''), false);
  assert.equal(connectionEditorCredentialSelectionIsComplete('saved', true, false, 'none'), true);
  assert.equal(connectionEditorCredentialSelectionIsComplete('saved', false, true, 'none'), true);
  assert.equal(connectionEditorCredentialSelectionIsComplete('quick', true, true, 'none'), true);
});

test('saved connection form blocks missing credential selections before workspace writes', () => {
  const submitStart = appSource.indexOf('async function submitNewConnection');
  const submitEnd = appSource.indexOf('async function submitFolderDetails', submitStart);
  const submitSource = appSource.slice(submitStart, submitEnd);
  const credentialFieldStart = appSource.indexOf('id="connection-credential"');
  const credentialFieldEnd = appSource.indexOf(
    '{!newConnectionForm.useSavedCredentials &&',
    credentialFieldStart,
  );
  const credentialFieldSource = appSource.slice(credentialFieldStart, credentialFieldEnd);

  assert.ok(
    submitStart >= 0 &&
      submitEnd > submitStart &&
      credentialFieldStart >= 0 &&
      credentialFieldEnd > credentialFieldStart,
  );
  assert.match(
    submitSource,
    /if \(!connectionEditorCredentialSelectionComplete\)[\s\S]*?return;[\s\S]*?updateWorkspaceNode/,
  );
  assert.match(
    appSource,
    /disabled=\{editorBusy \|\| !connectionEditorCredentialSelectionComplete\}/,
  );
  assert.match(
    credentialFieldSource,
    /!connectionEditorCredentialSelectionComplete[\s\S]*?connectionCredentialSelectionError/,
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

test('clearing a stored inline password updates the draft without submitting the form', () => {
  const control = appSource.indexOf('aria-pressed={newConnectionForm.removeInlinePassword}');
  assert.ok(control >= 0, 'missing inline password removal control');
  const start = appSource.lastIndexOf('<Button', control);
  const end = appSource.indexOf('</Button>', control);
  assert.ok(start >= 0 && end > control, 'password removal must use a button');
  const button = appSource.slice(start, end);

  assert.match(button, /type="button"/);
  assert.ok(
    />\s*[^<>{}\s][^<>{}]*(?=<|$)/.test(button) ||
      /aria-label="[^"\r\n]*[^"\s][^"\r\n]*"/.test(button),
    'password removal requires visible text or an accessible label',
  );
  assert.match(
    button,
    /onClick=\{\(\) =>\s*setNewConnectionForm\(\(form\) => \(\{[\s\S]*?inlinePassword: '',[\s\S]*?removeInlinePassword: !form\.removeInlinePassword/,
  );
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

test('credential source projection combines provider, search, and empty state', () => {
  const credentials = [
    {
      id: 'local-password',
      name: 'Production SSH',
      username: 'alice',
      provider: 'Local',
      kind: 'password',
    },
    {
      id: 'vault-password',
      name: 'Production RDP',
      username: 'bob',
      domain: 'CORP',
      provider: 'Bitwarden',
      kind: 'password',
    },
    {
      id: 'local-key',
      name: 'Jump host',
      username: 'carol',
      provider: 'Local',
      kind: 'sshKey',
      privateKeyFileName: 'id_ed25519',
    },
  ] as const;

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

  const localSearch = buildCredentialListProjection(credentials, 'Local', 'jump');
  assert.deepEqual(
    localSearch.credentials.map((credential) => credential.id),
    ['local-key'],
  );
  assert.equal(localSearch.emptyState, null);
  assert.equal(localSearch.resetKey, 'Local\u0000jump');

  const bitwardenSearch = buildCredentialListProjection(credentials, 'Bitwarden', 'alice');
  assert.deepEqual(bitwardenSearch.credentials, []);
  assert.equal(bitwardenSearch.emptyState, 'noMatches');
  assert.equal(bitwardenSearch.resetKey, 'Bitwarden\u0000alice');

  const empty = buildCredentialListProjection([], 'all', '');
  assert.deepEqual(empty.credentials, []);
  assert.equal(empty.emptyState, 'empty');
});

test('credential bulk selection follows the source-filtered projection', () => {
  const credentials = [
    { id: 'local-password', provider: 'Local' },
    { id: 'vault-password', provider: 'Bitwarden' },
    { id: 'local-key', provider: 'Local' },
  ];
  const localCredentials = filterCredentialsBySource(credentials, 'Local');

  const selected = credentialSelectionAfterSelectAll(localCredentials, new Set(['vault-password']));
  assert.deepEqual([...selected], ['local-password', 'local-key']);
  assert.deepEqual([...credentialSelectionAfterSelectAll(localCredentials, selected)], []);
  assert.deepEqual([...credentialSelectionAfterSelectAll([], new Set(['vault-password']))], []);
});

test('credentials page wires the source menu to the tested list projection', () => {
  const credentialsPage = appSource.slice(
    appSource.indexOf('function CredentialsPage('),
    appSource.indexOf('function TunnelsPage('),
  );

  assert.match(credentialsPage, /aria-label=\{`Filter credentials by source:/);
  assert.match(credentialsPage, /<DropdownMenuRadioGroup[\s\S]*?setCredentialSourceFilter/);
  assert.match(credentialsPage, /buildCredentialListProjection\(/);
  assert.match(credentialsPage, /credentialSelectionAfterSelectAll\(/);
  assert.match(credentialsPage, /resetKey=\{credentialListProjection\.resetKey\}/);
});

test('SSH keys are accepted only by SSH password-capable controls', () => {
  assert.equal(credentialCanUseProtocol('sshKey', 'ssh'), true);
  assert.equal(credentialCanUseProtocol('sshKey', 'rdp'), false);
  assert.equal(credentialCanUseProtocol('sshKey', 'vnc'), false);
  assert.equal(credentialCanUseProtocol('password', 'rdp'), true);
  assert.equal(credentialCanUseProtocol('password', 'vnc'), true);
  assert.equal(credentialCanUseProtocol('unsupported', 'ssh'), false);
});

test('credential deletion names its target for assistive technology', () => {
  const grid = appSource.match(/renderItem=\{\(credential\) => \([\s\S]*?resetKey=\{/)?.[0];
  assert.ok(grid, 'credential grid is missing');
  const button = grid
    .match(/<IconButton\b[\s\S]*?<\/IconButton>/g)
    ?.find((candidate) => candidate.includes('setPendingDeletion([credential.id])'));
  assert.ok(button, 'credential deletion control is missing');
  assert.match(button, /label=\{`Delete \$\{credential\.name\}`\}/);
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

  assert.match(mainSource, /showCoordinatedOpenDialog\(owner, options\)/);
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
