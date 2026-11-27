import assert from 'node:assert/strict';
import test from 'node:test';
import {
  hasNewerReleaseWithoutInstaller,
  isUpdateInstallable,
  shouldOfferUpdate,
  shouldShowReleaseNotes,
  unavailableInstallerMessage,
  updateStatusMessage,
} from '../src/update-state.ts';

const available = {
  latestVersion: '2.1.6',
  isNewerRelease: true,
  isUpdateAvailable: true,
};

test('operation status stays independent of the target version displayed on the update page', () => {
  assert.equal(updateStatusMessage('', available), '');
  assert.equal(updateStatusMessage('', { ...available, latestVersion: '2.1.7' }), '');
  assert.equal(updateStatusMessage('', null), '');
  for (const status of ['Checking for updates…', 'Downloading…', 'Install failed: offline']) {
    assert.equal(updateStatusMessage(status, available), status);
    assert.equal(updateStatusMessage(status, null), status);
  }
});

test('notifications require an installable version and only suppress the dismissed version', () => {
  assert.equal(shouldOfferUpdate(available, null), true);
  assert.equal(shouldOfferUpdate(available, '2.1.6'), false);
  assert.equal(shouldOfferUpdate(available, '2.1.5'), true);
  assert.equal(isUpdateInstallable(available), true);
  assert.equal(shouldShowReleaseNotes(available), true);
  assert.equal(hasNewerReleaseWithoutInstaller(available), false);
  assert.equal(unavailableInstallerMessage(available), null);
  for (const result of [
    { ...available, latestVersion: '' },
    { ...available, isUpdateAvailable: false, isNewerRelease: false },
  ]) {
    assert.equal(isUpdateInstallable(result), false);
    assert.equal(shouldOfferUpdate(result, null), false);
    assert.equal(shouldShowReleaseNotes(result), false);
    assert.equal(hasNewerReleaseWithoutInstaller(result), false);
    assert.equal(
      updateStatusMessage('', result),
      result.latestVersion ? "You're on the latest version." : '',
    );
  }
});

test('idle check failure and up-to-date messages follow the current result', () => {
  assert.equal(
    updateStatusMessage('', {
      latestVersion: '',
      isNewerRelease: false,
      isUpdateAvailable: false,
      checkFailed: true,
    }),
    "Couldn't reach the update server. Try again later.",
  );
  assert.equal(
    updateStatusMessage('', { ...available, isNewerRelease: false, isUpdateAvailable: false }),
    "You're on the latest version.",
  );
  assert.equal(updateStatusMessage('', available), '');
});

test('managed release notices preserve operation errors and only offer approved packages', () => {
  const managed = { ...available, updatePolicy: 'managed' as const };
  assert.equal(updateStatusMessage('', managed), 'Your administrator approved Wormhole 2.1.6.');
  assert.equal(
    updateStatusMessage('Installer verification failed', managed),
    'Installer verification failed',
  );
  assert.equal(shouldOfferUpdate(managed, null), true);
  const noPackage = { ...managed, isUpdateAvailable: false, latestVersion: '' };
  assert.equal(updateStatusMessage('', noPackage), 'Updates are managed by your administrator.');
  assert.equal(shouldOfferUpdate(noPackage, null), false);
  assert.equal(
    updateStatusMessage('', { ...noPackage, checkFailed: true }),
    'The managed update could not be verified. Contact your administrator.',
  );
});

test('a release without a verified installer keeps its version and changelog on the update page', () => {
  const result = { ...available, isUpdateAvailable: false };
  assert.equal(hasNewerReleaseWithoutInstaller(result), true);
  assert.equal(shouldShowReleaseNotes(result), true);
  assert.equal(shouldOfferUpdate(result, null), false);
  assert.equal(
    updateStatusMessage('', result),
    'Wormhole 2.1.6 is available, but no verified installer is published for this platform.',
  );
});
