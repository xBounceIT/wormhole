// Executed with production update handlers, controls, styles and overlay coordination.
declare const React: typeof import('react');
declare const createRoot: typeof import('react-dom/client').createRoot;
declare const assert: typeof import('node:assert/strict');
declare function ContextMenuOverlayProvider(
  props: Record<string, unknown>,
): import('react').ReactElement;
declare function UpdateHarness(props: Record<string, unknown>): import('react').ReactElement;
declare const updateTestControls: {
  dismiss: () => void;
  check: () => Promise<void>;
  install: () => Promise<void>;
  viewChanges: () => void;
  setAuthGate: (value: string) => void;
};

async function runUpdateNotificationTests() {
  const root = createRoot(document.getElementById('root'));
  const release = (version = '2.1.6') => ({
    latestVersion: version,
    isNewerRelease: true,
    isUpdateAvailable: true,
    checkFailed: false,
    installerUrl: 'https://example.test/Wormhole.exe',
    installerFileName: 'Wormhole.exe',
    installerSha256: 'a'.repeat(64),
    installerSize: 1234,
    releaseNotes: `## Wormhole ${version}\n\n- **Faster updates**\n- Improved connections`,
  });
  let key = 0;
  let previousListeners = new Set();
  const mount = async (options: Record<string, unknown> = {}) => {
    const listeners = new Set<(result: unknown) => void>();
    const progressListeners = new Set<(value: unknown) => void>();
    let resolveStatus: (value: unknown) => void;
    let finishDownload: () => void;
    const snapshot = { currentVersion: '2.1.5', result: options.result ?? release() };
    if (options.result === null) snapshot.result = null;
    const status = options.deferStatus
      ? new Promise((resolve) => {
          resolveStatus = resolve;
        })
      : Promise.resolve(snapshot);
    const api = {
      platform: options.platform ?? 'win32',
      checks: 0,
      downloads: [],
      installations: [],
      preferences: [],
      downloadFailure: false,
      downloadErrorMessage: 'download offline',
      installFailure: false,
      checkFailure: false,
      checkResult: release(),
      updateStatus: () => (options.statusFailure ? Promise.reject(new Error('offline')) : status),
      onUpdateResult: (listener) => {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
      onUpdateProgress: (listener) => {
        progressListeners.add(listener);
        return () => progressListeners.delete(listener);
      },
      emit: (result) => listeners.forEach((listener) => listener(result)),
      progress: (downloaded, total) =>
        progressListeners.forEach((listener) => listener({ downloaded, total })),
      resolveStatus: (value = snapshot) => resolveStatus(value),
      finishDownload: () => finishDownload(),
      readAppSettings: async () => ({ lastUpdateCheck: '2026-10-23T10:00:00Z' }),
      checkForUpdates: async () => {
        api.checks++;
        if (api.checkFailure) throw new Error('offline');
        return api.checkResult;
      },
      setUpdatePreferences: async (value) => {
        api.preferences.push(value);
      },
      downloadUpdate: async (request) => {
        api.downloads.push(request);
        if (api.downloadFailure) throw new Error(api.downloadErrorMessage);
        if (options.deferDownload)
          await new Promise<void>((resolve) => {
            finishDownload = resolve;
          });
        return 'verified-installer';
      },
      installUpdate: async (path) => {
        api.installations.push(path);
        if (api.installFailure) throw new Error('installer unavailable');
        return { appWillQuit: api.platform === 'win32' };
      },
    };
    window.wormhole = options.noBridge ? undefined : api;
    await React.act(async () =>
      root.render(
        <ContextMenuOverlayProvider key={++key}>
          <UpdateHarness
            initialSettings={{
              autoCheckForUpdates: true,
              lastUpdateCheck: null,
              skippedUpdateVersion: '2.1.6',
            }}
          />
        </ContextMenuOverlayProvider>,
      ),
    );
    assert.equal(previousListeners.size, 0, 'old result subscriptions must be released');
    previousListeners = listeners;
    return api;
  };
  const popup = () =>
    document.querySelector<HTMLElement>('[aria-labelledby="update-notification-title"]');
  const button = (label: string) =>
    [...document.querySelectorAll<HTMLButtonElement>('button')].find(
      (item) => (item.getAttribute('aria-label') ?? item.textContent) === label,
    );
  const click = async (label: string) => {
    const control = button(label);
    assert.ok(control, `Missing button: ${label}`);
    await React.act(async () => control.click());
  };
  const nativeState = () => document.getElementById('native-surface-state').textContent;

  let api = await mount({ result: null });
  assert.equal(popup(), null);
  await React.act(async () => updateTestControls.dismiss());
  await React.act(async () => api.emit(release()));
  assert.equal(api.checks, 0, 'startup results must not require another check');
  assert.equal(
    document.getElementById('update-notification-title').textContent,
    'Wormhole v2.1.6 is now available',
  );
  assert.ok(popup().textContent.includes('Update to use the best version of Wormhole'));
  assert.equal(nativeState(), 'hidden', 'native sessions must not cover the popup');
  const bounds = popup().getBoundingClientRect();
  assert.ok(Math.abs(innerWidth - bounds.right - 16) <= 1, 'popup must be anchored at the right');
  assert.ok(
    Math.abs(innerHeight - bounds.bottom - 16) <= 1,
    'popup must be anchored at the bottom',
  );
  assert.ok(bounds.left >= 0 && bounds.top >= 0, 'popup must fit the viewport');
  assert.equal(button('Dismiss'), undefined, 'the text Dismiss button must be removed');
  assert.deepEqual(
    [...popup().querySelectorAll('button')].map((item) => item.textContent).filter(Boolean),
    ['Update now', 'View changes'],
  );
  const closeBounds = button('Close update notification').getBoundingClientRect();
  assert.ok(closeBounds.top <= bounds.top + 16, 'the close button must be at the top');
  assert.ok(closeBounds.right >= bounds.right - 16, 'the close button must be at the right');
  assert.ok(
    document.getElementById('update-notification-title').getBoundingClientRect().right <=
      closeBounds.left,
    'the title must leave room for the close button',
  );
  for (const label of ['Update now', 'Close update notification', 'View changes']) {
    const control = button(label);
    const rect = control.getBoundingClientRect();
    assert.ok(
      rect.left >= bounds.left && rect.right <= bounds.right && rect.bottom <= bounds.bottom,
      label + ' must fit',
    );
    assert.ok(
      control.contains(
        document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2),
      ),
      label + ' must be reachable',
    );
  }

  await click('Close update notification');
  assert.equal(popup(), null);
  assert.equal(nativeState(), 'visible');
  assert.equal(api.preferences.length, 0, 'dismissal must not persist a skipped version');
  await React.act(async () => api.emit(release()));
  assert.equal(popup(), null, 'the same version stays dismissed for this launch');
  await React.act(async () => api.emit(release('2.1.7')));
  assert.ok(popup(), 'a different version may notify again');
  api = await mount();
  assert.ok(
    popup(),
    'relaunch must show the update, including previously persisted skipped versions',
  );
  await React.act(async () => updateTestControls.setAuthGate('locked'));
  assert.equal(popup(), null);
  assert.equal(nativeState(), 'visible');
  await React.act(async () => updateTestControls.setAuthGate('unlocked'));
  assert.ok(popup());

  await click('View changes');
  assert.equal(popup(), null);
  assert.equal(document.getElementById('updates-page').dataset.activeTab, 'updates');
  assert.ok(document.body.textContent.includes('Update available: 2.1.6'));
  const releaseNotesSection = [...document.querySelectorAll('#updates-page section')].find(
    (section) => section.querySelector('h3')?.textContent === 'Release notes',
  );
  assert.ok(releaseNotesSection);
  const availableVersion = [...releaseNotesSection.querySelectorAll('p')].find(
    (item) => item.textContent === 'Update available: 2.1.6',
  );
  assert.ok(availableVersion, 'the available version must appear with the release notes');
  assert.ok(
    availableVersion.compareDocumentPosition(
      releaseNotesSection.querySelector('[data-slot="card"]'),
    ) & Node.DOCUMENT_POSITION_FOLLOWING,
    'the available version must precede the changelog card',
  );
  const updateControlsSection = [...document.querySelectorAll('#updates-page section')].find(
    (section) => section.querySelector('h3')?.textContent === 'Wormhole updates',
  );
  assert.ok(
    !updateControlsSection.textContent.includes('Update available:'),
    'the available version must be removed from the update controls',
  );
  assert.ok(
    document.body.textContent.includes('Wormhole 2.1.5'),
    'the installed version remains distinct',
  );
  assert.equal(document.querySelector('#updates-page strong').textContent, 'Faster updates');
  assert.equal(api.checks, 0, 'opening the changelog must use the existing result');
  await click('General');
  await React.act(async () => api.emit(release('2.1.7')));
  await click('View changes');
  assert.equal(document.getElementById('updates-page').dataset.activeTab, 'updates');
  assert.ok(document.body.textContent.includes('Update available: 2.1.7'));

  api = await mount({ result: null, deferStatus: true });
  await React.act(async () => api.emit(release('2.1.7')));
  await React.act(async () =>
    api.resolveStatus({ currentVersion: '2.1.5', result: release('2.1.6') }),
  );
  assert.ok(
    popup().textContent.includes('v2.1.7'),
    'a late initial snapshot must not overwrite an update event',
  );
  api = await mount({ statusFailure: true });
  assert.equal(popup(), null);
  await React.act(async () => api.emit(release()));
  assert.ok(popup(), 'events still work when the initial status fails');
  const pending = await mount({ deferStatus: true });
  api = await mount();
  await React.act(async () => pending.resolveStatus());
  assert.ok(popup(), 'a disposed status request must not affect the new launch');

  for (const platform of ['win32', 'darwin', 'linux']) {
    api = await mount({ platform, deferDownload: true });
    await click('Update now');
    assert.equal(button('Update now').disabled, true);
    await React.act(async () => updateTestControls.install());
    await React.act(async () => updateTestControls.check());
    assert.equal(api.downloads.length, 1, 'busy actions must not start duplicate work');
    assert.equal(api.checks, 0);
    assert.deepEqual(api.downloads[0], {
      installerUrl: release().installerUrl,
      installerFileName: 'Wormhole.exe',
      installerSha256: 'a'.repeat(64),
      installerSize: 1234,
    });
    await React.act(async () => api.progress(50, 100));
    assert.equal(popup().querySelector('[role="progressbar"]').getAttribute('aria-valuenow'), '50');
    await React.act(async () => api.progress(500, 100));
    assert.equal(
      popup().querySelector('[role="progressbar"]').getAttribute('aria-valuenow'),
      '100',
    );
    await React.act(async () => api.progress(5, 0));
    assert.equal(popup().querySelector('[role="progressbar"]'), null);
    await React.act(async () => api.finishDownload());
    assert.deepEqual(api.installations, ['verified-installer']);
    if (platform !== 'win32') {
      assert.equal(button('Update now').disabled, false);
      assert.ok(
        popup().textContent.includes(
          platform === 'linux' ? 'AppImage downloaded.' : 'Installer opened.',
        ),
      );
    }
    await click('Close update notification');
    assert.equal(popup(), null, 'dismissal also works during installation');
  }

  api = await mount({ platform: 'linux' });
  await click('View changes');
  await click('Download AppImage');
  assert.deepEqual(
    api.installations,
    ['verified-installer'],
    'the dedicated page uses the same install flow',
  );
  api = await mount();
  api.downloadFailure = true;
  await click('Update now');
  assert.ok(popup().textContent.includes('Install failed: download offline'));
  assert.equal(button('Update now').disabled, false);
  api.downloadFailure = false;
  api.installFailure = true;
  await click('Update now');
  assert.ok(popup().textContent.includes('Install failed: installer unavailable'));
  assert.equal(button('Update now').disabled, false);

  for (const result of [
    { ...release(), installerUrl: '' },
    { ...release(), installerFileName: '' },
    { ...release(), isUpdateAvailable: false },
  ]) {
    api = await mount({ result });
    await React.act(async () => updateTestControls.install());
    assert.equal(api.downloads.length, 0, 'unavailable installers must not start a download');
  }
  api = await mount({ noBridge: true });
  await React.act(async () => {
    await updateTestControls.install();
    await updateTestControls.check();
  });
  assert.equal(api.downloads.length, 0);
  assert.equal(api.checks, 0);

  api = await mount({ result: null });
  api.checkFailure = true;
  await React.act(async () => updateTestControls.check());
  await React.act(async () => updateTestControls.viewChanges());
  assert.ok(document.body.textContent.includes("Couldn't reach the update server."));
  api.checkFailure = false;
  api.checkResult = {
    ...release(),
    latestVersion: '',
    checkFailed: true,
    isUpdateAvailable: false,
    isNewerRelease: false,
  };
  await click('Check now');
  assert.ok(document.body.textContent.includes("Couldn't reach the update server."));
  api.checkResult = release();
  await click('Check now');
  assert.ok(document.body.textContent.includes('Update available: 2.1.6'));
  assert.ok(popup());
  await click('Close update notification');
  api.checkResult = { ...release(), isUpdateAvailable: false };
  await click('Check now');
  assert.ok(document.body.textContent.includes('no verified installer is published'));
  api.checkResult = { ...release(), isUpdateAvailable: false, isNewerRelease: false };
  await click('Check now');
  assert.ok(document.body.textContent.includes("You're on the latest version."));

  const regressions: string[] = [];
  api = await mount({
    deferDownload: true,
    result: { ...release(), releaseNotes: '- Faster update checks' },
  });
  await click('Update now');
  await click('View changes');
  if (
    ![...document.querySelectorAll('#updates-page p')].some(
      (item) => item.textContent === 'Update available: 2.1.6',
    )
  ) {
    regressions.push('the update page loses the target version during a download');
  }
  await React.act(async () => api.finishDownload());

  api = await mount();
  await React.act(async () => updateTestControls.check());
  await click('View changes');
  await React.act(async () =>
    api.emit({ ...release('2.1.7'), releaseNotes: '- Faster update checks' }),
  );
  if (
    ![...document.querySelectorAll('#updates-page p')].some(
      (item) => item.textContent === 'Update available: 2.1.7',
    ) ||
    document.getElementById('updates-page').textContent.includes('Update available: 2.1.6')
  ) {
    regressions.push(
      'a later automatic result leaves the previous available version on the update page',
    );
  }

  api = await mount();
  api.downloadFailure = true;
  api.downloadErrorMessage = 'Download failed: ' + 'x'.repeat(4000);
  await click('Update now');
  const errorBounds = popup().getBoundingClientRect();
  if (
    errorBounds.top < 0 ||
    errorBounds.bottom > innerHeight ||
    popup().scrollWidth > popup().clientWidth
  ) {
    regressions.push('a long installation error pushes the popup outside the viewport');
  }
  assert.equal(
    popup().querySelector('[role="status"]').textContent,
    'Install failed: ' + api.downloadErrorMessage,
  );
  for (const label of ['Update now', 'Close update notification', 'View changes']) {
    const control = button(label);
    const rect = control.getBoundingClientRect();
    if (
      !control.contains(
        document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2),
      )
    ) {
      regressions.push(label + ' must remain reachable after a long installation error');
    }
  }
  assert.deepEqual(regressions, []);
  await React.act(async () => root.unmount());
  assert.equal(previousListeners.size, 0);
}

runUpdateNotificationTests();
