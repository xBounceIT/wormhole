export function hasNewerReleaseWithoutInstaller(result: {
  latestVersion: string;
  isNewerRelease: boolean;
  isUpdateAvailable: boolean;
}): boolean {
  return Boolean(result.latestVersion && result.isNewerRelease && !result.isUpdateAvailable);
}

export function isUpdateInstallable(result: {
  latestVersion: string;
  isUpdateAvailable: boolean;
}): boolean {
  return Boolean(result.isUpdateAvailable && result.latestVersion);
}

export function shouldShowReleaseNotes(result: {
  latestVersion: string;
  isNewerRelease: boolean;
  isUpdateAvailable: boolean;
}): boolean {
  return isUpdateInstallable(result) || hasNewerReleaseWithoutInstaller(result);
}

export function unavailableInstallerMessage(result: {
  latestVersion: string;
  isNewerRelease: boolean;
  isUpdateAvailable: boolean;
  updatePolicy?: 'notify' | 'managed';
}): string | null {
  if (result.updatePolicy === 'notify' && hasNewerReleaseWithoutInstaller(result))
    return `Wormhole ${result.latestVersion} is available. The workspace update policy limits this app to notifications.`;
  return hasNewerReleaseWithoutInstaller(result)
    ? `Wormhole ${result.latestVersion} is available, but no verified installer is published for this platform.`
    : null;
}

export function updateStatusMessage(
  status: string,
  result: {
    latestVersion: string;
    isNewerRelease: boolean;
    isUpdateAvailable: boolean;
    checkFailed?: boolean;
    updatePolicy?: 'notify' | 'managed';
  } | null,
): string {
  if (status || !result) return status;
  if (result.updatePolicy === 'managed') {
    if (result.checkFailed)
      return 'The managed update could not be verified. Contact your administrator.';
    return result.isUpdateAvailable
      ? `Your administrator approved Wormhole ${result.latestVersion}.`
      : 'Updates are managed by your administrator.';
  }
  if (result.checkFailed) return "Couldn't reach the update server. Try again later.";
  return (
    unavailableInstallerMessage(result) ??
    (result.latestVersion && !isUpdateInstallable(result) ? "You're on the latest version." : '')
  );
}

export function shouldOfferUpdate(
  result: {
    latestVersion: string;
    isUpdateAvailable: boolean;
    isNewerRelease?: boolean;
    updatePolicy?: 'notify' | 'managed';
  },
  dismissedVersion: string | null,
): boolean {
  return Boolean(
    result.latestVersion !== dismissedVersion &&
    (isUpdateInstallable(result) ||
      (result.updatePolicy === 'notify' && result.latestVersion && result.isNewerRelease)),
  );
}

export async function installCheckedUpdate(
  api: Pick<NonNullable<Window['wormhole']>, 'downloadUpdate' | 'installUpdate'>,
  release: WormholeUpdateCheckResult,
  onDownloaded: () => void,
) {
  if (!release.isUpdateAvailable || !release.installerUrl || !release.installerFileName)
    throw Error('There is no verified installer for this release.');
  const installerPath = await api.downloadUpdate({
    installerUrl: release.installerUrl,
    installerFileName: release.installerFileName,
    ...(release.installerSha256 ? { installerSha256: release.installerSha256 } : {}),
    ...(release.installerSize != null ? { installerSize: release.installerSize } : {}),
  });
  onDownloaded();
  const installation = await api.installUpdate(installerPath);
  const status = installation.appWillQuit
    ? ''
    : release.updatePolicy === 'managed'
      ? 'Verified system package ready. Ask your administrator to install it from the folder that opened.'
      : 'AppImage downloaded. Replace your current AppImage with the verified download.';
  return { ...installation, status };
}
