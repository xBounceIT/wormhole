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
}): string | null {
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
  } | null,
): string {
  if (status || !result) return status;
  if (result.checkFailed) return "Couldn't reach the update server. Try again later.";
  return (
    unavailableInstallerMessage(result) ??
    (result.latestVersion && !isUpdateInstallable(result) ? "You're on the latest version." : '')
  );
}

export function shouldOfferUpdate(
  result: { latestVersion: string; isUpdateAvailable: boolean },
  dismissedVersion: string | null,
): boolean {
  return isUpdateInstallable(result) && result.latestVersion !== dismissedVersion;
}
