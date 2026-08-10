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

export function shouldOfferUpdate(
  result: { latestVersion: string; isUpdateAvailable: boolean },
  skippedVersion: string | null,
): boolean {
  return isUpdateInstallable(result) && result.latestVersion !== skippedVersion;
}
