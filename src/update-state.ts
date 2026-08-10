export function hasNewerReleaseWithoutInstaller(result: {
  currentVersion: string;
  latestVersion: string;
  isUpdateAvailable: boolean;
}): boolean {
  return Boolean(
    result.latestVersion &&
    result.latestVersion !== result.currentVersion &&
    !result.isUpdateAvailable,
  );
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
