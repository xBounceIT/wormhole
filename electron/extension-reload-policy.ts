export function shouldDeferExtensionReload(
  loadedInstallKey: string | undefined,
  requestedInstallKey: string,
  activeSurfaceCount: number,
): boolean {
  return (
    loadedInstallKey !== undefined &&
    loadedInstallKey !== requestedInstallKey &&
    activeSurfaceCount > 0
  );
}
