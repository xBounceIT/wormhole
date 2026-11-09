import path from 'node:path';

export type UpdateInstallAction = 'execute' | 'open' | 'reveal';

export function updateInstallerExtension(platform: string): string | undefined {
  switch (platform) {
    case 'win32':
      return '.exe';
    case 'darwin':
      return '.dmg';
    case 'linux':
      return '.appimage';
    default:
      return undefined;
  }
}

export function isSafeUpdateInstallerPath(
  value: string,
  cacheRoot: string,
  platform: string,
): boolean {
  const expectedExtension = updateInstallerExtension(platform);
  if (!expectedExtension) return false;
  const installerPath = path.resolve(value);
  const resolvedCacheRoot = path.resolve(cacheRoot);
  const relative = path.relative(resolvedCacheRoot, installerPath);
  return (
    relative !== '' &&
    path.dirname(relative) === '.' &&
    path.extname(installerPath).toLowerCase() === expectedExtension
  );
}

export function updateInstallAction(platform: string): UpdateInstallAction | undefined {
  switch (platform) {
    case 'win32':
      return 'execute';
    case 'darwin':
      return 'open';
    case 'linux':
      // An AppImage has no installer transaction. Reveal the verified download so the user can
      // replace the AppImage they launched instead of running a temporary cached copy.
      return 'reveal';
    default:
      return undefined;
  }
}

type UpdateInstallerRuntime = {
  execute(installerPath: string): Promise<void>;
  openPath(installerPath: string): Promise<string>;
  showItemInFolder(installerPath: string): void;
  quit(): void | Promise<void>;
};

export async function launchDownloadedUpdate(
  installerPath: string,
  platform: string,
  runtime: UpdateInstallerRuntime,
): Promise<{ appWillQuit: boolean }> {
  switch (updateInstallAction(platform)) {
    case 'execute':
      await runtime.execute(installerPath);
      break;
    case 'open': {
      const error = await runtime.openPath(installerPath);
      if (error) throw new Error(error);
      break;
    }
    case 'reveal':
      runtime.showItemInFolder(installerPath);
      return { appWillQuit: false };
    default:
      throw new Error('Updates are not supported on this platform.');
  }
  // A mounted DMG can launch a second copy of Wormhole. Close the running app before
  // the user replaces it, using the same session cleanup as the Windows installer.
  await runtime.quit();
  return { appWillQuit: true };
}
