import type { ChildProcessByStdio } from 'node:child_process';
import path from 'node:path';
import type { Readable, Writable } from 'node:stream';

// Go holds the verified image until it receives exactly one decision and EOF.
// A clean exit after that decision acknowledges native process creation.
export function completeWindowsUpdateHandoff(
  child: ChildProcessByStdio<Writable, Readable, null>,
  request: object,
  authorize: (publisherVerified: boolean, commit: (restart: boolean) => void) => Promise<void>,
  timeoutMs = 120_000,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let closed = false;
    let committed = false;
    let receipt = '';
    const timeout = setTimeout(
      () =>
        fail(
          new Error(
            committed
              ? 'Windows did not confirm the installer launch. Check whether setup opened before trying again.'
              : 'Installer verification timed out.',
          ),
        ),
      timeoutMs,
    );
    function fail(error: Error) {
      if (closed) return;
      closed = true;
      clearTimeout(timeout);
      child.stdin.destroy();
      child.kill();
      reject(error);
    }
    child.once('error', fail);
    child.stdin.on('error', fail);
    child.stdout.on('error', fail);
    child.once('close', (code) => {
      if (closed) return;
      if (code !== 0 || !committed) {
        fail(
          new Error(
            committed
              ? 'The verified Windows installer could not be started.'
              : 'The Windows installer could not be verified.',
          ),
        );
        return;
      }
      closed = true;
      clearTimeout(timeout);
      resolve();
    });
    child.stdout.on('data', (chunk: Buffer) => {
      if (closed) return;
      if (receipt.length + chunk.length > 2) {
        fail(new Error('Invalid installer verification response.'));
        return;
      }
      receipt += chunk.toString('latin1');
      if (receipt.length < 2) return;
      if (receipt !== 'P\n' && receipt !== 'V\n') {
        fail(new Error('Invalid installer verification response.'));
        return;
      }
      void authorize(receipt === 'P\n', (restart) => {
        if (closed || committed) throw new Error('Installer authorization expired.');
        committed = true;
        timeout.refresh();
        child.stdin.end(restart ? 'R' : 'C');
      }).catch(fail);
    });
    try {
      const frame = JSON.stringify(request) + '\n';
      if (Buffer.byteLength(frame) > 16 * 1024) throw new Error();
      child.stdin.write(frame);
    } catch {
      fail(new Error('Invalid installer verification request.'));
    }
  });
}

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
  managed = false,
): boolean {
  const expectedExtension = updateInstallerExtension(platform);
  if (!expectedExtension) return false;
  const installerPath = path.resolve(value);
  const resolvedCacheRoot = path.resolve(cacheRoot);
  const relative = path.relative(resolvedCacheRoot, installerPath);
  const extension = path.extname(installerPath).toLowerCase();
  return (
    relative !== '' &&
    path.dirname(relative) === '.' &&
    (managed && platform === 'linux'
      ? extension === '.deb' || extension === '.rpm'
      : extension === expectedExtension)
  );
}

export function updateInstallAction(platform: string): UpdateInstallAction | undefined {
  switch (platform) {
    case 'win32':
      return 'execute';
    case 'darwin':
      return 'open';
    case 'linux':
      // Reveal the verified AppImage or system package for deployment.
      return 'reveal';
    default:
      return undefined;
  }
}

type UpdateInstallerRuntime = {
  execute(installerPath: string): Promise<void>;
  openPath(installerPath: string): Promise<string>;
  showItemInFolder(installerPath: string): void;
};

export async function launchDownloadedUpdate(
  installerPath: string,
  platform: string,
  runtime: UpdateInstallerRuntime,
): Promise<void> {
  switch (updateInstallAction(platform)) {
    case 'execute':
      await runtime.execute(installerPath);
      return;
    case 'open': {
      const error = await runtime.openPath(installerPath);
      if (error) throw new Error(error);
      return;
    }
    case 'reveal':
      runtime.showItemInFolder(installerPath);
      return;
    default:
      throw new Error('Updates are not supported on this platform.');
  }
}
