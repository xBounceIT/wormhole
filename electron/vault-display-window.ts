import type { BrowserWindow } from 'electron';
import { protectSecretWindow } from './vault-window-policy.ts';

export function protectVaultDisplayWindow(
  window: BrowserWindow,
  url: string,
  loaded: () => boolean,
  parentClosed: () => void,
  platform: NodeJS.Platform = process.platform,
): void {
  // Electron implements capture exclusion only on Windows and macOS.
  // Linux still uses the isolated recovery flow and displays this limitation.
  if (platform !== 'linux') protectSecretWindow(window);
  window.setMenu(null);
  window.webContents.on('did-start-navigation', (_event, _url, _inPlace, mainFrame) => {
    if (loaded() && mainFrame) parentClosed();
  });
  window.webContents.on('before-input-event', (event, input) => {
    if (
      ['F5', 'F12'].includes(input.key) ||
      ((input.control || input.meta) && ['p', 's', 'r'].includes(input.key.toLowerCase()))
    )
      event.preventDefault();
  });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event) => event.preventDefault());
  window.webContents.on('will-frame-navigate', (event) => event.preventDefault());
  window.webContents.on('context-menu', (event) => event.preventDefault());
  window.webContents.once('render-process-gone', parentClosed);
  window.webContents.session.setPermissionRequestHandler((_contents, _permission, callback) =>
    callback(false),
  );
  window.webContents.session.setPermissionCheckHandler(() => false);
  window.webContents.session.on('will-download', (event) => event.preventDefault());
  const target = new URL(url),
    directory = new URL('.', target);
  window.webContents.session.webRequest.onBeforeRequest((details, callback) => {
    try {
      const resource = new URL(details.url);
      callback({
        cancel:
          resource.protocol !== target.protocol ||
          resource.hostname !== target.hostname ||
          resource.origin !== target.origin ||
          (target.protocol === 'file:' && !resource.pathname.startsWith(directory.pathname)),
      });
    } catch {
      callback({ cancel: true });
    }
  });
}
