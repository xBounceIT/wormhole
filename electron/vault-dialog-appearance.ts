import type { BrowserWindow, BrowserWindowConstructorOptions } from 'electron';
import type { AppTheme } from './theme-settings.ts';

// Each protected dialog owns an ephemeral session. Register before loadURL so
// its first document gets the workspace palette alongside its isolated bridge.
export function createVaultDialogWindow(
  options: BrowserWindowConstructorOptions,
  theme: AppTheme,
  appearancePreload: string,
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow,
): BrowserWindow {
  const window = createWindow({
    ...options,
    webPreferences: {
      ...options.webPreferences,
      additionalArguments: [
        ...(options.webPreferences?.additionalArguments ?? []),
        '--wormhole-appearance=' + theme,
      ],
    },
  });
  try {
    window.webContents.session.registerPreloadScript({
      type: 'frame',
      filePath: appearancePreload,
    });
  } catch {
    // A missing cosmetic preload must leave the operation-specific bridge usable.
  }
  return window;
}
