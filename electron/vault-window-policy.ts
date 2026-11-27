import type { BrowserWindow, BrowserWindowConstructorOptions } from 'electron';
import type { VaultProfile } from './vault-security.ts';

type Window = Pick<
  BrowserWindow,
  'destroy' | 'isContentProtected' | 'isDestroyed' | 'setContentProtection' | 'show'
>;

const secretWindows = new WeakSet<Window>();
const unavailable = () => new Error('Content protection unavailable.');

function enableContentProtection(window: Window): void {
  window.setContentProtection(true);
  if (!window.isContentProtected()) throw unavailable();
}

// A dialog can independently require protection while the workspace requests
// it for all windows. A later unlock with a weaker profile must preserve this.
export function protectSecretWindow(window: Window): void {
  enableContentProtection(window);
  secretWindows.add(window);
}

type Options<T extends Window> = {
  platform: NodeJS.Platform;
  getWindows(): T[];
  createWindow(options: BrowserWindowConstructorOptions): T;
};

export class VaultWindowPolicy<T extends Window> {
  private readonly options: Options<T>;
  private allWindows = false;
  private readonly managed = new WeakSet<T>();

  constructor(options: Options<T>) {
    this.options = options;
  }

  get requiresContentProtection(): boolean {
    return this.allWindows;
  }

  // Called only with an authenticated profile. Lock leaves protection in place
  // while renderers are still painting or tearing down their previous workspace.
  apply(profile: VaultProfile): void {
    const allWindows = profile === 'hardened' || profile === 'paranoid';
    if (allWindows && this.options.platform !== 'win32' && this.options.platform !== 'darwin') {
      throw unavailable();
    }
    if (!allWindows && !this.allWindows) return;
    if (allWindows) this.allWindows = true;
    for (const window of this.options.getWindows()) {
      if (window.isDestroyed()) continue;
      if (allWindows) {
        this.protect(window);
      } else if (this.managed.has(window)) {
        if (!secretWindows.has(window)) window.setContentProtection(false);
        this.managed.delete(window);
      }
    }
    this.allWindows = allWindows;
  }

  createWindow(options: BrowserWindowConstructorOptions): T {
    const window = this.options.createWindow({
      ...options,
      ...(this.allWindows ? { show: false } : {}),
      webPreferences: {
        ...options.webPreferences,
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        devTools: false,
      },
    });
    if (!this.allWindows) return window;
    try {
      this.protect(window);
      if (options.show !== false) window.show();
      return window;
    } catch (error) {
      if (!window.isDestroyed()) window.destroy();
      throw error;
    }
  }

  private protect(window: T): void {
    if (!window.isContentProtected()) {
      this.managed.add(window);
      enableContentProtection(window);
    }
  }
}
