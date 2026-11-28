import { protectVaultDisplayWindow } from './vault-display-window.ts';
import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainInvokeEvent,
} from 'electron';
import {
  consumeVaultEnrollmentBegin,
  consumeVaultEnrollmentConfirm,
} from './vault-enrollment-contract.ts';
import type { VaultBackendHost } from './vault-host.js';

type Dialog = {
  window: BrowserWindow;
  parent: BrowserWindow;
  accepted: () => boolean;
  target: string;
  busy: boolean;
  enrollmentId?: string;
  vaultId?: string;
  finish: (success: boolean) => Promise<void>;
};
type Options = {
  host: VaultBackendHost;
  ipc: Pick<IpcMain, 'handle'>;
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  url: string;
  preload: string;
  activate: () => void;
  platform?: NodeJS.Platform;
};

// Only this main-owned window receives the enrollment bridge. The ordinary app
// can ask to open it, but cannot select an HPKE recipient or submit confirmations.
export class VaultCreateDialog {
  private current: Dialog | undefined;
  private readonly options: Options;
  constructor(options: Options) {
    this.options = options;
    options.ipc.handle('vault-enrollment:begin', async (event, ...args: unknown[]) => {
      const input = consumeVaultEnrollmentBegin(args[0]);
      let dialog: Dialog | undefined;
      let reserved = false;
      try {
        dialog = this.trusted(event);
        if (!dialog || args.length !== 1 || dialog.busy || dialog.enrollmentId)
          throw Error('Invalid vault dialog request.');
        dialog.busy = reserved = true;
        const result = await options.host.beginEnrollment(input);
        if (this.trusted(event) !== dialog) {
          await dialog.finish(false);
          throw Error('Vault dialog closed.');
        }
        dialog.enrollmentId = result.enrollmentId;
        dialog.vaultId = result.vaultId;
        return result;
      } finally {
        input.password.fill(0);
        input.publicKey.fill(0);
        if (dialog && reserved) dialog.busy = false;
      }
    });
    options.ipc.handle('vault-enrollment:confirm', async (event, ...args: unknown[]) => {
      const input = consumeVaultEnrollmentConfirm(args[0]);
      let dialog: Dialog | undefined;
      let reserved = false;
      try {
        dialog = this.trusted(event);
        if (
          !dialog ||
          args.length !== 1 ||
          dialog.busy ||
          dialog.enrollmentId !== input.enrollmentId
        )
          throw Error('Invalid vault dialog request.');
        dialog.busy = reserved = true;
        const result = await options.host.confirmEnrollment(input);
        if (this.trusted(event) !== dialog || options.host.unlockedWorkspaceId !== dialog.vaultId) {
          await dialog.finish(false);
          throw Error('Vault dialog closed.');
        }
        await dialog.finish(true);
        return result;
      } finally {
        input.groups.fill(0);
        if (dialog && reserved) dialog.busy = false;
      }
    });
    options.ipc.handle('vault-enrollment:cancel', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid vault dialog request.');
      await dialog.finish(false);
    });
  }
  get active(): boolean {
    return this.current !== undefined;
  }
  cancel(): Promise<void> {
    return this.current?.finish(false) ?? Promise.resolve();
  }
  private trusted(event: IpcMainInvokeEvent): Dialog | undefined {
    const dialog = this.current;
    try {
      return dialog &&
        !dialog.window.isDestroyed() &&
        !dialog.parent.isDestroyed() &&
        dialog.accepted() &&
        event.sender === dialog.window.webContents &&
        event.senderFrame === event.sender.mainFrame &&
        event.senderFrame?.url === dialog.target
        ? dialog
        : undefined;
    } catch {
      return undefined;
    }
  }
  open(parent: BrowserWindow, accepted: () => boolean): Promise<boolean> {
    if (this.current || parent.isDestroyed() || !accepted() || this.options.host.isVaultWorkspace)
      return Promise.reject(Error('Vault creation unavailable.'));
    const window = this.options.createWindow({
      width: 650,
      height: 650,
      minWidth: 520,
      minHeight: 540,
      parent,
      modal: true,
      show: false,
      autoHideMenuBar: true,
      title: 'Protect your Wormhole workspace',
      webPreferences: {
        preload: this.options.preload,
        partition: `vault-recovery-${randomUUID()}`,
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        webSecurity: true,
        devTools: false,
        spellcheck: false,
      },
    });
    let resolve!: (value: boolean) => void, reject!: (error: Error) => void;
    const result = new Promise<boolean>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    let finishing: Promise<void> | undefined;
    const parentClosed = () => {
      void dialog.finish(false).catch(() => undefined);
    };
    const timer = setTimeout(parentClosed, 7 * 60_000);
    timer.unref();
    const dialog: Dialog = {
      window,
      parent,
      accepted,
      target: this.options.url,
      busy: false,
      finish: (success) => {
        finishing ??= Promise.resolve().then(async () => {
          clearTimeout(timer);
          parent.removeListener('closed', parentClosed);
          let created = success;
          try {
            if (created) {
              if (
                !accepted() ||
                parent.isDestroyed() ||
                this.options.host.unlockedWorkspaceId !== dialog.vaultId
              )
                throw Error('Vault creation owner changed.');
              this.options.activate();
            }
          } catch {
            created = false;
          }
          if (!window.isDestroyed()) window.destroy();
          try {
            if (!created) await this.options.host.stop();
            resolve(created);
          } catch {
            reject(Error('Vault shutdown could not be confirmed.'));
          } finally {
            if (this.current === dialog) this.current = undefined;
          }
        });
        return finishing;
      },
    };
    this.current = dialog;
    parent.once('closed', parentClosed);
    window.once('closed', parentClosed);
    try {
      let loaded = false;
      protectVaultDisplayWindow(
        window,
        this.options.url,
        () => loaded,
        parentClosed,
        this.options.platform,
      );
      void window
        .loadURL(this.options.url)
        .then(() => {
          loaded = true;
          if (this.current === dialog && !finishing && !window.isDestroyed() && accepted())
            window.show();
          else return dialog.finish(false);
        })
        .catch(() => dialog.finish(false));
    } catch {
      void dialog.finish(false).catch(() => undefined);
    }
    return result;
  }
}
