import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainInvokeEvent,
} from 'electron';
import { protectVaultDisplayWindow } from './vault-display-window.ts';
import { consumeVaultUnlockInput, type VaultUnlockInput } from './vault-unlock.ts';
import type { VaultDescriptor } from './vault-contract.js';
import type { VaultFreshOperation } from './vault-host.js';

type Dialog = {
  window: BrowserWindow;
  valid: () => boolean;
  descriptor: VaultDescriptor;
  operation: VaultFreshOperation | 'migration-resume' | 'rotation-resume';
  busy: boolean;
  setBusy: (value: boolean) => void;
  submit: (input: VaultUnlockInput, owner: BrowserWindow) => Promise<unknown>;
  finish: (result?: { value: unknown }) => Promise<void>;
};
type Options = {
  ipc: Pick<IpcMain, 'handle'>;
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  stop: () => Promise<void>;
  url: string;
  preload: string;
  platform?: NodeJS.Platform;
};

// A main-owned dialog can submit a factor only for the action already captured
// by main. Its bridge cannot choose, replace or replay an operation.
export class VaultReauthenticationDialog {
  private current: Dialog | undefined;
  private readonly options: Options;
  constructor(options: Options) {
    this.options = options;
    options.ipc.handle('vault-reauth:context', (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid authentication dialog.');
      return { operation: dialog.operation, slots: dialog.descriptor };
    });
    options.ipc.handle('vault-reauth:submit', async (event, ...args: unknown[]) => {
      const input = consumeVaultUnlockInput(args[0]);
      let dialog: Dialog | undefined;
      try {
        dialog = this.trusted(event);
        if (
          !dialog ||
          args.length !== 1 ||
          dialog.busy ||
          input.vaultId !== dialog.descriptor.vaultId ||
          !dialog.descriptor.slots.some(
            (slot) =>
              slot.id === input.slotId &&
              slot.kind === (input.kind === 'password' ? 'password' : 'recovery'),
          )
        )
          throw Error('Invalid authentication dialog.');
        dialog.setBusy(true);
        try {
          const value = await dialog.submit(input, dialog.window);
          if (this.trusted(event) !== dialog) {
            await dialog.finish();
            return false;
          }
          dialog.setBusy(false);
          await dialog.finish({ value });
          return true;
        } catch {
          dialog.setBusy(false);
          if (this.trusted(event) !== dialog) await dialog.finish();
          return false;
        }
      } finally {
        input.factor.fill(0);
      }
    });
    options.ipc.handle('vault-reauth:cancel', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid authentication dialog.');
      await dialog.finish();
    });
  }
  cancel(): Promise<void> {
    return this.current?.finish() ?? Promise.resolve();
  }
  private trusted(event: IpcMainInvokeEvent): Dialog | undefined {
    const dialog = this.current;
    try {
      return dialog &&
        dialog.valid() &&
        event.sender === dialog.window.webContents &&
        event.senderFrame === event.sender.mainFrame &&
        event.senderFrame?.url === this.options.url
        ? dialog
        : undefined;
    } catch {
      return undefined;
    }
  }
  open<T>(
    parent: BrowserWindow,
    accepted: () => boolean,
    operation: VaultFreshOperation | 'migration-resume' | 'rotation-resume',
    descriptor: VaultDescriptor,
    submit: (input: VaultUnlockInput, owner: BrowserWindow) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T> {
    if (this.current || parent.isDestroyed() || !accepted() || signal?.aborted)
      return Promise.reject(Error('Authentication dialog unavailable.'));
    const window = this.options.createWindow({
      width: 510,
      height: 410,
      parent,
      modal: true,
      show: false,
      autoHideMenuBar: true,
      webPreferences: {
        preload: this.options.preload,
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        devTools: false,
        partition: `vault-reauth-${randomUUID()}`,
      },
    });
    let resolve!: (value: T) => void,
      reject!: (error: Error) => void,
      closing: Promise<void> | undefined;
    const result = new Promise<T>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const finish = (outcome?: { value: unknown }): Promise<void> => {
      if (closing) return closing;
      if (this.current === dialog) this.current = undefined;
      clearTimeout(timer);
      signal?.removeEventListener('abort', cancel);
      parent.removeListener('closed', cancel);
      parent.webContents.removeListener('did-start-navigation', navigation);
      parent.webContents.removeListener('render-process-gone', cancel);
      window.removeListener('closed', cancel);
      closing = Promise.resolve().then(async () => {
        try {
          if (!outcome && dialog.busy) await this.options.stop();
          if (outcome) resolve(outcome.value as T);
          else reject(Error('Authentication cancelled.'));
        } catch {
          reject(Error('Authentication cancelled.'));
        } finally {
          if (!window.isDestroyed()) window.destroy();
        }
      });
      return closing;
    };
    const cancel = () => {
      void finish();
    };
    const navigation = (_event: unknown, _url: string, _inPlace: boolean, mainFrame: boolean) => {
      if (mainFrame) cancel();
    };
    let timer = setTimeout(cancel, 5 * 60_000);
    timer.unref();
    const dialog: Dialog = {
      window,
      descriptor,
      operation,
      busy: false,
      setBusy: (value) => {
        dialog.busy = value;
        if (
          (operation === 'migration-resume' ||
            operation === 'rotation-resume' ||
            operation === 'local-backup-install') &&
          !closing
        ) {
          clearTimeout(timer);
          timer = setTimeout(cancel, (value ? 35 : 5) * 60_000);
          timer.unref();
        } else if (
          (operation === 'hello-enroll' ||
            operation === 'hello-remove' ||
            operation === 'touch-id-enroll' ||
            operation === 'touch-id-remove') &&
          !closing
        ) {
          clearTimeout(timer);
          timer = setTimeout(cancel, 5 * 60_000);
          timer.unref();
        }
      },
      submit,
      finish,
      valid: () =>
        this.current === dialog && !window.isDestroyed() && !parent.isDestroyed() && accepted(),
    };
    this.current = dialog;
    signal?.addEventListener('abort', cancel, { once: true });
    parent.once('closed', cancel);
    parent.webContents.on('did-start-navigation', navigation);
    parent.webContents.once('render-process-gone', cancel);
    window.once('closed', cancel);
    try {
      let loaded = false;
      protectVaultDisplayWindow(
        window,
        this.options.url,
        () => loaded,
        cancel,
        this.options.platform,
      );
      void window
        .loadURL(this.options.url)
        .then(() => {
          loaded = true;
          if (dialog.valid()) window.show();
          else cancel();
        })
        .catch(cancel);
    } catch {
      cancel();
    }
    return result;
  }
}
