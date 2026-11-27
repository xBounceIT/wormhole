import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainInvokeEvent,
} from 'electron';
import { protectVaultDisplayWindow } from './vault-display-window.ts';

type Dialog<C, E> = {
  window: BrowserWindow;
  context: C;
  valid: () => boolean;
  finish: (value?: E) => void;
};
export type ProtectedEntryOptions = {
  ipc: Pick<IpcMain, 'handle'>;
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  url: string;
  preload: string;
  platform?: NodeJS.Platform;
};
// Only a main-owned document can read the native recipient context or submit
// one opaque envelope. This bridge has no password, destination or vault API.
export class VaultProtectedEntryDialog<C, E> {
  private current?: Dialog<C, E>;
  private readonly options: ProtectedEntryOptions & {
    channel: string;
    title: string;
    height: number;
    parseContext: (value: unknown) => C | undefined;
    parseEnvelope: (value: unknown) => E | undefined;
  };
  constructor(options: VaultProtectedEntryDialog<C, E>['options']) {
    this.options = options;
    options.ipc.handle(`${options.channel}:context`, (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid password document.');
      return structuredClone(dialog.context);
    });
    options.ipc.handle(`${options.channel}:submit`, (event, ...args: unknown[]) => {
      const dialog = this.trusted(event),
        envelope = options.parseEnvelope(args[0]);
      if (!dialog || args.length !== 1 || !envelope) throw Error('Invalid password envelope.');
      dialog.finish(envelope);
      if (!dialog.window.isDestroyed())
        throw Error('Protected credential document could not be closed.');
      return true;
    });
    options.ipc.handle(`${options.channel}:cancel`, (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid password document.');
      return this.cancelCurrent();
    });
  }
  async cancel(): Promise<void> {
    return this.cancelCurrent();
  }
  private async cancelCurrent(): Promise<void> {
    const dialog = this.current;
    dialog?.finish();
    if (dialog && !dialog.window.isDestroyed())
      throw Error('Protected credential document shutdown could not be confirmed.');
  }
  protected cancelMatching(matches: (context: C) => boolean): Promise<void> {
    return this.current && matches(this.current.context) ? this.cancelCurrent() : Promise.resolve();
  }
  private trusted(event: IpcMainInvokeEvent): Dialog<C, E> | undefined {
    try {
      const dialog = this.current;
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
  open(
    parent: BrowserWindow,
    accepted: () => boolean,
    value: unknown,
    signal: AbortSignal,
  ): Promise<E> {
    const context = this.options.parseContext(value);
    if (!context || this.current || parent.isDestroyed() || !accepted() || signal.aborted)
      return Promise.reject(Error('Protected credential entry unavailable.'));
    const window = this.options.createWindow({
      width: 510,
      height: this.options.height,
      parent,
      modal: true,
      show: false,
      autoHideMenuBar: true,
      title: this.options.title,
      webPreferences: {
        preload: this.options.preload,
        partition: `${this.options.channel}-${randomUUID()}`,
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        webSecurity: true,
        devTools: false,
        spellcheck: false,
      },
    });
    let resolve!: (value: E) => void,
      reject!: (error: Error) => void,
      closing = false;
    const result = new Promise<E>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const finish = (envelope?: E): void => {
      if (closing) {
        // A previous native destroy may have failed. An explicit shutdown retry
        // can establish its positive exit proof without accepting that envelope.
        try {
          if (!window.isDestroyed()) window.destroy();
        } catch {
          // Keep the original document reserved until a later confirmed close.
        }
        if (window.isDestroyed() && this.current === dialog) this.current = undefined;
        return;
      }
      closing = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', cancel);
      parent.removeListener('closed', cancel);
      parent.webContents.removeListener('did-start-navigation', navigation);
      parent.webContents.removeListener('render-process-gone', cancel);
      window.removeListener('closed', cancel);
      try {
        if (!window.isDestroyed()) window.destroy();
        if (!window.isDestroyed())
          throw Error('Protected credential document could not be closed.');
        if (envelope) resolve(envelope);
        else reject(Error('Protected credential entry cancelled.'));
      } catch {
        reject(Error('Protected credential document could not be closed.'));
      } finally {
        if (window.isDestroyed() && this.current === dialog) this.current = undefined;
      }
    };
    const cancel = () => finish();
    const navigation = (_event: unknown, _url: string, _inPlace: boolean, mainFrame: boolean) => {
      if (mainFrame) cancel();
    };
    const timer = setTimeout(cancel, 5 * 60000);
    timer.unref();
    const dialog: Dialog<C, E> = {
      window,
      context,
      finish,
      valid: () =>
        this.current === dialog &&
        !closing &&
        !window.isDestroyed() &&
        !parent.isDestroyed() &&
        !signal.aborted &&
        accepted(),
    };
    this.current = dialog;
    signal.addEventListener('abort', cancel, { once: true });
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
      // Cover synchronous invalidation while installing window protection.
      if (!dialog.valid()) cancel();
    } catch {
      cancel();
    }
    return result;
  }
}
