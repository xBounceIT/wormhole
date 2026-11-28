import {
  vaultClipboardField,
  type VaultClipboardField,
  type VaultClipboardResult,
} from './vault-clipboard.ts';
import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainInvokeEvent,
} from 'electron';
import type { VaultBackendHost } from './vault-host.js';
import {
  parseVaultNotesSelection,
  type VaultNotesContext,
  type VaultNotesRequest,
  type VaultNotesDisplay,
} from './vault-notes.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import { protectVaultDisplayWindow } from './vault-display-window.ts';

export type VaultNodeDisplayOptions = {
  host: Pick<VaultBackendHost, 'unlockedWorkspaceId'>;
  ipc: Pick<IpcMain, 'handle'>;
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  url: string;
  preload: string;
  platform?: NodeJS.Platform;
};
type Options = VaultNodeDisplayOptions & {
  purpose: 'notes' | 'credentials';
  copy?(
    context: VaultNotesContext,
    field: VaultClipboardField,
    parent: BrowserWindow,
    accepted: () => boolean,
  ): Promise<VaultClipboardResult>;
  read(
    request: VaultNotesRequest,
    parent: BrowserWindow,
    accepted: () => boolean,
  ): Promise<VaultNotesDisplay>;
};
type Dialog = {
  window: BrowserWindow;
  valid: () => boolean;
  context: VaultNotesContext;
  used: boolean;
  ready: boolean;
  copying: boolean;
  finish: () => void;
};

// The app selects only an ID and revision. Recipient selection is available
// exclusively in the main-owned isolated window, once per window lifetime.
export class VaultNodeDisplayDialog {
  private current: Dialog | undefined;
  private readonly options: Options;
  constructor(options: Options) {
    this.options = options;
    const channel = `vault-${options.purpose}`;
    options.ipc.handle(`${channel}:context`, (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid display dialog request.');
      return { ...dialog.context };
    });
    options.ipc.handle(`${channel}:read`, async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (
        !dialog ||
        args.length !== 1 ||
        dialog.used ||
        typeof args[0] !== 'string' ||
        !enrollmentBytes(args[0], 32)
      )
        throw Error('Invalid display dialog request.');
      dialog.used = true;
      try {
        const result = await options.read(
          { ...dialog.context, publicKey: args[0] },
          dialog.window,
          dialog.valid,
        );
        if (this.trusted(event) !== dialog) throw Error('Display dialog closed.');
        dialog.ready = true;
        return result;
      } catch {
        // Backend messages and any attached diagnostics never cross this IPC.
        throw Error('Protected content is unavailable. Refresh the connection and try again.');
      }
    });
    if (options.copy)
      options.ipc.handle(`${channel}:copy`, async (event, ...args: unknown[]) => {
        const dialog = this.trusted(event);
        if (
          !dialog ||
          !dialog.ready ||
          dialog.copying ||
          args.length !== 1 ||
          !vaultClipboardField(args[0]) ||
          !['win32', 'darwin', 'linux'].includes(options.platform ?? process.platform)
        )
          throw Error('Invalid clipboard request.');
        dialog.copying = true;
        try {
          const result = await options.copy!(dialog.context, args[0], dialog.window, dialog.valid);
          if (this.trusted(event) !== dialog) throw Error('Display dialog closed.');
          return result;
        } catch {
          throw Error('Secure copy is unavailable. Refresh the connection and try again.');
        } finally {
          dialog.copying = false;
        }
      });
    options.ipc.handle(`${channel}:close`, (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid display dialog request.');
      dialog.finish();
    });
  }
  cancel(): void {
    this.current?.finish();
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
  open(parent: BrowserWindow, accepted: () => boolean, value: unknown): Promise<void> {
    const selection = parseVaultNotesSelection(value),
      workspace = this.options.host.unlockedWorkspaceId;
    if (!selection || !workspace || this.current || parent.isDestroyed() || !accepted())
      return Promise.reject(Error('Protected content is unavailable.'));
    const window = this.options.createWindow({
      width: 650,
      height: 540,
      parent,
      modal: true,
      show: false,
      autoHideMenuBar: true,
      title: this.options.purpose === 'notes' ? 'Stored notes' : 'Connection credentials',
      webPreferences: {
        preload: this.options.preload,
        partition: `vault-${this.options.purpose}-${randomUUID()}`,
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        webSecurity: true,
        devTools: false,
        spellcheck: false,
      },
    });
    let resolve!: () => void, reject!: (error: Error) => void;
    let failed = false;
    const result = new Promise<void>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const finish = () => {
      if (this.current !== dialog) return;
      this.current = undefined;
      clearTimeout(timer);
      parent.removeListener('closed', finish);
      parent.webContents.removeListener('did-start-navigation', parentNavigation);
      parent.webContents.removeListener('render-process-gone', finish);
      if (!window.isDestroyed()) window.destroy();
      if (failed) reject(Error('Protected window could not be opened.'));
      else resolve();
    };
    const fail = () => {
      failed = true;
      finish();
    };
    const parentNavigation = (
      _event: unknown,
      _url: string,
      _inPlace: boolean,
      mainFrame: boolean,
    ) => {
      if (mainFrame) finish();
    };
    const timer = setTimeout(finish, 5 * 60_000);
    timer.unref();
    const dialog: Dialog = {
      window,
      context: { ...selection, workspaceId: workspace, requestId: randomUUID() },
      used: false,
      ready: false,
      copying: false,
      valid: () =>
        this.current === dialog &&
        !window.isDestroyed() &&
        !parent.isDestroyed() &&
        accepted() &&
        this.options.host.unlockedWorkspaceId === workspace,
      finish,
    };
    this.current = dialog;
    parent.once('closed', finish);
    parent.webContents.on('did-start-navigation', parentNavigation);
    parent.webContents.once('render-process-gone', finish);
    window.once('closed', finish);
    try {
      let loaded = false;
      protectVaultDisplayWindow(
        window,
        this.options.url,
        () => loaded,
        finish,
        this.options.platform,
      );
      void window
        .loadURL(this.options.url)
        .then(() => {
          loaded = true;
          if (dialog.valid()) window.show();
          else finish();
        })
        .catch(fail);
    } catch {
      fail();
    }
    return result;
  }
}
