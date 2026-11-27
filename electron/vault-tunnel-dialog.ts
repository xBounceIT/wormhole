import { parseTunnelImportChoice, type VaultTunnelImportFormat } from './vault-tunnel-import.ts';
import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainInvokeEvent,
} from 'electron';
import type { VaultBackendHost, VaultFreshAuthentication } from './vault-host.js';
import {
  consumeVaultTunnelInput,
  parseVaultTunnelSelection,
  type VaultTunnelSelection,
  type VaultTunnelResult,
} from './vault-tunnel.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import { protectVaultDisplayWindow } from './vault-display-window.ts';
import type { VaultWorkspaceNode } from './vault-workspace.ts';

type Options = {
  host: VaultBackendHost;
  ipc: Pick<IpcMain, 'handle'>;
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  confirm: (parent: BrowserWindow, accepted: () => boolean) => VaultFreshAuthentication;
  url: string;
  preload: string;
  platform?: NodeJS.Platform;
  capabilities: () => Promise<{ openVpn: boolean }>;
  pickImport: (parent: BrowserWindow, format: VaultTunnelImportFormat) => Promise<string | null>;
};
type Dialog = {
  window: BrowserWindow;
  valid: () => boolean;
  context: { workspaceId: string; requestId: string; selection: VaultTunnelSelection | null };
  used: boolean;
  ready: boolean;
  busy: boolean;
  staged?: { id: string; kind: number };
  finish: (saved?: VaultTunnelResult) => Promise<void>;
};

// Only the isolated document can supply the recipient or a settings patch.
// The ordinary app selects an existing revision or null for a new tunnel.
export class VaultTunnelDialog {
  private current: Dialog | undefined;
  private readonly options: Options;
  constructor(options: Options) {
    this.options = options;
    options.ipc.handle('vault-tunnel:capabilities', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid tunnel editor request.');
      let available = false;
      try {
        available = (await options.capabilities()).openVpn === true;
      } catch {
        /* Probe failure keeps dependent providers unavailable. */
      }
      if (this.trusted(event) !== dialog) throw Error('Tunnel editor closed.');
      return { openVpn: available };
    });
    options.ipc.handle('vault-tunnel:references', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid tunnel editor request.');
      try {
        const workspace = await options.host.workspace();
        if (this.trusted(event) !== dialog) throw Error('Tunnel editor closed.');
        const connections: { id: string; name: string }[] = [];
        const visit = (nodes: VaultWorkspaceNode[]) => {
          for (const node of nodes) {
            if (node.kind === 'connection' && node.protocol === 'ssh')
              connections.push({ id: node.id, name: node.name });
            if (node.children) visit(node.children);
          }
        };
        visit(workspace.tree);
        return {
          connections,
          tunnels: workspace.tunnels
            .filter((t) => t.kind === 'Fortinet')
            .map(({ id, name }) => ({ id, name })),
          credentials: workspace.credentialOptions.ssh.map(({ id, name }) => ({ id, name })),
        };
      } catch {
        throw Error('Tunnel references are unavailable.');
      }
    });
    options.ipc.handle('vault-tunnel:context', (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid tunnel editor request.');
      return {
        ...dialog.context,
        selection: dialog.context.selection ? { ...dialog.context.selection } : null,
      };
    });
    options.ipc.handle('vault-tunnel:read', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event),
        selection = dialog?.context.selection;
      if (
        !dialog ||
        !selection ||
        args.length !== 1 ||
        dialog.used ||
        dialog.busy ||
        !enrollmentBytes(args[0], 32)
      )
        throw Error('Invalid tunnel editor request.');
      dialog.used = true;
      try {
        const result = await options.host.displayTunnelEditor({
          workspaceId: dialog.context.workspaceId,
          requestId: dialog.context.requestId,
          tunnelId: selection.id,
          rowVersion: selection.rowVersion,
          publicKey: args[0],
        });
        if (this.trusted(event) !== dialog) throw Error('Tunnel editor closed.');
        dialog.ready = true;
        return result;
      } catch {
        throw Error(
          'Stored tunnel settings are unavailable. Close the editor and refresh the tunnel.',
        );
      }
    });
    options.ipc.handle('vault-tunnel:import', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event),
        choice = parseTunnelImportChoice(args[0]);
      if (!dialog || !choice || args.length !== 1 || !dialog.ready || dialog.busy)
        throw Error('Invalid tunnel import request.');
      dialog.busy = true;
      try {
        const path = await options.pickImport(dialog.window, choice.format);
        if (this.trusted(event) !== dialog) throw Error('Tunnel editor closed.');
        if (path === null) return null;
        const result = await options.host.stageTunnelImport(
          {
            ...choice,
            path,
            workspaceId: dialog.context.workspaceId,
            editorId: dialog.context.requestId,
            tunnelId: dialog.context.selection?.id ?? '',
            rowVersion: dialog.context.selection?.rowVersion ?? '0',
          },
          () => this.trusted(event) === dialog,
        );
        if (this.trusted(event) !== dialog) throw Error('Tunnel editor closed.');
        dialog.staged = { id: choice.importId, kind: choice.kind };
        return result;
      } catch {
        throw Error('The profile could not be imported. Check the file and try again.');
      } finally {
        if (this.trusted(event) === dialog) dialog.busy = false;
        else await dialog.finish();
      }
    });
    options.ipc.handle('vault-tunnel:discard-import', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length || !dialog.ready || dialog.busy)
        throw Error('Invalid tunnel import discard.');
      dialog.busy = true;
      try {
        await options.host.discardTunnelImport({
          workspaceId: dialog.context.workspaceId,
          editorId: dialog.context.requestId,
          importId: '',
        });
        if (this.trusted(event) !== dialog) throw Error('Tunnel editor closed.');
        dialog.staged = undefined;
      } catch {
        // After an ambiguous discard the form cannot know which snapshot remains.
        await dialog.finish();
        throw Error('Tunnel import discard failed. Close the editor and try again.');
      } finally {
        if (this.trusted(event) === dialog) dialog.busy = false;
      }
    });
    options.ipc.handle('vault-tunnel:save', async (event, ...args: unknown[]) => {
      const input = consumeVaultTunnelInput(args[0]);
      let dialog: Dialog | undefined;
      try {
        dialog = this.trusted(event);
        if (
          !dialog ||
          args.length !== 1 ||
          !dialog.ready ||
          dialog.busy ||
          input.editorId !== undefined ||
          input.importId !== undefined ||
          (dialog.staged !== undefined && dialog.staged.kind !== input.metadata.kind) ||
          input.metadata.id !== (dialog.context.selection?.id ?? '') ||
          input.rowVersion !== (dialog.context.selection?.rowVersion ?? '0')
        )
          throw Error('Invalid tunnel editor request.');
        if (dialog.staged) {
          input.editorId = dialog.context.requestId;
          input.importId = dialog.staged.id;
        }
        dialog.busy = true;
        const active = dialog;
        try {
          const accepted = () => this.trusted(event) === active;
          const result = await options.host.editTunnel(
            input,
            options.confirm(dialog.window, accepted),
            accepted,
          );
          if (!accepted()) {
            await dialog.finish();
            return false;
          }
          await dialog.finish(result);
          return true;
        } catch {
          // Clear busy only while this exact document still owns the operation.
          // Cancellation otherwise waits for the native owner's confirmed exit.
          if (this.trusted(event) === dialog) dialog.busy = false;
          else await dialog.finish();
          return false;
        }
      } finally {
        input.patch.fill(0);
      }
    });
    options.ipc.handle('vault-tunnel:close', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Invalid tunnel editor request.');
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
  open(
    parent: BrowserWindow,
    accepted: () => boolean,
    value: unknown,
  ): Promise<VaultTunnelResult | null> {
    const selection = value === null ? null : parseVaultTunnelSelection(value),
      workspace = this.options.host.unlockedWorkspaceId;
    if (
      selection === undefined ||
      !workspace ||
      this.current ||
      parent.isDestroyed() ||
      !accepted()
    )
      return Promise.reject(Error('Tunnel editor unavailable.'));
    const window = this.options.createWindow({
      width: 780,
      height: 740,
      parent,
      modal: true,
      show: false,
      autoHideMenuBar: true,
      title: selection ? 'Edit VPN tunnel' : 'Add VPN tunnel',
      webPreferences: {
        preload: this.options.preload,
        partition: `vault-tunnel-${randomUUID()}`,
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        webSecurity: true,
        devTools: false,
        spellcheck: false,
      },
    });
    let resolve!: (saved: VaultTunnelResult | null) => void,
      reject!: (error: Error) => void,
      closing: Promise<void> | undefined,
      failed = false;
    const result = new Promise<VaultTunnelResult | null>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const finish = (saved?: VaultTunnelResult): Promise<void> => {
      if (closing) return closing;
      clearTimeout(timer);
      parent.removeListener('closed', cancel);
      parent.webContents.removeListener('did-start-navigation', navigation);
      parent.webContents.removeListener('render-process-gone', cancel);
      window.removeListener('closed', cancel);
      closing = Promise.resolve().then(async () => {
        try {
          // Retire the isolated document immediately, even if native shutdown
          // is slow. Keep this dialog reserved until exit is confirmed.
          try {
            if (!window.isDestroyed()) window.destroy();
          } finally {
            if (!saved && dialog.busy) await this.options.host.stop();
            else if (
              !saved &&
              dialog.staged &&
              this.options.host.unlockedWorkspaceId === workspace
            ) {
              try {
                await this.options.host.discardTunnelImport({
                  workspaceId: workspace,
                  editorId: dialog.context.requestId,
                  importId: '',
                });
              } catch {
                await this.options.host.stop();
              }
            }
          }
          if (failed) reject(Error('Tunnel editor could not be opened.'));
          else resolve(saved ?? null);
        } catch {
          reject(Error('Tunnel editor shutdown could not be confirmed.'));
        } finally {
          if (this.current === dialog) this.current = undefined;
          if (!window.isDestroyed()) window.destroy();
        }
      });
      return closing;
    };
    const cancel = () => {
      void finish();
    };
    const fail = () => {
      failed = true;
      cancel();
    };
    const navigation = (_event: unknown, _url: string, _inPlace: boolean, mainFrame: boolean) => {
      if (mainFrame) cancel();
    };
    const timer = setTimeout(cancel, 5 * 60_000);
    timer.unref();
    const dialog: Dialog = {
      window,
      context: { workspaceId: workspace, requestId: randomUUID(), selection },
      used: false,
      ready: selection === null,
      busy: false,
      finish,
      valid: () =>
        this.current === dialog &&
        !closing &&
        !window.isDestroyed() &&
        !parent.isDestroyed() &&
        accepted() &&
        this.options.host.unlockedWorkspaceId === workspace,
    };
    this.current = dialog;
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
        .catch(fail);
    } catch {
      fail();
    }
    return result;
  }
}
