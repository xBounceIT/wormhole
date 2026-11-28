import { consumeVaultMigrationBegin } from './vault-migration-setup.ts';
import { consumeOSMigrationPrepare } from './vault-os-migration-contract.ts';
import { consumeVaultRootEnrollmentBegin } from './vault-root-enrollment.ts';
import type { VaultDescriptor } from './vault-contract.ts';
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
  encryptDatabase: boolean;
  enrollmentId?: string;
  vaultId?: string;
  source?: VaultDescriptor;
  extendDeadline: () => void;
  finish: (success: boolean) => Promise<void>;
};
type Options = {
  host: VaultBackendHost;
  ipc: Pick<IpcMain, 'handle'>;
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  url: string;
  preload: string;
  platform?: NodeJS.Platform;
  mode?: 'migration' | 'rotation' | 'upgrade' | 'os-migration';
};

// Only this main-owned window receives the enrollment bridge. The ordinary app
// can ask to open it, but cannot select an HPKE recipient or submit confirmations.
export class VaultMigrationSetupDialog {
  private current: Dialog | undefined;
  private readonly options: Options;
  constructor(options: Options) {
    this.options = options;
    const rotation = options.mode === 'rotation',
      upgrade = options.mode === 'upgrade',
      osMigration = options.mode === 'os-migration',
      prefix = osMigration
        ? 'vault-os-migration-setup'
        : rotation
          ? 'vault-rotation-setup'
          : upgrade
            ? 'vault-upgrade-setup'
            : 'vault-migration-setup';
    options.ipc.handle(`${prefix}:context`, async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length || dialog.busy || dialog.enrollmentId)
        throw Error('Invalid migration dialog request.');
      dialog.busy = true;
      try {
        const context = osMigration
          ? await options.host.osMigrationContext()
          : upgrade
            ? await options.host.upgradeSetupContext()
            : rotation
              ? await options.host.rootRotationSetupContext()
              : await options.host.migrationSetupContext();
        if (this.trusted(event) !== dialog) throw Error('Migration dialog closed.');
        if ('slots' in context) {
          if (
            dialog.encryptDatabase &&
            (context.slots.encrypted || context.slots.vaultId !== dialog.vaultId)
          )
            throw Error('Database encryption context changed.');
          dialog.source = context.slots;
          if (dialog.encryptDatabase) return { slots: context.slots, encryptDatabase: true };
        } else if ('vaultId' in context) dialog.vaultId = context.vaultId;
        return context;
      } finally {
        dialog.busy = false;
      }
    });
    options.ipc.handle(`${prefix}:begin`, async (event, ...args: unknown[]) => {
      const request = osMigration
        ? { kind: 'os-migration' as const, input: consumeOSMigrationPrepare(args[0]) }
        : upgrade
          ? { kind: 'upgrade' as const, input: consumeVaultEnrollmentBegin(args[0]) }
          : rotation
            ? { kind: 'rotation' as const, input: consumeVaultRootEnrollmentBegin(args[0]) }
            : { kind: 'migration' as const, input: consumeVaultMigrationBegin(args[0]) };
      const { input } = request;
      let dialog: Dialog | undefined;
      let reserved = false;
      try {
        dialog = this.trusted(event);
        if (!dialog || args.length !== 1 || dialog.busy || dialog.enrollmentId)
          throw Error('Invalid vault dialog request.');
        if (upgrade && !dialog.vaultId) throw Error('Invalid vault dialog request.');
        if (
          request.kind === 'rotation' &&
          (!dialog.source ||
            request.input.authentication.vaultId !== dialog.source.vaultId ||
            !dialog.source.slots.some(
              (slot) =>
                slot.id === request.input.authentication.slotId &&
                slot.kind ===
                  (request.input.authentication.kind === 'password' ? 'password' : 'recovery'),
            ))
        )
          throw Error('Invalid vault dialog request.');
        dialog.busy = reserved = true;
        if (request.kind === 'os-migration') {
          const result = await options.host.prepareOSMigration(request.input);
          if (this.trusted(event) !== dialog) {
            await dialog.finish(false);
            throw Error('Vault dialog closed.');
          }
          dialog.vaultId = result.vaultId;
          await dialog.finish(true);
          return result;
        }
        const result =
          request.kind === 'rotation'
            ? await options.host.beginRootRotationSetup(request.input, dialog.encryptDatabase)
            : request.kind === 'migration'
              ? await options.host.beginMigrationSetup(request.input)
              : await options.host.beginUpgradeSetup(request.input);
        if (this.trusted(event) !== dialog || (upgrade && result.vaultId !== dialog.vaultId)) {
          await dialog.finish(false);
          throw Error('Vault dialog closed.');
        }
        dialog.enrollmentId = result.enrollmentId;
        dialog.vaultId = result.vaultId;
        return result;
      } finally {
        if (request.kind === 'migration' || request.kind === 'os-migration')
          request.input.legacyFactor.fill(0);
        else if (request.kind === 'rotation') request.input.authentication.factor.fill(0);
        if ('password' in input) input.password.fill(0);
        if ('publicKey' in input) input.publicKey.fill(0);
        if (dialog && reserved) dialog.busy = false;
      }
    });
    if (!osMigration)
      options.ipc.handle(`${prefix}:confirm`, async (event, ...args: unknown[]) => {
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
          if (rotation || upgrade) dialog.extendDeadline();
          const result = upgrade
            ? await options.host.confirmUpgradeSetup(input)
            : rotation
              ? await options.host.confirmRootRotationSetup(input)
              : await options.host.confirmMigrationSetup(input);
          if (this.trusted(event) !== dialog || result.vaultId !== dialog.vaultId) {
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
    options.ipc.handle(`${prefix}:cancel`, async (event, ...args: unknown[]) => {
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
  open(parent: BrowserWindow, accepted: () => boolean, encryptDatabase = false): Promise<boolean> {
    const rotation = this.options.mode === 'rotation';
    const upgrade = this.options.mode === 'upgrade';
    if (
      this.current ||
      parent.isDestroyed() ||
      !accepted() ||
      (encryptDatabase && !rotation) ||
      (upgrade
        ? !this.options.host.isVaultWorkspace ||
          this.options.host.isSharedWorkspace ||
          this.options.host.unlockedWorkspaceId !== undefined
        : rotation
          ? !this.options.host.unlockedWorkspaceId || this.options.host.isSharedWorkspace
          : this.options.host.isVaultWorkspace)
    )
      return Promise.reject(Error('Migration preparation unavailable.'));
    const window = this.options.createWindow({
      width: 650,
      height: 650,
      minWidth: 520,
      minHeight: 540,
      parent,
      modal: true,
      show: false,
      autoHideMenuBar: true,
      title: encryptDatabase
        ? 'Encrypt the vault database'
        : this.options.mode === 'os-migration'
          ? 'Move your existing workspace'
          : upgrade
            ? 'Set up vault protection'
            : rotation
              ? 'Update vault protection'
              : 'Protect your existing workspace',
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
    const parentNavigation = (
      _event: unknown,
      _url: string,
      _inPlace: boolean,
      mainFrame: boolean,
    ) => {
      if (mainFrame) parentClosed();
    };
    let timer = setTimeout(parentClosed, 7 * 60_000);
    timer.unref();
    const dialog: Dialog = {
      window,
      parent,
      accepted,
      target: this.options.url,
      busy: false,
      encryptDatabase,
      ...(encryptDatabase ? { vaultId: this.options.host.unlockedWorkspaceId } : {}),
      extendDeadline: () => {
        clearTimeout(timer);
        timer = setTimeout(parentClosed, 35 * 60_000);
        timer.unref();
      },
      finish: (success) => {
        finishing ??= Promise.resolve().then(async () => {
          clearTimeout(timer);
          parent.removeListener('closed', parentClosed);
          parent.webContents.removeListener('did-start-navigation', parentNavigation);
          parent.webContents.removeListener('render-process-gone', parentClosed);
          let created = success;
          try {
            if (created) {
              if (
                !accepted() ||
                parent.isDestroyed() ||
                this.options.host.unlockedWorkspaceId !== undefined
              )
                throw Error('Migration preparation owner changed.');
            }
          } catch {
            created = false;
          }
          if (!window.isDestroyed()) window.destroy();
          try {
            await this.options.host.stop();
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
    parent.webContents.on('did-start-navigation', parentNavigation);
    parent.webContents.once('render-process-gone', parentClosed);
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
