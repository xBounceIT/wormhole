import type { BrowserWindow, IpcMain, IpcMainInvokeEvent } from 'electron';
import type { VaultBackendHost } from './vault-host.ts';
import type { VaultMigrationSetupDialog } from './vault-migration-setup-dialog.ts';

type Options = {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'startup' | 'stop'> &
    Partial<Pick<VaultBackendHost, 'unlockedWorkspaceId' | 'protection'>>;
  dialog: Pick<VaultMigrationSetupDialog, 'open'>;
  rootDialog?: Pick<VaultMigrationSetupDialog, 'open'>;
  allowDatabaseEncryption?: boolean;
  osDialog?: Pick<VaultMigrationSetupDialog, 'open'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | undefined;
  requireAccess: () => void;
  canStart: () => boolean;
  hold: () => () => void;
  quiesce: (parent: BrowserWindow, retainVaultOwner?: boolean) => Promise<boolean>;
  restart: () => void;
  restartUpgrade?: () => void;
  fatal: () => void;
};

// Only an opt-in action enters this flow. The parent can select no path, proof,
// recipient or key. A held authorization barrier survives until process exit
// once the old native services have been stopped.
export function registerVaultProtectionIpc(options: Options) {
  let busy = false;
  const accepts = (event: IpcMainInvokeEvent) => {
    try {
      return options.trusted(event);
    } catch {
      return false;
    }
  };
  const canEncryptDatabase = (startup: Awaited<ReturnType<Options['host']['startup']>>) =>
    Boolean(
      options.allowDatabaseEncryption &&
      options.rootDialog &&
      startup.slots &&
      !startup.slots.encrypted &&
      options.host.unlockedWorkspaceId === startup.slots.vaultId &&
      !startup.newWorkspace &&
      !startup.shared &&
      !startup.sharedJoin &&
      !startup.rotation &&
      !startup.migration &&
      !startup.upgrade &&
      !startup.unprotected &&
      !startup.osMigration,
    );
  const run = async (
    event: IpcMainInvokeEvent,
    args: unknown[],
    entry: 'settings' | 'encrypt-database' | 'legacy' | 'legacy-os' = 'settings',
  ) => {
    const encryptDatabase = entry === 'encrypt-database';
    const startupEntry = entry === 'legacy' || entry === 'legacy-os';
    const unprotected = entry === 'legacy-os';
    if (
      busy ||
      args.length ||
      (encryptDatabase && !options.allowDatabaseEncryption) ||
      !accepts(event) ||
      !options.canStart()
    )
      throw Error('Workspace protection unavailable.');
    busy = true;
    let release: (() => void) | undefined,
      stopped = false,
      attempted = false;
    try {
      if (!startupEntry) options.requireAccess();
      const startup = await options.host.startup();
      if (!startupEntry) options.requireAccess();
      if (
        startupEntry &&
        (!startup.legacy ||
          options.host.unlockedWorkspaceId ||
          (unprotected && !startup.legacy.unprotectedAllowed))
      )
        throw Error('Workspace protection unavailable.');
      if (encryptDatabase && !canEncryptDatabase(startup))
        throw Error('Workspace protection unavailable.');
      const rotating = !!(
        startup.slots &&
        options.host.unlockedWorkspaceId &&
        options.host.unlockedWorkspaceId === startup.slots.vaultId &&
        options.rootDialog
      );
      const upgrading = !!(
        startup.unprotected &&
        options.host.unlockedWorkspaceId === startup.unprotected.vaultId &&
        options.restartUpgrade
      );
      if (
        !accepts(event) ||
        !options.canStart() ||
        (startup.slots && !rotating) ||
        (startup.unprotected && !upgrading) ||
        startup.upgrade ||
        startup.osMigration ||
        startup.rotation?.pending ||
        startup.migration?.pending ||
        startup.shared ||
        startup.newWorkspace
      )
        throw Error('Workspace protection unavailable.');
      if (upgrading) {
        if (!options.host.protection || (await options.host.protection()).protected)
          throw Error('Workspace protection unavailable.');
        options.requireAccess();
        if (
          !accepts(event) ||
          !options.canStart() ||
          options.host.unlockedWorkspaceId !== startup.unprotected!.vaultId
        )
          throw Error('Workspace protection unavailable.');
      }
      const parent = options.parent(event);
      if (!parent) throw Error('Workspace protection unavailable.');
      release = options.hold();
      attempted = true;
      if (!(await options.quiesce(parent, rotating))) {
        attempted = false;
        return false;
      }
      stopped = true;
      if (!accepts(event) || (encryptDatabase && !canEncryptDatabase(startup)))
        throw Error('Workspace protection unavailable.');
      if (upgrading) {
        await options.host.stop();
        options.restartUpgrade!();
        return true;
      }
      const dialog = unprotected
        ? options.osDialog!
        : rotating
          ? options.rootDialog!
          : options.dialog;
      const prepared = await (encryptDatabase
        ? dialog.open(parent, () => accepts(event), true)
        : dialog.open(parent, () => accepts(event)));
      if (!accepts(event)) throw Error('Workspace protection unavailable.');
      await options.host.stop();
      options.restart();
      return prepared;
    } catch {
      // An unsuccessful shutdown or uncertain confirmation cannot restore old
      // authorization or claim that a relaunch is safe. Pending capsules remain.
      if (attempted) {
        try {
          await options.host.stop();
        } catch {}
        options.fatal();
      }
      throw Error('Workspace protection unavailable.');
    } finally {
      if (!stopped && !attempted) release?.();
      busy = false;
    }
  };
  options.ipc.handle('vault:protect-existing', (event, ...args: unknown[]) => run(event, args));
  options.ipc.handle('vault:database-encryption-available', async (event, ...args: unknown[]) => {
    if (
      busy ||
      args.length ||
      !options.allowDatabaseEncryption ||
      !accepts(event) ||
      !options.canStart()
    )
      return false;
    try {
      options.requireAccess();
      const startup = await options.host.startup();
      options.requireAccess();
      return !busy && accepts(event) && options.canStart() && canEncryptDatabase(startup);
    } catch {
      return false;
    }
  });
  options.ipc.handle('vault:encrypt-database', (event, ...args: unknown[]) =>
    run(event, args, 'encrypt-database'),
  );
  if (options.osDialog) {
    options.ipc.handle('vault:prepare-legacy', (event, ...args: unknown[]) =>
      run(event, args, 'legacy'),
    );
    options.ipc.handle('vault:prepare-legacy-os', (event, ...args: unknown[]) =>
      run(event, args, 'legacy-os'),
    );
  }
}
