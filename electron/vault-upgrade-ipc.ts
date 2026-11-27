import type { BrowserWindow, IpcMain, IpcMainInvokeEvent } from 'electron';
import type { VaultBackendHost } from './vault-host.ts';
import type { VaultMigrationSetupDialog } from './vault-migration-setup-dialog.ts';

type Options = {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'startup' | 'stop' | 'unlockedWorkspaceId'>;
  dialog: Pick<VaultMigrationSetupDialog, 'open'>;
  trusted(event: IpcMainInvokeEvent): boolean;
  parent(event: IpcMainInvokeEvent): BrowserWindow | undefined;
  quiesced(): boolean;
  hold(): () => void;
  restart(): void;
  fatal(): void;
};

// The ordinary renderer can request only a main-owned window. It selects no
// source, factor, recipient, mode or launch authority, and receives no app grant.
export function registerVaultUpgradeIpc(options: Options) {
  let busy = false;
  const accepts = (event: IpcMainInvokeEvent) => {
    try {
      return options.quiesced() && options.trusted(event);
    } catch {
      return false;
    }
  };
  options.ipc.handle('vault:upgrade-protection', async (event, ...args: unknown[]) => {
    if (busy || args.length || !accepts(event)) throw Error('Vault upgrade unavailable.');
    busy = true;
    let release: (() => void) | undefined,
      entered = false;
    try {
      const startup = await options.host.startup();
      if (
        !accepts(event) ||
        !startup.upgrade ||
        startup.slots ||
        startup.shared ||
        startup.migration ||
        startup.rotation ||
        startup.newWorkspace ||
        options.host.unlockedWorkspaceId
      )
        throw Error('Vault upgrade unavailable.');
      const parent = options.parent(event);
      if (!parent) throw Error('Vault upgrade unavailable.');
      release = options.hold();
      entered = true;
      const prepared = await options.dialog.open(parent, () => accepts(event));
      if (!accepts(event) || options.host.unlockedWorkspaceId)
        throw Error('Vault upgrade owner changed.');
      await options.host.stop();
      options.restart();
      return prepared;
    } catch {
      if (entered) {
        try {
          await options.host.stop();
        } catch {
          /* Exit retains uncertain exclusion. */
        }
        options.fatal();
      }
      throw Error('Vault upgrade unavailable.');
    } finally {
      if (!entered) release?.();
      busy = false;
    }
  });
}
