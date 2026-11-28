import type { IpcMain, IpcMainInvokeEvent } from 'electron';
import type { VaultBackendHost } from './vault-host.ts';

export function registerVaultOSMigrationIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'resumeOSMigration' | 'stop' | 'unlockedWorkspaceId'>;
  trusted(event: IpcMainInvokeEvent): boolean;
  quiesced(): boolean;
  activate(): void;
  retire(): Promise<unknown>;
  fatal(): void;
}) {
  let busy = false;
  const accepts = (event: IpcMainInvokeEvent) => {
    try {
      return options.trusted(event) && options.quiesced();
    } catch {
      return false;
    }
  };
  options.ipc.handle('vault:os-migration-resume', async (event, ...args: unknown[]) => {
    if (args.length || busy || !accepts(event)) throw Error('Migration unavailable.');
    busy = true;
    try {
      await options.host.resumeOSMigration();
      if (!accepts(event) || !options.host.unlockedWorkspaceId)
        throw Error('Migration owner changed.');
      options.activate();
      if (!accepts(event)) throw Error('Migration owner changed.');
      return true;
    } catch {
      try {
        await options.host.stop();
        await options.retire();
      } catch {
        options.fatal();
      }
      throw Error('Migration unavailable.');
    } finally {
      busy = false;
    }
  });
}
