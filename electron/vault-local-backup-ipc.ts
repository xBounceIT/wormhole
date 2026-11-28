import type { BrowserWindow, IpcMain, IpcMainInvokeEvent } from 'electron';
import type { VaultBackendHost, VaultFreshAuthentication } from './vault-host.ts';

type Options = {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'localBackupAvailable' | 'exportLocalBackup' | 'restoreLocalBackup'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | undefined;
  pickExport: (parent: BrowserWindow) => Promise<string | null>;
  pickRestore: (parent: BrowserWindow) => Promise<string | null>;
  authenticate: (parent: BrowserWindow, accepted: () => boolean) => VaultFreshAuthentication;
  restart: () => Promise<void>;
};

export function registerVaultLocalBackupIpc(options: Options) {
  let busy = false;
  const accepts = (event: IpcMainInvokeEvent) => {
    try {
      return options.trusted(event);
    } catch {
      return false;
    }
  };
  const unavailable = () => Error('Encrypted vault backup is unavailable.');
  options.ipc.handle('vault:local-backup-available', async (event, ...args: unknown[]) => {
    if (args.length || !accepts(event)) throw unavailable();
    const result = await options.host.localBackupAvailable();
    return result && accepts(event);
  });
  const register = (channel: string, restore: boolean) =>
    options.ipc.handle(channel, async (event, ...args: unknown[]) => {
      if (args.length || busy || !accepts(event)) throw unavailable();
      const parent = options.parent(event);
      if (!parent || parent.isDestroyed()) throw unavailable();
      let valid = true;
      const invalidate = () => {
        valid = false;
      };
      const navigation = (_event: unknown, _url: string, inPlace: boolean, mainFrame: boolean) => {
        if (mainFrame && !inPlace) invalidate();
      };
      const accepted = () => valid && !parent.isDestroyed() && accepts(event);
      busy = true;
      event.sender.on('did-start-navigation', navigation);
      event.sender.once('render-process-gone', invalidate);
      event.sender.once('destroyed', invalidate);
      try {
        const authenticate = options.authenticate(parent, accepted);
        const result = restore
          ? await options.host.restoreLocalBackup(
              () => options.pickRestore(parent),
              authenticate,
              accepted,
            )
          : await options.host.exportLocalBackup(
              () => options.pickExport(parent),
              authenticate,
              accepted,
            );
        if (!accepted()) throw unavailable();
        if (restore && result) await options.restart();
        return result;
      } catch (error) {
        if (error instanceof Error && error.message === 'Authentication cancelled.') return false;
        throw error;
      } finally {
        invalidate();
        event.sender.removeListener('did-start-navigation', navigation);
        event.sender.removeListener('render-process-gone', invalidate);
        event.sender.removeListener('destroyed', invalidate);
        busy = false;
      }
    });
  register('vault:local-backup-export', false);
  register('vault:local-backup-restore', true);
}
