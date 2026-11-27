import type { BrowserWindow, IpcMain, IpcMainInvokeEvent } from 'electron';
import type { VaultBackendHost } from './vault-host.ts';

type Options = {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<
    VaultBackendHost,
    'startup' | 'stop' | 'openUnprotected' | 'protection' | 'unlockedWorkspaceId'
  >;
  trusted(event: IpcMainInvokeEvent): boolean;
  parent(event: IpcMainInvokeEvent): BrowserWindow | undefined;
  requireAccess(): void;
  canStart(): boolean;
  hold(): () => void;
  quiesce(parent: BrowserWindow, retainOwner?: boolean): Promise<boolean>;
  activate(): void;
  retire(): Promise<unknown>;
  restartUpgrade(): void;
  fatal(): void;
};

// Fixed verbs only. The renderer supplies no factors, source, policy or native
// launch arguments. Protection setup runs only after a fresh isolated launch.
export function registerVaultUnprotectedIpc(options: Options) {
  let busy = false;
  const current = (event: IpcMainInvokeEvent) => {
    try {
      return options.trusted(event) && options.canStart();
    } catch {
      return false;
    }
  };
  for (const create of [false, true])
    options.ipc.handle(
      create ? 'vault:unprotected-create' : 'vault:unprotected-open',
      async (event, ...args: unknown[]) => {
        if (args.length || busy || !current(event)) throw Error('Vault opening unavailable.');
        busy = true;
        let attempted = false;
        try {
          attempted = true;
          await options.host.openUnprotected(create);
          if (!current(event) || !options.host.unlockedWorkspaceId)
            throw Error('Vault owner changed.');
          options.activate();
          if (!current(event)) throw Error('Vault owner changed.');
          return true;
        } catch {
          if (attempted) {
            try {
              await options.host.stop();
              await options.retire();
            } catch {
              options.fatal();
            }
          }
          throw Error('Vault opening unavailable.');
        } finally {
          busy = false;
        }
      },
    );
  options.ipc.handle('vault:protection', async (event, ...args: unknown[]) => {
    if (args.length || !current(event)) throw Error('Vault protection unavailable.');
    options.requireAccess();
    const result = await options.host.protection();
    if (!current(event)) throw Error('Vault owner changed.');
    options.requireAccess();
    return result;
  });
  options.ipc.handle('vault:prepare-unprotected', async (event, ...args: unknown[]) => {
    if (args.length || busy || !current(event)) throw Error('Vault protection unavailable.');
    busy = true;
    let release: (() => void) | undefined,
      attempted = false,
      stopped = false;
    try {
      const startup = await options.host.startup();
      if (!current(event) || !startup.unprotected) throw Error('Vault source unavailable.');
      if (options.host.unlockedWorkspaceId) {
        options.requireAccess();
        if ((await options.host.protection()).protected || !current(event))
          throw Error('Vault owner changed.');
        options.requireAccess();
      }
      const parent = options.parent(event);
      if (!parent) throw Error('Vault source unavailable.');
      release = options.hold();
      attempted = true;
      if (!(await options.quiesce(parent, false))) {
        attempted = false;
        return false;
      }
      stopped = true;
      // A completed quiesce intentionally prevents starting new services.
      if (!options.trusted(event)) throw Error('Vault owner changed.');
      await options.host.stop();
      options.restartUpgrade();
      return true;
    } catch {
      if (attempted) {
        try {
          await options.host.stop();
        } catch {
          /* Keep exclusion until exit. */
        }
        options.fatal();
      }
      throw Error('Vault protection unavailable.');
    } finally {
      if (!stopped && !attempted) release?.();
      busy = false;
    }
  });
}
