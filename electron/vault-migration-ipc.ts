import type { BrowserWindow, IpcMain, IpcMainInvokeEvent } from 'electron';
import type { VaultBackendHost } from './vault-host.ts';
import type { VaultReauthenticationDialog } from './vault-reauth-dialog.ts';
import type { VaultUnlockInput } from './vault-unlock.ts';

type Options = {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'startup' | 'stop' | 'unlockedWorkspaceId'>;
  dialog: Pick<VaultReauthenticationDialog, 'open'>;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | undefined;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  quiesced: () => boolean;
  activate: () => void;
  retire: () => Promise<void>;
};

// The ordinary bridge can only open a native-owned prompt, never submit factors,
// paths, a plan, recipient or quiescence. Its operation and slots are captured here.
export function registerVaultMigrationIpc(
  options: Options & { host: Options['host'] & Pick<VaultBackendHost, 'resumeMigration'> },
) {
  registerVaultResumeIpc(options, 'migration', (input) => options.host.resumeMigration(input));
}

export function registerVaultRootRotationIpc(
  options: Options & { host: Options['host'] & Pick<VaultBackendHost, 'resumeRootRotation'> },
) {
  registerVaultResumeIpc(options, 'rotation', (input) => options.host.resumeRootRotation(input));
}

function registerVaultResumeIpc(
  options: Options,
  kind: 'migration' | 'rotation',
  submit: (input: VaultUnlockInput) => Promise<unknown>,
) {
  const label = kind === 'migration' ? 'Migration' : 'Vault rotation';
  let busy = false;
  const accepts = (event: IpcMainInvokeEvent) => {
    try {
      return options.quiesced() && options.trusted(event);
    } catch {
      return false;
    }
  };
  options.ipc.handle(`vault:${kind}-resume`, async (event, ...args: unknown[]) => {
    if (busy || !accepts(event) || args.length) throw Error(`${label} unavailable.`);
    busy = true;
    let id: string | undefined;
    try {
      const startup = await options.host.startup();
      if (
        !accepts(event) ||
        !(kind === 'migration' ? startup.migration?.pending : startup.rotation?.pending) ||
        !startup.slots ||
        startup.shared
      )
        throw Error(`${label} unavailable.`);
      const parent = options.parent(event);
      if (!parent) throw Error(`${label} unavailable.`);
      id = startup.slots.vaultId;
      await options.dialog.open(
        parent,
        () => accepts(event),
        `${kind}-resume`,
        startup.slots,
        submit,
      );
      if (!accepts(event) || options.host.unlockedWorkspaceId !== id)
        throw Error(`${label} unavailable.`);
      options.activate();
      if (!accepts(event) || options.host.unlockedWorkspaceId !== id)
        throw Error(`${label} unavailable.`);
      return true;
    } catch {
      if (id !== undefined && options.host.unlockedWorkspaceId === id) {
        let failed = false;
        try {
          await options.retire();
        } catch {
          failed = true;
        }
        try {
          await options.host.stop();
        } catch {
          failed = true;
        }
        if (failed) throw Error(`${label} shutdown could not be confirmed.`);
      }
      throw Error(`${label} unavailable.`);
    } finally {
      busy = false;
    }
  });
}
