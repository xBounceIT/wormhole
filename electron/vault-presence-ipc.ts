import type {
  BrowserWindow,
  IpcMain,
  IpcMainInvokeEvent,
  WebContentsDidStartNavigationEventParams,
} from 'electron';
import { runWithNativeAuthenticationWindow } from './native-auth-window.ts';
import { parseVaultPresenceSelection } from './vault-presence.ts';
import type { VaultBackendHost, VaultPresenceAuthentication } from './vault-host.ts';

type Options = {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<
    VaultBackendHost,
    'presenceStatus' | 'unlockPresence' | 'configurePresence' | 'unlockedWorkspaceId' | 'stop'
  >;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  owner: (event: IpcMainInvokeEvent) => BrowserWindow | null;
  nativeHandle: (window: BrowserWindow) => string;
  confirm: (owner: BrowserWindow, trusted: () => boolean) => VaultPresenceAuthentication;
  unlocked: () => void;
  platform?: NodeJS.Platform;
};

export function registerVaultPresenceIpc(options: Options): void {
  const { ipc, host } = options;
  const platform = options.platform ?? process.platform;
  const kind = platform === 'win32' ? 'hello' : platform === 'darwin' ? 'touch-id' : null;
  const trusted = (event: IpcMainInvokeEvent) => {
    try {
      return options.trusted(event);
    } catch {
      return false;
    }
  };
  ipc.handle('vault:presence-status', async (event, ...args: unknown[]) => {
    if (args.length || !trusted(event)) throw Error('Invalid biometric request.');
    const result = kind ? await host.presenceStatus(kind) : null;
    if (!trusted(event)) throw Error('Biometric request owner is no longer available.');
    return result;
  });
  ipc.handle('vault:presence-unlock', async (event, ...args: unknown[]) => {
    const selection = parseVaultPresenceSelection(args[0]);
    if (!selection || args.length !== 1 || !trusted(event))
      throw Error('Invalid biometric request.');
    if (!kind) return { status: 'unavailable' };
    const owner = options.owner(event);
    if (!owner || owner.isDestroyed()) throw Error('Biometric request window unavailable.');
    const controller = new AbortController();
    const cancel = () => controller.abort();
    const current = () => !controller.signal.aborted && trusted(event) && !owner.isDestroyed();
    const navigation = ({ isMainFrame }: WebContentsDidStartNavigationEventParams) => {
      if (isMainFrame) cancel();
    };
    const contents = owner.webContents;
    owner.once('closed', cancel);
    contents.once('render-process-gone', cancel);
    contents.on('did-start-navigation', navigation);
    try {
      const result =
        kind === 'hello'
          ? await runWithNativeAuthenticationWindow(owner, () =>
              host.unlockPresence(
                kind,
                selection,
                options.nativeHandle(owner),
                current,
                controller.signal,
              ),
            )
          : await host.unlockPresence(kind, selection, undefined, current, controller.signal);
      if ('unlocked' in result) {
        try {
          if (!current() || host.unlockedWorkspaceId !== selection.vaultId)
            throw Error('Vault is locked.');
          options.unlocked();
        } catch {
          await host.stop();
          throw Error('Vault session could not be activated.');
        }
      }
      if (!current()) throw Error('Biometric request owner is no longer available.');
      return result;
    } finally {
      owner.removeListener('closed', cancel);
      contents.removeListener('render-process-gone', cancel);
      contents.removeListener('did-start-navigation', navigation);
    }
  });
  ipc.handle('vault:presence-configure', async (event, ...args: unknown[]) => {
    const action = args[0];
    if (
      !kind ||
      args.length !== 1 ||
      (action !== 'enroll' && action !== 'remove') ||
      !trusted(event)
    )
      throw Error('Invalid biometric request.');
    const owner = options.owner(event);
    if (!owner || owner.isDestroyed()) throw Error('Biometric request window unavailable.');
    const current = () => trusted(event) && !owner.isDestroyed();
    const result = await host.configurePresence(
      kind,
      action,
      options.confirm(owner, current),
      current,
    );
    if (!current()) throw Error('Biometric request owner is no longer available.');
    return result;
  });
}
