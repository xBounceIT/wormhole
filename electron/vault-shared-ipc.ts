import type { BrowserWindow, IpcMain, IpcMainInvokeEvent } from 'electron';
import type { SharedRecoveryKitConfirmation, VaultBackendHost } from './vault-host.ts';
import type { VaultSharedAuthenticationDialog } from './vault-shared-dialog.ts';
import type { VaultSharedSetupDialog } from './vault-shared-setup-dialog.ts';
import { isSharedInitialStartup } from './vault-shared-invitation.ts';

export function registerSharedCatalogIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'sharedCatalog'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
}) {
  registerSharedReadIpc(options, 'vault:shared-catalog', (value, accepted) =>
    options.host.sharedCatalog(value, accepted),
  );
}

export function registerSharedNodeEditIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'sharedNodeEdit'>;
  dialog: Pick<VaultSharedAuthenticationDialog, 'open'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | null;
}) {
  registerSharedReadIpc(options, 'vault:shared-node-edit', (value, accepted, event) =>
    options.host.sharedNodeEdit(value, accepted, (startup, current, submit) => {
      const parent = options.parent(event);
      if (!parent || parent.isDestroyed() || !current())
        throw Error('Shared node edit unavailable.');
      return options.dialog.open(parent, current, 'edit-shared-node', startup, submit);
    }),
  );
}

export function registerSharedConnectionContextIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'sharedConnectionContext'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
}) {
  registerSharedReadIpc(options, 'vault:shared-connection-context', (value, accepted) =>
    options.host.sharedConnectionContext(value, accepted),
  );
}

export function registerSharedChangesIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'sharedChanges'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
}) {
  registerSharedReadIpc(options, 'vault:shared-changes', (value, accepted) =>
    options.host.sharedChanges(value, accepted),
  );
}

export function registerSharedRecoveryBackupIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'openSharedRecoveryBackup'>;
  dialog: Pick<VaultSharedSetupDialog, 'openBackup'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | null;
}) {
  registerSharedReadIpc(
    options,
    'vault:open-shared-recovery-backup',
    async (value, accepted, event) => {
      const parent = options.parent(event);
      if (value !== null || !parent || parent.isDestroyed())
        throw Error('Workspace backup is unavailable.');
      await options.host.openSharedRecoveryBackup(accepted, (current, operation) =>
        options.dialog.openBackup(parent, current, operation),
      );
    },
  );
}

export function registerSharedAccountResetIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'openSharedAccountReset'>;
  dialog: Pick<VaultSharedSetupDialog, 'openAccountReset'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | null;
}) {
  registerSharedReadIpc(
    options,
    'vault:open-shared-account-reset',
    async (value, accepted, event) => {
      const parent = options.parent(event);
      if (value !== null || !parent || parent.isDestroyed())
        throw Error('Account reset is unavailable.');
      await options.host.openSharedAccountReset(accepted, (current, operation) =>
        options.dialog.openAccountReset(parent, current, operation),
      );
    },
  );
}

export function registerSharedAdministrationIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'openSharedAdministration'>;
  dialog: Pick<VaultSharedSetupDialog, 'openAdministration'>;
  currentDeviceRevoked?: () => void;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | null;
}) {
  registerSharedReadIpc(
    options,
    'vault:open-shared-administration',
    async (value, accepted, event) => {
      const parent = options.parent(event);
      if (value !== null || !parent || parent.isDestroyed())
        throw Error('Workspace administration is unavailable.');
      await options.host.openSharedAdministration(accepted, (current, { access, ...ports }) =>
        options.dialog.openAdministration(parent, current, {
          ...ports,
          access:
            access &&
            (async (request) => {
              const reply = await access(request);
              if (reply.status === 'changed' && reply.currentDevice)
                options.currentDeviceRevoked?.();
              return reply;
            }),
        }),
      );
    },
  );
}

export function registerSharedRecoveryInspectionIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'startup'>;
  dialog: Pick<VaultSharedSetupDialog, 'open'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | null;
}) {
  registerSharedReadIpc(
    options,
    'vault:prepare-shared-workspace-restore',
    async (argument, accepted, event) => {
      if (argument !== null) throw Error('Workspace restore is unavailable.');
      const parent = options.parent(event);
      if (!parent || !isSharedInitialStartup(await options.host.startup()) || !accepted())
        throw Error('Workspace restore is unavailable.');
      await options.dialog.open(parent, accepted, undefined, false, 'restore');
    },
  );
}

export function registerSharedCertificateRenewalIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<
    VaultBackendHost,
    | 'renewSharedServerCertificate'
    | 'sharedWorkspaceCA'
    | 'exportSharedTLSBundle'
    | 'refreshSharedRecoveryKit'
  >;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  pickTLSExport?: (event: IpcMainInvokeEvent) => Promise<string | null>;
  lockAfterCARotation?: () => Promise<void>;
  pickRecoveryKit?: (event: IpcMainInvokeEvent, intent: 'open' | 'save') => Promise<string | null>;
  confirmRecoveryKit?: (
    event: IpcMainInvokeEvent,
    ...args: Parameters<SharedRecoveryKitConfirmation>
  ) => ReturnType<SharedRecoveryKitConfirmation>;
}) {
  registerSharedReadIpc(options, 'vault:shared-renew-server-certificate', (value, accepted) =>
    options.host.renewSharedServerCertificate(value, accepted),
  );
  registerSharedReadIpc(options, 'vault:shared-workspace-ca', (value, accepted) =>
    options.host.sharedWorkspaceCA(value, accepted, options.lockAfterCARotation),
  );
  registerSharedReadIpc(options, 'vault:shared-tls-export', (value, accepted, event) => {
    const choose = options.pickTLSExport;
    if (value !== null || !choose) throw Error('Signed trust bundle export unavailable.');
    return options.host.exportSharedTLSBundle(() => choose(event), accepted);
  });
  registerSharedReadIpc(options, 'vault:shared-recovery-kit-refresh', (value, accepted, event) => {
    const choose = options.pickRecoveryKit;
    if (value !== null || !choose) throw Error('Recovery kit refresh unavailable.');
    const confirm = options.confirmRecoveryKit;
    return options.host.refreshSharedRecoveryKit(
      (intent) => choose(event, intent),
      accepted,
      confirm && ((...args) => confirm(event, ...args)),
    );
  });
}

function registerSharedReadIpc(
  options: { ipc: Pick<IpcMain, 'handle'>; trusted: (event: IpcMainInvokeEvent) => boolean },
  channel: string,
  read: (value: unknown, accepted: () => boolean, event: IpcMainInvokeEvent) => Promise<unknown>,
) {
  options.ipc.handle(channel, async (event, ...args: unknown[]) => {
    let valid = true;
    const accepted = () => {
      try {
        return valid && options.trusted(event);
      } catch {
        return false;
      }
    };
    if (!accepted() || args.length !== 1) throw Error('Invalid shared catalog request.');
    const invalidate = () => {
      valid = false;
    };
    const navigation = (_event: unknown, _url: string, _inPlace: boolean, mainFrame: boolean) => {
      if (mainFrame) invalidate();
    };
    event.sender.on('did-start-navigation', navigation);
    event.sender.once('render-process-gone', invalidate);
    event.sender.once('destroyed', invalidate);
    try {
      return await read(args[0], accepted, event);
    } finally {
      invalidate();
      event.sender.removeListener('did-start-navigation', navigation);
      event.sender.removeListener('render-process-gone', invalidate);
      event.sender.removeListener('destroyed', invalidate);
    }
  });
}

export function registerSharedAuthenticationIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'startup' | 'stop' | 'isSharedWorkspace' | 'unlockedWorkspaceId'>;
  dialog: Pick<VaultSharedAuthenticationDialog, 'open'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | null;
  activate: () => void;
}) {
  options.ipc.handle('vault:shared-authenticate', async (event, ...args: unknown[]) => {
    let valid = true;
    const accepted = () => {
      try {
        return valid && options.trusted(event);
      } catch {
        return false;
      }
    };
    if (
      !accepted() ||
      args.length !== 1 ||
      (args[0] !== 'admit' &&
        args[0] !== 'recover-password' &&
        args[0] !== 'recover-enrollment' &&
        args[0] !== 'join-initial')
    )
      throw Error('Invalid shared authentication request.');
    const parent = options.parent(event);
    if (!parent) throw Error('Shared authentication unavailable.');
    const invalidate = () => {
      valid = false;
    };
    const navigation = (_event: unknown, _url: string, _inPlace: boolean, mainFrame: boolean) => {
      if (mainFrame) invalidate();
    };
    event.sender.on('did-start-navigation', navigation);
    event.sender.once('render-process-gone', invalidate);
    event.sender.once('destroyed', invalidate);
    try {
      const startup = await options.host.startup();
      // A previous attempt can complete durably before its reply is lost. The
      // fresh normal native checkpoint selects an ordinary protected prompt.
      const mode =
        args[0] === 'join-initial'
          ? startup.sharedJoin
            ? 'recover-enrollment'
            : startup.shared
              ? 'admit'
              : 'join-initial'
          : args[0] === 'recover-enrollment' && startup.shared && !startup.sharedJoin
            ? 'admit'
            : args[0];
      if (
        !accepted() ||
        !(mode === 'join-initial'
          ? isSharedInitialStartup(startup)
          : mode === 'recover-enrollment'
            ? startup.sharedJoin
            : startup.shared)
      )
        throw Error('Shared authentication unavailable.');
      const result = await options.dialog.open(parent, accepted, mode, startup);
      if (!accepted()) {
        if (result && 'admitted' in result) await options.host.stop();
        throw Error('Shared authentication owner changed.');
      }
      if (result && 'admitted' in result) {
        try {
          const workspace = options.host.unlockedWorkspaceId;
          if (
            (args[0] !== 'admit' &&
              args[0] !== 'recover-enrollment' &&
              args[0] !== 'join-initial') ||
            !options.host.isSharedWorkspace ||
            !workspace
          )
            throw Error('Shared authentication unavailable.');
          // The protected dialog has closed. Only this still-current parent may
          // publish application authentication, after native policy activation.
          options.activate();
          if (
            !accepted() ||
            !options.host.isSharedWorkspace ||
            options.host.unlockedWorkspaceId !== workspace
          )
            throw Error('Shared authentication owner changed.');
        } catch {
          await options.host.stop();
          throw Error('Shared authentication unavailable.');
        }
      }
      return result;
    } finally {
      invalidate();
      event.sender.removeListener('did-start-navigation', navigation);
      event.sender.removeListener('render-process-gone', invalidate);
      event.sender.removeListener('destroyed', invalidate);
    }
  });
}

export function registerSharedAdminRecoveryIpc(options: {
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'startup' | 'stop' | 'isSharedWorkspace' | 'unlockedWorkspaceId'>;
  dialog: Pick<VaultSharedSetupDialog, 'open'>;
  trusted: (event: IpcMainInvokeEvent) => boolean;
  parent: (event: IpcMainInvokeEvent) => BrowserWindow | null;
  activate: () => void;
}) {
  registerSharedReadIpc(
    options,
    'vault:recover-shared-workspace',
    async (argument, accepted, event) => {
      if (argument !== null) throw Error('Workspace recovery is unavailable.');
      const startup = await options.host.startup();
      const parent = options.parent(event);
      if (
        !accepted() ||
        !parent ||
        (!isSharedInitialStartup(startup) && !startup.sharedJoin?.adminRecovery)
      )
        throw Error('Workspace recovery is unavailable.');
      const result = await options.dialog.open(parent, accepted, accepted, false, 'recovery');
      if (!result) return null;
      try {
        const workspace = options.host.unlockedWorkspaceId;
        if (!('admitted' in result) || !accepted() || !options.host.isSharedWorkspace || !workspace)
          throw Error('Workspace recovery was interrupted.');
        options.activate();
        if (
          !accepted() ||
          !options.host.isSharedWorkspace ||
          options.host.unlockedWorkspaceId !== workspace
        )
          throw Error('Workspace recovery was interrupted.');
        return result;
      } catch {
        await options.host.stop();
        throw Error('Workspace recovery is unavailable.');
      }
    },
  );
}
