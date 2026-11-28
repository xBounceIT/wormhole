import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainInvokeEvent,
} from 'electron';
import type { VaultBackendHost } from './vault-host.ts';
import type { VaultStartupMetadata } from './vault-contract.ts';
import {
  consumeSharedVaultUnlockInput,
  consumeSharedVaultContinuationInput,
  hasSharedVaultContinuation,
  validSharedArtifactPath,
  validSharedTLSBundlePath,
  SharedReenrollmentPending,
  SharedConnectionLimit,
  type SharedVaultUnlockInput,
  type SharedVaultSessionAdmission,
  type SharedVaultRecovery,
  type SharedRecoveryKitRefresh,
} from './vault-shared-unlock.ts';
import { protectVaultDisplayWindow } from './vault-display-window.ts';
import { consumeSharedInitialJoinInput } from './vault-shared-initial-join.ts';
import { consumeSharedAccountResetInput } from './vault-shared-account-reset.ts';
import { isSharedInitialStartup } from './vault-shared-invitation.ts';

export type SharedAuthenticationMode =
  | 'admit'
  | 'recover-password'
  | 'recover-enrollment'
  | 'join-initial';
type Outcome = SharedVaultSessionAdmission | SharedVaultRecovery;
type ConfirmSharedAction<T> = (
  input: SharedVaultUnlockInput,
  accepted: () => boolean,
) => Promise<T>;
type DialogOutcome = Outcome | SharedRecoveryKitRefresh | true;
type Dialog = {
  window: BrowserWindow;
  startup: VaultStartupMetadata;
  mode:
    | SharedAuthenticationMode
    | 'refresh-recovery-kit'
    | 'tighten-profile'
    | 'trust-ssh-host'
    | 'edit-shared-node';
  valid: () => boolean;
  busy: boolean;
  tlsUpdatePath?: string;
  resetOfferPath?: string;
  factors?: Uint8Array[];
  confirmAction?: ConfirmSharedAction<SharedRecoveryKitRefresh | true>;
  finish: (outcome?: DialogOutcome) => Promise<void>;
};
type Options = {
  host: Pick<
    VaultBackendHost,
    | 'sharedUnlock'
    | 'sharedRecoverPassword'
    | 'sharedRecoverEnrollment'
    | 'sharedContinueEnrollment'
    | 'sharedJoinInitial'
    | 'sharedRedeemAccountReset'
    | 'inspectSharedInvitation'
    | 'readSharedInvitationFile'
    | 'startup'
    | 'stop'
  >;
  ipc: Pick<IpcMain, 'handle'>;
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  url: string;
  preload: string;
  appVersion: string;
  platform?: NodeJS.Platform;
  pickInvitation?: (window: BrowserWindow) => Promise<string | null>;
  pickResetOffer?: (window: BrowserWindow) => Promise<string | null>;
  pickTLSUpdate?: (window: BrowserWindow) => Promise<string | null>;
};

// Only this isolated window receives factors. Operation and native version are
// captured by main; the application renderer receives metadata acknowledgements.
export class VaultSharedAuthenticationDialog {
  private current: Dialog | undefined;
  private closing: Promise<void> | undefined;
  private readonly options: Options;
  constructor(options: Options) {
    this.options = options;
    options.ipc.handle('vault-shared:context', (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Shared authentication unavailable.');
      return { startup: dialog.startup, mode: dialog.mode };
    });
    options.ipc.handle('vault-shared:submit', async (event, ...args: unknown[]) => {
      try {
        const dialog = this.trusted(event);
        const request = args[0];
        const resetting =
          dialog?.mode === 'join-initial' &&
          typeof request === 'object' &&
          request !== null &&
          Object.hasOwn(request, 'kind');
        const input = resetting
          ? consumeSharedAccountResetInput(request, options.appVersion)
          : dialog?.mode === 'join-initial'
            ? consumeSharedInitialJoinInput(args[0], options.appVersion)
            : dialog?.mode === 'recover-enrollment' &&
                typeof args[0] === 'object' &&
                args[0] !== null &&
                Object.hasOwn(args[0], 'code')
              ? consumeSharedVaultContinuationInput(args[0], options.appVersion)
              : consumeSharedVaultUnlockInput(args[0], options.appVersion);
        try {
          const initial = 'deviceName' in input;
          const offerPath = dialog?.resetOfferPath;
          if (
            !dialog ||
            args.length !== 1 ||
            dialog.busy ||
            (resetting && !offerPath) ||
            (!initial &&
              'code' in input &&
              (dialog.mode !== 'recover-enrollment' ||
                dialog.startup.sharedJoin?.canContinue !== true)) ||
            (initial
              ? dialog.mode !== 'join-initial' || !isSharedInitialStartup(dialog.startup)
              : dialog.mode === 'join-initial' ||
                input.vaultId !== dialog.startup.slots?.vaultId ||
                !dialog.startup.slots.slots.some(
                  (slot) => slot.kind === 'password' && slot.id === input.slotId,
                ))
          )
            throw Error('Shared authentication unavailable.');
          dialog.busy = true;
          dialog.factors = [
            input.password,
            ...(input.ask ? [input.ask] : []),
            ...('code' in input ? [input.code] : []),
          ];
          try {
            const accepted = () => this.trusted(event) === dialog;
            const result = initial
              ? 'invitation' in input
                ? await options.host.sharedJoinInitial(input, options.appVersion, accepted)
                : await options.host.sharedRedeemAccountReset(
                    offerPath!,
                    input,
                    options.appVersion,
                    accepted,
                  )
              : dialog.confirmAction
                ? await dialog.confirmAction(input, accepted)
                : await this.authenticateExisting(dialog, input, accepted);
            if (!accepted()) {
              await dialog.finish();
              return false;
            }
            await dialog.finish(result);
            return true;
          } catch (error) {
            if (
              error instanceof SharedReenrollmentPending &&
              this.trusted(event) === dialog &&
              (resetting || dialog.startup.sharedJoin?.accountReset === true)
            ) {
              dialog.resetOfferPath = undefined;
              return 'awaiting-activation';
            }
            if (this.trusted(event) !== dialog) await dialog.finish();
            else if (dialog.mode === 'join-initial' || dialog.mode === 'recover-enrollment') {
              try {
                const current = await options.host.startup();
                if (
                  this.trusted(event) === dialog &&
                  (dialog.mode === 'join-initial'
                    ? !isSharedInitialStartup(current)
                    : current.shared && current.slots?.vaultId === dialog.startup.slots?.vaultId)
                )
                  await dialog.finish();
              } catch {
                if (dialog.mode === 'join-initial') await dialog.finish();
              }
            }
            return error instanceof SharedConnectionLimit && this.trusted(event) === dialog
              ? 'connection-limit'
              : false;
          } finally {
            dialog.busy = false;
            dialog.factors = undefined;
          }
        } finally {
          input.password.fill(0);
          input.ask?.fill(0);
          if ('code' in input) input.code.fill(0);
        }
      } finally {
        // Rejected senders/modes can still supply an initial code. Erase every
        // borrowed factor even when the ordinary consumer rejects that shape.
        const value =
          typeof args[0] === 'object' && args[0] !== null
            ? (args[0] as Record<string, unknown>)
            : undefined;
        for (const field of ['code', 'password', 'ask'])
          if (value?.[field] instanceof Uint8Array) (value[field] as Uint8Array).fill(0);
      }
    });
    options.ipc.handle('vault-shared:invitation', (event, ...args: unknown[]) =>
      this.invitation(event, args, false),
    );
    options.ipc.handle('vault-shared:open-invitation', (event, ...args: unknown[]) =>
      this.invitation(event, args, true),
    );
    options.ipc.handle('vault-shared:open-reset-offer', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      const pick = options.pickResetOffer;
      if (!dialog || dialog.mode !== 'join-initial' || dialog.busy || args.length || !pick)
        throw Error('Account reset file unavailable.');
      dialog.resetOfferPath = undefined;
      dialog.busy = true;
      try {
        const path = await pick(dialog.window);
        if (this.trusted(event) !== dialog || path === null) return false;
        if (!validSharedArtifactPath(path, '.whreset')) throw Error('Invalid account reset file.');
        dialog.resetOfferPath = path;
        return true;
      } finally {
        dialog.busy = false;
      }
    });
    options.ipc.handle('vault-shared:tls-update', (event, ...args: unknown[]) =>
      this.selectTLSUpdate(event, args),
    );
    options.ipc.handle('vault-shared:cancel', async (event, ...args: unknown[]) => {
      const dialog = this.trusted(event);
      if (!dialog || args.length) throw Error('Shared authentication unavailable.');
      await dialog.finish();
    });
  }
  cancel(): Promise<void> {
    return this.current?.finish() ?? this.closing ?? Promise.resolve();
  }
  private authenticateExisting(
    dialog: Dialog,
    input: SharedVaultUnlockInput,
    accepted: () => boolean,
  ): Promise<Outcome> {
    const { host, appVersion } = this.options;
    const factors = {
      vaultId: input.vaultId,
      slotId: input.slotId,
      password: input.password,
      ...(input.ask ? { ask: input.ask } : {}),
    };
    if (hasSharedVaultContinuation(input))
      return host.sharedContinueEnrollment(
        { ...factors, code: input.code, acknowledgeTLSOff: input.acknowledgeTLSOff },
        appVersion,
        accepted,
      );
    switch (dialog.mode) {
      case 'admit':
        return host.sharedUnlock(factors, appVersion, accepted, dialog.tlsUpdatePath);
      case 'recover-enrollment':
        return host.sharedRecoverEnrollment(factors, appVersion, accepted);
      default:
        return host.sharedRecoverPassword(factors, appVersion, accepted);
    }
  }
  private async selectTLSUpdate(event: IpcMainInvokeEvent, args: unknown[]): Promise<boolean> {
    const dialog = this.trusted(event);
    const picker = this.options.pickTLSUpdate;
    if (
      !dialog ||
      dialog.mode !== 'admit' ||
      dialog.busy ||
      !picker ||
      args.length !== 1 ||
      (args[0] !== 'choose' && args[0] !== 'clear')
    )
      throw Error('Signed trust update unavailable.');
    if (args[0] === 'clear') {
      dialog.tlsUpdatePath = undefined;
      return false;
    }
    dialog.busy = true;
    try {
      const path = await picker(dialog.window);
      if (this.trusted(event) !== dialog) throw Error('Signed trust update unavailable.');
      if (path !== null) {
        if (!validSharedTLSBundlePath(path)) throw Error('Invalid signed trust update file.');
        dialog.tlsUpdatePath = path;
      }
      return dialog.tlsUpdatePath !== undefined;
    } finally {
      dialog.busy = false;
    }
  }
  private async invitation(event: IpcMainInvokeEvent, args: unknown[], file: boolean) {
    const dialog = this.trusted(event);
    if (
      !dialog ||
      dialog.mode !== 'join-initial' ||
      dialog.busy ||
      args.length !== (file ? 0 : 1) ||
      (!file && typeof args[0] !== 'string')
    )
      throw Error('Invitation unavailable.');
    dialog.busy = true;
    const accepted = () => this.trusted(event) === dialog;
    try {
      let result;
      if (file) {
        if (!this.options.pickInvitation) throw Error('Invitation file unavailable.');
        const path = await this.options.pickInvitation(dialog.window);
        if (!accepted() || path === null) return null;
        result = await this.options.host.readSharedInvitationFile(path, accepted);
      } else result = await this.options.host.inspectSharedInvitation(args[0] as string, accepted);
      if (!accepted()) throw Error('Invitation owner changed.');
      return result;
    } catch {
      throw Error('Invitation unavailable.');
    } finally {
      dialog.busy = false;
    }
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
    mode: SharedAuthenticationMode,
    startup: VaultStartupMetadata,
  ): Promise<Outcome | null>;
  open(
    parent: BrowserWindow,
    accepted: () => boolean,
    mode: 'refresh-recovery-kit',
    startup: VaultStartupMetadata,
    refresh: ConfirmSharedAction<SharedRecoveryKitRefresh>,
  ): Promise<SharedRecoveryKitRefresh | null>;
  open(
    parent: BrowserWindow,
    accepted: () => boolean,
    mode: 'tighten-profile' | 'trust-ssh-host' | 'edit-shared-node',
    startup: VaultStartupMetadata,
    confirm: ConfirmSharedAction<true>,
    signal?: AbortSignal,
  ): Promise<true | null>;
  open(
    parent: BrowserWindow,
    accepted: () => boolean,
    mode: Dialog['mode'],
    startup: VaultStartupMetadata,
    confirmAction?: ConfirmSharedAction<SharedRecoveryKitRefresh | true>,
    signal?: AbortSignal,
  ): Promise<DialogOutcome | null> {
    if (
      this.current ||
      this.closing ||
      signal?.aborted ||
      parent.isDestroyed() ||
      !accepted() ||
      (mode === 'join-initial'
        ? !isSharedInitialStartup(startup)
        : !(mode === 'recover-enrollment' ? startup.sharedJoin : startup.shared) ||
          !startup.slots?.slots.some((slot) => slot.kind === 'password')) ||
      (mode === 'refresh-recovery-kit' ||
      mode === 'tighten-profile' ||
      mode === 'trust-ssh-host' ||
      mode === 'edit-shared-node'
        ? typeof confirmAction !== 'function'
        : confirmAction !== undefined ||
          (mode !== 'admit' &&
            mode !== 'recover-password' &&
            mode !== 'recover-enrollment' &&
            mode !== 'join-initial'))
    )
      return Promise.reject(Error('Shared authentication unavailable.'));
    const window = this.options.createWindow({
      width: 540,
      height: mode === 'join-initial' ? 840 : 590,
      parent,
      modal: true,
      show: false,
      autoHideMenuBar: true,
      webPreferences: {
        preload: this.options.preload,
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        devTools: false,
        partition: `vault-shared-${randomUUID()}`,
      },
    });
    let resolve!: (outcome: DialogOutcome | null) => void;
    let reject!: (error: Error) => void;
    let closing: Promise<void> | undefined;
    const result = new Promise<DialogOutcome | null>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const finish = (outcome?: DialogOutcome): Promise<void> => {
      if (closing) return closing;
      const stopOwner = !outcome && dialog.busy;
      if (this.current === dialog) this.current = undefined;
      dialog.factors?.forEach((bytes) => bytes.fill(0));
      clearTimeout(timer);
      signal?.removeEventListener('abort', cancel);
      parent.removeListener('closed', cancel);
      parent.webContents.removeListener('did-start-navigation', navigation);
      parent.webContents.removeListener('render-process-gone', cancel);
      window.removeListener('closed', cancel);
      closing = Promise.resolve().then(async () => {
        try {
          if (stopOwner) await this.options.host.stop();
          resolve(outcome ?? null);
        } catch {
          reject(Error('Shared authentication cleanup could not be confirmed.'));
        } finally {
          if (!window.isDestroyed()) window.destroy();
          if (this.closing === closing) this.closing = undefined;
        }
      });
      this.closing = closing;
      return closing;
    };
    const cancel = () => {
      void finish();
    };
    const navigation = (_event: unknown, _url: string, _inPlace: boolean, mainFrame: boolean) => {
      if (mainFrame) cancel();
    };
    const timer = setTimeout(cancel, (mode === 'join-initial' ? 10 : 5) * 60_000);
    timer.unref();
    const dialog: Dialog = {
      window,
      startup: structuredClone(startup),
      mode,
      confirmAction,
      busy: false,
      finish,
      valid: () =>
        this.current === dialog && !window.isDestroyed() && !parent.isDestroyed() && accepted(),
    };
    this.current = dialog;
    signal?.addEventListener('abort', cancel, { once: true });
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
        .catch(cancel);
    } catch {
      cancel();
    }
    return result;
  }
}
