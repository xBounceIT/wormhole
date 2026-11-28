import { randomUUID } from 'node:crypto';
import type {
  BrowserWindow,
  BrowserWindowConstructorOptions,
  IpcMain,
  IpcMainInvokeEvent,
} from 'electron';
import { protectVaultDisplayWindow } from './vault-display-window.ts';
import {
  consumeSharedSetupRequest,
  wipeSharedSetupRequest,
  type SharedAdminSetupRequest,
  type SharedSetupReply,
  type SharedSetupRequest,
  type SharedSetupCompletion,
} from './vault-shared-setup-contract.ts';
import type { SharedAdministrationPorts, VaultBackendHost } from './vault-host.ts';
import {
  consumeAdminRecoveryInput,
  wipeAdminRecoveryInput,
  type AdminRecoveryInput,
  type AdminRecoveryNativeInput,
} from './vault-admin-recovery.ts';
import {
  consumeSharedRecoveryBackup,
  wipeSharedRecoveryBackup,
  type SharedRecoveryBackupInput,
  type SharedRecoveryBackupOperation,
  type SharedRecoveryBackupResult,
} from './vault-shared-recovery-backup.ts';
import {
  consumeSharedRecoveryInspection,
  consumeSharedRecoveryRestore,
  wipeSharedRecoveryRestore,
  type SharedRecoveryInspection,
  type SharedRecoveryRestoreNative,
  type SharedRecoveryRestoreStatus,
} from './vault-shared-restore.ts';
import {
  consumeSharedAccountResetIssue,
  wipeSharedAccountResetIssue,
  type SharedAccountResetIssueInput,
  type SharedAccountResetIssueOperation,
  type SharedAccountResetIssueResult,
} from './vault-shared-account-reset-issue.ts';
import { enrollmentID } from './vault-enrollment-contract.ts';
import { parseAccountResetMark } from './vault-shared-account-reset-queue.ts';
import { parseAdminInventoryRequest, parseCreateSlot } from './vault-shared-admin-inventory.ts';
import { parseGroupRequest } from './vault-shared-admin-groups.ts';
import { isDeepStrictEqual } from 'node:util';
import {
  confirmedSlotDefault,
  parseSlotDefaultRequest,
  type SlotDefaultRequest,
} from './vault-shared-slot-default.ts';
import { parseSharedCatalogRequest } from './vault-shared-catalog.ts';
import { parseNodeGrantRequest } from './vault-shared-node-grants.ts';
import { parseGroupKeyRequest } from './vault-shared-group-key.ts';
import { parseMemberRotationRequest } from './vault-shared-group-member-rotation.ts';
import { parseGroupBoundaryGrantRequest } from './vault-shared-group-boundary-grant.ts';
import { parseWorkspaceAccessRequest, type WorkspaceAccessRequest } from './vault-shared-access.ts';
import {
  consumePersonalRootRecoveryFactors,
  parseAccountBoundaryRotationRequest,
  parseAccountSuspensionRequest,
  parsePersonalRootRecoveryRequest,
  wipePersonalRootRecoveryFactors,
  type AccountBoundaryRotationRequest,
  type PersonalRootRecoveryFactors,
  type PersonalRootRecoveryRequest,
} from './vault-account-suspension.ts';

type Administration = SharedAdministrationPorts & {
  accessReview?: WorkspaceAccessRequest;
  accountBoundaryReview?: AccountBoundaryRotationRequest;
  personalRecoveryReview?: PersonalRootRecoveryRequest;
  slotDefaultReview?: { request: SlotDefaultRequest; factors: boolean; personal: boolean };
  reenrollmentScope?: Omit<PersonalRootRecoveryRequest, 'review'>;
  busy: boolean;
};

type BackupWindow = {
  operation: SharedRecoveryBackupOperation;
  pending?: SharedRecoveryBackupInput;
  exported: boolean;
};

type SetupWindow = {
  window: BrowserWindow;
  accepted: () => boolean;
  acceptJoin?: () => boolean;
  joining: boolean;
  completion?: SharedSetupCompletion;
  switchOnRestart: boolean;
  mode:
    | 'setup'
    | 'recovery'
    | 'backup'
    | 'restore'
    | 'account-reset'
    | 'administration'
    | 'my-devices';
  administration?: Administration;
  backup?: BackupWindow;
  reset?: {
    operation: SharedAccountResetIssueOperation;
    issuedOffer?: string;
    queueBusy: boolean;
  };
  resetIssueFactors?: SharedAccountResetIssueInput;
  pending?: SharedSetupRequest;
  recoveryFactors?: AdminRecoveryInput;
  restoreFactors?: { password: Uint8Array; deployerPassword?: Uint8Array };
  restoreSelection?: Pick<
    SharedRecoveryRestoreNative,
    'path' | 'archiveDigest' | 'workspaceId' | 'roleTag'
  >;
  loaded: boolean;
  closing: boolean;
  finish: () => boolean;
};

type SetupDialogOptions = {
  colorScheme?: (parent: BrowserWindow) => 'light' | 'dark' | undefined;
  ipc: Pick<IpcMain, 'handle'>;
  host: Pick<VaultBackendHost, 'sharedSetup'>;
  createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;
  pickExport: (window: BrowserWindow, format?: 'sql' | 'hba') => Promise<string | null>;
  pickRecovery?: (window: BrowserWindow) => Promise<string | null>;
  pickBackup?: (window: BrowserWindow, accepted: () => boolean) => Promise<string | null>;
  pickAccountReset?: (window: BrowserWindow) => Promise<string | null>;
  restore?: {
    choose(window: BrowserWindow): Promise<string | null>;
    inspect: VaultBackendHost['inspectSharedRecoveryBackup'];
    apply?: VaultBackendHost['restoreSharedRecoveryBackup'];
  };
  recover?: {
    choose(window: BrowserWindow, artifact: 'kit' | 'trust'): Promise<string | null>;
    submit(
      input: AdminRecoveryNativeInput,
      accepted: () => boolean,
    ): Promise<SharedSetupCompletion>;
  };
  join?: (
    input: Extract<SharedAdminSetupRequest, { action: 'admin-join' }>,
    accepted: () => boolean,
  ) => Promise<SharedSetupCompletion>;
  url: string;
  preload: string;
  platform?: NodeJS.Platform;
};

export class VaultSharedSetupDialog {
  private current?: SetupWindow;
  private readonly options: SetupDialogOptions;

  constructor(options: SetupDialogOptions) {
    this.options = options;
    options.ipc.handle('vault-shared-setup:mode', (event, ...args: unknown[]) => {
      const current = this.trusted(event);
      if (!current || args.length) throw Error('Shared workspace setup is unavailable.');
      return current.mode;
    });
    options.ipc.handle('vault-shared-setup:grant-targets', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ nodeGrants }) => {
        const request = args.length === 1 ? parseSharedCatalogRequest(args[0]) : undefined;
        if (!request || !nodeGrants) throw Error('Invalid grant catalog request.');
        return nodeGrants.catalog(request);
      }),
    );
    options.ipc.handle('vault-shared-setup:node-grant', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ nodeGrants }) => {
        const request = args.length === 1 ? parseNodeGrantRequest(args[0]) : undefined;
        if (!request || !nodeGrants) throw Error('Invalid node grant request.');
        return nodeGrants.grant(request);
      }),
    );
    options.ipc.handle('vault-shared-setup:group-key', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ groupKey }) => {
        const request = args.length === 1 ? parseGroupKeyRequest(args[0]) : undefined;
        if (!request || !groupKey) throw Error('Invalid group key request.');
        return groupKey(request);
      }),
    );
    options.ipc.handle('vault-shared-setup:group-boundary-grant', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ nodeGrants }) => {
        const request = args.length === 1 ? parseGroupBoundaryGrantRequest(args[0]) : undefined;
        if (!request || !nodeGrants?.boundary) throw Error('Invalid boundary grant request.');
        return nodeGrants.boundary(request);
      }),
    );
    options.ipc.handle('vault-shared-setup:group-boundary-rotation', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ nodeGrants }) => {
        const request =
          args.length === 1 ? parseGroupBoundaryGrantRequest(args[0], true) : undefined;
        if (!request || !nodeGrants?.rotation) throw Error('Invalid boundary rotation request.');
        return nodeGrants.rotation(request);
      }),
    );
    options.ipc.handle('vault-shared-setup:group-member-rotation', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ memberRotation }) => {
        const request = args.length === 1 ? parseMemberRotationRequest(args[0]) : undefined;
        if (!request || !memberRotation) throw Error('Invalid member rotation request.');
        return memberRotation(request);
      }),
    );
    options.ipc.handle('vault-shared-setup:admin-inventory', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ read }) => {
        const request = args.length === 1 ? parseAdminInventoryRequest(args[0]) : undefined;
        if (!request) throw Error('Invalid administration page request.');
        return read(request);
      }),
    );
    options.ipc.handle('vault-shared-setup:workspace-access', (event, ...args: unknown[]) =>
      this.runAdministration(event, async (port) => {
        const request = args.length === 1 ? parseWorkspaceAccessRequest(args[0]) : undefined;
        const reviewed = port.accessReview;
        port.accessReview = undefined;
        if (
          !request ||
          !port.access ||
          (request.revision !== undefined &&
            (reviewed?.action !== request.action ||
              reviewed.targetId !== request.targetId ||
              reviewed.revision !== request.revision))
        )
          throw Error('Review the workspace access change first.');
        const result = await port.access(request);
        if (result.status === 'review') port.accessReview = result.review;
        return result;
      }),
    );
    options.ipc.handle('vault-shared-setup:account-suspension', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ suspension }) => {
        const request = args.length === 1 ? parseAccountSuspensionRequest(args[0]) : undefined;
        if (!request || !suspension) throw Error('Account access review is unavailable.');
        return suspension(request);
      }),
    );
    options.ipc.handle(
      'vault-shared-setup:account-boundary-rotation',
      (event, ...args: unknown[]) =>
        this.runAdministration(event, async (port) => {
          const request =
            args.length === 1 ? parseAccountBoundaryRotationRequest(args[0]) : undefined;
          const review = port.accountBoundaryReview;
          port.accountBoundaryReview = undefined;
          if (
            !request ||
            !port.accountRotation ||
            (request.review && (!review || JSON.stringify(review) !== JSON.stringify(request)))
          )
            throw Error('Review the boundary key rotation first.');
          const reply = await port.accountRotation(request);
          if (reply.status === 'review')
            port.accountBoundaryReview = { ...request, review: reply.review };
          return reply;
        }),
    );
    options.ipc.handle(
      'vault-shared-setup:personal-root-recovery',
      async (event, ...args: unknown[]) => {
        let factors: PersonalRootRecoveryFactors | undefined;
        try {
          return await this.runAdministration(event, async (port, accepted) => {
            const request = parsePersonalRootRecoveryRequest(args[0]);
            const reviewed = port.personalRecoveryReview;
            port.personalRecoveryReview = undefined;
            port.reenrollmentScope = undefined;
            if (
              !request ||
              !port.personalRecovery ||
              args.length !== (request.review ? 2 : 1) ||
              (request.review &&
                (reviewed?.review !== request.review ||
                  reviewed.accountId !== request.accountId ||
                  reviewed.suspension !== request.suspension))
            )
              throw Error('Review personal key recovery first.');
            if (request.review) factors = consumePersonalRootRecoveryFactors(args[1]);
            const result = await port.personalRecovery(request, factors, accepted);
            if (!request.review && result.status === 'review')
              port.personalRecoveryReview = { ...request, review: result.review };
            if (!request.review && result.status === 'enrollment-required' && result.canReenroll) {
              if (!port.reenrollment || !options.pickAccountReset)
                return { status: 'enrollment-required' };
              port.reenrollmentScope = {
                accountId: request.accountId,
                suspension: request.suspension,
              };
            }
            return result;
          });
        } finally {
          wipePersonalRootRecoveryFactors(args[1]);
          wipePersonalRootRecoveryFactors(factors);
        }
      },
    );
    options.ipc.handle('vault-shared-setup:create-slot', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ createSlot }) => {
        const request = args.length === 1 ? parseCreateSlot(args[0]) : undefined;
        if (!request || !createSlot) throw Error('Invalid credential slot request.');
        return createSlot(request);
      }),
    );
    for (const channel of ['slot-default', 'personal-slot'] as const) {
      const personal = channel === 'personal-slot';
      options.ipc.handle('vault-shared-setup:' + channel, async (event, ...args: unknown[]) => {
        let factors: PersonalRootRecoveryFactors | undefined;
        try {
          return await this.runAdministration(event, async (port, accepted) => {
            const previous = port.slotDefaultReview;
            port.slotDefaultReview = undefined;
            const request = parseSlotDefaultRequest(args[0], personal);
            const change = personal ? port.personalSlot : port.slotDefault;
            if (
              !request ||
              !change ||
              (request.confirmation &&
                (previous?.personal !== personal ||
                  !isDeepStrictEqual(request, previous.request))) ||
              args.length !== (request.confirmation && previous?.factors ? 2 : 1)
            )
              throw Error('Review this slot default first.');
            if (args.length === 2) factors = consumePersonalRootRecoveryFactors(args[1]);
            const result = await change(request, factors, accepted);
            if (result.status === 'review')
              port.slotDefaultReview = {
                personal,
                request: confirmedSlotDefault(result),
                factors: result.authenticationRequired === true,
              };
            return result;
          });
        } finally {
          wipePersonalRootRecoveryFactors(args[1]);
          wipePersonalRootRecoveryFactors(factors);
        }
      });
    }
    options.ipc.handle('vault-shared-setup:admin-groups', (event, ...args: unknown[]) =>
      this.runAdministration(event, async ({ groups }) => {
        const request = args.length === 1 ? parseGroupRequest(args[0]) : undefined;
        if (!request || !groups) throw Error('Invalid group administration request.');
        return groups(request);
      }),
    );
    options.ipc.handle(
      'vault-shared-setup:inspect-backup',
      async (event, ...args: unknown[]): Promise<SharedRecoveryInspection | null> => {
        const current = this.trusted(event);
        const restore = options.restore;
        if (
          !current ||
          current.mode !== 'restore' ||
          current.restoreFactors ||
          args.length !== 1 ||
          !restore
        ) {
          wipeSharedRecoveryRestore(args[0]);
          throw Error('Workspace restore is unavailable.');
        }
        const { password, saveScript } = consumeSharedRecoveryInspection(args[0]);
        const accepted = () => this.trusted(event) === current;
        current.restoreSelection = undefined;
        current.restoreFactors = { password };
        try {
          const path = await restore.choose(current.window);
          if (!accepted() || path === null) return null;
          const scriptPath = saveScript ? await options.pickExport(current.window) : undefined;
          if (!accepted() || scriptPath === null) return null;
          const result = await restore.inspect({ path, scriptPath, password }, accepted);
          if (!accepted()) throw Error('Workspace restore was interrupted.');
          if (!('summary' in result)) return result;
          const { status, summary, archiveDigest } = result;
          current.restoreSelection = {
            path,
            archiveDigest,
            workspaceId: summary.workspaceId,
            roleTag: summary.roleTag,
          };
          return { status, summary };
        } finally {
          this.releaseRestoreFactors(current);
        }
      },
    );
    options.ipc.handle(
      'vault-shared-setup:apply-backup',
      async (event, ...args: unknown[]): Promise<SharedRecoveryRestoreStatus> => {
        const current = this.trusted(event);
        const apply = options.restore?.apply;
        const selection = current?.restoreSelection;
        if (
          !current ||
          current.mode !== 'restore' ||
          !selection ||
          !apply ||
          current.restoreFactors ||
          args.length !== 1
        ) {
          wipeSharedRecoveryRestore(args[0]);
          throw Error('Workspace restore is unavailable.');
        }
        const { confirmed: _confirmed, ...input } = consumeSharedRecoveryRestore(args[0]);
        const accepted = () => this.trusted(event) === current;
        current.restoreFactors = input;
        try {
          const status = await apply({ ...input, ...selection }, accepted);
          if (!accepted()) throw Error('Workspace restore was interrupted.');
          if (
            status === 'restored' ||
            status === 'already-restored' ||
            status === 'archive-changed' ||
            status === 'invalid-backup'
          )
            current.restoreSelection = undefined;
          return status;
        } finally {
          this.releaseRestoreFactors(current);
        }
      },
    );
    options.ipc.handle('vault-shared-setup:backup-context', (event, ...args: unknown[]) => {
      const backup = this.trusted(event)?.backup;
      if (!backup || args.length) throw Error('Workspace backup is unavailable.');
      return backup.operation.authenticationRequired;
    });
    options.ipc.handle(
      'vault-shared-setup:export-backup',
      async (event, ...args: unknown[]): Promise<SharedRecoveryBackupResult | null> => {
        const current = this.trusted(event);
        const backup = current?.backup;
        const pick = options.pickBackup;
        if (
          !current ||
          !backup ||
          backup.pending ||
          backup.exported ||
          args.length !== 1 ||
          !pick
        ) {
          wipeSharedRecoveryBackup(args[0]);
          throw Error('Workspace backup is unavailable.');
        }
        const input = consumeSharedRecoveryBackup(args[0], backup.operation.authenticationRequired);
        const accepted = () => this.trusted(event) === current;
        backup.pending = input;
        try {
          const path = await pick(current.window, accepted);
          if (!accepted()) throw Error('Workspace backup was interrupted.');
          if (path === null) return null;
          const result = await backup.operation.submit(path, input, accepted);
          if (!accepted()) throw Error('Workspace backup was interrupted.');
          backup.exported = result.status === 'exported';
          return result;
        } finally {
          wipeSharedRecoveryBackup(input);
          backup.pending = undefined;
          if (current.closing && current.window.isDestroyed() && this.current === current)
            this.current = undefined;
        }
      },
    );
    options.ipc.handle('vault-shared-setup:reset-context', (event, ...args: unknown[]) => {
      const current = this.trusted(event);
      const administration = current?.administration;
      const operation =
        current?.reset?.operation ??
        (administration?.reenrollmentScope && administration.reenrollment);
      if (!operation || args.length) throw Error('Account reset is unavailable.');
      return operation.workspaceId;
    });
    options.ipc.handle('vault-shared-setup:reset-targets', (event, ...args: unknown[]) => {
      const after = args[0];
      if (args.length !== 1 || (after !== null && !enrollmentID(after)))
        throw Error('Account reset is unavailable.');
      return this.withResetQueue(event, (reset, accepted) =>
        reset.operation.targets(after, accepted),
      );
    });
    options.ipc.handle('vault-shared-setup:mark-reset-handover', (event, ...args: unknown[]) => {
      const mark = parseAccountResetMark(args[0]);
      if (args.length !== 1 || !mark) throw Error('Account reset is unavailable.');
      return this.withResetQueue(event, async (reset, accepted) => {
        if (reset.issuedOffer && reset.issuedOffer !== mark.offerId)
          throw Error('Account reset is unavailable.');
        const result = await reset.operation.mark(mark, accepted);
        if (result.status === 'handed-over' || result.status === 'redeemed')
          reset.issuedOffer = undefined;
        return result;
      });
    });
    options.ipc.handle('vault-shared-setup:leave-reset-pending', (event, ...args: unknown[]) => {
      const current = this.trusted(event);
      const reset = current?.reset;
      if (
        !reset ||
        current.resetIssueFactors ||
        reset.queueBusy ||
        args.length !== 1 ||
        !enrollmentID(args[0]) ||
        args[0] !== reset.issuedOffer
      )
        throw Error('Account reset is unavailable.');
      reset.issuedOffer = undefined;
      return true;
    });
    options.ipc.handle(
      'vault-shared-setup:issue-reset',
      async (event, ...args: unknown[]): Promise<SharedAccountResetIssueResult | null> => {
        const current = this.trusted(event);
        const reset = current?.reset;
        const administration = current?.administration;
        const scope = administration?.reenrollmentScope;
        const operation = reset?.operation ?? (scope && administration?.reenrollment);
        const pick = options.pickAccountReset;
        if (
          !current ||
          !operation ||
          !pick ||
          current.resetIssueFactors ||
          reset?.queueBusy ||
          reset?.issuedOffer ||
          administration?.busy ||
          args.length !== 1
        ) {
          wipeSharedAccountResetIssue(args[0]);
          throw Error('Account reset is unavailable.');
        }
        const input = consumeSharedAccountResetIssue(args[0]);
        const accepted = () => this.trusted(event) === current;
        try {
          if (
            reset
              ? input.suspension !== undefined
              : !scope ||
                input.targetUserId !== scope.accountId ||
                input.suspension !== scope.suspension
          )
            throw Error('The account or suspension does not match the review.');
          current.resetIssueFactors = input;
          if (administration) administration.busy = true;
          const path = await pick(current.window);
          if (!accepted()) throw Error('Account reset was interrupted.');
          if (path === null) return null;
          const result = await operation.submit(path, input, accepted);
          if (!accepted()) throw Error('Account reset was interrupted.');
          if (result.status === 'issued') {
            if (reset) reset.issuedOffer = result.handover.offerId;
            if (administration) administration.reenrollmentScope = undefined;
          }
          return result;
        } finally {
          wipeSharedAccountResetIssue(input);
          if (current.resetIssueFactors === input) {
            current.resetIssueFactors = undefined;
            if (administration) administration.busy = false;
          }
          if (current.closing && current.window.isDestroyed() && this.current === current)
            this.current = undefined;
        }
      },
    );
    options.ipc.handle('vault-shared-setup:recover-admin', async (event, ...args: unknown[]) => {
      const input = consumeAdminRecoveryInput(args[0]);
      try {
        const current = this.trusted(event);
        const recover = options.recover;
        if (
          !current ||
          current.mode !== 'recovery' ||
          !current.acceptJoin?.() ||
          !recover ||
          args.length !== 1 ||
          current.joining
        )
          throw Error('Workspace recovery is unavailable.');
        const accepted = () => this.trusted(event) === current;
        current.joining = true;
        current.recoveryFactors = input;
        try {
          const kitPath = await recover.choose(current.window, 'kit');
          if (!accepted() || kitPath === null) return false;
          const trustPath = await recover.choose(current.window, 'trust');
          if (!accepted() || trustPath === null) return false;
          const completion = await recover.submit({ ...input, kitPath, trustPath }, accepted);
          if (!accepted()) throw Error('Workspace recovery was interrupted.');
          current.completion = completion;
          if (!current.finish()) throw Error('Workspace recovery could not close.');
          return true;
        } finally {
          current.recoveryFactors = undefined;
          current.joining = false;
          if (current.closing && current.window.isDestroyed() && this.current === current)
            this.current = undefined;
        }
      } finally {
        wipeAdminRecoveryInput(input);
      }
    });
    options.ipc.handle(
      'vault-shared-setup:request',
      async (event, ...args: unknown[]): Promise<SharedSetupReply | null> => {
        // Consume and wipe any copied password even if the sender is rejected.
        const input = consumeSharedSetupRequest(args[0]);
        try {
          const current = this.trusted(event);
          if (
            !current ||
            current.mode !== 'setup' ||
            !input ||
            args.length !== 1 ||
            current.pending
          )
            throw Error('Shared workspace setup is unavailable.');
          const accepted = () => this.trusted(event) === current;
          current.pending = input;
          try {
            if (
              (input.action === 'admin-import-start' ||
                input.action === 'import-review' ||
                (input.action === 'admin-join' && input.importConfirmation)) &&
              !current.switchOnRestart
            )
              throw Error('Local workspace import is unavailable.');
            if (input.action === 'admin-join') {
              if (!current.acceptJoin?.() || !options.join)
                throw Error('First administrator Join is unavailable.');
              current.joining = true;
              const completion = await options.join(input, accepted);
              if (!accepted()) throw Error('Shared workspace setup was interrupted.');
              current.completion = completion;
              if (!current.finish()) throw Error('Shared workspace setup could not close.');
              return null;
            }
            if (input.action === 'export' || input.action === 'export-hba') {
              const path = await options.pickExport(
                current.window,
                input.action === 'export-hba' ? 'hba' : 'sql',
              );
              if (!accepted()) throw Error('Shared workspace setup was interrupted.');
              if (path === null) return null;
              return await options.host.sharedSetup({ ...input, path }, accepted);
            }
            if (input.action === 'admin-recovery') {
              if (!options.pickRecovery) throw Error('Recovery export is unavailable.');
              const path = await options.pickRecovery(current.window);
              if (!accepted()) throw Error('Shared workspace setup was interrupted.');
              if (path === null) return null;
              return await options.host.sharedSetup({ ...input, path }, accepted);
            }
            const reply = await options.host.sharedSetup(input, accepted);
            return input.action === 'plan' && current.acceptJoin
              ? {
                  ...reply,
                  joinAvailable: true,
                  ...(current.switchOnRestart ? { joinSwitchesOnRestart: true } : {}),
                }
              : reply;
          } finally {
            current.joining = false;
            current.pending = undefined;
            if (current.closing && current.window.isDestroyed() && this.current === current)
              this.current = undefined;
          }
        } finally {
          wipeSharedSetupRequest(input);
        }
      },
    );
    options.ipc.handle('vault-shared-setup:close', (event, ...args: unknown[]) => {
      const current = this.trusted(event);
      if (
        !current ||
        args.length ||
        current.pending ||
        current.joining ||
        current.backup?.pending ||
        current.resetIssueFactors ||
        current.reset?.queueBusy ||
        current.restoreFactors
      )
        throw Error('Shared workspace setup is busy.');
      if (!current.finish()) throw Error('Shared workspace setup window could not be closed.');
      return true;
    });
  }

  private releaseRestoreFactors(current: SetupWindow): void {
    wipeSharedRecoveryRestore(current.restoreFactors);
    current.restoreFactors = undefined;
    if (current.closing && current.window.isDestroyed() && this.current === current)
      this.current = undefined;
  }

  private async withResetQueue<T>(
    event: IpcMainInvokeEvent,
    run: (reset: NonNullable<SetupWindow['reset']>, accepted: () => boolean) => Promise<T>,
  ): Promise<T> {
    const current = this.trusted(event);
    const reset = current?.reset;
    if (!current || !reset || current.resetIssueFactors || reset.queueBusy)
      throw Error('Account reset is unavailable.');
    reset.queueBusy = true;
    const accepted = () => this.trusted(event) === current;
    try {
      const result = await run(reset, accepted);
      if (!accepted()) throw Error('Account reset was interrupted.');
      return result;
    } finally {
      reset.queueBusy = false;
      if (current.closing && current.window.isDestroyed() && this.current === current)
        this.current = undefined;
    }
  }

  private trusted(event: IpcMainInvokeEvent): SetupWindow | undefined {
    try {
      const current = this.current;
      if (
        current &&
        !current.closing &&
        !current.window.isDestroyed() &&
        (current.joining ? current.acceptJoin?.() : current.accepted()) &&
        event.sender === current.window.webContents &&
        event.senderFrame === event.sender.mainFrame &&
        event.senderFrame?.url === this.options.url
      )
        return current;
    } catch {
      // A destroyed renderer can throw during sender validation.
    }
    return undefined;
  }

  private async runAdministration<T>(
    event: IpcMainInvokeEvent,
    run: (port: Administration, accepted: () => boolean) => Promise<T>,
  ): Promise<T> {
    const current = this.trusted(event);
    const port = current?.administration;
    if (!current || !port || port.busy) throw Error('Workspace administration is unavailable.');
    port.busy = true;
    try {
      const accepted = () => this.trusted(event) === current;
      const result = await run(port, accepted);
      if (!accepted()) throw Error('Workspace administration was interrupted.');
      return result;
    } finally {
      port.busy = false;
    }
  }

  async cancel(): Promise<void> {
    if (this.current && !this.current.finish())
      throw Error('Shared workspace setup window could not be closed.');
  }

  get active(): boolean {
    return this.current !== undefined;
  }

  async openBackup(
    parent: BrowserWindow,
    accepted: () => boolean,
    operation: SharedRecoveryBackupOperation,
  ): Promise<void> {
    await this.open(parent, accepted, undefined, false, 'backup', operation);
  }

  async openAccountReset(
    parent: BrowserWindow,
    accepted: () => boolean,
    operation: SharedAccountResetIssueOperation,
  ): Promise<void> {
    await this.open(parent, accepted, undefined, false, 'account-reset', undefined, operation);
  }

  async openAdministration(
    parent: BrowserWindow,
    accepted: () => boolean,
    ports: SharedAdministrationPorts,
  ): Promise<void> {
    await this.open(
      parent,
      accepted,
      undefined,
      false,
      ports.ownDevicesOnly ? 'my-devices' : 'administration',
      undefined,
      undefined,
      { ...ports, busy: false },
    );
  }

  open(
    parent: BrowserWindow,
    accepted: () => boolean,
    acceptJoin?: () => boolean,
    switchOnRestart = false,
    mode: SetupWindow['mode'] = 'setup',
    operation?: SharedRecoveryBackupOperation,
    resetOperation?: SharedAccountResetIssueOperation,
    administration?: Administration,
  ): Promise<SharedSetupCompletion | undefined> {
    if (this.current || parent.isDestroyed() || !accepted())
      return Promise.reject(Error('Shared workspace setup is unavailable.'));
    const window = this.options.createWindow({
      width: 700,
      height: 760,
      minWidth: 480,
      minHeight: 500,
      parent,
      modal: true,
      show: false,
      autoHideMenuBar: true,
      title: {
        setup: 'Create a shared workspace',
        recovery: 'Recover shared workspace access',
        backup: 'Export workspace recovery backup',
        restore: 'Restore a shared workspace',
        'account-reset': 'Issue account reset',
        administration: 'Workspace administration',
        'my-devices': 'My workspace',
      }[mode],
      webPreferences: {
        preload: this.options.preload,
        additionalArguments:
          mode === 'administration' || mode === 'my-devices'
            ? ['--wormhole-appearance=' + (this.options.colorScheme?.(parent) ?? 'system')]
            : [],
        partition: `vault-shared-setup-${randomUUID()}`,
        contextIsolation: true,
        sandbox: true,
        nodeIntegration: false,
        webSecurity: true,
        devTools: false,
        spellcheck: false,
      },
    });
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        parent.removeListener('closed', finish);
        parent.webContents.removeListener('did-start-navigation', navigation);
        parent.webContents.removeListener('render-process-gone', finish);
      };
      const finish = () => {
        current.closing = true;
        wipeSharedSetupRequest(current.pending);
        wipeAdminRecoveryInput(current.recoveryFactors);
        wipeSharedRecoveryBackup(current.backup?.pending);
        wipeSharedAccountResetIssue(current.resetIssueFactors);
        wipeSharedRecoveryRestore(current.restoreFactors);
        current.restoreSelection = undefined;
        try {
          if (!window.isDestroyed()) window.destroy();
          if (!window.isDestroyed())
            throw Error('Shared workspace setup window could not be closed.');
          cleanup();
          if (
            !current.pending &&
            !current.joining &&
            !current.backup?.pending &&
            !current.resetIssueFactors &&
            !current.reset?.queueBusy &&
            !current.restoreFactors &&
            this.current === current
          )
            this.current = undefined;
          resolve(current.completion);
          return true;
        } catch {
          reject(Error('Shared workspace setup window could not be closed.'));
          return false;
        }
      };
      const navigation = (_event: unknown, _url: string, _inPlace: boolean, mainFrame: boolean) => {
        if (mainFrame) finish();
      };
      const current: SetupWindow = {
        window,
        accepted,
        acceptJoin,
        switchOnRestart,
        mode,
        ...(operation ? { backup: { operation, exported: false } } : {}),
        ...(resetOperation ? { reset: { operation: resetOperation, queueBusy: false } } : {}),
        administration,
        joining: false,
        loaded: false,
        closing: false,
        finish,
      };
      this.current = current;
      try {
        protectVaultDisplayWindow(
          window,
          this.options.url,
          () => current.loaded,
          finish,
          this.options.platform,
        );
        parent.once('closed', finish);
        parent.webContents.on('did-start-navigation', navigation);
        parent.webContents.once('render-process-gone', finish);
        window.on('close', (event) => {
          if (
            current.pending ||
            current.joining ||
            current.backup?.pending ||
            current.resetIssueFactors ||
            current.reset?.queueBusy ||
            current.restoreFactors
          )
            event.preventDefault();
        });
        window.once('closed', () => {
          // A native close can still arrive after a failed destroy attempt.
          if (!current.closing || window.isDestroyed()) finish();
        });
        // Renderer module scripts run during loadURL. Permit only the exact
        // protected document as soon as it can send its initial plan request.
        window.webContents.on('dom-ready', () => {
          current.loaded = true;
        });
        void window
          .loadURL(this.options.url)
          .then(() => {
            if (!current.closing && accepted()) window.show();
            else finish();
          })
          .catch(() => {
            reject(Error('Shared workspace setup window could not be loaded.'));
            finish();
          });
      } catch (error) {
        reject(error);
        finish();
      }
    });
  }
}
