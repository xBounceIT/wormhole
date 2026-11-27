import { enrollmentBytes, enrollmentID } from './vault-enrollment-contract.ts';
import { vaultFields, vaultRecord } from './vault-contract.ts';
import { parsePersonalRootRecoveryRequest } from './vault-account-suspension.ts';
import type {
  AccountResetMark,
  AccountResetMarkResult,
  AccountResetTargetPage,
} from './vault-shared-account-reset-queue.ts';

export type SharedAccountResetIssueInput = {
  targetLogin: string;
  targetUserId?: string;
  suspension?: string;
  requestId: string;
  recipient: Uint8Array;
  password: Uint8Array;
  ask?: Uint8Array;
};

export type SharedAccountResetHandover = {
  workspaceId: string;
  requestId: string;
  offerId: string;
  bundle: { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
};

export type SharedAccountResetIssueResult =
  | { status: 'issued'; handover: SharedAccountResetHandover }
  | {
      status:
        | 'unavailable'
        | 'invalid-login'
        | 'invalid-authentication'
        | 'invalid-recipient'
        | 'publication-disabled'
        | 'save-failed';
    };

export type SharedAccountResetIssueOperation = {
  workspaceId: string;
  targets(after: string | null, accepted: () => boolean): Promise<AccountResetTargetPage>;
  mark(handover: AccountResetMark, accepted: () => boolean): Promise<AccountResetMarkResult>;
  submit(
    path: string,
    input: SharedAccountResetIssueInput,
    accepted: () => boolean,
  ): Promise<SharedAccountResetIssueResult>;
};

export function accountResetDisplayEnvelope(value: unknown) {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2
  )
    return;
  const enc = enrollmentBytes(value.enc, 32);
  const ciphertext = enrollmentBytes(value.ciphertext, 64);
  if (enc && ciphertext) return { enc, ciphertext };
}

export function parseSharedAccountResetIssue(
  value: unknown,
): SharedAccountResetIssueResult | undefined {
  if (!vaultRecord(value)) return;
  if (value.status === 'issued') {
    const handover = value.handover;
    if (
      vaultFields(value, ['status', 'handover']) &&
      vaultRecord(handover) &&
      vaultFields(handover, ['workspaceId', 'requestId', 'offerId', 'bundle']) &&
      enrollmentID(handover.workspaceId) &&
      enrollmentID(handover.requestId) &&
      enrollmentID(handover.offerId) &&
      accountResetDisplayEnvelope(handover.bundle)
    )
      return { status: 'issued', handover: handover as SharedAccountResetHandover };
  } else if (
    vaultFields(value, ['status']) &&
    (value.status === 'unavailable' ||
      value.status === 'invalid-login' ||
      value.status === 'invalid-authentication' ||
      value.status === 'invalid-recipient' ||
      value.status === 'publication-disabled' ||
      value.status === 'save-failed')
  ) {
    return { status: value.status };
  }
}

function factor(value: unknown, min: number, max = min): value is Uint8Array {
  return (
    value instanceof Uint8Array &&
    value.buffer instanceof ArrayBuffer &&
    value.length >= min &&
    value.length <= max
  );
}

export function wipeSharedAccountResetIssue(value: unknown): void {
  if (!vaultRecord(value)) return;
  for (const field of ['password', 'ask', 'recipient']) {
    const data = value[field];
    if (data instanceof Uint8Array) data.fill(0);
  }
}

export function consumeSharedAccountResetIssue(value: unknown): SharedAccountResetIssueInput {
  try {
    if (
      !vaultRecord(value) ||
      !vaultFields(value, [
        'targetLogin',
        ...(Object.hasOwn(value, 'targetUserId') ? ['targetUserId'] : []),
        ...(Object.hasOwn(value, 'suspension') ? ['suspension'] : []),
        'requestId',
        'recipient',
        'password',
        ...(Object.hasOwn(value, 'ask') ? ['ask'] : []),
      ]) ||
      typeof value.targetLogin !== 'string' ||
      !value.targetLogin ||
      value.targetLogin.length > 256 ||
      new TextEncoder().encode(value.targetLogin).length > 256 ||
      /\p{Cc}/u.test(value.targetLogin) ||
      (Object.hasOwn(value, 'targetUserId') && !enrollmentID(value.targetUserId)) ||
      (Object.hasOwn(value, 'suspension') &&
        !parsePersonalRootRecoveryRequest({
          accountId: value.targetUserId,
          suspension: value.suspension,
        })) ||
      !enrollmentID(value.requestId) ||
      !factor(value.recipient, 32) ||
      !factor(value.password, 1, 1024) ||
      (Object.hasOwn(value, 'ask') && !factor(value.ask, 32))
    )
      throw Error('Invalid account reset request.');
    return {
      targetLogin: value.targetLogin,
      ...(enrollmentID(value.targetUserId) ? { targetUserId: value.targetUserId } : {}),
      ...(typeof value.suspension === 'string' ? { suspension: value.suspension } : {}),
      requestId: value.requestId,
      recipient: new Uint8Array(value.recipient),
      password: new Uint8Array(value.password),
      ...(value.ask instanceof Uint8Array ? { ask: new Uint8Array(value.ask) } : {}),
    };
  } finally {
    wipeSharedAccountResetIssue(value);
  }
}
