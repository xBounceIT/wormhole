import { vaultFields, vaultRecord } from './vault-contract.ts';
import { enrollmentID } from './vault-enrollment-contract.ts';

export type AccountResetTargetStatus =
  | 'not-issued'
  | 'awaiting-handover'
  | 'handed-over'
  | 'redeemed'
  | 'expired'
  | 'inactive';

export type AccountResetTarget = {
  userId: string;
  loginName: string;
  eligible: boolean;
} & (
  | { status: 'not-issued' }
  | {
      status: Exclude<AccountResetTargetStatus, 'not-issued'>;
      offerId: string;
      expiresAt: number;
    }
);

type QueueUnavailable = { status: 'unsupported' | 'unavailable' | 'busy' };
export type AccountResetTargetPage =
  | { status: 'ready'; page: { targets: AccountResetTarget[]; next?: string } }
  | QueueUnavailable;
export type AccountResetMarkResult = { status: 'handed-over' | 'redeemed' } | QueueUnavailable;
export type AccountResetMark = { userId: string; offerId: string };

export function parseAccountResetMark(value: unknown): AccountResetMark | undefined {
  if (
    vaultRecord(value) &&
    vaultFields(value, ['userId', 'offerId']) &&
    enrollmentID(value.userId) &&
    enrollmentID(value.offerId)
  )
    return { userId: value.userId, offerId: value.offerId };
}

function parseUnavailable(value: unknown): QueueUnavailable | undefined {
  if (
    vaultRecord(value) &&
    vaultFields(value, ['status']) &&
    (value.status === 'unsupported' || value.status === 'unavailable' || value.status === 'busy')
  )
    return { status: value.status };
}

export function parseAccountResetMarkResult(value: unknown): AccountResetMarkResult | undefined {
  if (
    vaultRecord(value) &&
    vaultFields(value, ['status']) &&
    (value.status === 'handed-over' || value.status === 'redeemed')
  )
    return { status: value.status };
  return parseUnavailable(value);
}

function parseTarget(value: unknown): AccountResetTarget | undefined {
  if (
    !vaultRecord(value) ||
    !enrollmentID(value.userId) ||
    typeof value.loginName !== 'string' ||
    !value.loginName ||
    value.loginName.length > 256 ||
    new TextEncoder().encode(value.loginName).length > 256 ||
    /\p{Cc}/u.test(value.loginName) ||
    typeof value.eligible !== 'boolean'
  )
    return;
  const base = { userId: value.userId, loginName: value.loginName, eligible: value.eligible };
  const fields = ['userId', 'loginName', 'eligible', 'status'];
  if (value.status === 'not-issued') {
    if (vaultFields(value, fields)) return { ...base, status: value.status };
  } else if (
    vaultFields(value, [...fields, 'offerId', 'expiresAt']) &&
    (value.status === 'awaiting-handover' ||
      value.status === 'handed-over' ||
      value.status === 'redeemed' ||
      value.status === 'expired' ||
      value.status === 'inactive') &&
    enrollmentID(value.offerId) &&
    typeof value.expiresAt === 'number' &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > 0 &&
    value.expiresAt <= 253402300799
  ) {
    return { ...base, status: value.status, offerId: value.offerId, expiresAt: value.expiresAt };
  }
}

export function parseAccountResetTargetPage(
  value: unknown,
  after: string | null,
): AccountResetTargetPage | undefined {
  if (!vaultRecord(value) || value.status !== 'ready') return parseUnavailable(value);
  const page = value.page;
  if (
    !vaultFields(value, ['status', 'page']) ||
    !vaultRecord(page) ||
    !vaultFields(page, Object.hasOwn(page, 'next') ? ['targets', 'next'] : ['targets']) ||
    !Array.isArray(page.targets) ||
    page.targets.length > 50
  )
    return;
  const targets: AccountResetTarget[] = [];
  let cursor = after ?? '';
  for (const value of page.targets) {
    const target = parseTarget(value);
    if (!target || target.userId <= cursor) return;
    targets.push(target);
    cursor = target.userId;
  }
  if (Object.hasOwn(page, 'next')) {
    if (targets.length !== 50 || !enrollmentID(page.next) || page.next !== cursor) return;
    return { status: 'ready', page: { targets, next: page.next } };
  }
  return { status: 'ready', page: { targets } };
}
