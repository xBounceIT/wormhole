import { enrollmentBytes, enrollmentID } from './vault-enrollment-contract.ts';
import { vaultFields, vaultRecord } from './vault-contract.ts';
import { validSharedInvitationText } from './vault-shared-invitation.ts';
import type { PersonalRootRecoveryFactors } from './vault-account-suspension.ts';

export type MemberInvitationRequest = {
  login: string;
  name: string;
  requestId: string;
  recipient: string;
};
type Bundle = { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
export type MemberInvitationReply =
  | {
      status: 'issued';
      handover: {
        workspaceId: string;
        requestId: string;
        inviteId: string;
        token: string;
        bundle: Bundle;
      };
    }
  | {
      status:
        | 'unsupported'
        | 'unavailable'
        | 'changed'
        | 'busy'
        | 'invalid-login'
        | 'invalid-authentication'
        | 'invalid-recipient'
        | 'publication-disabled';
    };
export type MemberInvitationPort = (
  request: MemberInvitationRequest,
  factors: PersonalRootRecoveryFactors,
) => Promise<MemberInvitationReply>;

export function parseMemberInvitationRequest(value: unknown): MemberInvitationRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['login', 'name', 'requestId', 'recipient']) ||
    typeof value.login !== 'string' ||
    !value.login ||
    new TextEncoder().encode(value.login).length > 256 ||
    typeof value.name !== 'string' ||
    new TextEncoder().encode(value.name).length > 4096 ||
    /\p{Cc}/u.test(value.login) ||
    /\p{Cc}/u.test(value.name) ||
    !enrollmentID(value.requestId) ||
    typeof value.recipient !== 'string' ||
    !enrollmentBytes(value.recipient, 32)
  )
    return;
  return {
    login: value.login,
    name: value.name,
    requestId: value.requestId,
    recipient: value.recipient,
  };
}

export function memberInvitationEnvelope(value: unknown, sealedBytes = 32) {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2
  )
    return;
  const enc = enrollmentBytes(value.enc, 32);
  const ciphertext = enrollmentBytes(value.ciphertext, sealedBytes);
  if (enc && ciphertext) return { enc, ciphertext };
}

export type InvitationCopyScope = { workspaceId: string; requestId: string; inviteId: string };
export type InvitationCopyRequest = {
  requestId: string;
  inviteId: string;
  copyId: string;
  recipient?: string;
};
export type InvitationCopyReply =
  | { status: 'unavailable' }
  | { status: 'copied'; expiresInSeconds: 20 | 30 }
  | { status: 'sealed'; bundle: Bundle };
export function parseInvitationCopyReply(value: unknown): InvitationCopyReply | undefined {
  if (!vaultRecord(value)) return;
  if (value.status === 'unavailable' && vaultFields(value, ['status']))
    return { status: 'unavailable' };
  if (
    value.status === 'copied' &&
    vaultFields(value, ['status', 'expiresInSeconds']) &&
    (value.expiresInSeconds === 20 || value.expiresInSeconds === 30)
  )
    return { status: 'copied', expiresInSeconds: value.expiresInSeconds };
  if (
    value.status === 'sealed' &&
    vaultFields(value, ['status', 'bundle']) &&
    memberInvitationEnvelope(value.bundle, 50)
  )
    return { status: 'sealed', bundle: value.bundle as Bundle };
}

export function parseMemberInvitationReply(value: unknown): MemberInvitationReply | undefined {
  if (!vaultRecord(value)) return;
  if (value.status === 'issued') {
    const receipt = value.handover;
    if (
      vaultFields(value, ['status', 'handover']) &&
      vaultRecord(receipt) &&
      vaultFields(receipt, ['workspaceId', 'requestId', 'inviteId', 'token', 'bundle']) &&
      enrollmentID(receipt.workspaceId) &&
      enrollmentID(receipt.requestId) &&
      enrollmentID(receipt.inviteId) &&
      validSharedInvitationText(receipt.token) &&
      /^WHINV3-[A-Za-z0-9_-]+\.[0-9a-f]{64}$/.test(receipt.token) &&
      memberInvitationEnvelope(receipt.bundle)
    ) {
      return {
        status: 'issued',
        handover: {
          workspaceId: receipt.workspaceId,
          requestId: receipt.requestId,
          inviteId: receipt.inviteId,
          token: receipt.token,
          bundle: receipt.bundle as Bundle,
        },
      };
    }
    return;
  }
  if (!vaultFields(value, ['status'])) return;
  switch (value.status) {
    case 'unsupported':
    case 'unavailable':
    case 'changed':
    case 'busy':
    case 'invalid-login':
    case 'invalid-authentication':
    case 'invalid-recipient':
    case 'publication-disabled':
      return { status: value.status };
  }
}
