import {
  vaultFields,
  vaultID,
  vaultMetadataText,
  vaultRecord,
  vaultRevision,
} from './vault-contract.ts';
import type { PersonalRootRecoveryFactors } from './vault-account-suspension.ts';

export type SlotDefaultConfirmation = {
  workspaceId: string;
  slotRevision: string;
  credentialId: string;
  credentialRevision: string;
};
export type SlotDefaultRequest = {
  slotId: string;
  credentialName: string;
  confirmation?: SlotDefaultConfirmation;
};
type SlotDefaultChoice = {
  slotId: string;
  slotName: string;
  slotRevision: string;
  protocol: 'ssh' | 'rdp' | 'vnc';
  credentialName: string;
  credentialId: string;
  credentialRevision: string;
  hasDefault: boolean;
};
export type SlotDefaultReply =
  | {
      status: 'review';
      workspaceId: string;
      choice: SlotDefaultChoice;
      authenticationRequired?: true;
    }
  | {
      status:
        | 'unchanged'
        | 'saved'
        | 'authentication-required'
        | 'stale'
        | 'unavailable'
        | 'busy'
        | 'unsupported';
    };
export type SlotDefaultPort = (
  request: SlotDefaultRequest,
  factors?: PersonalRootRecoveryFactors,
) => Promise<SlotDefaultReply>;

export function confirmedSlotDefault(
  reply: Extract<SlotDefaultReply, { status: 'review' }>,
): SlotDefaultRequest {
  const { slotId, credentialName, slotRevision, credentialId, credentialRevision } = reply.choice;
  return {
    slotId,
    credentialName,
    confirmation: {
      workspaceId: reply.workspaceId,
      slotRevision,
      credentialId,
      credentialRevision,
    },
  };
}

const nameText = (value: unknown): value is string =>
  typeof value === 'string' &&
  value.length <= 1024 &&
  new TextEncoder().encode(value).length <= 1024 &&
  !/[\p{Cc}\p{Cs}]/u.test(value);
function matchesCredential(name: string, id: unknown, revision: unknown) {
  return name === '' ? id === '' && revision === '' : vaultID(id) && vaultRevision(revision);
}

export function parseSlotDefaultRequest(value: unknown): SlotDefaultRequest | undefined {
  if (!vaultRecord(value) || !vaultID(value.slotId) || !nameText(value.credentialName)) return;
  const { slotId, credentialName } = value;
  if (!('confirmation' in value))
    return vaultFields(value, ['slotId', 'credentialName'])
      ? { slotId, credentialName }
      : undefined;
  const c = value.confirmation;
  if (
    !vaultFields(value, ['slotId', 'credentialName', 'confirmation']) ||
    !vaultRecord(c) ||
    !vaultFields(c, ['workspaceId', 'slotRevision', 'credentialId', 'credentialRevision']) ||
    !vaultID(c.workspaceId) ||
    !vaultRevision(c.slotRevision) ||
    c.slotRevision === '9223372036854775807' ||
    typeof c.credentialId !== 'string' ||
    typeof c.credentialRevision !== 'string' ||
    !matchesCredential(credentialName, c.credentialId, c.credentialRevision)
  )
    return;
  return {
    slotId,
    credentialName,
    confirmation: {
      workspaceId: c.workspaceId,
      slotRevision: c.slotRevision,
      credentialId: c.credentialId,
      credentialRevision: c.credentialRevision,
    },
  };
}
export function parseSlotDefaultReply(
  v: unknown,
  request: SlotDefaultRequest,
): SlotDefaultReply | undefined {
  if (!vaultRecord(v)) return;
  const { status } = v;
  if (status !== 'review') {
    if (!vaultFields(v, ['status'])) return;
    if (
      status === 'unavailable' ||
      status === 'busy' ||
      status === 'unsupported' ||
      status === 'stale' ||
      status === 'unchanged' ||
      (request.confirmation && (status === 'saved' || status === 'authentication-required'))
    )
      return { status };
    return;
  }
  const c = v.choice;
  if (
    request.confirmation ||
    !vaultFields(v, [
      'status',
      'workspaceId',
      'choice',
      ...('authenticationRequired' in v ? ['authenticationRequired'] : []),
    ]) ||
    ('authenticationRequired' in v && v.authenticationRequired !== true) ||
    !vaultID(v.workspaceId) ||
    !vaultRecord(c) ||
    !vaultFields(c, [
      'slotId',
      'slotName',
      'slotRevision',
      'protocol',
      'credentialName',
      'credentialId',
      'credentialRevision',
      'hasDefault',
    ]) ||
    c.slotId !== request.slotId ||
    !vaultMetadataText(c.slotName, 1024, true) ||
    !vaultRevision(c.slotRevision) ||
    c.slotRevision === '9223372036854775807' ||
    (c.protocol !== 'ssh' && c.protocol !== 'rdp' && c.protocol !== 'vnc') ||
    c.credentialName !== request.credentialName ||
    typeof c.credentialId !== 'string' ||
    typeof c.credentialRevision !== 'string' ||
    !matchesCredential(request.credentialName, c.credentialId, c.credentialRevision) ||
    typeof c.hasDefault !== 'boolean'
  )
    return;
  return {
    status,
    workspaceId: v.workspaceId,
    choice: {
      slotId: request.slotId,
      slotName: c.slotName,
      slotRevision: c.slotRevision,
      protocol: c.protocol,
      credentialName: request.credentialName,
      credentialId: c.credentialId,
      credentialRevision: c.credentialRevision,
      hasDefault: c.hasDefault,
    },
    ...(v.authenticationRequired ? { authenticationRequired: true } : {}),
  };
}
