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
  userId?: string;
  valueRevision?: string;
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
  userId?: string;
  valueRevision?: string;
  provider?: 'local' | 'bitwarden';
  hasAssignment?: true;
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
      ...(reply.choice.userId
        ? { userId: reply.choice.userId, valueRevision: reply.choice.valueRevision }
        : {}),
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

function assignmentScope(value: Record<string, unknown>, personal: boolean) {
  if (!personal) return {};
  const { userId, valueRevision } = value;
  if (
    vaultID(userId) &&
    (valueRevision === '0' || vaultRevision(valueRevision)) &&
    valueRevision !== '9223372036854775807'
  )
    return { userId, valueRevision };
}

export function parseSlotDefaultRequest(
  value: unknown,
  personal = false,
): SlotDefaultRequest | undefined {
  if (!vaultRecord(value) || !vaultID(value.slotId) || !nameText(value.credentialName)) return;
  const { slotId, credentialName } = value;
  if (!('confirmation' in value))
    return vaultFields(value, ['slotId', 'credentialName'])
      ? { slotId, credentialName }
      : undefined;
  const c = value.confirmation;
  if (!vaultRecord(c)) return;
  const scope = assignmentScope(c, personal);
  if (
    !vaultFields(value, ['slotId', 'credentialName', 'confirmation']) ||
    !scope ||
    !vaultFields(c, [
      'workspaceId',
      'slotRevision',
      'credentialId',
      'credentialRevision',
      ...Object.keys(scope),
    ]) ||
    !vaultID(c.workspaceId) ||
    !vaultRevision(c.slotRevision) ||
    (!personal && c.slotRevision === '9223372036854775807') ||
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
      ...scope,
    },
  };
}
export function parseSlotDefaultReply(
  v: unknown,
  request: SlotDefaultRequest,
  personal = false,
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
  if (!vaultRecord(c)) return;
  const scope = assignmentScope(c, personal);
  const provider = c.provider;
  if (personal && request.credentialName && provider !== 'local' && provider !== 'bitwarden')
    return;
  const assigned = personal && Object.hasOwn(c, 'hasAssignment');
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
    !scope ||
    (assigned && (c.hasAssignment !== true || c.valueRevision === '0')) ||
    !vaultFields(c, [
      'slotId',
      'slotName',
      'slotRevision',
      'protocol',
      'credentialName',
      'credentialId',
      'credentialRevision',
      'hasDefault',
      ...Object.keys(scope),
      ...(personal && request.credentialName ? ['provider'] : []),
      ...(assigned ? ['hasAssignment'] : []),
    ]) ||
    c.slotId !== request.slotId ||
    !vaultMetadataText(c.slotName, 1024, true) ||
    !vaultRevision(c.slotRevision) ||
    (!personal && c.slotRevision === '9223372036854775807') ||
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
      ...scope,
      ...(provider === 'local' || provider === 'bitwarden' ? { provider } : {}),
      ...(assigned ? { hasAssignment: true } : {}),
    },
    ...(v.authenticationRequired ? { authenticationRequired: true } : {}),
  };
}
