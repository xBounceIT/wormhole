import { vaultFields, vaultID, vaultRecord, vaultRevision } from './vault-contract.ts';

export type GroupKeyRequest = { groupId: string; revision: string; review?: string };
export type GroupKeyMember = { id: string; login: string };
type GroupKeyPreview = {
  groupId: string;
  revision: string;
  review: string;
  members: GroupKeyMember[];
};
export type GroupKeyStatus =
  | 'busy'
  | 'stale'
  | 'unavailable'
  | 'unsupported'
  | 'no-members'
  | 'too-large'
  | 'incomplete'
  | 'provisioned'
  | 'issued';
export type GroupKeyReply =
  | { status: 'review'; preview: GroupKeyPreview }
  | { status: GroupKeyStatus };
export type GroupKeyPort = (request: GroupKeyRequest) => Promise<GroupKeyReply>;

export const reviewDigest = (value: unknown): value is string =>
  typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

export function parseGroupKeyRequest(value: unknown): GroupKeyRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultID(value.groupId) ||
    !vaultRevision(value.revision) ||
    value.revision === '9223372036854775807'
  )
    return;
  const confirming = Object.hasOwn(value, 'review');
  if (
    !vaultFields(value, ['groupId', 'revision', ...(confirming ? ['review'] : [])]) ||
    (confirming && !reviewDigest(value.review))
  )
    return;
  return {
    groupId: value.groupId,
    revision: value.revision,
    ...(typeof value.review === 'string' ? { review: value.review } : {}),
  };
}

export function parseGroupKeyReply(
  value: unknown,
  request: GroupKeyRequest,
): GroupKeyReply | undefined {
  if (!vaultRecord(value)) return;
  const { status, preview } = value;
  if (status !== 'review') {
    if (
      vaultFields(value, ['status']) &&
      (status === 'busy' ||
        status === 'stale' ||
        status === 'unavailable' ||
        status === 'unsupported' ||
        status === 'no-members' ||
        status === 'too-large' ||
        status === 'incomplete' ||
        status === 'provisioned' ||
        (status === 'issued' && request.review))
    )
      return { status };
    return;
  }
  if (
    request.review ||
    !vaultFields(value, ['status', 'preview']) ||
    !vaultRecord(preview) ||
    !vaultFields(preview, ['groupId', 'revision', 'review', 'members']) ||
    preview.groupId !== request.groupId ||
    preview.revision !== request.revision ||
    !reviewDigest(preview.review)
  )
    return;
  const members = parseCertifiedGroupMembers(preview.members);
  if (!members) return;
  return {
    status,
    preview: {
      groupId: request.groupId,
      revision: request.revision,
      review: preview.review,
      members,
    },
  };
}

export function parseCertifiedGroupMembers(value: unknown): GroupKeyMember[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) return;
  let previous = '';
  const members: GroupKeyMember[] = [];
  for (const row of value) {
    if (
      !vaultRecord(row) ||
      !vaultFields(row, ['id', 'login']) ||
      !vaultID(row.id) ||
      row.id <= previous ||
      typeof row.login !== 'string' ||
      !row.login ||
      row.login.length > 256 ||
      /\p{Cc}/u.test(row.login) ||
      new TextEncoder().encode(row.login).length > 256
    )
      return;
    previous = row.id;
    members.push({ id: row.id, login: row.login });
  }
  return members;
}
