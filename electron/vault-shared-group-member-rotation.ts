import { vaultFields, vaultID, vaultRecord, vaultRevision } from './vault-contract.ts';
import { parseGroupRequest } from './vault-shared-admin-groups.ts';
import {
  parseCertifiedGroupMembers,
  reviewDigest,
  type GroupKeyMember,
} from './vault-shared-group-key.ts';

type RemoveMember = {
  action: 'remove';
  groupId: string;
  jobId: string;
  memberId: string;
  revision: string;
  suspension?: string;
  review?: string;
};
type AddMember = Omit<RemoveMember, 'action' | 'memberId' | 'suspension'> & {
  action: 'add';
  login: string;
};
type ReconcileRotation = Pick<RemoveMember, 'groupId' | 'jobId' | 'review'> & {
  action: 'reconcile';
};
export type MemberRotationRequest =
  | RemoveMember
  | AddMember
  | ReconcileRotation
  | { action: 'resume'; groupId: string; jobId?: string };
type MemberRotationPreview = Omit<RemoveMember, 'action' | 'review'> & {
  review: string;
  remaining: GroupKeyMember[];
  boundaries: number;
};
type MemberAdditionPreview = Omit<AddMember, 'action' | 'login'> & {
  review: string;
  member: GroupKeyMember;
  boundaries: number;
};
type Receipt = { jobId: string; pending: number };
type ReconciliationPreview = Omit<ReconcileRotation, 'action' | 'review'> & {
  targetGroupId: string;
  groupName: string;
  boundaries: number;
  members: GroupKeyMember[];
  review: string;
};
export type MemberRotationStatus =
  | 'unsupported'
  | 'unavailable'
  | 'incomplete'
  | 'rotation-pending'
  | 'busy'
  | 'stale'
  | 'account-unavailable'
  | 'unchanged';
export type MemberRotationReply =
  | { status: 'review'; preview: MemberRotationPreview }
  | { status: 'review-add'; addition: MemberAdditionPreview }
  | { status: 'reconcile-review'; reconciliation: ReconciliationPreview }
  | { status: 'rotated' | 'pending' | 'added' | 'roster-changed'; receipt: Receipt }
  | { status: 'complete'; receipt?: Receipt }
  | { status: MemberRotationStatus | 'reconciled' };
export type MemberRotationPort = (request: MemberRotationRequest) => Promise<MemberRotationReply>;

export function parseMemberRotationRequest(value: unknown): MemberRotationRequest | undefined {
  if (!vaultRecord(value) || !vaultID(value.groupId)) return;
  if (value.action === 'resume') {
    const hasJob = Object.hasOwn(value, 'jobId');
    if (!vaultFields(value, ['action', 'groupId', ...(hasJob ? ['jobId'] : [])])) return;
    if (hasJob && !vaultID(value.jobId)) return;
    return {
      action: value.action,
      groupId: value.groupId,
      ...(typeof value.jobId === 'string' ? { jobId: value.jobId } : {}),
    };
  }
  const action = value.action;
  const reviewed = Object.hasOwn(value, 'review');
  if (action === 'reconcile') {
    if (
      !vaultFields(value, ['action', 'groupId', 'jobId', ...(reviewed ? ['review'] : [])]) ||
      !vaultID(value.jobId) ||
      (reviewed && !reviewDigest(value.review))
    )
      return;
    return {
      action,
      groupId: value.groupId,
      jobId: value.jobId,
      ...(typeof value.review === 'string' ? { review: value.review } : {}),
    };
  }
  if (action !== 'add' && action !== 'remove') return;
  const scoped = action === 'remove' && Object.hasOwn(value, 'suspension');
  if (
    !vaultFields(value, [
      'action',
      'groupId',
      'jobId',
      action === 'add' ? 'login' : 'memberId',
      'revision',
      ...(scoped ? ['suspension'] : []),
      ...(reviewed ? ['review'] : []),
    ]) ||
    !vaultID(value.jobId) ||
    !vaultRevision(value.revision) ||
    value.revision === '9223372036854775807' ||
    (reviewed && !reviewDigest(value.review))
  )
    return;
  const request = {
    groupId: value.groupId,
    jobId: value.jobId,
    revision: value.revision,
    ...(typeof value.review === 'string' ? { review: value.review } : {}),
  };
  if (action === 'remove') {
    if (!vaultID(value.memberId)) return;
    if (scoped)
      return vaultRevision(value.suspension)
        ? { action, ...request, memberId: value.memberId, suspension: value.suspension }
        : undefined;
    return { action, ...request, memberId: value.memberId };
  }
  const addition = parseGroupRequest({
    action: 'add-member',
    groupId: request.groupId,
    revision: request.revision,
    login: value.login,
  });
  if (addition?.action === 'add-member') return { action, ...request, login: addition.login };
}

const boundaryCount = (value: unknown): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 4096;

export function parseMemberRotationReply(
  value: unknown,
  request: MemberRotationRequest,
): MemberRotationReply | undefined {
  if (!vaultRecord(value)) return;
  const { status, preview, receipt, addition, reconciliation } = value;
  if (status === 'reconcile-review') {
    if (
      request.action !== 'reconcile' ||
      request.review ||
      !vaultFields(value, ['status', 'reconciliation']) ||
      !vaultRecord(reconciliation) ||
      !vaultFields(reconciliation, [
        'jobId',
        'groupId',
        'targetGroupId',
        'groupName',
        'boundaries',
        'members',
        'review',
      ]) ||
      reconciliation.jobId !== request.jobId ||
      reconciliation.groupId !== request.groupId ||
      !vaultID(reconciliation.targetGroupId) ||
      !boundaryCount(reconciliation.boundaries) ||
      reconciliation.boundaries === 0 ||
      !reviewDigest(reconciliation.review)
    )
      return;
    const group = parseGroupRequest({
      action: 'rename',
      groupId: reconciliation.targetGroupId,
      revision: '1',
      name: reconciliation.groupName,
    });
    const members =
      Array.isArray(reconciliation.members) && !reconciliation.members.length
        ? []
        : parseCertifiedGroupMembers(reconciliation.members);
    if (group?.action !== 'rename' || !members) return;
    return {
      status,
      reconciliation: {
        jobId: request.jobId,
        groupId: request.groupId,
        targetGroupId: group.groupId,
        groupName: group.name,
        boundaries: reconciliation.boundaries,
        review: reconciliation.review,
        members,
      },
    };
  }
  if (
    status === 'reconciled' &&
    request.action === 'reconcile' &&
    request.review &&
    vaultFields(value, ['status'])
  )
    return { status };
  if (status === 'review-add') {
    if (
      request.action !== 'add' ||
      request.review ||
      !vaultFields(value, ['status', 'addition']) ||
      !vaultRecord(addition) ||
      !vaultFields(addition, ['groupId', 'jobId', 'revision', 'review', 'boundaries', 'member']) ||
      addition.groupId !== request.groupId ||
      addition.jobId !== request.jobId ||
      addition.revision !== request.revision ||
      !reviewDigest(addition.review) ||
      !boundaryCount(addition.boundaries)
    )
      return;
    const member = parseCertifiedGroupMembers([addition.member])?.[0];
    if (!member || member.login !== request.login) return;
    return {
      status,
      addition: {
        groupId: request.groupId,
        jobId: request.jobId,
        revision: request.revision,
        review: addition.review,
        boundaries: addition.boundaries,
        member,
      },
    };
  }
  if (status === 'review') {
    if (
      request.action !== 'remove' ||
      request.review ||
      !vaultFields(value, ['status', 'preview']) ||
      !vaultRecord(preview) ||
      !vaultFields(preview, [
        'groupId',
        'jobId',
        'memberId',
        'revision',
        'review',
        'remaining',
        'boundaries',
        ...(request.suspension === undefined ? [] : ['suspension']),
      ]) ||
      preview.groupId !== request.groupId ||
      preview.jobId !== request.jobId ||
      preview.memberId !== request.memberId ||
      preview.revision !== request.revision ||
      preview.suspension !== request.suspension ||
      !reviewDigest(preview.review) ||
      !boundaryCount(preview.boundaries)
    )
      return;
    const members =
      Array.isArray(preview.remaining) && !preview.remaining.length
        ? []
        : parseCertifiedGroupMembers(preview.remaining);
    if (!members || members.some(({ id }) => id === request.memberId)) return;
    return {
      status,
      preview: {
        groupId: request.groupId,
        jobId: request.jobId,
        memberId: request.memberId,
        revision: request.revision,
        ...(request.suspension === undefined ? {} : { suspension: request.suspension }),
        review: preview.review,
        boundaries: preview.boundaries,
        remaining: members,
      },
    };
  }
  if (
    status === 'complete' &&
    request.action === 'resume' &&
    !request.jobId &&
    vaultFields(value, ['status'])
  )
    return { status };
  if (
    status === 'pending' ||
    status === 'complete' ||
    status === 'rotated' ||
    status === 'added' ||
    status === 'roster-changed'
  ) {
    const expected = status === 'added' ? 'add' : status === 'rotated' ? 'remove' : 'resume';
    if (
      request.action !== expected ||
      !vaultFields(value, ['status', 'receipt']) ||
      !vaultRecord(receipt) ||
      !vaultFields(receipt, ['jobId', 'pending']) ||
      !vaultID(receipt.jobId) ||
      (request.jobId && receipt.jobId !== request.jobId) ||
      !boundaryCount(receipt.pending) ||
      ((status === 'complete' || status === 'added') && receipt.pending !== 0) ||
      ((status === 'pending' || status === 'roster-changed') && receipt.pending === 0)
    )
      return;
    return { status, receipt: { jobId: receipt.jobId, pending: receipt.pending } };
  }
  if (
    vaultFields(value, ['status']) &&
    (status === 'unsupported' ||
      status === 'unavailable' ||
      status === 'incomplete' ||
      status === 'rotation-pending' ||
      status === 'busy' ||
      status === 'stale' ||
      (request.action === 'add' && status === 'account-unavailable') ||
      ((request.action === 'add' || request.action === 'reconcile') && status === 'unchanged'))
  )
    return { status };
}
