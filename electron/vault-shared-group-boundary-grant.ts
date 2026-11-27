import { vaultFields, vaultID, vaultRecord, vaultRevision } from './vault-contract.ts';
import {
  parseCertifiedGroupMembers,
  reviewDigest,
  type GroupKeyMember,
} from './vault-shared-group-key.ts';

export type GroupBoundaryMask = 1 | 2 | 3;
export type GroupBoundaryGrantRequest = {
  nodeId: string;
  nodeRevision: string;
  boundaryId: string;
  groupId: string;
  groupRevision: string;
  mask: 0 | GroupBoundaryMask;
  review?: string;
};
export type GroupBoundaryGrantStatus =
  | 'unavailable'
  | 'unsupported'
  | 'stale'
  | 'busy'
  | 'key-required'
  | 'rotation-required'
  | 'changed'
  | 'unchanged';
export type GroupBoundaryGrantReply =
  | {
      status: 'review';
      preview: GroupBoundaryGrantRequest & {
        review: string;
        previousMask: 0 | GroupBoundaryMask;
        members: GroupKeyMember[];
      };
    }
  | { status: GroupBoundaryGrantStatus };
export type GroupBoundaryGrantPort = (
  request: GroupBoundaryGrantRequest,
) => Promise<GroupBoundaryGrantReply>;

const selection = [
  'nodeId',
  'nodeRevision',
  'boundaryId',
  'groupId',
  'groupRevision',
  'mask',
] as const;

export function parseGroupBoundaryGrantRequest(
  value: unknown,
  rotation = false,
): GroupBoundaryGrantRequest | undefined {
  if (!vaultRecord(value)) return;
  const reviewed = Object.hasOwn(value, 'review');
  if (
    !vaultFields(value, [...selection, ...(reviewed ? ['review'] : [])]) ||
    !vaultID(value.nodeId) ||
    !vaultID(value.boundaryId) ||
    !vaultID(value.groupId) ||
    !vaultRevision(value.nodeRevision) ||
    !vaultRevision(value.groupRevision) ||
    (value.mask !== 1 && value.mask !== 2 && value.mask !== 3 && value.mask !== 0) ||
    (rotation ? value.mask === 3 : value.mask === 0) ||
    (reviewed && !reviewDigest(value.review))
  )
    return;
  return {
    nodeId: value.nodeId,
    nodeRevision: value.nodeRevision,
    boundaryId: value.boundaryId,
    groupId: value.groupId,
    groupRevision: value.groupRevision,
    mask: value.mask,
    ...(typeof value.review === 'string' ? { review: value.review } : {}),
  };
}

export function parseGroupBoundaryGrantReply(
  value: unknown,
  request: GroupBoundaryGrantRequest,
  rotation = false,
): GroupBoundaryGrantReply | undefined {
  if (!vaultRecord(value)) return;
  const { status, preview } = value;
  if (status !== 'review') {
    if (
      vaultFields(value, ['status']) &&
      (status === 'unavailable' ||
        status === 'unsupported' ||
        status === 'stale' ||
        status === 'busy' ||
        status === 'key-required' ||
        status === 'rotation-required' ||
        status === 'unchanged' ||
        (status === 'changed' && request.review))
    )
      return { status };
    return;
  }
  if (
    request.review ||
    !vaultFields(value, ['status', 'preview']) ||
    !vaultRecord(preview) ||
    !vaultFields(preview, [
      ...selection,
      'review',
      'previousMask',
      ...(rotation ? [] : ['members']),
    ]) ||
    selection.some((field) => preview[field] !== request[field]) ||
    !reviewDigest(preview.review)
  )
    return;
  const previous = preview.previousMask;
  const members = rotation ? [] : parseCertifiedGroupMembers(preview.members);
  if (
    (previous !== 0 && previous !== 1 && previous !== 2 && previous !== 3) ||
    (previous & request.mask) !== (rotation ? request.mask : previous) ||
    previous === request.mask ||
    !members
  )
    return;
  return {
    status,
    preview: { ...request, review: preview.review, previousMask: previous, members },
  };
}
