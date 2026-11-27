import { vaultFields, vaultID, vaultRecord, vaultRevision } from './vault-contract.ts';
import type { SharedCatalogPage, SharedCatalogRequest } from './vault-shared-catalog.ts';
import type { GroupBoundaryGrantPort } from './vault-shared-group-boundary-grant.ts';

export type GrantKind = 'account' | 'group';
type Target = { nodeId: string; nodeRevision: string; kind: GrantKind };
type Snapshot = { epoch: string; changeSeq: string };
type GrantList = Target &
  (Partial<Record<keyof Snapshot | 'after', never>> | (Snapshot & { after: string }));
type GrantChange = Target &
  Snapshot & { grantRevision: string; mask: number } & ({ subjectId: string } | { login: string });
export type NodeGrantRequest = GrantList | GrantChange;
export type DirectNodeGrant = { subjectId: string; revision: string; label: string; mask: number };
export type NodeGrantPage = Snapshot & { grants: DirectNodeGrant[]; after?: string };
export type NodeGrantStatus =
  | 'unavailable'
  | 'unsupported'
  | 'busy'
  | 'stale'
  | 'changed'
  | 'unchanged'
  | 'subject-unavailable'
  | 'signed-grant'
  | 'cannot-delegate';
export type NodeGrantReply = { status: 'ready'; page: NodeGrantPage } | { status: NodeGrantStatus };
export type NodeGrantAdministration = {
  catalog(request: SharedCatalogRequest): Promise<SharedCatalogPage>;
  grant(request: NodeGrantRequest): Promise<NodeGrantReply>;
  boundary?: GroupBoundaryGrantPort;
  rotation?: GroupBoundaryGrantPort;
};

export const workspacePermissionLabels = ['View', 'Use', 'Write', 'Reveal', 'Manage'] as const;

const sequence = (value: unknown): value is string =>
  vaultRevision(value, true) && !value.startsWith('-');
const mask = (value: unknown, min: number): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= min && value <= 31;
const label = (value: unknown, max: number): value is string =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.length <= max &&
  !/\p{Cc}/u.test(value) &&
  new TextEncoder().encode(value).length <= max;

export function parseNodeGrantRequest(value: unknown): NodeGrantRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultID(value.nodeId) ||
    !vaultRevision(value.nodeRevision) ||
    (value.kind !== 'account' && value.kind !== 'group')
  )
    return;
  const base = ['nodeId', 'nodeRevision', 'kind'];
  if (!Object.hasOwn(value, 'mask')) {
    const hasCursor = Object.hasOwn(value, 'after');
    if (
      !vaultFields(value, hasCursor ? [...base, 'after', 'epoch', 'changeSeq'] : base) ||
      (hasCursor &&
        (!vaultID(value.after) || !vaultRevision(value.epoch) || !sequence(value.changeSeq)))
    )
      return;
  } else {
    const newAccount = Object.hasOwn(value, 'login');
    if (
      !vaultFields(value, [
        ...base,
        'mask',
        'epoch',
        'changeSeq',
        'grantRevision',
        newAccount ? 'login' : 'subjectId',
      ]) ||
      !vaultRevision(value.epoch) ||
      !sequence(value.changeSeq) ||
      !sequence(value.grantRevision) ||
      !mask(value.mask, value.grantRevision === '0' ? 1 : 0) ||
      (newAccount
        ? value.kind !== 'account' || value.grantRevision !== '0' || !label(value.login, 256)
        : !vaultID(value.subjectId))
    )
      return;
  }
  return value as NodeGrantRequest;
}

export function parseNodeGrantReply(
  value: unknown,
  request: NodeGrantRequest,
): NodeGrantReply | undefined {
  if (!vaultRecord(value)) return;
  const { status, page } = value;
  if (status !== 'ready') {
    if (!vaultFields(value, ['status'])) return;
    if (
      status === 'busy' ||
      status === 'unavailable' ||
      status === 'unsupported' ||
      status === 'stale' ||
      ('mask' in request &&
        (status === 'changed' ||
          status === 'unchanged' ||
          status === 'subject-unavailable' ||
          status === 'signed-grant' ||
          status === 'cannot-delegate'))
    )
      return { status };
    return;
  }
  if (
    'mask' in request ||
    !vaultFields(value, ['status', 'page']) ||
    !vaultRecord(page) ||
    !vaultFields(page, [
      'epoch',
      'changeSeq',
      'grants',
      ...(Object.hasOwn(page, 'after') ? ['after'] : []),
    ]) ||
    !vaultRevision(page.epoch) ||
    !sequence(page.changeSeq) ||
    !Array.isArray(page.grants) ||
    page.grants.length > 25 ||
    (request.after && (request.epoch !== page.epoch || request.changeSeq !== page.changeSeq))
  )
    return;
  let last = request.after ?? '';
  const grants: DirectNodeGrant[] = [];
  for (const row of page.grants) {
    if (
      !vaultRecord(row) ||
      !vaultFields(row, ['subjectId', 'revision', 'label', 'mask']) ||
      !vaultID(row.subjectId) ||
      row.subjectId <= last ||
      !vaultRevision(row.revision) ||
      !label(row.label, request.kind === 'group' ? 1024 : 256) ||
      !mask(row.mask, 1)
    )
      return;
    last = row.subjectId;
    grants.push({
      subjectId: row.subjectId,
      revision: row.revision,
      label: row.label,
      mask: row.mask,
    });
  }
  if (Object.hasOwn(page, 'after') && (grants.length !== 25 || page.after !== last)) return;
  return {
    status,
    page: {
      epoch: page.epoch,
      changeSeq: page.changeSeq,
      grants,
      ...(page.after === last ? { after: last } : {}),
    },
  };
}
