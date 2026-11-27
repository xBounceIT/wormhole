import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';

type AccessAction = 'disable-account' | 'enable-account' | 'revoke-device';
export type WorkspaceAccessRequest = {
  action: AccessAction;
  targetId: string;
  revision?: string;
};
type AccessReview = Required<WorkspaceAccessRequest> & {
  login: string;
  name: string;
  currentDevice: boolean;
};
export type WorkspaceAccessReply =
  | { status: 'review'; review: AccessReview }
  | { status: 'changed'; currentDevice?: true }
  | {
      status:
        | 'unchanged'
        | 'stale'
        | 'busy'
        | 'unavailable'
        | 'unsupported'
        | 'personal-recovery-required';
    };
export type WorkspaceAccessPort = (
  request: WorkspaceAccessRequest,
) => Promise<WorkspaceAccessReply>;

const revisionID = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^[1-9][0-9]{0,18}$/.test(value) &&
  (value.length < 19 || value <= '9223372036854775807');

const text = (value: unknown, max: number): value is string =>
  typeof value === 'string' &&
  value.length <= max &&
  new TextEncoder().encode(value).length <= max &&
  !/\p{Cc}/u.test(value);

export function parseWorkspaceAccessRequest(value: unknown): WorkspaceAccessRequest | undefined {
  if (!vaultRecord(value)) return;
  const { action, targetId, revision } = value;
  if (
    !vaultID(targetId) ||
    (action !== 'disable-account' && action !== 'enable-account' && action !== 'revoke-device')
  )
    return;
  if (!Object.hasOwn(value, 'revision'))
    return vaultFields(value, ['action', 'targetId']) ? { action, targetId } : undefined;
  if (vaultFields(value, ['action', 'targetId', 'revision']) && revisionID(revision))
    return { action, targetId, revision };
}

export function parseWorkspaceAccessReply(
  value: unknown,
  request: WorkspaceAccessRequest,
): WorkspaceAccessReply | undefined {
  if (!vaultRecord(value)) return;
  const { status } = value;
  switch (status) {
    case 'changed':
      if (request.revision === undefined) return;
      if (
        request.action === 'revoke-device' &&
        value.currentDevice === true &&
        vaultFields(value, ['status', 'currentDevice'])
      )
        return { status, currentDevice: true };
      return vaultFields(value, ['status']) ? { status } : undefined;
    case 'unchanged':
    case 'stale':
    case 'busy':
    case 'unavailable':
    case 'unsupported':
      return vaultFields(value, ['status']) ? { status } : undefined;
    case 'personal-recovery-required':
      return request.action === 'enable-account' && vaultFields(value, ['status'])
        ? { status }
        : undefined;
    case 'review': {
      const review = value.review;
      if (
        request.revision !== undefined ||
        !vaultFields(value, ['status', 'review']) ||
        !vaultRecord(review) ||
        !vaultFields(review, [
          'action',
          'targetId',
          'revision',
          'login',
          'name',
          'currentDevice',
        ]) ||
        review.action !== request.action ||
        review.targetId !== request.targetId ||
        !revisionID(review.revision) ||
        !text(review.login, 256) ||
        !review.login ||
        !text(review.name, 4096) ||
        typeof review.currentDevice !== 'boolean' ||
        (review.currentDevice && request.action !== 'revoke-device')
      )
        return;
      return {
        status,
        review: {
          action: request.action,
          targetId: request.targetId,
          revision: review.revision,
          login: review.login,
          name: review.name,
          currentDevice: review.currentDevice,
        },
      };
    }
  }
}
