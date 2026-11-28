import {
  vaultFields,
  vaultID,
  vaultMetadataText,
  vaultRecord,
  vaultRevision,
} from './vault-contract.ts';
import type { PersonalRootRecoveryFactors } from './vault-account-suspension.ts';

export type NodeCredentialSelection = {
  scope: 'shared' | 'personal' | 'inherit';
  credentialName: string;
  confirmation?: string;
};
export type NodeCredentialRequest = NodeCredentialSelection & { nodeId: string };
export type NodeCredentialReply =
  | {
      status: 'review';
      workspaceId: string;
      review: string;
      nodeName: string;
      credentialId: string;
      protocol: 'ssh' | 'rdp' | 'vnc';
      provider: '' | 'local' | 'bitwarden';
      authenticationRequired: boolean;
    }
  | {
      status:
        | 'stale'
        | 'unavailable'
        | 'busy'
        | 'unsupported'
        | 'unchanged'
        | 'saved'
        | 'authentication-required';
    };
export type NodeCredentialPort = (
  request: NodeCredentialSelection,
  factors?: PersonalRootRecoveryFactors,
) => Promise<NodeCredentialReply>;

const digest = (v: unknown): v is string =>
  typeof v === 'string' && v.length === 64 && /^[0-9a-f]+$/.test(v);
const revision = (v: unknown) => v === '0' || vaultRevision(v);

export function parseNodeCredentialRequest(v: unknown): NodeCredentialRequest | undefined {
  if (
    !vaultRecord(v) ||
    !vaultFields(v, [
      'nodeId',
      'scope',
      'credentialName',
      ...('confirmation' in v ? ['confirmation'] : []),
    ])
  )
    return;
  const { nodeId, scope, credentialName, confirmation } = v;
  if (
    !vaultID(nodeId) ||
    (scope !== 'personal' && scope !== 'shared' && scope !== 'inherit') ||
    typeof credentialName !== 'string' ||
    (scope === 'inherit') !== (credentialName === '') ||
    !vaultMetadataText(credentialName, 1024) ||
    /[\p{Cc}\p{Cs}]/u.test(credentialName) ||
    ('confirmation' in v && !digest(confirmation))
  )
    return;
  return {
    nodeId,
    scope,
    credentialName,
    ...(typeof confirmation === 'string' ? { confirmation } : {}),
  };
}

export function parseNodeCredentialReply(
  v: unknown,
  r: NodeCredentialRequest,
): NodeCredentialReply | undefined {
  if (!vaultRecord(v)) return;
  const { status } = v;
  if (status !== 'review') {
    if (
      vaultFields(v, ['status']) &&
      (status === 'busy' ||
        status === 'stale' ||
        status === 'unavailable' ||
        status === 'unsupported' ||
        status === 'unchanged' ||
        (!!r.confirmation && (status === 'saved' || status === 'authentication-required')))
    )
      return { status };
    return;
  }
  const c = v.choice;
  if (
    r.confirmation ||
    !vaultFields(v, [
      'status',
      'workspaceId',
      'choice',
      'review',
      ...('authenticationRequired' in v ? ['authenticationRequired'] : []),
    ]) ||
    !vaultID(v.workspaceId) ||
    !digest(v.review) ||
    ('authenticationRequired' in v && v.authenticationRequired !== true) ||
    !vaultRecord(c) ||
    !vaultFields(c, [
      'nodeId',
      'nodeName',
      'userId',
      'protocol',
      'scope',
      'credentialName',
      'credentialId',
      'provider',
      'epoch',
      'changeSeq',
      'overrideRevision',
    ]) ||
    c.nodeId !== r.nodeId ||
    c.scope !== r.scope ||
    c.credentialName !== r.credentialName ||
    !vaultMetadataText(c.nodeName, 1024, true) ||
    !vaultID(c.userId) ||
    (c.protocol !== 'ssh' && c.protocol !== 'rdp' && c.protocol !== 'vnc') ||
    !vaultRevision(c.epoch) ||
    !revision(c.changeSeq) ||
    !revision(c.overrideRevision) ||
    c.overrideRevision === '9223372036854775807' ||
    typeof c.credentialId !== 'string' ||
    (r.scope === 'inherit' ? c.credentialId !== '' : !vaultID(c.credentialId))
  )
    return;
  const provider = c.provider;
  if (
    (provider !== '' && provider !== 'local' && provider !== 'bitwarden') ||
    (r.scope === 'inherit') !== (provider === '') ||
    (provider === 'bitwarden' && r.scope !== 'personal')
  )
    return;
  return {
    status,
    workspaceId: v.workspaceId,
    review: v.review,
    nodeName: c.nodeName,
    credentialId: c.credentialId,
    protocol: c.protocol,
    provider,
    authenticationRequired: v.authenticationRequired === true,
  };
}
