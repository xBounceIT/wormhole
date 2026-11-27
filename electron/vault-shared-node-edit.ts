import {
  vaultFields,
  vaultID,
  vaultMetadataText,
  vaultRecord,
  vaultRevision,
} from './vault-contract.ts';

export const sharedEditFields = {
  name: { label: 'Name', type: 'name', max: 1024 },
  protocol: {
    label: 'Protocol',
    type: 'choice',
    options: { 0: 'SSH', 1: 'RDP', 3: 'HTTP', 4: 'HTTPS', 5: 'Serial', 6: 'VNC', 7: 'SFTP' },
  },
  host: { label: 'Host', type: 'text', max: 16384 },
  port: { label: 'Port', type: 'port' },
  username: { label: 'Username', type: 'text', max: 2048 },
  credentialMode: {
    label: 'Credential mode',
    type: 'choice',
    options: {
      0: 'Inherit credential',
      1: 'No credential',
      2: 'Saved credential',
      3: 'Credential slot',
    },
  },
  credentialId: { label: 'Saved credential ID', type: 'id' },
  credentialSlotId: { label: 'Credential slot ID', type: 'id' },
  tunnelEnabled: { label: 'Use tunnel', type: 'boolean' },
  tunnelConfigId: { label: 'Tunnel ID', type: 'id' },
  httpPath: { label: 'HTTP path', type: 'text', max: 16384 },
  httpIgnoreCertErrors: { label: 'Ignore HTTP certificate errors', type: 'boolean' },
  rdpDomain: { label: 'RDP domain', type: 'text', max: 2048 },
  rdpGatewayUsageMethod: {
    label: 'RDP gateway method',
    type: 'choice',
    options: {
      0: 'None',
      1: 'Always use this gateway',
      2: 'Detect automatically',
      3: 'System default',
    },
  },
  rdpGatewayHostname: { label: 'RDP gateway host', type: 'text', max: 4096 },
  rdpGatewayCredentialId: { label: 'RDP gateway credential ID', type: 'id' },
  rdpGatewayUseSameCreds: { label: 'Reuse the RDP account at the gateway', type: 'boolean' },
  rdpGatewayBypassLocal: { label: 'Bypass the RDP gateway for local addresses', type: 'boolean' },
} as const;
export type SharedEditKey = keyof typeof sharedEditFields;
export type SharedEditValue = string | number | boolean | null;
export type SharedEditValues = Record<SharedEditKey, SharedEditValue>;
export type SharedMoveParent = { id: string; revision: string } | null;
export type SharedNodeChanges = Partial<SharedEditValues> | { parent: SharedMoveParent };
export type SharedNodeEditRequest = { nodeId: string; revision: string } & (
  | { changes?: undefined }
  | { workspaceId: string; epoch: string; changeSeq: string; changes: SharedNodeChanges }
);
export type SharedNodeEditReply =
  | { status: 'unavailable' | 'authentication-required' }
  | {
      status: 'ready';
      nodeId: string;
      revision: string;
      workspaceId: string;
      epoch: string;
      changeSeq: string;
      fields: SharedEditValues;
      canMove?: true;
    }
  | { status: 'saved'; nodeId: string; revision: string };

function validValues(input: unknown, complete: true): input is SharedEditValues;
function validValues(input: unknown, complete: false): input is Partial<SharedEditValues>;
function validValues(input: unknown, complete: boolean): boolean {
  if (!vaultRecord(input)) return false;
  const keys = Object.keys(input);
  if (!keys.length || (complete && keys.length !== Object.keys(sharedEditFields).length))
    return false;
  return keys.every((key) => {
    if (!Object.hasOwn(sharedEditFields, key)) return false;
    const f = sharedEditFields[key as SharedEditKey],
      v = input[key];
    if (v === null) return f.type !== 'name';
    switch (f.type) {
      case 'name':
        return vaultMetadataText(v, f.max, true) && [...v].length <= 256 && !/\p{Cc}/u.test(v);
      case 'text':
        return vaultMetadataText(v, f.max) && (key === 'httpPath' || !/[\r\n]/.test(v));
      case 'id':
        return vaultID(v);
      case 'boolean':
        return typeof v === 'boolean';
      case 'choice':
        return typeof v === 'number' && Number.isInteger(v) && Object.hasOwn(f.options, v);
      case 'port':
        return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 65535;
    }
  });
}
export function parseSharedNodeEditRequest(v: unknown): SharedNodeEditRequest | undefined {
  if (!vaultRecord(v) || !vaultID(v.nodeId) || !vaultRevision(v.revision)) return;
  if (!('changes' in v))
    return vaultFields(v, ['nodeId', 'revision'])
      ? { nodeId: v.nodeId, revision: v.revision }
      : undefined;
  if (
    !vaultFields(v, ['nodeId', 'revision', 'workspaceId', 'epoch', 'changeSeq', 'changes']) ||
    v.revision === '9223372036854775807' ||
    !vaultID(v.workspaceId) ||
    !vaultRevision(v.epoch) ||
    !vaultRevision(v.changeSeq, true) ||
    v.changeSeq.startsWith('-')
  )
    return;
  let changes: SharedNodeChanges;
  if (vaultRecord(v.changes) && vaultFields(v.changes, ['parent'])) {
    const parent = v.changes.parent;
    if (parent === null) changes = { parent: null };
    else if (
      vaultRecord(parent) &&
      vaultFields(parent, ['id', 'revision']) &&
      vaultID(parent.id) &&
      parent.id !== v.nodeId &&
      vaultRevision(parent.revision)
    )
      changes = { parent: { id: parent.id, revision: parent.revision } };
    else return;
  } else if (validValues(v.changes, false)) changes = { ...v.changes };
  else return;
  return {
    nodeId: v.nodeId,
    revision: v.revision,
    workspaceId: v.workspaceId,
    epoch: v.epoch,
    changeSeq: v.changeSeq,
    changes,
  };
}
export function parseSharedNodeEditReply(
  v: unknown,
  q: SharedNodeEditRequest,
): SharedNodeEditReply | undefined {
  if (!vaultRecord(v)) return;
  if (v.status === 'unavailable' || (v.status === 'authentication-required' && q.changes)) {
    return vaultFields(v, ['status']) ? { status: v.status } : undefined;
  }
  if (v.nodeId !== q.nodeId || !vaultRevision(v.revision)) return;
  if (
    v.status === 'saved' &&
    q.changes &&
    vaultFields(v, ['status', 'nodeId', 'revision']) &&
    BigInt(v.revision) === BigInt(q.revision) + 1n
  )
    return { status: 'saved', nodeId: q.nodeId, revision: v.revision };
  if (
    v.status === 'ready' &&
    !q.changes &&
    v.revision === q.revision &&
    vaultFields(v, [
      'status',
      'nodeId',
      'revision',
      'workspaceId',
      'epoch',
      'changeSeq',
      'fields',
      ...('canMove' in v ? ['canMove'] : []),
    ]) &&
    (!('canMove' in v) || v.canMove === true) &&
    vaultID(v.workspaceId) &&
    vaultRevision(v.epoch) &&
    vaultRevision(v.changeSeq, true) &&
    !v.changeSeq.startsWith('-') &&
    validValues(v.fields, true)
  )
    return {
      status: 'ready',
      nodeId: q.nodeId,
      revision: v.revision,
      workspaceId: v.workspaceId,
      epoch: v.epoch,
      changeSeq: v.changeSeq,
      fields: { ...v.fields },
      ...(v.canMove === true ? { canMove: true } : {}),
    };
}
