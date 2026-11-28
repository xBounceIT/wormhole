import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { parseSftpEditEvent, type SftpEditView } from './sftp-contract.ts';

export type VaultRecoveryRequest =
  | { nodeId: string; operation: 'list'; after?: string }
  | { nodeId: string; operation: 'reveal'; editId: string }
  | { nodeId: string; operation: 'discard'; editId: string; decision: 'discard' };
export type VaultRecoveryRecords = { edits: SftpEditView[]; after: string; busy: boolean };
export type VaultRecoveryRecordsReply = VaultRecoveryRecords & { revealPath?: string };

export function parseVaultRecoveryRequest(value: unknown): VaultRecoveryRequest | undefined {
  if (!vaultRecord(value) || !vaultID(value.nodeId)) return undefined;
  if (value.operation === 'list') {
    if (
      !vaultFields(value, [
        'nodeId',
        'operation',
        ...(Object.hasOwn(value, 'after') ? ['after'] : []),
      ]) ||
      (value.after !== undefined && value.after !== '' && !vaultID(value.after))
    )
      return undefined;
  } else if (value.operation === 'reveal' || value.operation === 'discard') {
    if (
      !vaultFields(value, [
        'nodeId',
        'operation',
        'editId',
        ...(value.operation === 'discard' ? ['decision'] : []),
      ]) ||
      !vaultID(value.editId) ||
      (value.operation === 'discard' && value.decision !== 'discard')
    )
      return undefined;
  } else return undefined;
  return { ...value } as VaultRecoveryRequest;
}

export function parseVaultRecoveryRecords(
  value: unknown,
  q: VaultRecoveryRequest,
  revealPath?: string,
): VaultRecoveryRecordsReply | undefined {
  if (
    !vaultRecord(value) ||
    typeof value.busy !== 'boolean' ||
    typeof value.after !== 'string' ||
    !Array.isArray(value.edits) ||
    value.edits.length > 32
  )
    return undefined;
  const reveal = q.operation === 'reveal' && !value.busy;
  if (
    !vaultFields(value, ['edits', 'after', 'busy', ...(reveal ? ['revealReady'] : [])]) ||
    (reveal && (value.revealReady !== true || !revealPath))
  )
    return undefined;
  const parsed = parseSftpEditEvent({
    type: 'sftp.edit',
    session_id: 'sftp-recovery',
    edits: value.edits,
  });
  if (
    !parsed ||
    parsed.edits.some(
      (e, i, items) =>
        !vaultRecord(e) ||
        !vaultFields(e, [
          'id',
          'sessionId',
          'nodeId',
          'name',
          'remotePath',
          'editor',
          'state',
          'pending',
          'recovered',
          ...(Object.hasOwn(e, 'error') ? ['error'] : []),
          ...(Object.hasOwn(e, 'uploadedAt') ? ['uploadedAt'] : []),
        ]) ||
        !vaultID(e.id) ||
        e.nodeId !== q.nodeId ||
        !e.recovered ||
        e.state !== 'Recovered' ||
        e.id <= (i ? items[i - 1].id : q.operation === 'list' ? (q.after ?? '') : ''),
    ) ||
    (value.busy && (parsed.edits.length > 0 || value.after !== '')) ||
    (q.operation !== 'list' && (parsed.edits.length > 0 || value.after !== '')) ||
    (value.after !== '' && value.after !== parsed.edits.at(-1)?.id)
  )
    return undefined;
  return {
    edits: parsed.edits.map((e) => ({ ...e })),
    after: value.after,
    busy: value.busy,
    ...(reveal ? { revealPath } : {}),
  };
}

export type VaultRecoveryScopes = { nodeIds: string[]; after: string };

export function parseVaultRecoveryScopes(
  value: unknown,
  cursor = '',
): VaultRecoveryScopes | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodeIds', 'after']) ||
    !Array.isArray(value.nodeIds) ||
    value.nodeIds.length > 64 ||
    !value.nodeIds.every(
      (id, index, ids) => vaultID(id) && id > (index ? ids[index - 1] : cursor),
    ) ||
    typeof value.after !== 'string' ||
    (value.after !== '' && (value.nodeIds.length !== 64 || value.after !== value.nodeIds.at(-1)))
  )
    return undefined;
  return { nodeIds: [...value.nodeIds], after: value.after };
}
