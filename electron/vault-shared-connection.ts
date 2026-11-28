import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';

export type SharedConnectionContextRequest = { nodeId: string };
export type SharedConnectionContext = { nodeId: string; protocol: number };
export function parseSharedConnectionContextRequest(
  value: unknown,
): SharedConnectionContextRequest | undefined {
  if (!vaultRecord(value) || !vaultFields(value, ['nodeId']) || !vaultID(value.nodeId))
    return undefined;
  return { nodeId: value.nodeId };
}
export function parseSharedConnectionContext(
  value: unknown,
  request: SharedConnectionContextRequest,
): SharedConnectionContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodeId', 'protocol']) ||
    value.nodeId !== request.nodeId ||
    ![0, 1, 3, 4, 5, 6, 7].includes(value.protocol as number)
  )
    return undefined;
  return { nodeId: request.nodeId, protocol: value.protocol as number };
}
