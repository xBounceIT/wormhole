import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { parseVaultQuickTarget, type VaultQuickTarget } from './vault-quick-target.ts';

export type VaultWebOpen = { sessionId: string } & (
  | { nodeId: string; quickTarget?: never }
  | { quickTarget: VaultQuickTarget; nodeId?: never }
);
export function parseVaultWebOpen(value: unknown): VaultWebOpen | undefined {
  if (
    !vaultRecord(value) ||
    !vaultID(value.sessionId) ||
    !vaultFields(value, [
      'sessionId',
      ...(value.quickTarget !== undefined ? ['quickTarget'] : ['nodeId']),
    ])
  )
    return undefined;
  if (value.quickTarget !== undefined) {
    const quickTarget = parseVaultQuickTarget(value.quickTarget);
    return quickTarget && (quickTarget.protocol === 'http' || quickTarget.protocol === 'https')
      ? { sessionId: value.sessionId, quickTarget }
      : undefined;
  }
  return vaultID(value.nodeId) ? { sessionId: value.sessionId, nodeId: value.nodeId } : undefined;
}
export type VaultWebRequest = VaultWebOpen & { attempt: number };
export function parseVaultWebRequest(value: unknown): VaultWebRequest | undefined {
  if (!vaultRecord(value) || !Number.isSafeInteger(value.attempt) || (value.attempt as number) < 1)
    return undefined;
  const { attempt, ...target } = value;
  const input = parseVaultWebOpen(target);
  return input ? { ...input, attempt: attempt as number } : undefined;
}
