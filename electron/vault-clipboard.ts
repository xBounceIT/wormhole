import { vaultRecord, vaultFields, vaultID } from './vault-contract.ts';
import { parseVaultNotesSelection, type VaultNotesSelection } from './vault-notes.ts';
export type VaultClipboardField = 'username' | 'domain' | 'secret';
export type VaultClipboardRequest = VaultNotesSelection & {
  workspaceId: string;
  field: VaultClipboardField;
};
export type VaultClipboardResult = { expiresInSeconds: 20 | 30 };
export function vaultClipboardField(value: unknown): value is VaultClipboardField {
  return value === 'username' || value === 'domain' || value === 'secret';
}
export function parseVaultClipboardRequest(value: unknown): VaultClipboardRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'nodeId', 'rowVersion', 'field']) ||
    !vaultID(value.workspaceId) ||
    !vaultClipboardField(value.field)
  )
    return undefined;
  const selection = parseVaultNotesSelection({
    nodeId: value.nodeId,
    rowVersion: value.rowVersion,
  });
  return selection
    ? { ...selection, workspaceId: value.workspaceId, field: value.field }
    : undefined;
}
export function parseVaultClipboardResult(value: unknown): VaultClipboardResult | undefined {
  return vaultRecord(value) &&
    vaultFields(value, ['expiresInSeconds']) &&
    (value.expiresInSeconds === 20 || value.expiresInSeconds === 30)
    ? { expiresInSeconds: value.expiresInSeconds }
    : undefined;
}
