import { vaultRecord, vaultFields, vaultID, vaultRevision } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';

export type VaultNotesSelection = { nodeId: string; rowVersion: string };
export type VaultNotesContext = VaultNotesSelection & { workspaceId: string; requestId: string };
export type VaultNotesRequest = VaultNotesContext & { publicKey: string };
export type VaultNotesDisplay = VaultNotesContext & {
  bundle: { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
};
export function parseVaultNotesSelection(value: unknown): VaultNotesSelection | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodeId', 'rowVersion']) ||
    !vaultID(value.nodeId) ||
    !vaultRevision(value.rowVersion)
  )
    return undefined;
  return { nodeId: value.nodeId, rowVersion: value.rowVersion };
}
export function parseVaultNotesContext(value: unknown): VaultNotesContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'requestId', 'nodeId', 'rowVersion']) ||
    !vaultID(value.workspaceId) ||
    !vaultID(value.requestId)
  )
    return undefined;
  const selection = parseVaultNotesSelection({
    nodeId: value.nodeId,
    rowVersion: value.rowVersion,
  });
  return selection
    ? { ...selection, workspaceId: value.workspaceId, requestId: value.requestId }
    : undefined;
}
export function parseVaultNotesRequest(value: unknown): VaultNotesRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'requestId', 'nodeId', 'rowVersion', 'publicKey']) ||
    !enrollmentBytes(value.publicKey, 32)
  )
    return undefined;
  const context = parseVaultNotesContext({
    workspaceId: value.workspaceId,
    requestId: value.requestId,
    nodeId: value.nodeId,
    rowVersion: value.rowVersion,
  });
  return context ? { ...context, publicKey: value.publicKey as string } : undefined;
}
export function notesCiphertext(value: unknown): Uint8Array | undefined {
  if (typeof value !== 'string' || value.length < 24 || value.length > 87404) return undefined;
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  const size = (value.length / 4) * 3 - padding;
  return size >= 16 && size <= 65552 ? enrollmentBytes(value, size) : undefined;
}
export function parseVaultNotesDisplay(
  value: unknown,
  expected: VaultNotesContext,
): VaultNotesDisplay | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'requestId', 'nodeId', 'rowVersion', 'bundle']) ||
    value.workspaceId !== expected.workspaceId ||
    value.requestId !== expected.requestId ||
    value.nodeId !== expected.nodeId ||
    value.rowVersion !== expected.rowVersion ||
    !vaultRecord(value.bundle) ||
    !vaultFields(value.bundle, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.bundle.formatVersion !== 1 ||
    value.bundle.suiteId !== 2 ||
    !enrollmentBytes(value.bundle.enc, 32) ||
    !notesCiphertext(value.bundle.ciphertext)
  )
    return undefined;
  return {
    workspaceId: expected.workspaceId,
    nodeId: expected.nodeId,
    requestId: expected.requestId,
    rowVersion: expected.rowVersion,
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: value.bundle.enc as string,
      ciphertext: value.bundle.ciphertext as string,
    },
  };
}
