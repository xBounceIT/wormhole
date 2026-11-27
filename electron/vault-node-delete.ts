import { vaultRecord, vaultFields, vaultID, vaultRevision } from './vault-contract.ts';

export type VaultNodeDeleteRequest = { nodes: { id: string; rowVersion: string }[] };
export type VaultNodeDeleteResult = { deleted: true; deletedCount: string };

export function parseVaultNodeDelete(value: unknown): VaultNodeDeleteRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodes']) ||
    !Array.isArray(value.nodes) ||
    value.nodes.length === 0 ||
    value.nodes.length > 4096
  )
    return undefined;
  const nodes: VaultNodeDeleteRequest['nodes'] = [],
    seen = new Set<string>();
  for (const node of value.nodes) {
    if (
      !vaultRecord(node) ||
      !vaultFields(node, ['id', 'rowVersion']) ||
      !vaultID(node.id) ||
      !vaultRevision(node.rowVersion) ||
      node.rowVersion === '9223372036854775807' ||
      seen.has(node.id)
    )
      return undefined;
    seen.add(node.id);
    nodes.push({ id: node.id, rowVersion: node.rowVersion });
  }
  return { nodes };
}

export function parseVaultNodeDeleteResult(value: unknown): VaultNodeDeleteResult | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['deleted', 'deletedCount']) ||
    value.deleted !== true ||
    !vaultRevision(value.deletedCount)
  )
    return undefined;
  return { deleted: true, deletedCount: value.deletedCount };
}
