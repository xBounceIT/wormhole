import { vaultRecord, vaultFields, vaultRevision } from './vault-contract.ts';
import { parseVaultNodeDelete } from './vault-node-delete.ts';

export type VaultNodeMoveRequest = {
  nodes: { id: string; rowVersion: string }[];
  target: { id: string; rowVersion: string };
  placement: 'inside' | 'before' | 'after';
};
export type VaultNodeMoveResult = { moved: true; updatedCount: string };

export function parseVaultNodeMove(value: unknown): VaultNodeMoveRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodes', 'target', 'placement']) ||
    !Array.isArray(value.nodes) ||
    value.nodes.length === 0 ||
    value.nodes.length > 1000 ||
    (value.placement !== 'inside' && value.placement !== 'before' && value.placement !== 'after')
  )
    return undefined;
  const revisions = parseVaultNodeDelete({ nodes: [...value.nodes, value.target] });
  if (!revisions) return undefined;
  return {
    nodes: revisions.nodes.slice(0, -1),
    target: revisions.nodes.at(-1)!,
    placement: value.placement,
  };
}

export function parseVaultNodeMoveResult(value: unknown): VaultNodeMoveResult | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['moved', 'updatedCount']) ||
    value.moved !== true ||
    !vaultRevision(value.updatedCount, true)
  )
    return undefined;
  return { moved: true, updatedCount: value.updatedCount };
}
