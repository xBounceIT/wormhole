import {
  parseVaultNodeDelete,
  type VaultNodeDeleteRequest,
} from '../electron/vault-node-delete.ts';

type SelectedNode = { id: string; rowVersion?: string; children?: SelectedNode[] };

// Keep the revisions from the deletion confirmation, not a later refresh that
// the user has not reviewed. No metadata lookup may silently renew this intent.
export function vaultDeleteSelection(
  selected: readonly SelectedNode[],
  ids: readonly string[],
): VaultNodeDeleteRequest {
  const versions = new Map<string, string | undefined>();
  const stack = [...selected];
  while (stack.length) {
    const node = stack.pop()!;
    if (versions.has(node.id) || versions.size >= 50_000) throw Error('Invalid vault selection.');
    versions.set(node.id, node.rowVersion);
    if (node.children) stack.push(...node.children);
  }
  const request = parseVaultNodeDelete({
    nodes: ids.map((id) => ({ id, rowVersion: versions.get(id) })),
  });
  if (!request)
    throw Error('The selected vault nodes changed. Refresh the workspace and select them again.');
  return request;
}
