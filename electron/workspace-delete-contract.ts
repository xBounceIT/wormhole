export type WorkspaceNodesRequest = { nodeIds: string[] };

const maximumWorkspaceNodeIDs = 1_000;
const maximumWorkspaceNodeIDBytes = 128;
export const workspaceDeleteNodesMaxRequestBytes = 256 * 1024;

function isWorkspaceNodeID(value: unknown): value is string {
  const hasControlCharacter =
    typeof value === 'string' &&
    [...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint < 0x20 || codePoint === 0x7f;
    });
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maximumWorkspaceNodeIDBytes &&
    value.trim() === value &&
    !hasControlCharacter
  );
}

export function parseWorkspaceNodesRequest(value: unknown): WorkspaceNodesRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Workspace connections are invalid.');
  }
  const rawNodeIDs = (value as Record<string, unknown>).nodeIds;
  if (!Array.isArray(rawNodeIDs)) {
    throw new Error('Workspace connections are invalid.');
  }

  // Array.from materializes sparse entries as undefined. Array#every skips holes, which would
  // otherwise let malformed IPC arrays through this boundary before JSON turns them into null.
  const nodeIDs = Array.from(rawNodeIDs);
  if (
    nodeIDs.length === 0 ||
    nodeIDs.length > maximumWorkspaceNodeIDs ||
    !nodeIDs.every(isWorkspaceNodeID)
  ) {
    throw new Error('Workspace connections are invalid.');
  }
  return { nodeIds: [...new Set(nodeIDs)] };
}
