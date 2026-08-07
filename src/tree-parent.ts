export type TreeParentNode = {
  id: string;
  kind: 'folder' | 'connection';
  children?: TreeParentNode[];
};

export function findParentFolderId(
  nodes: readonly TreeParentNode[],
  childId: string,
): string | undefined {
  for (const node of nodes) {
    if (node.kind === 'folder' && node.children?.some((child) => child.id === childId)) {
      return node.id;
    }

    if (node.children) {
      const parentId = findParentFolderId(node.children, childId);
      if (parentId) return parentId;
    }
  }

  return undefined;
}
