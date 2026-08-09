export type ConnectionTreeShortcutNode = {
  id: string;
  kind: 'folder' | 'connection';
  children?: readonly ConnectionTreeShortcutNode[];
};

export type ConnectionTreeShortcutEvent = {
  key: string;
  ctrlKey: boolean;
  metaKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  isComposing?: boolean;
  repeat?: boolean;
  getModifierState?(keyArg: string): boolean;
};

export type ConnectionTreeShortcutContext = {
  unlocked: boolean;
  dialogOpen: boolean;
  editableTarget: boolean;
  portaledWidgetOpen: boolean;
  withinTree: boolean;
  deleteBusy: boolean;
  tree: readonly ConnectionTreeShortcutNode[];
  visibleTree: readonly ConnectionTreeShortcutNode[];
  selectedNodeId: string;
  selectedNodeIds: readonly string[];
};

export type ConnectionTreeShortcutAction =
  | { kind: 'quick-connect' }
  | { kind: 'new-folder'; parentFolderId: null }
  | { kind: 'new-connection'; parentFolderId: null }
  | { kind: 'edit'; nodeId: string }
  | { kind: 'delete'; nodeIds: string[] }
  | { kind: 'open'; nodeId: string };

export function isEditableConnectionTreeShortcutTarget(target: {
  tagName?: string;
  isContentEditable?: boolean;
}): boolean {
  const tagName = target.tagName?.toLowerCase();
  return (
    tagName === 'input' ||
    tagName === 'textarea' ||
    tagName === 'select' ||
    target.isContentEditable === true
  );
}

function collectNodeIds(
  nodes: readonly ConnectionTreeShortcutNode[],
  result = new Set<string>(),
): Set<string> {
  for (const node of nodes) {
    result.add(node.id);
    if (node.children) collectNodeIds(node.children, result);
  }
  return result;
}

function findNode(
  nodes: readonly ConnectionTreeShortcutNode[],
  nodeId: string,
): ConnectionTreeShortcutNode | undefined {
  for (const node of nodes) {
    if (node.id === nodeId) return node;
    const child = node.children ? findNode(node.children, nodeId) : undefined;
    if (child) return child;
  }
  return undefined;
}

export function canonicalizeConnectionTreeNodeIds(
  tree: readonly ConnectionTreeShortcutNode[],
  candidateIds: readonly string[],
): string[] {
  const candidates = new Set(candidateIds);
  const result: string[] = [];

  const visit = (nodes: readonly ConnectionTreeShortcutNode[], ancestorSelected: boolean) => {
    for (const node of nodes) {
      const selected = candidates.has(node.id);
      if (selected && !ancestorSelected) result.push(node.id);
      if (node.children) visit(node.children, ancestorSelected || selected);
    }
  };

  visit(tree, false);
  return result;
}

export function resolveVisibleConnectionTreeSelection(
  visibleTree: readonly ConnectionTreeShortcutNode[],
  selectedNodeId: string,
  selectedNodeIds: readonly string[],
): string[] {
  const visibleIds = collectNodeIds(visibleTree);
  const selectedIds = [...new Set(selectedNodeIds)].filter((id) => visibleIds.has(id));
  if (selectedIds.length > 0) return selectedIds;
  return selectedNodeId && visibleIds.has(selectedNodeId) ? [selectedNodeId] : [];
}

function isUnmodified(event: ConnectionTreeShortcutEvent): boolean {
  return !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey;
}

function usesPrimaryModifier(event: ConnectionTreeShortcutEvent): boolean {
  return (
    (event.ctrlKey || event.metaKey) &&
    !(event.ctrlKey && event.metaKey) &&
    !event.altKey &&
    event.getModifierState?.('AltGraph') !== true
  );
}

export function resolveConnectionTreeShortcut(
  event: ConnectionTreeShortcutEvent,
  context: ConnectionTreeShortcutContext,
): ConnectionTreeShortcutAction | null {
  if (
    event.isComposing ||
    event.repeat ||
    !context.unlocked ||
    context.dialogOpen ||
    context.editableTarget ||
    context.portaledWidgetOpen
  ) {
    return null;
  }

  const key = event.key.toLowerCase();
  if (usesPrimaryModifier(event) && key === 'k' && !event.shiftKey) {
    return { kind: 'quick-connect' };
  }
  if (usesPrimaryModifier(event) && key === 'n') {
    return event.shiftKey
      ? { kind: 'new-folder', parentFolderId: null }
      : { kind: 'new-connection', parentFolderId: null };
  }
  if (!isUnmodified(event) || !context.withinTree) return null;
  if (event.key !== 'Delete' && event.key !== 'F2' && event.key !== 'Enter') return null;

  const selection = resolveVisibleConnectionTreeSelection(
    context.visibleTree,
    context.selectedNodeId,
    context.selectedNodeIds,
  );
  if (event.key === 'Delete') {
    if (context.deleteBusy || selection.length === 0) return null;
    const nodeIds = canonicalizeConnectionTreeNodeIds(context.tree, selection);
    return nodeIds.length > 0 ? { kind: 'delete', nodeIds } : null;
  }
  if (selection.length !== 1) return null;

  const node = findNode(context.tree, selection[0]);
  if (!node) return null;
  if (event.key === 'F2') return { kind: 'edit', nodeId: node.id };
  return node.kind === 'connection' ? { kind: 'open', nodeId: node.id } : null;
}
