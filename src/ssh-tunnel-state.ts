export type JumpNode = {
  id: string;
  name: string;
  kind: 'folder' | 'connection';
  protocol?: string;
  tunnelEnabled?: boolean | null;
  tunnelConfigId?: string;
  children?: JumpNode[];
};

// null marks a non-SSH tunnel. Missing catalog entries fail closed until loading completes.
export function sshJumpCandidates(
  nodes: JumpNode[],
  tunnelId: string | undefined,
  catalog: Record<string, Record<string, unknown> | null>,
): { value: string; label: string }[] {
  const connections = new Map<
    string,
    { name: string; protocol: string; route: string | undefined }
  >();
  function visit(items: JumpNode[], protocol = '', enabled = false, configId = '') {
    for (const node of items) {
      const resolvedProtocol = node.protocol ?? protocol;
      const resolvedEnabled = node.tunnelEnabled ?? enabled;
      const resolvedConfigId = node.tunnelConfigId || configId;
      if (node.kind === 'connection')
        connections.set(node.id, {
          name: node.name,
          protocol: resolvedProtocol,
          route: resolvedEnabled ? resolvedConfigId || undefined : '',
        });
      if (node.children) visit(node.children, resolvedProtocol, resolvedEnabled, resolvedConfigId);
    }
  }
  visit(nodes);
  function safe(route: string | undefined, seen: Set<string>, depth: number): boolean {
    if (route === undefined) return false; // Enabled without a configured route also fails in Go.
    if (!route) return true;
    if (seen.has(route) || route === tunnelId || depth >= 3 || !Object.hasOwn(catalog, route))
      return false;
    const settings = catalog[route];
    if (settings === null) return true;
    if (settings.Mode === 'manual') return true;
    const jump = connections.get(String(settings.JumpConnectionId));
    if (settings.Mode !== 'connection' || !jump || jump.protocol !== 'ssh') return false;
    return safe(jump.route, new Set([...seen, route]), depth + 1);
  }
  return [...connections]
    .filter(([, node]) => node.protocol === 'ssh' && safe(node.route, new Set(), 1))
    .map(([id, node]) => ({ value: id, label: node.name }))
    .sort((a, b) => a.label.localeCompare(b.label));
}
