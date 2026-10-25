import { parentLocalSftpPath, parentSftpPath } from './sftp-state.ts';

export type SftpTreeEntry = { fullPath: string; name: string; isDirectory: boolean };
type TreeNode = {
  children: SftpTreeEntry[];
  status: 'idle' | 'loading' | 'ready' | 'failed';
  requestId?: string;
  error?: string;
};
export type SftpTreeState = {
  pane: 'local' | 'remote';
  path: string;
  expanded: string[];
  nodes: Record<string, TreeNode>;
};
export const sftpTreeCacheLimit = 128;

export function sftpTreeAncestors(pane: SftpTreeState['pane'], path: string): string[] {
  const result: string[] = [];
  const parent = pane === 'local' ? parentLocalSftpPath : parentSftpPath;
  for (let current = path; current && result.length < 256; current = parent(current)) {
    result.unshift(current);
    if (parent(current) === current) break;
  }
  return result;
}

export function createSftpTree(pane: SftpTreeState['pane']): SftpTreeState {
  return { pane, path: '', expanded: [], nodes: {} };
}

function boundTree(state: SftpTreeState): SftpTreeState {
  const protectedPaths = new Set(sftpTreeAncestors(state.pane, state.path));
  const keys = Object.keys(state.nodes);
  const removable = keys.filter(
    (path) => !protectedPaths.has(path) && state.nodes[path].status !== 'loading',
  );
  const remove = new Set(removable.slice(0, Math.max(0, keys.length - sftpTreeCacheLimit)));
  const nodes = Object.fromEntries(
    Object.entries(state.nodes).filter(([path]) => !remove.has(path)),
  );
  return { ...state, nodes, expanded: state.expanded.filter((path) => path in nodes) };
}

export function revealSftpTreePath(state: SftpTreeState, path: string): SftpTreeState {
  const ancestors = sftpTreeAncestors(state.pane, path);
  const nodes = { ...state.nodes };
  for (const ancestor of ancestors) nodes[ancestor] ??= { children: [], status: 'idle' };
  return boundTree({
    ...state,
    path,
    nodes,
    expanded: [...new Set([...state.expanded, ...ancestors])],
  });
}

export function toggleSftpTreePath(state: SftpTreeState, path: string): SftpTreeState {
  if (state.expanded.includes(path))
    return { ...state, expanded: state.expanded.filter((value) => value !== path) };
  return boundTree({
    ...state,
    nodes: { ...state.nodes, [path]: state.nodes[path] ?? { children: [], status: 'idle' } },
    expanded: [...state.expanded, path],
  });
}

export function beginSftpTreeRequest(
  state: SftpTreeState,
  path: string,
  requestId: string,
): SftpTreeState {
  return {
    ...state,
    nodes: {
      ...state.nodes,
      [path]: { children: state.nodes[path]?.children ?? [], status: 'loading', requestId },
    },
  };
}

export function finishSftpTreeRequest(
  state: SftpTreeState,
  path: string,
  requestId: string,
  children: SftpTreeEntry[],
  error?: string,
): SftpTreeState {
  if (state.nodes[path]?.requestId !== requestId) return state;
  return boundTree({
    ...state,
    nodes: {
      ...state.nodes,
      [path]: {
        status: error ? 'failed' : 'ready',
        children: children.filter((entry) => entry.isDirectory).slice(0, 4096),
        error,
      },
    },
  });
}

export function invalidateSftpTree(state: SftpTreeState): SftpTreeState {
  // Keep visible children while a mutation/transfer refreshes expanded folders.
  return {
    ...state,
    nodes: Object.fromEntries(
      Object.entries(state.nodes).map(([path, node]) => [
        path,
        { ...node, status: 'idle', requestId: undefined },
      ]),
    ),
  };
}

export function sftpTreeRows(state: SftpTreeState): {
  path: string;
  name: string;
  depth: number;
  expanded: boolean;
  status?: TreeNode['status'];
  error?: string;
}[] {
  const ancestors = sftpTreeAncestors(state.pane, state.path);
  const rows: ReturnType<typeof sftpTreeRows> = [];
  function visit(path: string, name: string, depth: number) {
    if (rows.length >= 4096 || depth >= 256) return;
    const node = state.nodes[path];
    const expanded = state.expanded.includes(path);
    rows.push({ path, name, depth, expanded, status: node?.status, error: node?.error });
    if (!expanded) return;
    const children = [...(node?.children ?? [])];
    const ancestorIndex = ancestors.indexOf(path);
    const child = ancestorIndex < 0 ? undefined : ancestors[ancestorIndex + 1];
    if (child && !children.some((entry) => entry.fullPath === child))
      children.push({
        fullPath: child,
        name: child.split(/[\\/]/).filter(Boolean).at(-1) ?? child,
        isDirectory: true,
      });
    children.sort((a, b) => a.name.localeCompare(b.name));
    const seen = new Set<string>();
    for (const entry of children) {
      if (
        entry.fullPath === path ||
        seen.has(entry.fullPath) ||
        ancestors.slice(0, ancestorIndex + 1).includes(entry.fullPath)
      )
        continue;
      seen.add(entry.fullPath);
      visit(entry.fullPath, entry.name, depth + 1);
    }
  }
  if (ancestors[0]) visit(ancestors[0], ancestors[0], 0);
  return rows;
}

export function sftpShortcut(
  event: {
    key: string;
    ctrlKey?: boolean;
    metaKey?: boolean;
    altKey?: boolean;
    shiftKey?: boolean;
  },
  editing: boolean,
): 'switch' | 'up' | 'copy' | 'rename' | 'mkdir' | 'delete' | 'refresh' | 'edit' | undefined {
  if (editing) return undefined;
  const key = event.key.toLowerCase();
  if ((event.ctrlKey || event.metaKey) && !event.altKey) return key === 'r' ? 'refresh' : undefined;
  if (event.altKey) return key === 'arrowup' ? 'up' : undefined;
  return (
    {
      tab: 'switch',
      backspace: 'up',
      f5: 'copy',
      f2: 'rename',
      f7: 'mkdir',
      delete: 'delete',
      f4: 'edit',
    } as const
  )[key as 'tab'];
}
