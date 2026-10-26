import { parentLocalSftpPath, parentSftpPath } from './sftp-state.ts';
import { compareSftpEntries, type SftpSortColumn } from './sftp-state.ts';
import { isLocalSftpPathRoot, isSftpPathWithin } from './sftp-state.ts';

export type SftpTreeEntry = {
  fullPath: string;
  name: string;
  isDirectory: boolean;
  lastModifiedUtc?: string;
  size?: number;
};
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

export function createSftpTree(pane: SftpTreeState['pane']): SftpTreeState {
  return { pane, path: '', expanded: [], nodes: {} };
}

function boundTree(state: SftpTreeState): SftpTreeState {
  const keys = Object.keys(state.nodes);
  const removable = keys.filter(
    (path) => path !== state.path && state.nodes[path].status !== 'loading',
  );
  const remove = new Set(removable.slice(0, Math.max(0, keys.length - sftpTreeCacheLimit)));
  const nodes = Object.fromEntries(
    Object.entries(state.nodes).filter(([path]) => !remove.has(path)),
  );
  return { ...state, nodes, expanded: state.expanded.filter((path) => path in nodes) };
}

export function revealSftpTreePath(state: SftpTreeState, path: string): SftpTreeState {
  const nodes = { ...state.nodes };
  if (path) nodes[path] ??= { children: [], status: 'idle' };
  return boundTree({
    ...state,
    path,
    nodes,
    expanded: path
      ? [
          path,
          ...state.expanded.filter(
            (value) => value !== path && isSftpPathWithin(state.pane, path, value),
          ),
        ]
      : [],
  });
}

export function toggleSftpTreePath(state: SftpTreeState, path: string): SftpTreeState {
  if (!isSftpPathWithin(state.pane, state.path, path)) return state;
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

export function sftpTreeRows(
  state: SftpTreeState,
  sortColumn: SftpSortColumn = 'name',
  ascending = true,
): {
  path: string;
  name: string;
  depth: number;
  expanded: boolean;
  status?: TreeNode['status'];
  error?: string;
  lastModifiedUtc?: string;
}[] {
  const rows: ReturnType<typeof sftpTreeRows> = [];
  const visited = new Set<string>();
  function visit(path: string, name: string, depth: number, lastModifiedUtc?: string) {
    if (rows.length >= 4096 || depth >= 256 || visited.has(path)) return;
    visited.add(path);
    const node = state.nodes[path];
    const expanded = state.expanded.includes(path);
    rows.push({
      path,
      name,
      depth,
      expanded,
      status: node?.status,
      error: node?.error,
      lastModifiedUtc,
    });
    if (!expanded) return;
    const children = [...(node?.children ?? [])];
    children.sort((a, b) => compareSftpEntries(a, b, sortColumn, ascending));
    for (const entry of children) {
      if (
        !isSftpPathWithin(state.pane, path, entry.fullPath) ||
        isSftpPathWithin(state.pane, entry.fullPath, path)
      )
        continue;
      visit(entry.fullPath, entry.name, depth + 1, entry.lastModifiedUtc);
    }
  }
  if (state.path) {
    const parent =
      state.pane === 'local' ? parentLocalSftpPath(state.path) : parentSftpPath(state.path);
    // Reuse cached parent metadata when available; rooting the tree must not read ancestors.
    const entry = state.nodes[parent]?.children.find((child) => child.fullPath === state.path);
    const root =
      parent === state.path || (state.pane === 'local' && isLocalSftpPathRoot(state.path));
    const name = root
      ? state.path
      : (state.path
          .split(state.pane === 'local' && !state.path.startsWith('/') ? /[\\/]/ : /\//)
          .filter(Boolean)
          .at(-1) ?? state.path);
    visit(state.path, entry?.name ?? name, 0, entry?.lastModifiedUtc);
  }
  return rows;
}

export function filterSftpTreeRows(
  rows: ReturnType<typeof sftpTreeRows>,
  search: string,
): ReturnType<typeof sftpTreeRows> {
  const query = search.trim().toLocaleLowerCase();
  if (!query) return rows;
  const ancestors: string[] = [];
  const included = new Set<string>();
  for (const row of rows) {
    ancestors.length = row.depth;
    ancestors.push(row.path);
    if (row.name.toLocaleLowerCase().includes(query))
      for (const path of ancestors) included.add(path);
  }
  return rows.filter((row) => included.has(row.path));
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
