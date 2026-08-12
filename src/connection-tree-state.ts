export type ConnectionTreeStateNode = {
  id: string;
  kind: 'folder' | 'connection';
  children?: readonly ConnectionTreeStateNode[];
};

export type ConnectionTreeIndex = {
  folderIds: string[];
  parentFolderIdByNodeId: Map<string, string>;
};

export type ConnectionTreeExpansionState = {
  defaultExpanded: boolean;
  folderIds: string[];
};

export const connectionTreeExpansionSaveDelayMs = 250;

export function indexConnectionTree(
  nodes: readonly ConnectionTreeStateNode[],
): ConnectionTreeIndex {
  const folderIds: string[] = [];
  const parentFolderIdByNodeId = new Map<string, string>();

  const pending: Array<{ node: ConnectionTreeStateNode; parentFolderId?: string }> = [];
  for (let index = nodes.length - 1; index >= 0; index--) {
    pending.push({ node: nodes[index] });
  }
  while (pending.length > 0) {
    const { node, parentFolderId } = pending.pop()!;
    if (parentFolderId) parentFolderIdByNodeId.set(node.id, parentFolderId);
    if (node.kind !== 'folder') continue;

    folderIds.push(node.id);
    const children = node.children;
    if (!children) continue;
    for (let index = children.length - 1; index >= 0; index--) {
      pending.push({ node: children[index], parentFolderId: node.id });
    }
  }

  return { folderIds, parentFolderIdByNodeId };
}

export function restoreExpandedFolderIds(
  folderIds: readonly string[],
  persistedState: ConnectionTreeExpansionState | null,
): Set<string> {
  if (persistedState === null) return new Set(folderIds);

  const exceptions = new Set(persistedState.folderIds);
  return new Set(
    folderIds.filter((id) =>
      persistedState.defaultExpanded ? !exceptions.has(id) : exceptions.has(id),
    ),
  );
}

export function serializeConnectionTreeExpansion(
  folderIds: readonly string[],
  expandedFolderIds: ReadonlySet<string>,
): ConnectionTreeExpansionState {
  const expanded: string[] = [];
  const collapsed: string[] = [];
  for (const id of folderIds) {
    (expandedFolderIds.has(id) ? expanded : collapsed).push(id);
  }
  if (expanded.length <= collapsed.length) {
    return { defaultExpanded: false, folderIds: expanded };
  }
  return { defaultExpanded: true, folderIds: collapsed };
}

export function shouldRenderConnectionTreeChildren(
  hasChildren: boolean,
  isExpanded: boolean,
): boolean {
  return hasChildren && isExpanded;
}

export function reconcileExpandedFolderIds(
  folderIds: readonly string[],
  expandedFolderIds: Set<string>,
): Set<string> {
  const available = new Set(folderIds);
  const next = new Set([...expandedFolderIds].filter((id) => available.has(id)));
  return setsEqual(next, expandedFolderIds) ? expandedFolderIds : next;
}

type Scheduler = {
  set(callback: () => void, delayMs: number): unknown;
  clear(handle: unknown): void;
};

const defaultScheduler: Scheduler = {
  set: (callback, delayMs) => globalThis.setTimeout(callback, delayMs),
  clear: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

function expansionStatesEqual(
  left: ConnectionTreeExpansionState,
  right: ConnectionTreeExpansionState,
): boolean {
  return (
    left.defaultExpanded === right.defaultExpanded &&
    left.folderIds.length === right.folderIds.length &&
    left.folderIds.every((value, index) => value === right.folderIds[index])
  );
}

function setsEqual(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

export function createConnectionTreeExpansionWriter(
  write: (state: ConnectionTreeExpansionState) => void | Promise<void>,
  options: {
    delayMs?: number;
    initialState?: ConnectionTreeExpansionState;
    scheduler?: Scheduler;
  } = {},
) {
  const delayMs = options.delayMs ?? connectionTreeExpansionSaveDelayMs;
  const scheduler = options.scheduler ?? defaultScheduler;
  let handle: unknown;
  let pending: { folderIds: readonly string[]; expandedFolderIds: ReadonlySet<string> } | undefined;
  let commitQueue = Promise.resolve();
  let lastWritten = options.initialState;

  const commit = async (): Promise<void> => {
    const snapshot = pending;
    if (!snapshot) return;
    const state = serializeConnectionTreeExpansion(snapshot.folderIds, snapshot.expandedFolderIds);
    if (lastWritten && expansionStatesEqual(state, lastWritten)) {
      pending = undefined;
      return;
    }
    await write(state);
    if (pending === snapshot) pending = undefined;
    lastWritten = state;
  };
  const enqueueCommit = (): Promise<void> => {
    commitQueue = commitQueue.then(commit, commit);
    return commitQueue;
  };

  return {
    schedule(folderIds: readonly string[], expandedFolderIds: ReadonlySet<string>) {
      pending = { folderIds, expandedFolderIds };
      if (handle !== undefined) scheduler.clear(handle);
      handle = scheduler.set(() => {
        handle = undefined;
        void enqueueCommit().catch(() => undefined);
      }, delayMs);
    },
    async flush() {
      if (handle !== undefined) scheduler.clear(handle);
      handle = undefined;
      await enqueueCommit();
    },
    cancel() {
      if (handle !== undefined) scheduler.clear(handle);
      handle = undefined;
      pending = undefined;
    },
  };
}
