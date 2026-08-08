export const maxSessionPanes = 4;

export type SessionLayoutEdge = 'left' | 'right' | 'top' | 'bottom';
export type SessionSplitOrientation = 'horizontal' | 'vertical';

export type SessionPane = {
  kind: 'pane';
  id: string;
  tabs: string[];
  activeSessionId: string;
};

export type SessionSplit = {
  kind: 'split';
  id: string;
  orientation: SessionSplitOrientation;
  ratio: number;
  first: SessionLayoutNode;
  second: SessionLayoutNode;
};

export type SessionLayoutNode = SessionPane | SessionSplit;

export type SessionLayoutState = {
  root: SessionLayoutNode | null;
  activePaneId: string | null;
  nextPaneId: number;
  nextSplitId: number;
};

export type SessionPaneRect = {
  paneId: string;
  x: number;
  y: number;
  width: number;
  height: number;
};

export type SessionSplitDivider = {
  splitId: string;
  orientation: SessionSplitOrientation;
  ratio: number;
  x: number;
  y: number;
  width: number;
  height: number;
};

export function createSessionLayout(
  sessionIds: readonly string[] = [],
  selectedSessionId?: string,
): SessionLayoutState {
  const tabs = unique(sessionIds);
  if (tabs.length === 0) {
    return { root: null, activePaneId: null, nextPaneId: 1, nextSplitId: 1 };
  }
  const pane = createPane('pane-0', tabs, selectedSessionId);
  return { root: pane, activePaneId: pane.id, nextPaneId: 1, nextSplitId: 1 };
}

export function sessionPanes(root: SessionLayoutNode | null): SessionPane[] {
  if (!root) return [];
  if (root.kind === 'pane') return [root];
  return [...sessionPanes(root.first), ...sessionPanes(root.second)];
}

export function findSessionPane(
  root: SessionLayoutNode | null,
  sessionId: string,
): SessionPane | undefined {
  return sessionPanes(root).find((pane) => pane.tabs.includes(sessionId));
}

export function focusSessionPane(state: SessionLayoutState, paneId: string): SessionLayoutState {
  return state.activePaneId === paneId || !findPane(state.root, paneId)
    ? state
    : { ...state, activePaneId: paneId };
}

export function selectSession(
  state: SessionLayoutState,
  paneId: string,
  sessionId: string,
): SessionLayoutState {
  const pane = findPane(state.root, paneId);
  if (!pane?.tabs.includes(sessionId)) return state;
  if (pane.activeSessionId === sessionId && state.activePaneId === paneId) return state;
  return {
    ...state,
    root: mapPane(state.root, paneId, (current) => ({ ...current, activeSessionId: sessionId })),
    activePaneId: paneId,
  };
}

export function reconcileSessionLayout(
  state: SessionLayoutState,
  sessionIds: readonly string[],
  selectedSessionId?: string,
): SessionLayoutState {
  const wanted = unique(sessionIds);
  const wantedSet = new Set(wanted);
  let next = state;
  for (const pane of sessionPanes(next.root)) {
    for (const tab of pane.tabs) {
      if (!wantedSet.has(tab)) next = removeSession(next, tab);
    }
  }

  const placed = new Set(sessionPanes(next.root).flatMap((pane) => pane.tabs));
  for (const sessionId of wanted) {
    if (placed.has(sessionId)) continue;
    next = appendSession(next, sessionId);
    placed.add(sessionId);
  }

  if (selectedSessionId && wantedSet.has(selectedSessionId)) {
    const pane = findSessionPane(next.root, selectedSessionId);
    if (pane) next = selectSession(next, pane.id, selectedSessionId);
  }
  return next;
}

export function removeSession(state: SessionLayoutState, sessionId: string): SessionLayoutState {
  const source = findSessionPane(state.root, sessionId);
  if (!source) return state;
  const tabs = source.tabs.filter((tab) => tab !== sessionId);
  if (tabs.length > 0) {
    const removedIndex = source.tabs.indexOf(sessionId);
    const activeSessionId =
      source.activeSessionId === sessionId
        ? (tabs[Math.min(removedIndex, tabs.length - 1)] ?? tabs[0])
        : source.activeSessionId;
    return {
      ...state,
      root: mapPane(state.root, source.id, (pane) => ({ ...pane, tabs, activeSessionId })),
    };
  }

  const root = collapsePane(state.root, source.id);
  const panes = sessionPanes(root);
  return {
    ...state,
    root,
    activePaneId:
      state.activePaneId === source.id ? (panes[0]?.id ?? null) : normalizeActivePane(panes, state),
  };
}

export function canSplitSession(
  state: SessionLayoutState,
  targetPaneId: string,
  sessionId: string,
): boolean {
  const target = findPane(state.root, targetPaneId);
  const source = findSessionPane(state.root, sessionId);
  if (!target || !source) return false;
  if (source.id === target.id && source.tabs.length === 1) return false;
  return sessionPanes(state.root).length < maxSessionPanes || source.tabs.length === 1;
}

export function splitSession(
  state: SessionLayoutState,
  targetPaneId: string,
  edge: SessionLayoutEdge,
  sessionId: string,
): SessionLayoutState {
  if (!canSplitSession(state, targetPaneId, sessionId)) return state;
  const detached = removeSession(state, sessionId);
  const target = findPane(detached.root, targetPaneId);
  if (!target) return state;

  const paneId = `pane-${detached.nextPaneId}`;
  const incoming = createPane(paneId, [sessionId]);
  const incomingFirst = edge === 'left' || edge === 'top';
  const split: SessionSplit = {
    kind: 'split',
    id: `split-${detached.nextSplitId}`,
    orientation: edge === 'left' || edge === 'right' ? 'horizontal' : 'vertical',
    ratio: 0.5,
    first: incomingFirst ? incoming : target,
    second: incomingFirst ? target : incoming,
  };
  return {
    ...detached,
    root: replacePane(detached.root, targetPaneId, split),
    activePaneId: paneId,
    nextPaneId: detached.nextPaneId + 1,
    nextSplitId: detached.nextSplitId + 1,
  };
}

export function moveSession(
  state: SessionLayoutState,
  targetPaneId: string,
  sessionId: string,
  targetIndex?: number,
): SessionLayoutState {
  const targetBefore = findPane(state.root, targetPaneId);
  const source = findSessionPane(state.root, sessionId);
  if (!targetBefore || !source) return state;

  if (source.id === targetPaneId) {
    const tabs = source.tabs.filter((tab) => tab !== sessionId);
    tabs.splice(clampIndex(targetIndex, tabs.length), 0, sessionId);
    return {
      ...state,
      root: mapPane(state.root, source.id, (pane) => ({
        ...pane,
        tabs,
        activeSessionId: sessionId,
      })),
      activePaneId: source.id,
    };
  }

  const detached = removeSession(state, sessionId);
  const target = findPane(detached.root, targetPaneId);
  if (!target) return state;
  const tabs = [...target.tabs];
  tabs.splice(clampIndex(targetIndex, tabs.length), 0, sessionId);
  return {
    ...detached,
    root: mapPane(detached.root, targetPaneId, (pane) => ({
      ...pane,
      tabs,
      activeSessionId: sessionId,
    })),
    activePaneId: targetPaneId,
  };
}

export function sessionPaneRects(root: SessionLayoutNode | null): SessionPaneRect[] {
  const result: SessionPaneRect[] = [];
  function visit(
    node: SessionLayoutNode | null,
    x: number,
    y: number,
    width: number,
    height: number,
  ) {
    if (!node) return;
    if (node.kind === 'pane') {
      result.push({ paneId: node.id, x, y, width, height });
      return;
    }
    const ratio = Math.max(0.15, Math.min(0.85, node.ratio));
    if (node.orientation === 'horizontal') {
      visit(node.first, x, y, width * ratio, height);
      visit(node.second, x + width * ratio, y, width * (1 - ratio), height);
    } else {
      visit(node.first, x, y, width, height * ratio);
      visit(node.second, x, y + height * ratio, width, height * (1 - ratio));
    }
  }
  visit(root, 0, 0, 100, 100);
  return result;
}

export function setSessionSplitRatio(
  state: SessionLayoutState,
  splitId: string,
  ratio: number,
): SessionLayoutState {
  if (!Number.isFinite(ratio)) return state;
  const nextRatio = Math.max(0.15, Math.min(0.85, ratio));
  function update(node: SessionLayoutNode | null): SessionLayoutNode | null {
    if (!node || node.kind === 'pane') return node;
    if (node.id === splitId) return node.ratio === nextRatio ? node : { ...node, ratio: nextRatio };
    const first = update(node.first)!;
    const second = update(node.second)!;
    return first === node.first && second === node.second ? node : { ...node, first, second };
  }
  const root = update(state.root);
  return root === state.root ? state : { ...state, root };
}

export function sessionSplitDividers(root: SessionLayoutNode | null): SessionSplitDivider[] {
  const result: SessionSplitDivider[] = [];
  function visit(
    node: SessionLayoutNode | null,
    x: number,
    y: number,
    width: number,
    height: number,
  ) {
    if (!node || node.kind === 'pane') return;
    const ratio = Math.max(0.15, Math.min(0.85, node.ratio));
    result.push({
      splitId: node.id,
      orientation: node.orientation,
      ratio,
      x,
      y,
      width,
      height,
    });
    if (node.orientation === 'horizontal') {
      visit(node.first, x, y, width * ratio, height);
      visit(node.second, x + width * ratio, y, width * (1 - ratio), height);
    } else {
      visit(node.first, x, y, width, height * ratio);
      visit(node.second, x, y + height * ratio, width, height * (1 - ratio));
    }
  }
  visit(root, 0, 0, 100, 100);
  return result;
}

export function assertSessionLayout(state: SessionLayoutState): void {
  const panes = sessionPanes(state.root);
  if (panes.length > maxSessionPanes) throw new Error('session layout exceeds the four-pane cap');
  const paneIds = new Set<string>();
  const sessions = new Set<string>();
  for (const pane of panes) {
    if (paneIds.has(pane.id)) throw new Error(`duplicate pane id: ${pane.id}`);
    paneIds.add(pane.id);
    if (pane.tabs.length === 0) throw new Error(`empty pane: ${pane.id}`);
    if (!pane.tabs.includes(pane.activeSessionId)) {
      throw new Error(`pane active session is missing: ${pane.id}`);
    }
    for (const sessionId of pane.tabs) {
      if (sessions.has(sessionId)) throw new Error(`duplicate session placement: ${sessionId}`);
      sessions.add(sessionId);
    }
  }
  if (state.activePaneId && !paneIds.has(state.activePaneId)) {
    throw new Error(`active pane is missing: ${state.activePaneId}`);
  }
}

function appendSession(state: SessionLayoutState, sessionId: string): SessionLayoutState {
  if (!state.root) {
    const id = `pane-${state.nextPaneId}`;
    return {
      ...state,
      root: createPane(id, [sessionId]),
      activePaneId: id,
      nextPaneId: state.nextPaneId + 1,
    };
  }
  const pane = findPane(state.root, state.activePaneId ?? '') ?? sessionPanes(state.root)[0];
  return {
    ...state,
    root: mapPane(state.root, pane.id, (current) => ({
      ...current,
      tabs: [...current.tabs, sessionId],
      activeSessionId: sessionId,
    })),
    activePaneId: pane.id,
  };
}

function createPane(id: string, tabs: string[], selectedSessionId?: string): SessionPane {
  return {
    kind: 'pane',
    id,
    tabs,
    activeSessionId:
      (selectedSessionId && tabs.includes(selectedSessionId) ? selectedSessionId : tabs[0]) ?? '',
  };
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function clampIndex(index: number | undefined, length: number): number {
  if (index === undefined || !Number.isFinite(index)) return length;
  return Math.max(0, Math.min(length, Math.trunc(index)));
}

function findPane(root: SessionLayoutNode | null, paneId: string): SessionPane | undefined {
  return sessionPanes(root).find((pane) => pane.id === paneId);
}

function normalizeActivePane(panes: SessionPane[], state: SessionLayoutState): string | null {
  return panes.some((pane) => pane.id === state.activePaneId)
    ? state.activePaneId
    : (panes[0]?.id ?? null);
}

function mapPane(
  node: SessionLayoutNode | null,
  paneId: string,
  map: (pane: SessionPane) => SessionPane,
): SessionLayoutNode | null {
  if (!node) return null;
  if (node.kind === 'pane') return node.id === paneId ? map(node) : node;
  const first = mapPane(node.first, paneId, map)!;
  const second = mapPane(node.second, paneId, map)!;
  return first === node.first && second === node.second ? node : { ...node, first, second };
}

function replacePane(
  node: SessionLayoutNode | null,
  paneId: string,
  replacement: SessionLayoutNode,
): SessionLayoutNode | null {
  if (!node) return null;
  if (node.kind === 'pane') return node.id === paneId ? replacement : node;
  const first = replacePane(node.first, paneId, replacement)!;
  const second = replacePane(node.second, paneId, replacement)!;
  return first === node.first && second === node.second ? node : { ...node, first, second };
}

function collapsePane(node: SessionLayoutNode | null, paneId: string): SessionLayoutNode | null {
  if (!node) return null;
  if (node.kind === 'pane') return node.id === paneId ? null : node;
  const first = collapsePane(node.first, paneId);
  const second = collapsePane(node.second, paneId);
  if (!first) return second;
  if (!second) return first;
  return first === node.first && second === node.second ? node : { ...node, first, second };
}
