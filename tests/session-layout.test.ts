import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertSessionLayout,
  createSessionLayout,
  findSessionPane,
  focusSessionPane,
  maxSessionPanes,
  moveSession,
  reconcileSessionLayout,
  removeSession,
  restoreSessionFullView,
  sessionPaneRects,
  sessionPanes,
  selectSession,
  sessionSplitDividers,
  setSessionSplitRatio,
  splitSession,
} from '../src/session-layout.ts';
import { newSessionToken } from '../src/session-token.ts';

test('creates unique cryptographically secure session tokens', () => {
  const first = newSessionToken();
  const second = newSessionToken();

  assert.match(first, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  assert.notEqual(first, second);
});

test('splits on every edge with deterministic orientation and order', () => {
  for (const edge of ['left', 'right', 'top', 'bottom'] as const) {
    let layout = createSessionLayout(['a', 'b'], 'a');
    layout = splitSession(layout, 'pane-0', edge, 'b');
    assert.equal(layout.root?.kind, 'split');
    if (layout.root?.kind !== 'split') continue;
    assert.equal(
      layout.root.orientation,
      edge === 'left' || edge === 'right' ? 'horizontal' : 'vertical',
    );
    const order = sessionPanes(layout.root).map((pane) => pane.activeSessionId);
    assert.deepEqual(order, edge === 'left' || edge === 'top' ? ['b', 'a'] : ['a', 'b']);
    assertSessionLayout(layout);
  }
});

test('enforces four panes while allowing a visible single-tab pane to move', () => {
  let layout = createSessionLayout(['a', 'b', 'c', 'd', 'extra']);
  for (const sessionId of ['b', 'c', 'd']) {
    layout = splitSession(layout, 'pane-0', 'right', sessionId);
  }
  assert.equal(sessionPanes(layout.root).length, maxSessionPanes);
  assert.equal(splitSession(layout, 'pane-0', 'bottom', 'extra'), layout);

  const source = findSessionPane(layout.root, 'd')!;
  assert.equal(source.tabs.length, 1);
  layout = splitSession(layout, 'pane-0', 'bottom', 'd');
  assert.equal(sessionPanes(layout.root).length, maxSessionPanes);
  assertSessionLayout(layout);
});

test('moves and reorders tabs without changing session identity', () => {
  let layout = createSessionLayout(['surface-a', 'surface-b', 'surface-c']);
  layout = splitSession(layout, 'pane-0', 'right', 'surface-c');
  const right = findSessionPane(layout.root, 'surface-c')!;
  layout = moveSession(layout, right.id, 'surface-a', 0);
  assert.deepEqual(findSessionPane(layout.root, 'surface-a')?.tabs, ['surface-a', 'surface-c']);
  layout = moveSession(layout, right.id, 'surface-c', 0);
  assert.deepEqual(findSessionPane(layout.root, 'surface-c')?.tabs, ['surface-c', 'surface-a']);
  assertSessionLayout(layout);
});

test('reselecting the active tab or pane is referentially stable', () => {
  const layout = createSessionLayout(['a', 'b'], 'a');
  assert.equal(focusSessionPane(layout, 'pane-0'), layout);
  assert.equal(selectSession(layout, 'pane-0', 'a'), layout);
});

test('moving the sole tab onto another pane collapses the empty source leaf', () => {
  let layout = createSessionLayout(['a', 'b', 'c']);
  layout = splitSession(layout, 'pane-0', 'right', 'c');
  const source = findSessionPane(layout.root, 'c')!;
  const target = findSessionPane(layout.root, 'a')!;
  assert.equal(source.tabs.length, 1);
  layout = moveSession(layout, target.id, 'c', 1);
  assert.equal(sessionPanes(layout.root).length, 1);
  assert.deepEqual(sessionPanes(layout.root)[0].tabs, ['a', 'c', 'b']);
  assert.equal(layout.activePaneId, target.id);
  assertSessionLayout(layout);
});

test('restoring full view collapses every pane without dropping or recreating sessions', () => {
  let layout = createSessionLayout(['a', 'b', 'c', 'd'], 'a');
  layout = splitSession(layout, 'pane-0', 'right', 'c');
  layout = splitSession(layout, findSessionPane(layout.root, 'c')!.id, 'bottom', 'd');
  const sourcePaneId = findSessionPane(layout.root, 'd')!.id;

  layout = restoreSessionFullView(layout, 'd');

  assert.equal(layout.root?.kind, 'pane');
  assert.equal(layout.activePaneId, sourcePaneId);
  assert.deepEqual(sessionPanes(layout.root)[0], {
    kind: 'pane',
    id: sourcePaneId,
    tabs: ['a', 'b', 'c', 'd'],
    activeSessionId: 'd',
  });
  assertSessionLayout(layout);
});

test('restoring an unknown session is stable and a single pane only changes selection', () => {
  const layout = createSessionLayout(['a', 'b'], 'a');
  assert.equal(restoreSessionFullView(layout, 'missing'), layout);
  const restored = restoreSessionFullView(layout, 'b');
  assert.equal(restored.root?.kind, 'pane');
  assert.equal(sessionPanes(restored.root)[0].activeSessionId, 'b');
  assertSessionLayout(restored);
});

test('closing or terminating the final tab collapses its leaf and focuses a survivor', () => {
  let layout = createSessionLayout(['a', 'b']);
  layout = splitSession(layout, 'pane-0', 'right', 'b');
  layout = removeSession(layout, 'b');
  assert.equal(sessionPanes(layout.root).length, 1);
  assert.equal(layout.activePaneId, 'pane-0');
  layout = reconcileSessionLayout(layout, []);
  assert.equal(layout.root, null);
  assert.equal(layout.activePaneId, null);
  assertSessionLayout(layout);
});

test('reconcile preserves placement and adds reopened sessions to the active pane', () => {
  let layout = createSessionLayout(['a', 'b', 'c']);
  layout = splitSession(layout, 'pane-0', 'right', 'c');
  const before = JSON.stringify(layout.root);
  layout = reconcileSessionLayout(layout, ['a', 'b', 'c']);
  assert.equal(JSON.stringify(layout.root), before);
  layout = reconcileSessionLayout(layout, ['a', 'b', 'c', 'reopened'], 'reopened');
  assert.equal(findSessionPane(layout.root, 'reopened')?.id, layout.activePaneId);
  assertSessionLayout(layout);
});

test('layout rectangles tile the full workspace at a four-pane cap', () => {
  let layout = createSessionLayout(['a', 'b', 'c', 'd']);
  layout = splitSession(layout, 'pane-0', 'right', 'b');
  layout = splitSession(layout, 'pane-0', 'bottom', 'c');
  layout = splitSession(layout, findSessionPane(layout.root, 'b')!.id, 'bottom', 'd');
  const rects = sessionPaneRects(layout.root);
  assert.equal(rects.length, 4);
  assert.equal(
    rects.reduce((sum, rect) => sum + rect.width * rect.height, 0),
    10_000,
  );
  assertSessionLayout(layout);
});

test('split resizing clamps ratios and updates pane geometry without moving session identities', () => {
  let layout = createSessionLayout(['a', 'b']);
  layout = splitSession(layout, 'pane-0', 'right', 'b');
  const split = layout.root?.kind === 'split' ? layout.root : undefined;
  assert.ok(split);
  layout = setSessionSplitRatio(layout, split.id, 0.01);
  assert.equal(sessionSplitDividers(layout.root)[0].ratio, 0.15);
  assert.deepEqual(
    sessionPaneRects(layout.root).map((rect) => rect.width),
    [15, 85],
  );
  layout = setSessionSplitRatio(layout, split.id, 0.99);
  assert.equal(sessionSplitDividers(layout.root)[0].ratio, 0.85);
  assert.equal(findSessionPane(layout.root, 'a')?.id, 'pane-0');
  assert.equal(setSessionSplitRatio(layout, split.id, Number.NaN), layout);
  assertSessionLayout(layout);
});

test('property-style command sequences retain unique placement and tree invariants', () => {
  const ids = Array.from({ length: 8 }, (_, index) => `s${index}`);
  let layout = createSessionLayout(ids);
  for (let index = 0; index < 250; index += 1) {
    const sessionId = ids[(index * 7) % ids.length];
    const panes = sessionPanes(layout.root);
    const target = panes[(index * 3) % panes.length];
    if (index % 5 === 0) layout = splitSession(layout, target.id, 'right', sessionId);
    else if (index % 7 === 0) layout = removeSession(layout, sessionId);
    else layout = moveSession(layout, target.id, sessionId, index % (target.tabs.length + 1));
    layout = reconcileSessionLayout(layout, ids);
    assertSessionLayout(layout);
    assert.equal(new Set(sessionPanes(layout.root).flatMap((pane) => pane.tabs)).size, ids.length);
  }
});
