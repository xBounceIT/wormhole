import assert from 'node:assert/strict';
import test from 'node:test';
import { hasOpenOverlay, updateOpenOverlayIds } from '../src/native-surface-overlay-state.ts';

test('native surfaces stay hidden until every renderer overlay closes', () => {
  const none = new Set<string>();
  const firstOpen = updateOpenOverlayIds(none, 'connection-menu', true);
  const bothOpen = updateOpenOverlayIds(firstOpen, 'session-menu', true);
  const secondOnly = updateOpenOverlayIds(bothOpen, 'connection-menu', false);
  const closed = updateOpenOverlayIds(secondOnly, 'session-menu', false);

  assert.equal(hasOpenOverlay(none), false);
  assert.equal(hasOpenOverlay(firstOpen), true);
  assert.equal(hasOpenOverlay(bothOpen), true);
  assert.equal(hasOpenOverlay(secondOnly), true);
  assert.equal(hasOpenOverlay(closed), false);
  assert.deepEqual([...bothOpen], ['connection-menu', 'session-menu']);
});

test('duplicate overlay notifications are idempotent and do not mutate prior state', () => {
  const initial = new Set(['connection-menu']);
  const reopened = updateOpenOverlayIds(initial, 'connection-menu', true);
  const missingClosed = updateOpenOverlayIds(reopened, 'missing-menu', false);

  assert.deepEqual([...initial], ['connection-menu']);
  assert.deepEqual([...reopened], ['connection-menu']);
  assert.deepEqual([...missingClosed], ['connection-menu']);
  assert.notEqual(reopened, initial);
});
