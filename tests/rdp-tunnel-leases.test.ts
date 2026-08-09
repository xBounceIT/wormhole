import assert from 'node:assert/strict';
import test from 'node:test';

import { settleTunnelCleanup } from '../electron/tunnel-lease-registry.ts';

test('RDP cleanup waits for both process and tunnel settlement before rejecting', async () => {
  let finishRelease!: () => void;
  const release = new Promise<void>((resolve) => {
    finishRelease = resolve;
  });
  let settled = false;
  const cleanup = settleTunnelCleanup(
    Promise.reject(new Error('disconnect failed')),
    release,
  ).finally(() => {
    settled = true;
  });

  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(settled, false);
  finishRelease();
  await assert.rejects(cleanup, /disconnect failed/);
});
