import assert from 'node:assert/strict';
import test from 'node:test';
import { KeyedSingleFlight } from '../electron/keyed-single-flight.ts';

test('keyed single-flight coalesces concurrent operations for the same key', async () => {
  const coordinator = new KeyedSingleFlight<string, number>();
  let calls = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const operation = async () => {
    calls++;
    await gate;
    return 42;
  };

  const first = coordinator.run('session-1', operation);
  const second = coordinator.run('session-1', operation);
  release();

  assert.deepEqual(await Promise.all([first, second]), [42, 42]);
  assert.equal(calls, 1);
});

test('keyed single-flight permits a retry after a rejected operation', async () => {
  const coordinator = new KeyedSingleFlight<string, number>();

  await assert.rejects(coordinator.run('session-1', async () => Promise.reject(new Error('boom'))));

  assert.equal(await coordinator.run('session-1', async () => 7), 7);
});
