import assert from 'node:assert/strict';
import test from 'node:test';
import { KeyedSingleFlight } from '../electron/keyed-single-flight.ts';

test('keyed single-flight coalesces concurrent operations for the same key', async () => {
  const coordinator = new KeyedSingleFlight<string>();
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
  const coordinator = new KeyedSingleFlight<string>();

  await assert.rejects(coordinator.run('session-1', async () => Promise.reject(new Error('boom'))));

  assert.equal(await coordinator.run('session-1', async () => 7), 7);
});

test('keyed exclusive operations reject duplicates and expose an idle boundary', async () => {
  const coordinator = new KeyedSingleFlight<string>();
  let release!: () => void;
  const first = coordinator.runExclusive(
    'session-1',
    () => new Promise<number>((resolve) => (release = () => resolve(42))),
    'already starting',
  );
  await Promise.resolve();

  await assert.rejects(
    coordinator.runExclusive('session-1', async () => 7, 'already starting'),
    /already starting/,
  );
  let idle = false;
  const waiting = coordinator.waitForIdle('session-1').then(() => {
    idle = true;
  });
  await Promise.resolve();
  assert.equal(idle, false);
  release();
  assert.equal(await first, 42);
  await waiting;
  assert.equal(idle, true);

  const resume = coordinator.suspend('session-1');
  await assert.rejects(
    coordinator.runExclusive('session-1', async () => 9, 'cleanup in progress'),
    /cleanup in progress/,
  );
  resume();
  assert.equal(await coordinator.runExclusive('session-1', async () => 9, 'blocked'), 9);
});
