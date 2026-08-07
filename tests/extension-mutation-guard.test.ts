import assert from 'node:assert/strict';
import test from 'node:test';
import { ExtensionMutationGuard } from '../electron/extension-mutation-guard.ts';

test('extension mutation guard blocks replacement while an extension tab is reserved', async () => {
  const guard = new ExtensionMutationGuard();
  const release = guard.reserveUse();

  assert.equal(guard.canAutoMutate, false);
  await assert.rejects(
    guard.runMutation(
      async () => undefined,
      async () => undefined,
    ),
    /Close every HTTPS tab/,
  );

  release();
  release();
  assert.equal(guard.canAutoMutate, true);
});

test('extension mutation guard prevents new tabs throughout pending flush and replacement', async () => {
  const guard = new ExtensionMutationGuard();
  let finishFlush!: () => void;
  let finishMutation!: () => void;
  const flush = new Promise<void>((resolve) => (finishFlush = resolve));
  const mutation = new Promise<void>((resolve) => (finishMutation = resolve));
  const running = guard.runMutation(
    () => flush,
    () => mutation,
  );

  assert.throws(() => guard.reserveUse(), /being updated/);
  finishFlush();
  await Promise.resolve();
  assert.throws(() => guard.reserveUse(), /being updated/);
  finishMutation();
  await running;

  const release = guard.reserveUse();
  release();
});

test('extension mutation guard prepares an update before exposing the install to a new tab', async () => {
  const guard = new ExtensionMutationGuard();
  let releaseFlush!: () => void;
  const flush = new Promise<void>((resolve) => {
    releaseFlush = resolve;
  });
  const events: string[] = [];

  const prepared = guard.prepareUse(
    async () => {
      events.push('flush-started');
      await flush;
      events.push('flush-finished');
    },
    async (canMutate) => {
      assert.equal(canMutate, true);
      events.push('updated');
      return '2026.8.0';
    },
  );
  await Promise.resolve();

  assert.throws(() => guard.reserveUse(), /being updated/i);
  releaseFlush();
  const use = await prepared;

  assert.equal(use.result, '2026.8.0');
  assert.deepEqual(events, ['flush-started', 'flush-finished', 'updated']);
  assert.equal(guard.canAutoMutate, false);
  use.release();
  assert.equal(guard.canAutoMutate, true);
});

test('extension mutation guard skips update preparation while another tab uses the install', async () => {
  const guard = new ExtensionMutationGuard();
  const releaseFirst = guard.reserveUse();
  let waited = false;

  const second = await guard.prepareUse(
    async () => {
      waited = true;
    },
    async (canMutate) => canMutate,
  );

  assert.equal(second.result, false);
  assert.equal(waited, false);
  releaseFirst();
  assert.equal(guard.canAutoMutate, false);
  second.release();
  assert.equal(guard.canAutoMutate, true);
});
