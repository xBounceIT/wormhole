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
