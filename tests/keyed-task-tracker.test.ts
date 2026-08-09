import assert from 'node:assert/strict';
import test from 'node:test';
import { KeyedTaskTracker } from '../electron/keyed-task-tracker.ts';

test('keyed task tracker waits for every task already running for a key', async () => {
  const tracker = new KeyedTaskTracker<string>();
  const releases: Array<() => void> = [];
  const completed: number[] = [];

  for (const value of [1, 2]) {
    void tracker.run('profile-1', async () => {
      await new Promise<void>((resolve) => releases.push(resolve));
      completed.push(value);
    });
  }

  await Promise.resolve();
  const waiting = tracker.waitForIdle('profile-1');
  releases.splice(0).forEach((release) => release());
  await waiting;

  assert.deepEqual(completed.sort(), [1, 2]);
});

test('keyed task tracker includes work added while a waiter is draining the key', async () => {
  const tracker = new KeyedTaskTracker<string>();
  let releaseFirst!: () => void;
  let releaseSecond!: () => void;
  let idle = false;

  void tracker.run('profile-1', () => new Promise<void>((resolve) => (releaseFirst = resolve)));
  await Promise.resolve();
  const waiting = tracker.waitForIdle('profile-1').then(() => {
    idle = true;
  });
  void tracker.run('profile-1', () => new Promise<void>((resolve) => (releaseSecond = resolve)));
  await Promise.resolve();

  releaseFirst();
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(idle, false);

  releaseSecond();
  await waiting;
  assert.equal(idle, true);
});

test('keyed task tracker isolates keys and releases rejected tasks', async () => {
  const tracker = new KeyedTaskTracker<string>();
  let release!: () => void;
  const blocked = tracker.run(
    'profile-1',
    () => new Promise<void>((resolve) => (release = resolve)),
  );
  const rejected = tracker.run('profile-2', async () => Promise.reject(new Error('boom')));

  await tracker.waitForIdle('profile-2');
  await assert.rejects(rejected, /boom/);
  release();
  await blocked;
  await tracker.waitForIdle('profile-1');
});

test('keyed task tracker waits for tasks across every key', async () => {
  const tracker = new KeyedTaskTracker<string>();
  const releases: Array<() => void> = [];
  let completed = 0;
  for (const key of ['profile-1', 'profile-2']) {
    void tracker.run(key, async () => {
      await new Promise<void>((resolve) => releases.push(resolve));
      completed++;
    });
  }

  await Promise.resolve();
  const waiting = tracker.waitForAllIdle();
  releases.splice(0).forEach((release) => release());
  await waiting;
  assert.equal(completed, 2);
});
