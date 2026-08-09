import assert from 'node:assert/strict';
import test from 'node:test';
import { KeyedRetryQueue } from '../src/keyed-retry-queue.ts';

test('keyed retry queue drains every waiting session after one unlock', () => {
  const queue = new KeyedRetryQueue<string>();
  const retried: string[] = [];

  assert.equal(
    queue.upsert('ssh:one', () => retried.push('ssh:one')),
    true,
  );
  assert.equal(
    queue.upsert('rdp:two', () => retried.push('rdp:two')),
    false,
  );

  for (const retry of queue.drain()) retry();

  assert.deepEqual(retried, ['ssh:one', 'rdp:two']);
  assert.deepEqual(queue.drain(), []);
});

test('keyed retry queue replaces duplicate session retries and removes closed sessions', () => {
  const queue = new KeyedRetryQueue<string>();
  const retried: string[] = [];

  queue.upsert('vnc:one', () => retried.push('stale'));
  queue.upsert('vnc:one', () => retried.push('current'));
  queue.upsert('ssh:closed', () => retried.push('closed'));
  queue.remove('ssh:closed');

  for (const retry of queue.drain()) retry();

  assert.deepEqual(retried, ['current']);
});

test('keyed retry queue cancellation discards every pending retry', () => {
  const queue = new KeyedRetryQueue<string>();
  let retried = false;

  queue.upsert('rdp:one', () => {
    retried = true;
  });
  queue.clear();
  for (const retry of queue.drain()) retry();

  assert.equal(retried, false);
  assert.equal(queue.isEmpty, true);
  assert.equal(
    queue.upsert('rdp:two', () => undefined),
    true,
  );
  assert.equal(queue.isEmpty, false);
});
