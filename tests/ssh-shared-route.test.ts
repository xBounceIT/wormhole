import assert from 'node:assert/strict';
import test from 'node:test';
import { SharedSshRoutes } from '../electron/ssh-shared-route.ts';
import { WindowCloseCoordinator } from '../electron/window-lifecycle.ts';

test('shared VPN routes survive closing the shell and repeated lifecycle notifications', () => {
  const routes = new SharedSshRoutes();
  routes.attach('shell', 'files');
  routes.attach('files', 'files-copy');
  assert.equal(routes.release('shell'), undefined);
  assert.equal(routes.release('shell'), undefined);
  assert.equal(routes.release('files'), undefined);
  assert.equal(routes.release('files'), undefined);
  assert.equal(routes.release('files-copy'), 'shell');
  assert.equal(routes.release('standalone'), 'standalone');
});

test('closing an SFTP tab first keeps both independent route groups alive', () => {
  const routes = new SharedSshRoutes();
  routes.attach('one', 'one-files');
  routes.attach('two', 'two-files');
  assert.equal(routes.release('one-files'), undefined);
  assert.equal(routes.release('two'), undefined);
  assert.equal(routes.release('one'), 'one');
  assert.equal(routes.release('two-files'), 'two');
});

test('backend restarts clear abandoned route groups', () => {
  const routes = new SharedSshRoutes();
  routes.attach('shell', 'pending');
  routes.clear();
  assert.equal(routes.release('shell'), 'shell');
});

test('pending edit checks run before closing an idle window and cancellation preserves its sessions', async () => {
  const coordinator = new WindowCloseCoordinator();
  const calls: string[] = [];
  const request = {
    reason: 'window' as const,
    confirmationEnabled: false,
    prepare: async () => {
      calls.push('edits');
      return false;
    },
    confirm: async () => {
      calls.push('sessions');
      return true;
    },
    teardown: async () => {
      calls.push('teardown');
    },
    close: () => {
      calls.push('close');
    },
  };
  assert.equal(await coordinator.request(request), false);
  assert.deepEqual(calls, ['edits']);
  assert.equal(await coordinator.request({ ...request, prepare: async () => true }), true);
  assert.deepEqual(calls, ['edits', 'teardown', 'close']);
});
