import assert from 'node:assert/strict';
import test from 'node:test';
import { shouldDeferExtensionReload } from '../electron/extension-reload-policy.ts';

test('extension update is deferred while its browser partition has live tabs', () => {
  assert.equal(shouldDeferExtensionReload('old-install', 'new-install', 1), true);
});

test('extension can reload after the last browser tab closes', () => {
  assert.equal(shouldDeferExtensionReload('old-install', 'new-install', 0), false);
});

test('an already loaded install is reused without entering the deferral path', () => {
  assert.equal(shouldDeferExtensionReload('same-install', 'same-install', 2), false);
  assert.equal(shouldDeferExtensionReload(undefined, 'first-install', 2), false);
});
