import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildBitwardenBrowserContext,
  buildBitwardenPersistentRouteKey,
  getBitwardenBrowserPartition,
} from '../electron/bitwarden-browser-profile.ts';

test('Bitwarden route identity is stable across runtime SOCKS endpoints', () => {
  const first = buildBitwardenPersistentRouteKey(
    '11111111-2222-3333-4444-555555555555',
    'socks5',
    'https://Router.Example:8443/login',
  );
  const second = buildBitwardenPersistentRouteKey(
    '11111111222233334444555555555555',
    'socks5',
    'https://router.example:8443/other',
  );
  assert.equal(first, second);
  assert.equal(first, '6c62bd6f334907a2a871f8247a697a868c6149352136a722bfe9df2ad45b782f');
});

test('Bitwarden SOCKS profiles isolate concurrent endpoints while sharing a route key', () => {
  const routeKey = buildBitwardenPersistentRouteKey(
    '11111111-2222-3333-4444-555555555555',
    'socks5',
    'https://router.example/',
  );
  const firstContext = buildBitwardenBrowserContext('socks5://127.0.0.1:41001', routeKey);
  const secondContext = buildBitwardenBrowserContext('socks5://127.0.0.1:41002', routeKey);
  assert.notEqual(
    getBitwardenBrowserPartition(firstContext, false),
    getBitwardenBrowserPartition(secondContext, false),
  );
  assert.match(firstContext, new RegExp(`route-key=${routeKey}$`));
  assert.match(secondContext, new RegExp(`route-key=${routeKey}$`));
});

test('Bitwarden forwarder profiles stay stable because they have no session-wide proxy', () => {
  const routeKey = buildBitwardenPersistentRouteKey(
    '11111111-2222-3333-4444-555555555555',
    'forwarder',
    'https://router.example/',
  );
  const context = buildBitwardenBrowserContext(undefined, routeKey);
  assert.equal(context, `route-key=${routeKey}`);
  const partition = getBitwardenBrowserPartition(context, false);
  assert.equal(getBitwardenBrowserPartition(context, false), partition);
});
