import assert from 'node:assert/strict';
import test from 'node:test';
import type { Cookie } from 'electron';
import {
  bitwardenCookieIdentity,
  buildBitwardenCookieRefreshPlan,
  buildBitwardenCookieSetDetails,
  getBitwardenCookieHosts,
  selectBitwardenCookiesForTarget,
} from '../electron/bitwarden-cookie-seed.ts';

function cookie(overrides: Partial<Cookie>): Cookie {
  return {
    name: 'session',
    value: 'secret',
    sameSite: 'lax',
    domain: 'router.example.com',
    path: '/',
    secure: true,
    httpOnly: true,
    session: true,
    hostOnly: true,
    ...overrides,
  };
}

test('Bitwarden cookie migration includes the target and parent domains only', () => {
  assert.deepEqual(
    [...getBitwardenCookieHosts('https://router.office.example.com:8443/login')],
    ['router.office.example.com', 'office.example.com', 'example.com'],
  );
  const selected = selectBitwardenCookiesForTarget(
    [
      cookie({ name: 'host', domain: 'router.office.example.com' }),
      cookie({ name: 'parent', domain: '.office.example.com', hostOnly: false }),
      cookie({ name: 'sibling', domain: 'other.office.example.com' }),
      cookie({ name: 'unrelated', domain: '.unrelated.example', hostOnly: false }),
    ],
    'https://router.office.example.com:8443/login',
  );
  assert.deepEqual(
    selected.map((value) => value.name),
    ['host', 'parent'],
  );
});

test('Bitwarden cookie migration keeps IP addresses scoped to the exact host', () => {
  assert.deepEqual([...getBitwardenCookieHosts('https://192.0.2.10/')], ['192.0.2.10']);
  assert.deepEqual([...getBitwardenCookieHosts('https://[2001:db8::10]/')], ['2001:db8::10']);
});

test('Bitwarden cookie migration never broadens host-only cookies', () => {
  const details = buildBitwardenCookieSetDetails(
    cookie({ path: '/admin', expirationDate: undefined, session: true }),
    'https://router.example.com:8443/login',
  );
  assert.equal(details.url, 'https://router.example.com:8443/admin');
  assert.equal(details.domain, undefined);
  assert.equal(details.expirationDate, undefined);
  assert.equal(details.value, 'secret');
});

test('Bitwarden cookie migration preserves domain and persistence attributes', () => {
  const details = buildBitwardenCookieSetDetails(
    cookie({
      domain: '.example.com',
      hostOnly: false,
      expirationDate: 2_000_000_000,
      session: false,
      sameSite: 'no_restriction',
    }),
    'https://router.example.com/',
  );
  assert.equal(details.domain, '.example.com');
  assert.equal(details.expirationDate, 2_000_000_000);
  assert.equal(details.sameSite, 'no_restriction');
});

test('Bitwarden cookie refresh identity distinguishes domain, path, and name', () => {
  assert.equal(
    bitwardenCookieIdentity(cookie({ domain: '.Example.COM', path: '/admin', name: 'session' })),
    'example.com\0/admin\0session',
  );
  assert.notEqual(
    bitwardenCookieIdentity(cookie({ path: '/admin' })),
    bitwardenCookieIdentity(cookie({ path: '/' })),
  );
});

test('Bitwarden cookie refresh replaces changed cookies and removes stale login state', () => {
  const retained = cookie({ name: 'retained', value: 'old' });
  const stale = cookie({ name: 'logged-in', value: 'stale' });
  const replacement = cookie({ name: 'retained', value: 'new' });
  const refresh = buildBitwardenCookieRefreshPlan([retained, stale], [replacement]);

  assert.deepEqual(refresh.set, [replacement]);
  assert.deepEqual(refresh.remove, [stale]);
  assert.deepEqual(buildBitwardenCookieRefreshPlan([stale], []).remove, [stale]);
});
