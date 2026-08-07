import assert from 'node:assert/strict';
import test from 'node:test';
import { getInSessionNavigationUrl } from '../electron/web-new-window-navigation.ts';

test('direct and SOCKS sessions keep HTTP targets in the current browser surface', () => {
  assert.equal(
    getInSessionNavigationUrl('  https://vault.bitwarden.com/#/login  '),
    'https://vault.bitwarden.com/#/login',
  );
  assert.equal(
    getInSessionNavigationUrl('http://appliance.local/help'),
    'http://appliance.local/help',
  );
});

test('blank and about:blank targets are suppressed', () => {
  for (const target of [
    undefined,
    '',
    ' ',
    'about:blank',
    'ABOUT:blank#blocked',
    'about:blank?popup',
  ]) {
    assert.equal(getInSessionNavigationUrl(target), undefined);
  }
});

test('forwarder sessions rewrite the original appliance origin through loopback', () => {
  assert.equal(
    getInSessionNavigationUrl(
      'https://fw.local:443/dashboard?tab=vpn#status',
      'https://127.0.0.1:51515/',
      'https://fw.local:443/',
    ),
    'https://127.0.0.1:51515/dashboard?tab=vpn#status',
  );
});

test('forwarder sessions keep already routed targets and reject route escapes', () => {
  assert.equal(
    getInSessionNavigationUrl(
      'https://127.0.0.1:51515/dashboard',
      'https://127.0.0.1:51515/',
      'https://fw.local:443/',
    ),
    'https://127.0.0.1:51515/dashboard',
  );
  for (const target of [
    'https://docs.example.com/',
    'https://fw.local:8443/dashboard',
    '/relative-popup',
  ]) {
    assert.equal(
      getInSessionNavigationUrl(target, 'https://127.0.0.1:51515/', 'https://fw.local:443/'),
      undefined,
    );
  }
});
