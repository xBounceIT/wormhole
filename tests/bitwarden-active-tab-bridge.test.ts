import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createBitwardenActiveTabContext,
  selectBitwardenTabRegistrationPartition,
} from '../electron/bitwarden-active-tab-bridge.ts';

test('direct and SOCKS targets expose the live redirect URL', () => {
  const context = createBitwardenActiveTabContext(
    'https://appliance.example/',
    undefined,
    'https://login.appliance.example/sso/callback#complete',
  );
  assert.deepEqual(context, {
    physicalUrl: 'https://login.appliance.example/sso/callback#complete',
    logicalUrl: 'https://login.appliance.example/sso/callback#complete',
  });
});

test('forwarder targets expose the original authority with the live path', () => {
  const context = createBitwardenActiveTabContext(
    'https://127.0.0.1:51515/',
    'https://appliance.example:8443/',
    'https://127.0.0.1:51515/admin/page?section=vpn#status',
  );
  assert.deepEqual(context, {
    physicalUrl: 'https://127.0.0.1:51515/admin/page?section=vpn#status',
    logicalUrl: 'https://appliance.example:8443/admin/page?section=vpn#status',
  });
});

test('non-web current URLs fall back to the initial target', () => {
  assert.deepEqual(
    createBitwardenActiveTabContext('https://appliance.example/', undefined, 'about:blank'),
    {
      physicalUrl: 'https://appliance.example/',
      logicalUrl: 'https://appliance.example/',
    },
  );
});

test('HTTPS tabs register only after Bitwarden exposes an active popup context', () => {
  assert.equal(selectBitwardenTabRegistrationPartition('persist:prepared', undefined), undefined);
  assert.equal(
    selectBitwardenTabRegistrationPartition('persist:prepared', 'persist:other'),
    undefined,
  );
  assert.equal(
    selectBitwardenTabRegistrationPartition('persist:prepared', 'persist:prepared'),
    'persist:prepared',
  );
});
