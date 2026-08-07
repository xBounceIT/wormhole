import assert from 'node:assert/strict';
import test from 'node:test';
import {
  isTunnelTestCancellation,
  isTunnelTestNotice,
  missingTunnelFields,
  normalizeTunnelEditorSettings,
  tunnelModeFor,
  tunnelValueFor,
  userFacingTunnelError,
} from '../src/tunnel-state.ts';

const tunnelId = 'b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7';

test('VPN route state preserves independent enable and config inheritance', () => {
  const states = [
    { tunnelEnabled: null, tunnelConfigId: '' },
    { tunnelEnabled: false, tunnelConfigId: '' },
    { tunnelEnabled: true, tunnelConfigId: '' },
    { tunnelEnabled: true, tunnelConfigId: tunnelId },
    { tunnelEnabled: null, tunnelConfigId: tunnelId },
  ] as const;

  for (const state of states) {
    assert.deepEqual(tunnelValueFor(tunnelModeFor(state)), state);
  }
});

test('recoverable Stormshield outcomes are informational tunnel-test notices', () => {
  assert.equal(
    isTunnelTestNotice(
      'Stormshield downloaded and protected a fresh VPN profile; connect again with a new one-time code',
    ),
    true,
  );
  assert.equal(
    isTunnelTestNotice(
      'that Stormshield one-time code was just used; wait until your authenticator shows a new code',
    ),
    true,
  );
  assert.equal(
    isTunnelTestNotice(
      'Stormshield downloaded a fresh VPN profile, but could not protect its cache; reconnecting will download it again',
    ),
    true,
  );
  assert.equal(isTunnelTestNotice('the VPN gateway rejected the credentials'), false);
});

test('VPN editor normalizes every numeric input and removes cleared optional values', () => {
  assert.deepEqual(
    normalizeTunnelEditorSettings(2, {
      Port: ' 10443 ',
      SamlRedirectPort: '8020',
      Mtu: '',
      PersistentKeepaliveSeconds: '   ',
    }),
    { Port: 10443, SamlRedirectPort: 8020 },
  );
});

test('VPN editor matches WinUI normalization for Fortinet and Cisco secrets', () => {
  assert.deepEqual(
    normalizeTunnelEditorSettings(2, {
      Host: 'vpn.example.com',
      UseSingleSignOn: true,
      UseExternalBrowser: true,
      Username: 'must-go',
      Password: 'must-go',
      TotpSecret: ' ABCD EFGH ',
      Realm: 'must-go',
      ServerCertSha256Pin: ' ab cd ',
    }),
    {
      Host: 'vpn.example.com',
      UseSingleSignOn: true,
      UseExternalBrowser: true,
      ServerCertSha256Pin: 'abcd',
    },
  );
  assert.deepEqual(
    normalizeTunnelEditorSettings(6, {
      Host: 'vpn.example.com',
      Username: 'alice',
      Password: 'secret\r\n',
      Group: '  ',
      TotpSecret: 'ABCD EFGH',
      SecondaryPassword: 'push\r\n',
      ServerCertSha256Pin: ' abcd ',
    }),
    {
      Host: 'vpn.example.com',
      Username: 'alice',
      Password: 'secret',
      TotpSecret: 'ABCDEFGH',
      SecondaryPassword: 'push',
      ServerCertSha256Pin: 'abcd',
    },
  );
});

test('missing tunnel fields match the WinUI required-field gates', () => {
  assert.deepEqual(
    missingTunnelFields({
      name: '',
      kind: 0,
      settings: { InterfacePrivateKey: '', InterfaceAddress: '10.0.0.2/32' },
    }),
    ['Name', 'Interface private key', 'Peer public key', 'Peer endpoint'],
  );
  assert.deepEqual(
    missingTunnelFields({
      name: 'Forti',
      kind: 2,
      settings: {
        Host: 'vpn.example.com',
        Port: 443,
        UseSingleSignOn: true,
        UseExternalBrowser: true,
        SamlRedirectPort: 8020,
      },
    }),
    [],
  );
  assert.deepEqual(
    missingTunnelFields({
      name: 'Cisco',
      kind: 6,
      settings: { Host: 'vpn.example.com', Port: 443, Username: 'alice' },
    }),
    ['Password'],
  );
});

test('user-facing tunnel errors strip the Electron IPC wrapper', () => {
  assert.equal(
    userFacingTunnelError(
      new Error(
        "Error invoking remote method 'tunnel:test': Error: VPN authentication was cancelled",
      ),
    ),
    'VPN authentication was cancelled',
  );
  assert.equal(
    userFacingTunnelError(new Error('VPN authentication was cancelled')),
    'VPN authentication was cancelled',
  );
});

test('VPN test cancellation detection only matches voluntary cancellation messages', () => {
  assert.equal(isTunnelTestCancellation('VPN authentication was cancelled'), true);
  assert.equal(isTunnelTestCancellation('VPN tunnel establishment was cancelled'), true);
  assert.equal(isTunnelTestCancellation('the operation was cancelled'), true);
  assert.equal(
    isTunnelTestCancellation('the VPN gateway cancelled the session mid-handshake'),
    false,
  );
  assert.equal(
    isTunnelTestCancellation(
      'the VPN gateway rejected the username, password, or authentication step',
    ),
    false,
  );
});
