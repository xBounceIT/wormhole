import assert from 'node:assert/strict';
import test from 'node:test';
import {
  appendTunnelTestLog,
  isTunnelTestCancellation,
  isTunnelTestNotice,
  missingTunnelFields,
  normalizeTunnelEditorSettings,
  parseTunnelProbeTarget,
  tunnelModeFor,
  tunnelTestPhaseLabel,
  tunnelValueFor,
  updateTunnelEditorSetting,
  userFacingTunnelError,
  watchguardSsoEnabledForEditor,
} from '../src/tunnel-state.ts';

const tunnelId = 'b2a0a6b0-69c8-4f3e-a4cb-f3395aa0a9f7';

test('VPN route state only exposes inherit, off, or an explicit tunnel', () => {
  const states = [
    { tunnelEnabled: null, tunnelConfigId: '' },
    { tunnelEnabled: false, tunnelConfigId: '' },
    { tunnelEnabled: true, tunnelConfigId: tunnelId },
  ] as const;

  for (const state of states) {
    assert.deepEqual(tunnelValueFor(tunnelModeFor(state)), state);
  }

  assert.equal(tunnelModeFor({ tunnelEnabled: null, tunnelConfigId: tunnelId }), tunnelId);
  assert.equal(tunnelModeFor({ tunnelEnabled: true, tunnelConfigId: '' }), 'inherit');
  assert.deepEqual(tunnelValueFor('on'), { tunnelEnabled: null, tunnelConfigId: '' });
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

test('VPN editor removes WatchGuard credentials for SSO and obsolete Stormshield SSO state', () => {
  assert.deepEqual(
    normalizeTunnelEditorSettings(3, {
      Server: 'firebox.example.com',
      AuthMode: 0,
      UseSingleSignOn: true,
      Username: 'must-go',
      Password: 'must-go',
    }),
    {
      Server: 'firebox.example.com',
      AuthMode: 2,
      UseSingleSignOn: true,
      VerifyX509Name: '/O=WatchGuard_Technologies/OU=Fireware/CN=Fireware_SSLVPN_Server',
    },
  );
  assert.deepEqual(
    normalizeTunnelEditorSettings(4, {
      Server: 'sns.example.com',
      Username: 'alice',
      Password: 'secret\r\n',
      UseSingleSignOn: true,
    }),
    {
      Server: 'sns.example.com',
      Username: 'alice',
      Password: 'secret',
      Mode: 0,
      AppToken: 'sslclient',
    },
  );
});

test('WatchGuard editor keeps the SSO checkbox, authentication mode, and credentials atomic', () => {
  const credentials = { AuthMode: 1, Username: 'alice', Password: 'secret' };
  assert.deepEqual(updateTunnelEditorSetting(3, credentials, 'UseSingleSignOn', true), {
    AuthMode: 2,
    UseSingleSignOn: true,
  });
  assert.deepEqual(
    updateTunnelEditorSetting(3, { AuthMode: 2, UseSingleSignOn: true }, 'UseSingleSignOn', false),
    { AuthMode: 0, UseSingleSignOn: false },
  );
  assert.deepEqual(updateTunnelEditorSetting(3, credentials, 'AuthMode', 2), {
    AuthMode: 2,
    UseSingleSignOn: true,
  });
  assert.deepEqual(updateTunnelEditorSetting(4, credentials, 'UseOtp', true), {
    ...credentials,
    UseOtp: true,
  });
});

test('WatchGuard editor preserves legacy automatic SSO without reclassifying manual profiles', () => {
  assert.equal(watchguardSsoEnabledForEditor({ AuthMode: 0 }), true);
  assert.equal(
    watchguardSsoEnabledForEditor({ AuthMode: 0, Username: 'alice', Password: 'secret' }),
    false,
  );
  assert.equal(
    watchguardSsoEnabledForEditor({ AuthMode: 0, ProfileOvpn: 'client\nremote firebox 443' }),
    false,
  );
  assert.equal(watchguardSsoEnabledForEditor({ AuthMode: 0, UseSingleSignOn: false }), false);
  assert.equal(watchguardSsoEnabledForEditor({ AuthMode: 2 }), true);
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
  assert.deepEqual(
    missingTunnelFields({
      name: 'WatchGuard SSO',
      kind: 3,
      settings: {
        Server: 'firebox.example.com',
        Port: 443,
        AuthMode: 2,
        UseSingleSignOn: true,
      },
    }),
    [],
  );
  assert.deepEqual(
    missingTunnelFields({
      name: 'WatchGuard password',
      kind: 3,
      settings: {
        Server: 'firebox.example.com',
        Port: 443,
        AuthMode: 0,
        UseSingleSignOn: false,
      },
    }),
    ['Username', 'Password'],
  );
  assert.deepEqual(
    missingTunnelFields({
      name: 'Stormshield',
      kind: 4,
      settings: {
        Server: 'sns.example.com',
        Port: 443,
        Mode: 0,
        UseSingleSignOn: true,
      },
    }),
    ['Username', 'Password'],
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
  assert.equal(isTunnelTestCancellation('VPN tunnel test was cancelled.'), true);
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

test('VPN tunnel target probes require a complete bounded host and port pair', () => {
  assert.deepEqual(parseTunnelProbeTarget('', ''), {});
  assert.deepEqual(parseTunnelProbeTarget('', '22'), {
    error: 'Target host is required when a target port is provided.',
  });
  assert.deepEqual(parseTunnelProbeTarget('server.internal', ''), {
    error: 'Target port must be between 1 and 65535.',
  });
  assert.deepEqual(parseTunnelProbeTarget(' server.internal ', ' 22 '), {
    target: { host: 'server.internal', port: 22 },
  });
  assert.match(parseTunnelProbeTarget('bad\nhost', '443').error ?? '', /invalid/i);
  assert.match(parseTunnelProbeTarget('server.internal', '0').error ?? '', /between/i);
  assert.match(parseTunnelProbeTarget('server.internal', '65536').error ?? '', /between/i);
  assert.match(parseTunnelProbeTarget('server.internal', '22.5').error ?? '', /between/i);
  assert.match(parseTunnelProbeTarget('server.internal', '1e2').error ?? '', /between/i);
});

test('VPN diagnostics label native phases and retain a bounded timestamped log', () => {
  assert.equal(
    tunnelTestPhaseLabel('authenticating', 'detail'),
    'Authenticating with the VPN gateway',
  );
  assert.equal(tunnelTestPhaseLabel('provider-step', 'Provider detail'), 'Provider detail');

  const timestamp = new Date('2026-08-09T12:34:56Z');
  const initial = appendTunnelTestLog([], 'Starting\nprovider', timestamp, 2);
  assert.equal(initial.length, 1);
  assert.match(initial[0], /^\[.+\] Starting provider$/);
  const bounded = appendTunnelTestLog(
    appendTunnelTestLog(initial, 'Second', timestamp, 2),
    'Third',
    timestamp,
    2,
  );
  assert.equal(bounded.length, 2);
  assert.match(bounded[0], /Second$/);
  assert.match(bounded[1], /Third$/);
});
