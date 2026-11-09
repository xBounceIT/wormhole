import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  fortinetIPsecDefaults,
  fortinetIPsecFields,
  missingFortinetIPsecFields,
  normalizeFortinetIPsecSettings,
  fortinetIPsecEditorSettings,
  fortinetIPsecFieldVisible,
} from '../src/fortinet-ipsec-state.ts';
import { missingTunnelFields, normalizeTunnelEditorSettings } from '../src/tunnel-state.ts';
import {
  parseTunnelWriteRequest,
  parseTunnelDetailsResponse,
} from '../electron/tunnel-test-contract.ts';

const settings = { ...fortinetIPsecDefaults, Host: 'vpn.test', HasPreSharedKey: true };

test('IPsec editor keeps only key presence and strips PSK, SSL and ephemeral credentials', () => {
  const normalized = normalizeFortinetIPsecSettings({
    ...settings,
    Host: ' vpn.test ',
    Port: ' 500 ',
    SamlPort: '1001',
    LocalId: ' client ',
    RemoteId: '',
    TrustServerCertificate: false,
    Username: 'ignored',
    Password: 'ignored',
    SamlUid: 'ignored',
    SamlToken: 'ignored',
    PreSharedKey: 'must-never-enter-editor-state',
  });
  assert.deepEqual(normalized, {
    ...settings,
    Username: 'ignored',
    LocalId: 'client',
    TrustServerCertificate: false,
  });
  assert.deepEqual(normalizeTunnelEditorSettings(9, settings), settings);
  assert.deepEqual(normalizeFortinetIPsecSettings({ Port: 'bad', SamlPort: null }), {
    Port: 'bad',
    SamlPort: null,
  });
  assert.deepEqual(normalizeFortinetIPsecSettings({ RemoteId: ' vpn.test ' }), {
    RemoteId: 'vpn.test',
  });
});

test('shared create/edit validation requires gateway and ports; the native save flow owns PSK input', () => {
  assert.deepEqual(missingFortinetIPsecFields(settings), []);
  assert.deepEqual(missingTunnelFields({ name: 'IPsec', kind: 9, settings }), []);
  assert.deepEqual(missingTunnelFields({ name: '', kind: 9, settings }), ['Name']);
  for (const key of ['Host']) {
    for (const value of ['', ' ', null, 42])
      assert.ok(missingFortinetIPsecFields({ ...settings, UserAuth: 3, [key]: value }).length);
  }
  for (const key of ['Port', 'SamlPort']) {
    for (const value of ['', ' ', 0, 65536, 1.2, false, null, undefined, 'wrong', '1.5'])
      assert.ok(missingFortinetIPsecFields({ ...settings, UserAuth: 3, [key]: value }).length);
    for (const value of [1, 65535, ' 500 '])
      assert.deepEqual(missingFortinetIPsecFields({ ...settings, UserAuth: 3, [key]: value }), []);
  }
});

test('IPsec editor exposes only key presence/replacement and uses the shared form', () => {
  assert.equal(
    fortinetIPsecFields.some((field) => field.key === 'PreSharedKey'),
    false,
  );
  assert.ok(fortinetIPsecFields.some((field) => field.key === 'SamlPort'));
  assert.equal(
    fortinetIPsecFields.some((field) => /token|uid|password|cookie/i.test(field.key)),
    false,
  );
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(app, /value: 9, label: 'Fortinet IPsec'/);
  assert.match(app, /if \(kind === 9\) return fortinetIPsecFields/);
  assert.match(app, /case 9:\s*return \{ \.\.\.fortinetIPsecDefaults \}/);
  const start = app.indexOf('{value.kind === 9 ? (');
  const surface = app.slice(start, app.indexOf('{value.kind === 7 ? (', start));
  for (const section of ['Gateway', 'Authentication', 'VPN settings', 'Phase 1', 'Phase 2'])
    assert.ok(surface.includes(`rows('${section}'`));
  assert.match(surface, /Has\$\{secret\}/);
  assert.match(surface, /Replace\$\{secret\}/);
  assert.match(surface, /separate secure window when\s+you save/);
  assert.match(surface, /ClientCert/);
});

test('new profiles choose PSK without SAML; existing profiles preserve their SAML behavior', () => {
  assert.equal(fortinetIPsecDefaults.UserAuth, 0);
  assert.equal(fortinetIPsecEditorSettings({ Host: 'vpn.test' }).UserAuth, 3);
  assert.equal(fortinetIPsecEditorSettings({ Host: 'vpn.test' }).AutoProposals, true);
  assert.equal(fortinetIPsecEditorSettings({ UserAuth: 2 }).UserAuth, 2);
  for (const auth of [0, 1, 2, 3]) {
    const value = { ...settings, UserAuth: auth };
    assert.equal(fortinetIPsecFieldVisible('Username', value), auth === 1 || auth === 2);
    assert.equal(fortinetIPsecFieldVisible('SamlPort', value), auth === 3);
    assert.equal(fortinetIPsecFieldVisible('TrustServerCertificate', value), auth === 3);
  }
  for (const [key, condition] of [
    ['ExchangeMode', 'IkeVersion'],
    ['ManualAddress', 'AddressAssignment'],
    ['ManualDns', 'AddressAssignment'],
  ] as const) {
    assert.equal(fortinetIPsecFieldVisible(key, { [condition]: 1 }), true);
    assert.equal(fortinetIPsecFieldVisible(key, { [condition]: 2 }), false);
  }
  for (const [key, condition] of [
    ['Phase2Lifetime', 'Phase2TimeLifetime'],
    ['Phase2LifetimeKb', 'Phase2ByteLifetime'],
    ['PfsGroup', 'Pfs'],
  ] as const) {
    assert.equal(fortinetIPsecFieldVisible(key, { [condition]: true }), true);
    assert.equal(fortinetIPsecFieldVisible(key, { [condition]: false }), false);
  }
  assert.equal(fortinetIPsecFieldVisible('Host', {}), true);
  assert.equal(fortinetIPsecFieldVisible('AutoProposals', { IkeVersion: 2 }), true);
  assert.equal(
    fortinetIPsecFieldVisible('DhGroups', { IkeVersion: 2, AutoProposals: true }),
    false,
  );
  assert.equal(
    fortinetIPsecFieldVisible('Phase1Encryption', { IkeVersion: 2, AutoProposals: true }),
    false,
  );
});

test('advanced fields, errors and credential markers survive the shared editor contract', () => {
  for (const field of fortinetIPsecFields) {
    const value =
      field.type === 'select'
        ? field.options![0].value
        : field.type === 'number'
          ? 100
          : field.type === 'switch'
            ? true
            : 'example';
    const input = {
      [field.key]: field.type === 'select' || field.type === 'number' ? String(value) : value,
    };
    const normalized = normalizeFortinetIPsecSettings(input);
    assert.equal(normalized[field.key], value);
    assert.doesNotThrow(() =>
      parseTunnelWriteRequest({ name: 'VPN', kind: 9, settings: normalized }, false),
    );
  }
  assert.deepEqual(missingFortinetIPsecFields({ ...settings, SamlPort: 'ignored' }), []);
  assert.ok(missingFortinetIPsecFields({ ...settings, UserAuth: 2 }).includes('Username'));
  assert.ok(
    missingFortinetIPsecFields({ ...settings, AddressAssignment: 1 }).includes(
      'Client IPv4 address',
    ),
  );
  assert.ok(
    missingFortinetIPsecFields({ ...settings, UserAuth: 3, IkeVersion: 1 }).includes(
      'SAML requires IKEv2',
    ),
  );
  assert.ok(
    missingFortinetIPsecFields({ ...settings, UserAuth: 3, AuthMethod: 1 }).includes(
      'SAML requires PSK',
    ),
  );
  for (const [key, value] of [
    ['IkeVersion', 4],
    ['Phase1Lifetime', 0],
    ['Phase2Lifetime', 'wrong'],
  ])
    assert.ok(missingFortinetIPsecFields({ ...settings, [key]: value }).length);
  for (const secret of ['PreSharedKey', 'Password', 'ClientCert', 'ClientKey', 'CaCert']) {
    const normalized = normalizeFortinetIPsecSettings({
      [secret]: 'never expose',
      [`Has${secret}`]: true,
      [`Replace${secret}`]: false,
    });
    assert.deepEqual(normalized, { [`Has${secret}`]: true, [`Replace${secret}`]: false });
    assert.throws(() =>
      parseTunnelWriteRequest({ name: 'VPN', kind: 9, settings: { [secret]: 'secret' } }, false),
    );
  }
  assert.throws(() =>
    parseTunnelWriteRequest(
      { name: 'VPN', kind: 9, settings: { Description: 'x'.repeat(32769) } },
      false,
    ),
  );
});

test('IPC admits the persisted IPsec kind and rejects unknown provider numbers', () => {
  const request = { name: 'IPsec', kind: 9, settings };
  assert.deepEqual(parseTunnelWriteRequest(request, false), request);
  const details = { ...request, id: '11111111-2222-3333-4444-555555555555' };
  assert.equal(parseTunnelDetailsResponse(details).kind, 9);
  assert.throws(() => parseTunnelWriteRequest({ ...request, kind: 10 }, false));
  assert.throws(() => parseTunnelDetailsResponse({ ...details, kind: 10 }));
  for (const key of ['PreSharedKey', 'SamlToken', 'SamlUid']) {
    assert.throws(() =>
      parseTunnelWriteRequest({ ...request, settings: { ...settings, [key]: 'secret' } }, false),
    );
    assert.throws(() =>
      parseTunnelDetailsResponse({ ...details, settings: { ...settings, [key]: 'secret' } }),
    );
  }
  for (const key of ['HasPreSharedKey', 'ReplacePreSharedKey']) {
    assert.throws(() =>
      parseTunnelWriteRequest({ ...request, settings: { ...settings, [key]: 'true' } }, false),
    );
  }
});

test('release and development plans include the IPsec sidecar on every platform', () => {
  for (const path of [
    'scripts/Build-ElectronBackend.mjs',
    'scripts/Build-ElectronUniversalBackend.mjs',
    'scripts/Build-ElectronVpnSidecars.ps1',
    'package.json',
  ]) {
    const source = readFileSync(new URL('../' + path, import.meta.url), 'utf8');
    assert.ok(source.includes('wormhole-fortiipsecproxy'), path);
  }
  const dev = readFileSync(new URL('../scripts/dev-runtime-plan.ts', import.meta.url), 'utf8');
  assert.ok(dev.includes("'tools/vendor/go-ipsec'"));
  assert.ok(dev.includes("'fortiipsecproxy'"));
});

test('IPsec and SAML consumers require the patched Go certificate toolchain', () => {
  for (const module of ['wormhole-backend', 'wormhole-fortiipsecproxy', 'vendor/go-ipsec']) {
    const source = readFileSync(new URL(`../tools/${module}/go.mod`, import.meta.url), 'utf8');
    const version = /^go (\d+)\.(\d+)\.(\d+)$/m.exec(source)?.slice(1).map(Number);
    assert.ok(version, module);
    const [major, minor, patch] = version;
    assert.ok(major > 1 || (major === 1 && (minor > 26 || (minor === 26 && patch >= 10))), module);
  }
});
