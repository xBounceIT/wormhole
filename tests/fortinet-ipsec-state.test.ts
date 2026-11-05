import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  fortinetIPsecDefaults,
  fortinetIPsecFields,
  missingFortinetIPsecFields,
  normalizeFortinetIPsecSettings,
} from '../src/fortinet-ipsec-state.ts';
import { missingTunnelFields, normalizeTunnelEditorSettings } from '../src/tunnel-state.ts';
import {
  parseTunnelWriteRequest,
  parseTunnelDetailsResponse,
} from '../electron/tunnel-test-contract.ts';

const settings = { ...fortinetIPsecDefaults, Host: 'vpn.test', PreSharedKey: ' key with spaces ' };

test('IPsec editor preserves PSK and strips SSL and ephemeral SAML credentials', () => {
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
  });
  assert.deepEqual(normalized, { ...settings, LocalId: 'client', TrustServerCertificate: false });
  assert.deepEqual(normalizeTunnelEditorSettings(9, settings), settings);
  assert.deepEqual(normalizeFortinetIPsecSettings({ Port: 'bad', SamlPort: null }), {
    Port: 'bad',
    SamlPort: null,
  });
  assert.deepEqual(normalizeFortinetIPsecSettings({ RemoteId: ' vpn.test ' }), {
    RemoteId: 'vpn.test',
  });
});

test('shared create/edit validation requires gateway, PSK and both transport ports', () => {
  assert.deepEqual(missingFortinetIPsecFields(settings), []);
  assert.deepEqual(missingTunnelFields({ name: 'IPsec', kind: 9, settings }), []);
  assert.deepEqual(missingTunnelFields({ name: '', kind: 9, settings }), ['Name']);
  for (const key of ['Host', 'PreSharedKey']) {
    for (const value of ['', ' ', null, 42])
      assert.ok(missingFortinetIPsecFields({ ...settings, [key]: value }).length);
  }
  for (const key of ['Port', 'SamlPort']) {
    for (const value of ['', ' ', 0, 65536, 1.2, false, null, undefined, 'wrong', '1.5'])
      assert.ok(missingFortinetIPsecFields({ ...settings, [key]: value }).length);
    for (const value of [1, 65535, ' 500 '])
      assert.deepEqual(missingFortinetIPsecFields({ ...settings, [key]: value }), []);
  }
});

test('IPsec settings use password masking and the shared editor in create and edit', () => {
  assert.equal(fortinetIPsecFields.find((field) => field.key === 'PreSharedKey')?.type, 'password');
  assert.ok(fortinetIPsecFields.some((field) => field.key === 'SamlPort'));
  assert.equal(
    fortinetIPsecFields.some((field) => /token|uid|username|password|cookie/i.test(field.key)),
    false,
  );
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(app, /value: 9, label: 'Fortinet IPsec \(SAML\)'/);
  assert.match(app, /if \(kind === 9\) return fortinetIPsecFields/);
  assert.match(app, /case 9:\s*return \{ \.\.\.fortinetIPsecDefaults \}/);
  const start = app.indexOf('{value.kind === 9 ? (');
  const surface = app.slice(start, app.indexOf('{value.kind === 7 ? (', start));
  for (const section of ['Gateway', 'Authentication', 'Advanced'])
    assert.ok(surface.includes(`rows('${section}')`));
  assert.match(surface, /SAML sign-in in a dedicated window/);
});

test('IPC admits the persisted IPsec kind and rejects unknown provider numbers', () => {
  const request = { name: 'IPsec', kind: 9, settings };
  assert.deepEqual(parseTunnelWriteRequest(request, false), request);
  const details = { ...request, id: '11111111-2222-3333-4444-555555555555' };
  assert.equal(parseTunnelDetailsResponse(details).kind, 9);
  assert.throws(() => parseTunnelWriteRequest({ ...request, kind: 10 }, false));
  assert.throws(() => parseTunnelDetailsResponse({ ...details, kind: 10 }));
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
