import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  tunnelKinds,
  tunnelKindLabel,
  tunnelDefaultSettings,
  tunnelEditorFields,
} from '../src/tunnel-editor-schema.ts';
import { consumeVaultTunnelProjection, vaultTunnelFields } from '../src/vault-tunnel-form.ts';
import { fortinetIPsecDefaults } from '../src/fortinet-ipsec-state.ts';

const native = readFileSync(
  new URL('../tools/wormhole-backend/vault_tunnel_editor.go', import.meta.url),
  'utf8',
);
const display = readFileSync(
  new URL('../tools/wormhole-backend/vault_tunnel_display.go', import.meta.url),
  'utf8',
);
const publicNames = new Set(display.match(/const names = "([^"]+)"/)![1].split(' '));
function fields(kind: number) {
  return native.match(new RegExp('case ' + kind + ':\\s*fields = "([^"]+)"'))![1].split(' ');
}
function sample(kind: number, field: string): unknown {
  if (
    [
      'UseSingleSignOn',
      'UseExternalBrowser',
      'TrustServerCertificate',
      'UseOtp',
      'AutoProposals',
      'DeadPeerDetection',
      'NatTraversal',
      'EnableLocalLan',
      'Phase2TimeLifetime',
      'Phase2ByteLifetime',
      'ReplayDetection',
      'Pfs',
    ].includes(field)
  )
    return false;
  if (
    [
      'Mtu',
      'Port',
      'PersistentKeepaliveSeconds',
      'SamlRedirectPort',
      'AuthMode',
      'Protocol',
      'OpenVpnTransportOverride',
      'OpenVpnCompressionFramingOverride',
      'KeepaliveSeconds',
      'AuthMethod',
      'UserAuth',
      'SamlPort',
      'IkeVersion',
      'ExchangeMode',
      'AddressAssignment',
      'Phase1Encryption',
      'Phase1Authentication',
      'Phase1Encryption2',
      'Phase1Authentication2',
      'Phase1Lifetime',
      'Phase2Encryption',
      'Phase2Authentication',
      'Phase2Encryption2',
      'Phase2Authentication2',
      'Phase2Lifetime',
      'Phase2LifetimeKb',
      'PfsGroup',
    ].includes(field) ||
    (field === 'Mode' && kind !== 8)
  )
    return 1;
  if (['Dns', 'AllowedIps', 'Servers'].includes(field)) return ['first', 'second'];
  return field === 'Mode' ? 'manual' : 'public-value';
}
function projection(kind = 1): any {
  return { name: 'Tunnel', kind, settings: {}, present: [] };
}
function consume(value: unknown) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  try {
    return consumeVaultTunnelProjection(bytes);
  } finally {
    assert.ok(
      bytes.every((b) => b === 0),
      'Borrowed plaintext was retained',
    );
  }
}

test('shared schema retains all provider labels, control types, defaults and independent drafts', () => {
  assert.deepEqual(
    tunnelKinds.map((k) => k.value),
    [0, 1, 2, 9, 3, 4, 5, 6, 7, 8],
  );
  for (const kind of tunnelKinds) {
    assert.equal(tunnelKindLabel(kind.value), kind.label);
    const ordinary = tunnelEditorFields(kind.value),
      protectedFields = vaultTunnelFields(kind.value);
    const keys = fields(kind.value);
    assert.ok(protectedFields.length > 0);
    assert.equal(new Set(protectedFields.map((f) => f.key)).size, protectedFields.length);
    for (const field of protectedFields) {
      assert.ok(keys.includes(field.key), `${kind.label}: unexpected editable field ${field.key}`);
      assert.equal(
        field.secret,
        !publicNames.has(field.key),
        `${kind.label}: incorrect secret classification ${field.key}`,
      );
      if (field.secret) assert.ok(field.type === 'password' || field.type === 'textarea');
    }
    for (const field of ordinary) {
      const corresponding = protectedFields.find((f) => f.key === field.key)!;
      assert.equal(corresponding.label, field.label);
      assert.equal(corresponding.section, field.section);
      assert.deepEqual(corresponding.options, field.options);
      if (!corresponding.secret) assert.equal(corresponding.type, field.type);
    }
    const defaults = tunnelDefaultSettings(kind.value),
      fresh = tunnelDefaultSettings(kind.value);
    assert.deepEqual(defaults, fresh);
    defaults.changed = 1;
    assert.equal(fresh.changed, undefined);
    const again = vaultTunnelFields(kind.value);
    protectedFields[0].label = 'changed';
    assert.notEqual(again[0].label, 'changed');
  }
  assert.equal(tunnelKindLabel(99), 'Unknown');
  assert.deepEqual(tunnelEditorFields(99), []);
  assert.deepEqual(tunnelDefaultSettings(99), {});
  assert.deepEqual(vaultTunnelFields(99), []);
  assert.ok(!vaultTunnelFields(5).some((field) => field.key === 'ServerSecretHex'));
  const ssh = vaultTunnelFields(8);
  assert.equal(ssh.find((f) => f.key === 'JumpConnectionId')!.reference, 'connection');
  assert.equal(ssh.find((f) => f.key === 'CredentialId')!.reference, 'credential');
  assert.ok(!ssh.some((f) => f.key === 'HostKeySha256'));
  assert.deepEqual(tunnelDefaultSettings(2), { Port: 443 });
  const ipsecDefaults = tunnelDefaultSettings(9);
  assert.deepEqual(ipsecDefaults, fortinetIPsecDefaults);
  ipsecDefaults.Port = 0;
  assert.equal(tunnelDefaultSettings(9).Port, 500);
  assert.equal(fortinetIPsecDefaults.Port, 500);
  assert.ok(vaultTunnelFields(9).some((f) => f.key === 'PreSharedKey' && f.secret));
  assert.deepEqual(tunnelDefaultSettings(8), { Mode: 'connection', KeepaliveSeconds: 30 });
});

test('redacted form consumes every native provider projection without hydrating stored factors', () => {
  for (let kind = 0; kind <= 9; kind++) {
    const value = projection(kind);
    for (const field of fields(kind)) {
      if (publicNames.has(field)) value.settings[field] = sample(kind, field);
      else value.present.push(field);
    }
    assert.deepEqual(consume(value), value);
    const nulls = structuredClone(value);
    for (const field of Object.keys(nulls.settings)) nulls.settings[field] = null;
    assert.deepEqual(consume(nulls), nulls);
    for (const field of fields(kind).filter((f) => !publicNames.has(f))) {
      const injected = structuredClone(value);
      injected.settings[field] = 'stored-secret-must-not-be-hydrated';
      assert.throws(
        () => consume(injected),
        (error) => !String(error).includes('stored-secret'),
      );
    }
  }
  for (const field of ['Dns', 'AllowedIps']) {
    const value = projection(0);
    value.settings[field] = '1, 2';
    assert.deepEqual(consume(value), value);
  }
  const padded = projection();
  padded.name = '😀'.repeat(128);
  assert.deepEqual(consume(padded), padded);
});

test('projection rejects unbounded, malformed, cross-provider and wrong-shaped display data and wipes input', () => {
  for (const raw of [
    new Uint8Array([255]),
    new TextEncoder().encode('{'),
    new Uint8Array(512 * 1024 + 1).fill(32),
  ]) {
    assert.throws(() => consumeVaultTunnelProjection(raw), /could not be read/);
    assert.ok(raw.every((b) => b === 0));
  }
  for (const bad of [
    null,
    [],
    {},
    { ...projection(), extra: 1 },
    ...['', ' ', 'x'.repeat(129), '😀'.repeat(129), '\ud800', 'x\0'].map((name) => ({
      ...projection(),
      name,
    })),
    ...[-1, 10, 0.5, '1', null].map((kind) => ({ ...projection(), kind })),
    ...[null, [], false].map((settings) => ({ ...projection(), settings })),
    ...[
      null,
      {},
      ['Password', 'Password'],
      ['ProfileOvpn', 'Password', 'Password', 'Password'],
      [false],
      ['Unknown'],
      ['Username'],
      ['ClientKeyPem'],
    ].map((present) => ({ ...projection(), present })),
    { ...projection(), settings: { LegacyCookie: 'secret' } },
    { ...projection(), settings: { Host: 'foreign-provider' } },
    { ...projection(8), settings: { Mode: 1 } },
    { ...projection(4), settings: { Mode: '1' } },
    ...[true, '443', Number.MAX_SAFE_INTEGER + 1, 1.1, {}].map((Port) => ({
      ...projection(2),
      settings: { Port },
    })),
    ...[1, 'true', [], {}].map((UseSingleSignOn) => ({
      ...projection(2),
      settings: { UseSingleSignOn },
    })),
    ...[1, false, {}, [null], new Array(257).fill('x')].map((Dns) => ({
      ...projection(0),
      settings: { Dns },
    })),
    ...[1, false, {}, [], 'a\0', '\ud800'].map((Host) => ({
      ...projection(2),
      settings: { Host },
    })),
  ])
    assert.throws(() => consume(bad), /could not be read/);
  const polluted = JSON.parse(
    '{"name":"Tunnel","kind":1,"settings":{"__proto__":{}},"present":[]}',
  );
  assert.throws(() => consume(polluted));
});
