import { tunnelEditorFields, type TunnelField } from './tunnel-editor-schema.ts';
import { vaultRecord, vaultFields, vaultMetadataText } from '../electron/vault-contract.ts';

export type VaultTunnelField = Omit<TunnelField, 'options'> & {
  options?: { value: string | number; label: string }[];
  reference?: 'connection' | 'credential' | 'tunnel';
  secret: boolean;
};
const secretFields = new Set([
  'InterfacePrivateKey',
  'PeerPresharedKey',
  'Password',
  'SecondaryPassword',
  'TotpSecret',
  'ClientKeyPem',
  'ClientCertPem',
  'CaPem',
  'ProfileOvpn',
  'ServerSecretHex',
  'AppToken',
  'PreSharedKey',
  'ClientCert',
  'ClientKey',
  'CaCert',
]);
const publicFields = new Set(
  (
    'InterfaceAddress Mtu Dns PeerPublicKey PeerEndpoint AllowedIps ' +
    'PersistentKeepaliveSeconds Username Host Port Realm UseSingleSignOn UseSamlCallback UseExternalBrowser ' +
    'SamlRedirectPort TrustServerCertificate ServerCertSha256Pin Server AuthMode Domain ' +
    'VerifyX509Name Mode Description UseOtp OpenVpnTransportOverride OpenVpnCompressionFramingOverride ' +
    'Servers Protocol TenantId Audience ApplicationId Issuer Group JumpConnectionId CredentialId ' +
    'HostKeySha256 KeepaliveSeconds RemoteGateways AuthMethod UserAuth SamlPort IkeVersion ExchangeMode AddressAssignment ManualAddress ManualDns Phase1Encryption Phase1Authentication Phase1Encryption2 Phase1Authentication2 DhGroups Phase1Lifetime LocalId RemoteId DeadPeerDetection NatTraversal EnableLocalLan Phase2Encryption Phase2Authentication Phase2Encryption2 Phase2Authentication2 Phase2TimeLifetime Phase2Lifetime Phase2ByteLifetime Phase2LifetimeKb ReplayDetection Pfs PfsGroup AutoProposals FallbackTunnelId'
  ).split(' '),
);
const booleanFields = new Set([
  'UseSingleSignOn',
  'UseSamlCallback',
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
]);
const numberFields = new Set([
  'Mtu',
  'Port',
  'PersistentKeepaliveSeconds',
  'SamlRedirectPort',
  'AuthMode',
  'OpenVpnTransportOverride',
  'OpenVpnCompressionFramingOverride',
  'Protocol',
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
]);
const listFields = new Set(['Dns', 'AllowedIps', 'Servers']);

// The ordinary editor and isolated editor share labels, defaults and field
// sections. Secret classification is explicit and independent of input styling.
export function vaultTunnelFields(kind: number): VaultTunnelField[] {
  if (!Number.isInteger(kind) || kind < 0 || kind > 9) return [];
  let fields: Omit<VaultTunnelField, 'secret'>[] = tunnelEditorFields(kind);
  if (kind === 9)
    fields = [
      ...fields,
      { key: 'PreSharedKey', label: 'Pre-shared key', section: 'Authentication', type: 'password' },
      {
        key: 'Password',
        label: 'Saved login password',
        section: 'Authentication',
        type: 'password',
      },
      ...(['ClientCert', 'ClientKey', 'CaCert'] as const).map((key) => ({
        key,
        label:
          key === 'ClientCert'
            ? 'Client certificate (PEM)'
            : key === 'ClientKey'
              ? 'Client private key (PEM)'
              : 'CA certificates (PEM)',
        section: 'Authentication',
        type: 'textarea' as const,
      })),
      {
        key: 'FallbackTunnelId',
        label: 'SSL VPN fallback',
        section: 'Gateway',
        reference: 'tunnel',
      },
    ];
  if (kind === 8)
    fields = [
      {
        key: 'Mode',
        label: 'SSH tunnel mode',
        type: 'select',
        section: 'Gateway',
        options: [
          { value: 'connection', label: 'Saved SSH connection' },
          { value: 'manual', label: 'Manual jump host' },
        ],
      },
      {
        key: 'JumpConnectionId',
        label: 'SSH connection',
        section: 'Gateway',
        reference: 'connection',
      },
      { key: 'Host', label: 'Host', section: 'Gateway' },
      { key: 'Port', label: 'Port', section: 'Gateway', type: 'number' },
      { key: 'Username', label: 'Username', section: 'Authentication' },
      {
        key: 'CredentialId',
        label: 'Saved SSH credential',
        section: 'Authentication',
        reference: 'credential',
      },
      {
        key: 'KeepaliveSeconds',
        label: 'Keepalive interval (seconds)',
        section: 'Advanced',
        type: 'number',
      },
    ];
  return fields.map((field) => ({
    ...field,
    secret: secretFields.has(field.key),
    ...(secretFields.has(field.key) && field.type !== 'textarea'
      ? { type: 'password' as const }
      : {}),
  }));
}
export type VaultTunnelProjection = {
  name: string;
  kind: number;
  settings: Record<string, string | number | boolean | string[] | null>;
  present: string[];
};

function displayValue(kind: number, field: string, value: unknown): boolean {
  if (value === null) return true;
  if (booleanFields.has(field)) return typeof value === 'boolean';
  if (numberFields.has(field) || (field === 'Mode' && kind !== 8))
    return Number.isSafeInteger(value);
  if (listFields.has(field) && Array.isArray(value))
    return value.length <= 256 && value.every((item) => vaultMetadataText(item, 512 * 1024));
  return vaultMetadataText(value, 512 * 1024);
}

// Consume only the redacted projection. Even a known provider factor is refused
// in settings: saved secret values must never be hydrated into form controls.
export function consumeVaultTunnelProjection(bytes: Uint8Array): VaultTunnelProjection {
  try {
    if (bytes.length > 512 * 1024) throw Error('Invalid tunnel display.');
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (
      !vaultRecord(value) ||
      !vaultFields(value, ['name', 'kind', 'settings', 'present']) ||
      !vaultMetadataText(value.name, 512, true) ||
      [...value.name].length > 128 ||
      !Number.isInteger(value.kind) ||
      (value.kind as number) < 0 ||
      (value.kind as number) > 9 ||
      !vaultRecord(value.settings) ||
      !Array.isArray(value.present)
    )
      throw Error('Invalid tunnel display.');
    const kind = value.kind as number;
    const known = new Set(vaultTunnelFields(kind).map((field) => field.key));
    // Legacy compatibility fields have no editable control but remain native.
    if (kind === 2) {
      known.add('UseExternalBrowser');
      known.add('SamlRedirectPort');
    }
    if (kind === 3 || kind === 4) known.add('UseSingleSignOn');
    if (kind === 8) known.add('HostKeySha256');
    // Azure's server key remains import-owned, never a raw-key form control.
    if (kind === 5) known.add('ServerSecretHex');
    const settings: VaultTunnelProjection['settings'] = {};
    for (const [field, item] of Object.entries(value.settings)) {
      if (!known.has(field) || !publicFields.has(field) || !displayValue(kind, field, item))
        throw Error('Invalid tunnel display.');
      settings[field] = item as VaultTunnelProjection['settings'][string];
    }
    const present = value.present;
    if (
      present.length > known.size ||
      new Set(present).size !== present.length ||
      present.some(
        (field) => typeof field !== 'string' || !known.has(field) || !secretFields.has(field),
      )
    )
      throw Error('Invalid tunnel display.');
    return { name: value.name, kind, settings, present: [...present] };
  } catch {
    throw Error('Stored tunnel settings could not be read.');
  } finally {
    bytes.fill(0);
  }
}
