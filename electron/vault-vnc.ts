import { vaultFields, vaultMetadataText, vaultRecord } from './vault-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';
import {
  parseVaultRouteRequest,
  parseVaultRouteBinding,
  parseVaultRouteBundle,
  validVaultRouteEndpoint,
  type VaultRouteRequest,
  type VaultRouteBinding,
  type VaultRouteBundle,
} from './vault-route.ts';

// Native/main-only bundle API. The general app preload exposes no recipient or bundle.
export type VaultVncRequest = VaultRouteRequest;
export type VaultVncBundle = {
  binding: Omit<
    VaultRouteBinding,
    'fileId' | 'kind' | 'rowVersion' | 'configurationVersion' | 'tunnelConfigId' | 'protocol'
  > & {
    protocol: 'vnc';
    tunnelConfigId: '';
  };
  bundle: VaultRouteBundle['bundle'];
};
export type VaultRoutedVncRequest = VaultVncRequest & {
  route: VaultRouteBinding;
  endpoint: string;
};
export type VaultRoutedVncBundle = VaultRouteBundle & { endpoint: string };
const maximumCiphertext = 6 + 16384 + 16;
function vncCiphertext(value: unknown, manual = false): boolean {
  return (
    vaultRecord(value) &&
    vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) &&
    value.formatVersion === 1 &&
    value.suiteId === 2 &&
    canonicalBase64(value.enc, 32, 32) &&
    canonicalBase64(
      value.ciphertext,
      manual ? 75 : 22,
      manual ? maximumCiphertext + 53 : maximumCiphertext,
    )
  );
}

function parseVncBundle(
  value: unknown,
  request: VaultVncRequest,
  manual = false,
): VaultVncBundle | undefined {
  const q = parseVaultRouteRequest(request);
  if (!q || !vaultRecord(value) || !vaultFields(value, ['binding', 'bundle'])) return undefined;
  const b = value.binding,
    s = value.bundle;
  if (
    !vaultRecord(b) ||
    !vaultFields(b, [
      'workspaceId',
      'nodeId',
      'sessionId',
      'requestId',
      'protocol',
      'host',
      'port',
      'epoch',
      'tunnelConfigId',
      'useExternalClient',
    ]) ||
    b.workspaceId !== q.workspaceId ||
    b.nodeId !== q.nodeId ||
    b.sessionId !== q.sessionId ||
    b.requestId !== q.requestId ||
    b.epoch !== q.epoch ||
    b.protocol !== 'vnc' ||
    b.tunnelConfigId !== '' ||
    b.useExternalClient !== false ||
    !vaultMetadataText(b.host, 1024, true) ||
    /[\p{White_Space}\p{Cc}]/u.test(b.host) ||
    !Number.isInteger(b.port) ||
    (b.port as number) < 1 ||
    (b.port as number) > 65535 ||
    !vncCiphertext(s, manual)
  )
    return undefined;
  const bundle = s as VaultVncBundle['bundle'];
  return {
    binding: {
      workspaceId: q.workspaceId,
      nodeId: q.nodeId,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: q.epoch,
      protocol: 'vnc',
      host: b.host,
      port: b.port as number,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    bundle: { formatVersion: 1, suiteId: 2, enc: bundle.enc, ciphertext: bundle.ciphertext },
  };
}

export function parseVaultRoutedVncRequest(value: unknown): VaultRoutedVncRequest | undefined {
  if (!vaultRecord(value)) return undefined;
  const { route: rawRoute, endpoint, ...base } = value;
  const q = parseVaultRouteRequest(base);
  if (!q || !validVaultRouteEndpoint(endpoint)) return undefined;
  const { publicKey: _, ...context } = q;
  const route = parseVaultRouteBinding(rawRoute, context);
  return route?.protocol === 'vnc' ? { ...q, route, endpoint } : undefined;
}
function parseRoutedVncBundle(
  value: unknown,
  request: VaultRoutedVncRequest,
  manual = false,
): VaultRoutedVncBundle | undefined {
  const q = parseVaultRoutedVncRequest(request);
  if (
    !q ||
    !vaultRecord(value) ||
    !vaultFields(value, ['binding', 'bundle', 'endpoint']) ||
    value.endpoint !== q.endpoint ||
    !vncCiphertext(value.bundle, manual)
  )
    return undefined;
  const { route, endpoint, ...base } = q;
  const result = parseVaultRouteBundle({ binding: value.binding, bundle: value.bundle }, base);
  if (!result || JSON.stringify(result.binding) !== JSON.stringify(route)) return undefined;
  return { ...result, endpoint };
}

export function parseVaultVncBundle(
  value: unknown,
  request: VaultVncRequest,
): VaultVncBundle | undefined {
  return parseVncBundle(value, request);
}
export function parseVaultManualVncBundle(
  value: unknown,
  request: VaultVncRequest,
): VaultVncBundle | undefined {
  return parseVncBundle(value, request, true);
}
export function parseVaultRoutedVncBundle(
  value: unknown,
  request: VaultRoutedVncRequest,
): VaultRoutedVncBundle | undefined {
  return parseRoutedVncBundle(value, request);
}
export function parseVaultManualRoutedVncBundle(
  value: unknown,
  request: VaultRoutedVncRequest,
): VaultRoutedVncBundle | undefined {
  return parseRoutedVncBundle(value, request, true);
}
