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
export type VaultRdpRequest = VaultRouteRequest;
export type VaultRdpBundle = {
  binding: Omit<
    VaultRouteBinding,
    'fileId' | 'kind' | 'rowVersion' | 'configurationVersion' | 'tunnelConfigId' | 'protocol'
  > & {
    protocol: 'rdp';
    tunnelConfigId: '';
  };
  bundle: VaultRouteBundle['bundle'];
};
export type VaultRoutedRdpRequest = VaultRdpRequest & {
  route: VaultRouteBinding;
  endpoint: string;
};
export type VaultRoutedRdpBundle = VaultRouteBundle & { endpoint: string };
const maximumCiphertext = 64 * 1024 + 16;
function rdpCiphertext(value: unknown): boolean {
  return (
    vaultRecord(value) &&
    vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) &&
    value.formatVersion === 1 &&
    value.suiteId === 2 &&
    canonicalBase64(value.enc, 32, 32) &&
    canonicalBase64(value.ciphertext, 42, maximumCiphertext)
  );
}

export function parseVaultRdpBundle(
  value: unknown,
  request: VaultRdpRequest,
): VaultRdpBundle | undefined {
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
    b.protocol !== 'rdp' ||
    b.tunnelConfigId !== '' ||
    b.useExternalClient !== false ||
    !vaultMetadataText(b.host, 1024, true) ||
    /[\p{White_Space}\p{Cc}]/u.test(b.host) ||
    !Number.isInteger(b.port) ||
    (b.port as number) < 1 ||
    (b.port as number) > 65535 ||
    !rdpCiphertext(s)
  )
    return undefined;
  const bundle = s as VaultRdpBundle['bundle'];
  return {
    binding: {
      workspaceId: q.workspaceId,
      nodeId: q.nodeId,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: q.epoch,
      protocol: 'rdp',
      host: b.host,
      port: b.port as number,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    bundle: { formatVersion: 1, suiteId: 2, enc: bundle.enc, ciphertext: bundle.ciphertext },
  };
}

export function parseVaultRoutedRdpRequest(value: unknown): VaultRoutedRdpRequest | undefined {
  if (!vaultRecord(value)) return undefined;
  const { route: rawRoute, endpoint, ...base } = value;
  const q = parseVaultRouteRequest(base);
  if (!q || !validVaultRouteEndpoint(endpoint)) return undefined;
  const { publicKey: _, ...context } = q;
  const route = parseVaultRouteBinding(rawRoute, context);
  return route?.protocol === 'rdp' ? { ...q, route, endpoint } : undefined;
}
export function parseVaultRoutedRdpBundle(
  value: unknown,
  request: VaultRoutedRdpRequest,
): VaultRoutedRdpBundle | undefined {
  const q = parseVaultRoutedRdpRequest(request);
  if (
    !q ||
    !vaultRecord(value) ||
    !vaultFields(value, ['binding', 'bundle', 'endpoint']) ||
    value.endpoint !== q.endpoint ||
    !rdpCiphertext(value.bundle)
  )
    return undefined;
  const { route, endpoint, ...base } = q;
  const result = parseVaultRouteBundle({ binding: value.binding, bundle: value.bundle }, base);
  if (!result || JSON.stringify(result.binding) !== JSON.stringify(route)) return undefined;
  return { ...result, endpoint };
}
