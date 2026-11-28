import {
  vaultFields,
  vaultID,
  vaultMetadataText,
  vaultRecord,
  vaultRevision,
} from './vault-contract.ts';
import { canonicalBase64, type VaultSshRequest } from './vault-ssh.ts';

// Main-only route handoff. There is deliberately no preload/renderer endpoint.
export type VaultRouteRequest = Omit<VaultSshRequest, 'sftpOnly'>;
export type VaultRoutePlanRequest = Omit<VaultRouteRequest, 'publicKey'>;
export type VaultRouteBundle = {
  binding: {
    workspaceId: string;
    fileId: string;
    nodeId: string;
    sessionId: string;
    requestId: string;
    protocol: 'ssh' | 'sftp' | 'rdp' | 'vnc' | 'http' | 'https';
    host: string;
    port: number;
    epoch: number;
    tunnelConfigId: string;
    useExternalClient: false;
    kind: number;
    rowVersion: string;
    configurationVersion: string;
  };
  bundle: { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
};
export type VaultRouteBinding = VaultRouteBundle['binding'];
export function validVaultRouteEndpoint(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(value) &&
    Number(value.split(':')[1]) <= 65535
  );
}
const routeRequestFields = [
  'workspaceId',
  'nodeId',
  'credentialOverride',
  'sessionId',
  'requestId',
  'epoch',
];
export function parseVaultRoutePlanRequest(value: unknown): VaultRoutePlanRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, routeRequestFields) ||
    ![value.workspaceId, value.nodeId, value.sessionId, value.requestId].every(vaultID) ||
    !(value.credentialOverride === '' || vaultID(value.credentialOverride)) ||
    !Number.isSafeInteger(value.epoch) ||
    (value.epoch as number) < 1
  )
    return undefined;
  return {
    workspaceId: value.workspaceId as string,
    nodeId: value.nodeId as string,
    credentialOverride: value.credentialOverride,
    sessionId: value.sessionId as string,
    requestId: value.requestId as string,
    epoch: value.epoch as number,
  };
}
export function parseVaultRouteRequest(value: unknown): VaultRouteRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [...routeRequestFields, 'publicKey']) ||
    !canonicalBase64(value.publicKey, 32, 32)
  )
    return undefined;
  const { publicKey, ...context } = value;
  const q = parseVaultRoutePlanRequest(context);
  return q ? { ...q, publicKey } : undefined;
}
export function parseVaultRouteBinding(
  value: unknown,
  request: VaultRoutePlanRequest,
): VaultRouteBinding | undefined {
  const q = parseVaultRoutePlanRequest(request),
    b = value;
  if (!q) return undefined;
  if (
    !vaultRecord(b) ||
    !vaultFields(b, [
      'workspaceId',
      'fileId',
      'nodeId',
      'sessionId',
      'requestId',
      'protocol',
      'host',
      'port',
      'epoch',
      'tunnelConfigId',
      'useExternalClient',
      'kind',
      'rowVersion',
      'configurationVersion',
    ]) ||
    b.workspaceId !== q.workspaceId ||
    b.nodeId !== q.nodeId ||
    b.sessionId !== q.sessionId ||
    b.requestId !== q.requestId ||
    b.epoch !== q.epoch ||
    !vaultID(b.fileId) ||
    !vaultID(b.tunnelConfigId) ||
    b.useExternalClient !== false ||
    !['ssh', 'sftp', 'rdp', 'vnc', 'http', 'https'].includes(b.protocol as string) ||
    !vaultMetadataText(b.host, 1024, true) ||
    /[\p{White_Space}\p{Cc}]/u.test(b.host) ||
    !Number.isInteger(b.port) ||
    (b.port as number) < 1 ||
    (b.port as number) > 65535 ||
    !Number.isInteger(b.kind) ||
    (b.kind as number) < 0 ||
    (b.kind as number) > 9 ||
    !vaultRevision(b.rowVersion) ||
    !vaultRevision(b.configurationVersion) ||
    BigInt(b.configurationVersion) > BigInt(b.rowVersion)
  )
    return undefined;
  return {
    workspaceId: q.workspaceId,
    fileId: b.fileId,
    nodeId: q.nodeId,
    sessionId: q.sessionId,
    requestId: q.requestId,
    epoch: q.epoch,
    protocol: b.protocol as VaultRouteBundle['binding']['protocol'],
    host: b.host,
    port: b.port as number,
    tunnelConfigId: b.tunnelConfigId,
    useExternalClient: false,
    kind: b.kind as number,
    rowVersion: b.rowVersion,
    configurationVersion: b.configurationVersion,
  };
}

export function parseVaultRouteBundle(
  value: unknown,
  request: VaultRouteRequest,
): VaultRouteBundle | undefined {
  const q = parseVaultRouteRequest(request);
  if (!q || !vaultRecord(value) || !vaultFields(value, ['binding', 'bundle'])) return undefined;
  const { publicKey: _, ...context } = q;
  const binding = parseVaultRouteBinding(value.binding, context),
    s = value.bundle;
  if (
    !binding ||
    !vaultRecord(s) ||
    !vaultFields(s, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    s.formatVersion !== 1 ||
    s.suiteId !== 2 ||
    !canonicalBase64(s.enc, 32, 32) ||
    !canonicalBase64(s.ciphertext, 17, 4 * 1024 * 1024 + 16)
  )
    return undefined;
  return {
    binding,
    bundle: { formatVersion: 1, suiteId: 2, enc: s.enc, ciphertext: s.ciphertext },
  };
}

export function parseVaultConnectionRoute(
  value: unknown,
  request: VaultRoutePlanRequest,
): VaultRouteBinding | null | undefined {
  if (!parseVaultRoutePlanRequest(request)) return undefined;
  return value === null ? null : parseVaultRouteBinding(value, request);
}
