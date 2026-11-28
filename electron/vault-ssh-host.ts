import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';
import type { VaultSshBundle } from './vault-ssh.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import {
  parseVaultRoutePlanRequest,
  parseVaultRouteBinding,
  type VaultRoutePlanRequest,
  type VaultRouteBinding,
} from './vault-route.ts';

export type VaultSshHostRequest = VaultRoutePlanRequest & { route: VaultRouteBinding | null };
export type VaultSshHostPlan = {
  binding: Omit<VaultSshBundle['binding'], 'tunnelConfigId'> & { tunnelConfigId: string };
  fileId: string;
  revision: string;
  fingerprint: string;
};
export type VaultSshHostTrust = VaultSshHostRequest & {
  expected: VaultSshHostPlan;
  received: string;
};

export function validVaultSshFingerprint(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.startsWith('SHA256:') &&
    enrollmentBytes(value.slice(7) + '=', 32) !== undefined
  );
}
export function parseVaultSshHostRequest(value: unknown): VaultSshHostRequest | undefined {
  if (!vaultRecord(value)) return undefined;
  const { route, ...base } = value;
  const q = parseVaultRoutePlanRequest(base);
  if (!q) return undefined;
  const parsed = route === null ? null : parseVaultRouteBinding(route, q);
  if (
    parsed === undefined ||
    (parsed !== null && parsed.protocol !== 'ssh' && parsed.protocol !== 'sftp')
  )
    return undefined;
  return { ...q, route: parsed };
}
export function parseVaultSshHostPlan(
  value: unknown,
  request: VaultSshHostRequest,
): VaultSshHostPlan | undefined {
  const q = parseVaultSshHostRequest(request);
  if (
    !q ||
    !vaultRecord(value) ||
    !vaultFields(value, ['binding', 'fileId', 'revision', 'fingerprint']) ||
    !vaultID(value.fileId) ||
    typeof value.revision !== 'string' ||
    !/^[a-f0-9]{64}$/.test(value.revision) ||
    !(value.fingerprint === '' || validVaultSshFingerprint(value.fingerprint))
  )
    return undefined;
  const b = value.binding;
  if (
    !vaultRecord(b) ||
    !vaultFields(b, [
      'workspaceId',
      'sessionId',
      'requestId',
      'nodeId',
      'protocol',
      'host',
      'port',
      'epoch',
      'tunnelConfigId',
      'useExternalClient',
    ]) ||
    b.workspaceId !== q.workspaceId ||
    b.sessionId !== q.sessionId ||
    b.requestId !== q.requestId ||
    b.nodeId !== q.nodeId ||
    b.epoch !== q.epoch ||
    (b.protocol !== 'ssh' && b.protocol !== 'sftp') ||
    b.useExternalClient !== false ||
    b.tunnelConfigId !== (q.route?.tunnelConfigId ?? '') ||
    !vaultMetadataText(b.host, 1024, true) ||
    /[\p{White_Space}\p{Cc}]/u.test(b.host) ||
    typeof b.port !== 'number' ||
    !Number.isInteger(b.port) ||
    b.port < 1 ||
    b.port > 65535 ||
    (q.route &&
      (b.protocol !== q.route.protocol ||
        b.host !== q.route.host ||
        b.port !== q.route.port ||
        value.fileId !== q.route.fileId))
  )
    return undefined;
  return {
    binding: {
      workspaceId: q.workspaceId,
      nodeId: q.nodeId,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: q.epoch,
      protocol: b.protocol,
      host: b.host,
      port: b.port,
      tunnelConfigId: q.route?.tunnelConfigId ?? '',
      useExternalClient: false,
    },
    fileId: value.fileId,
    revision: value.revision,
    fingerprint: value.fingerprint,
  };
}
export function parseVaultSshHostTrust(value: unknown): VaultSshHostTrust | undefined {
  if (!vaultRecord(value)) return undefined;
  const { expected, received, ...base } = value;
  const q = parseVaultSshHostRequest(base);
  const plan = q && parseVaultSshHostPlan(expected, q);
  if (!q || !plan || !validVaultSshFingerprint(received) || received === plan.fingerprint)
    return undefined;
  return { ...q, expected: plan, received };
}

export function vaultSshHostPayload(q: VaultSshHostRequest | VaultSshHostTrust) {
  return {
    nodeId: q.nodeId,
    credentialOverride: q.credentialOverride,
    sessionId: q.sessionId,
    requestId: q.requestId,
    epoch: String(q.epoch),
    route: q.route,
    ...('expected' in q ? { expected: q.expected, received: q.received } : {}),
  };
}
