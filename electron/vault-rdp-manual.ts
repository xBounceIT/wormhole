import { vaultFields, vaultRecord } from './vault-contract.ts';
import { parseVaultRoutePlanRequest, type VaultRoutePlanRequest } from './vault-route.ts';
import {
  parseVaultRdpCredentialsContext,
  parseVaultRdpCredentialsEnvelope,
  rdpCredentialsInfo,
  type VaultRdpCredentialsContext,
  type VaultRdpCredentialsEnvelope,
} from './vault-rdp-credentials.ts';
import {
  parseVaultRdpBundle,
  parseVaultRoutedRdpBundle,
  type VaultRdpBundle,
  type VaultRdpRequest,
  type VaultRoutedRdpBundle,
  type VaultRoutedRdpRequest,
} from './vault-rdp.ts';

export type VaultRdpManualRequest = {
  context: VaultRdpCredentialsContext;
  credentialOverride: string;
  manual: VaultRdpCredentialsEnvelope;
};
export function parseVaultRdpPlan(
  value: unknown,
  request: unknown,
): VaultRdpBundle['binding'] | undefined {
  const q = parseVaultRoutePlanRequest(request);
  if (!q || !vaultRecord(value) || !vaultFields(value, ['binding'])) return undefined;
  const context = parseVaultRdpCredentialsContext({
    binding: value.binding,
    publicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  });
  const b = context?.binding;
  return b &&
    !('fileId' in b) &&
    b.workspaceId === q.workspaceId &&
    b.nodeId === q.nodeId &&
    b.sessionId === q.sessionId &&
    b.requestId === q.requestId &&
    b.epoch === q.epoch
    ? b
    : undefined;
}
export function parseVaultRdpManualRequest(value: unknown): VaultRdpManualRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['context', 'credentialOverride', 'manual']) ||
    value.credentialOverride !== ''
  )
    return undefined;
  const context = parseVaultRdpCredentialsContext(value.context),
    manual = parseVaultRdpCredentialsEnvelope(value.manual);
  return context && manual
    ? { context, manual, credentialOverride: value.credentialOverride as string }
    : undefined;
}
export function rdpPlanPayload(q: VaultRoutePlanRequest) {
  return {
    nodeId: q.nodeId,
    credentialOverride: q.credentialOverride,
    sessionId: q.sessionId,
    requestId: q.requestId,
    epoch: String(q.epoch),
  };
}
export function rdpManualPayload(q: VaultRdpManualRequest) {
  const { context: c } = q,
    b = c.binding;
  return {
    ...rdpPlanPayload({ ...b, credentialOverride: q.credentialOverride }),
    publicKey: c.publicKey,
    manual: q.manual,
    ...(c.endpoint && 'fileId' in b ? { route: b, endpoint: c.endpoint } : { binding: b }),
  };
}
export function rdpManualTarget(q: VaultRdpManualRequest): VaultRdpRequest | VaultRoutedRdpRequest {
  const c = q.context,
    b = c.binding;
  // The wire request contains only identity fields, never the binding's metadata.
  const base = {
    workspaceId: b.workspaceId,
    nodeId: b.nodeId,
    sessionId: b.sessionId,
    requestId: b.requestId,
    epoch: b.epoch,
    publicKey: c.publicKey,
    credentialOverride: q.credentialOverride,
  };
  return c.endpoint && 'fileId' in b ? { ...base, route: b, endpoint: c.endpoint } : base;
}

export function parseVaultRdpManualBundle(
  value: unknown,
  q: VaultRdpManualRequest,
): VaultRdpBundle | VaultRoutedRdpBundle | undefined {
  const target = rdpManualTarget(q);
  const result =
    'route' in target
      ? parseVaultRoutedRdpBundle(value, target)
      : parseVaultRdpBundle(value, target);
  if (!result) return undefined;
  const c = q.context;
  const expected = rdpCredentialsInfo(c),
    actual = rdpCredentialsInfo({ ...c, binding: result.binding });
  return expected.length === actual.length && expected.every((v, i) => v === actual[i])
    ? result
    : undefined;
}
