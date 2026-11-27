import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { parseVaultRoutePlanRequest, type VaultRoutePlanRequest } from './vault-route.ts';
import {
  parseVaultVncPasswordContext,
  parseVaultVncPasswordEnvelope,
  vncPasswordInfo,
  type VaultVncPasswordContext,
  type VaultVncPasswordEnvelope,
} from './vault-vnc-password.ts';
import {
  parseVaultManualVncBundle,
  parseVaultManualRoutedVncBundle,
  type VaultVncBundle,
  type VaultRoutedVncBundle,
} from './vault-vnc.ts';

export type VaultVncManualRequest = {
  context: VaultVncPasswordContext;
  credentialOverride: string;
  manual: VaultVncPasswordEnvelope;
};
export function parseVaultVncPlan(
  value: unknown,
  request: unknown,
): VaultVncBundle['binding'] | undefined {
  const q = parseVaultRoutePlanRequest(request);
  if (!q || !vaultRecord(value) || !vaultFields(value, ['binding'])) return undefined;
  const context = parseVaultVncPasswordContext({
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
export function parseVaultVncManualRequest(value: unknown): VaultVncManualRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['context', 'credentialOverride', 'manual']) ||
    (value.credentialOverride !== '' && !vaultID(value.credentialOverride))
  )
    return undefined;
  const context = parseVaultVncPasswordContext(value.context),
    manual = parseVaultVncPasswordEnvelope(value.manual);
  return context && manual
    ? { context, manual, credentialOverride: value.credentialOverride as string }
    : undefined;
}
export function vncPlanPayload(q: VaultRoutePlanRequest) {
  return {
    nodeId: q.nodeId,
    credentialOverride: q.credentialOverride,
    sessionId: q.sessionId,
    requestId: q.requestId,
    epoch: String(q.epoch),
  };
}
export function vncManualPayload(q: VaultVncManualRequest) {
  const { context: c } = q,
    b = c.binding;
  return {
    ...vncPlanPayload({ ...b, credentialOverride: q.credentialOverride }),
    publicKey: c.publicKey,
    manual: q.manual,
    ...(c.endpoint && 'fileId' in b ? { route: b, endpoint: c.endpoint } : { binding: b }),
  };
}
export function parseVaultVncManualBundle(
  value: unknown,
  q: VaultVncManualRequest,
): VaultVncBundle | VaultRoutedVncBundle | undefined {
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
  const result =
    c.endpoint && 'fileId' in b
      ? parseVaultManualRoutedVncBundle(value, { ...base, route: b, endpoint: c.endpoint })
      : parseVaultManualVncBundle(value, base);
  if (!result) return undefined;
  const expected = vncPasswordInfo(c),
    actual = vncPasswordInfo({ ...c, binding: result.binding });
  return expected.length === actual.length && expected.every((v, i) => v === actual[i])
    ? result
    : undefined;
}
