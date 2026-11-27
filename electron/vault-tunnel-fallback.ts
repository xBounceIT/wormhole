import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';
import {
  parseVaultRouteBinding,
  parseVaultRouteBundle,
  parseVaultRoutePlanRequest,
  type VaultRouteBinding,
  type VaultRouteBundle,
  type VaultRoutePlanRequest,
} from './vault-route.ts';

// Main-only public context. Native Go still authenticates the encrypted reference
// and both sources; this pair is neither source permission nor process-exit proof.
export type VaultTunnelFallbackBinding = {
  primary: VaultRouteBinding;
  fallback: VaultRouteBinding;
};
export type VaultTunnelFallbackPlanRequest = VaultRoutePlanRequest & {
  primary: VaultRouteBinding;
  fallbackRequestId: string;
};
export type VaultTunnelFallbackRequest = VaultRoutePlanRequest & {
  binding: VaultTunnelFallbackBinding;
  publicKey: string;
};
export type VaultTunnelFallbackBundle = {
  binding: VaultTunnelFallbackBinding;
  bundle: VaultRouteBundle['bundle'];
};

function sameBinding(a: VaultRouteBinding, b: VaultRouteBinding): boolean {
  return (Object.keys(a) as (keyof VaultRouteBinding)[]).every((key) => a[key] === b[key]);
}

export function parseVaultTunnelFallbackPlanRequest(
  value: unknown,
): VaultTunnelFallbackPlanRequest | undefined {
  if (!vaultRecord(value)) return undefined;
  const { primary, fallbackRequestId, ...context } = value;
  const q = parseVaultRoutePlanRequest(context);
  const p = q && parseVaultRouteBinding(primary, q);
  if (!q || !p || p.kind !== 9 || !vaultID(fallbackRequestId) || fallbackRequestId === q.requestId)
    return undefined;
  return { ...q, primary: p, fallbackRequestId };
}

export function parseVaultTunnelFallbackBinding(
  value: unknown,
  request: VaultTunnelFallbackPlanRequest,
): VaultTunnelFallbackBinding | undefined {
  const q = parseVaultTunnelFallbackPlanRequest(request);
  if (!q || !vaultRecord(value) || !vaultFields(value, ['primary', 'fallback'])) return undefined;
  const { primary: expected, fallbackRequestId, ...context } = q;
  const primary = parseVaultRouteBinding(value.primary, context);
  const fallback = parseVaultRouteBinding(value.fallback, {
    ...context,
    requestId: fallbackRequestId,
  });
  if (
    !primary ||
    !fallback ||
    !sameBinding(primary, expected) ||
    fallback.kind !== 2 ||
    fallback.tunnelConfigId === primary.tunnelConfigId ||
    fallback.fileId !== primary.fileId ||
    fallback.protocol !== primary.protocol ||
    fallback.host !== primary.host ||
    fallback.port !== primary.port
  )
    return undefined;
  return { primary, fallback };
}

export function parseVaultTunnelFallbackRequest(
  value: unknown,
): VaultTunnelFallbackRequest | undefined {
  if (!vaultRecord(value) || !canonicalBase64(value.publicKey, 32, 32)) return undefined;
  const { binding, publicKey, ...context } = value;
  const route = parseVaultRoutePlanRequest(context);
  if (!route || !vaultRecord(binding) || !vaultRecord(binding.fallback)) return undefined;
  const plan = {
    ...route,
    primary: binding.primary,
    fallbackRequestId: binding.fallback.requestId,
  };
  const q = parseVaultTunnelFallbackPlanRequest(plan);
  const pair = q && parseVaultTunnelFallbackBinding(binding, q);
  if (!q || !pair) return undefined;
  return { ...route, binding: pair, publicKey };
}

export function parseVaultTunnelFallbackBundle(
  value: unknown,
  request: VaultTunnelFallbackRequest,
): VaultTunnelFallbackBundle | undefined {
  const q = parseVaultTunnelFallbackRequest(request);
  if (!q || !vaultRecord(value) || !vaultFields(value, ['binding', 'bundle'])) return undefined;
  const { binding: expected, publicKey, ...context } = q;
  const binding = parseVaultTunnelFallbackBinding(value.binding, {
    ...context,
    primary: expected.primary,
    fallbackRequestId: expected.fallback.requestId,
  });
  if (!binding || !sameBinding(binding.fallback, expected.fallback)) return undefined;
  const packet = parseVaultRouteBundle(
    { binding: binding.fallback, bundle: value.bundle },
    { ...context, requestId: binding.fallback.requestId, publicKey },
  );
  return packet ? { binding, bundle: packet.bundle } : undefined;
}
