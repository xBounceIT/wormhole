import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';
import {
  parseVaultRoutePlanRequest,
  parseVaultRouteBinding,
  type VaultRouteBinding,
  type VaultRoutePlanRequest,
} from './vault-route.ts';
import { webTargetURLMatchesEndpoint } from './web-target-validation.ts';
export type VaultWebBinding = Omit<
  VaultRouteBinding,
  'fileId' | 'kind' | 'rowVersion' | 'configurationVersion' | 'protocol'
> & { protocol: 'http' | 'https' };
export type VaultWebTarget = {
  url: string;
  protocol: 'http' | 'https';
  host: string;
  port: number;
  ignoreCertErrors: boolean;
  tunnelConfigId?: string;
};
export type VaultWebPlan = {
  binding: VaultWebBinding;
  route: VaultRouteBinding | null;
  target: VaultWebTarget;
  temporary?: true;
  archiveBinding?: string;
  viewGeneration?: string;
};

export type VaultWebView = { nodeId: string; generation: string };

export function parseVaultWebViews(value: unknown): VaultWebView[] | undefined {
  if (!Array.isArray(value) || value.length < 1 || value.length > 32) return undefined;
  const views: VaultWebView[] = [];
  for (const entry of value) {
    if (
      !vaultRecord(entry) ||
      !vaultFields(entry, ['nodeId', 'generation']) ||
      !vaultID(entry.nodeId) ||
      !vaultID(entry.generation)
    )
      return undefined;
    views.push({ nodeId: entry.nodeId, generation: entry.generation });
  }
  return views;
}

export function parseVaultWebViewReply(value: unknown, count: number): boolean[] | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['current']) ||
    !Array.isArray(value.current) ||
    value.current.length !== count
  )
    return undefined;
  const current: boolean[] = [];
  for (const confirmed of value.current) {
    if (typeof confirmed !== 'boolean') return undefined;
    current.push(confirmed);
  }
  return current;
}
export function parseVaultWebRequest(value: unknown): VaultRoutePlanRequest | undefined {
  const q = parseVaultRoutePlanRequest(value);
  return q?.credentialOverride === '' ? q : undefined;
}
export function parseVaultWebPlan(value: unknown, request: unknown): VaultWebPlan | undefined {
  const q = parseVaultWebRequest(request);
  if (
    !q ||
    !vaultRecord(value) ||
    !vaultFields(value, [
      'binding',
      'route',
      'target',
      ...(value.temporary !== undefined ? ['temporary'] : []),
      ...(value.archiveBinding !== undefined ? ['archiveBinding'] : []),
      ...(value.viewGeneration !== undefined ? ['viewGeneration'] : []),
    ]) ||
    (value.temporary !== undefined && value.temporary !== true) ||
    (value.archiveBinding !== undefined &&
      (value.temporary === true ||
        typeof value.archiveBinding !== 'string' ||
        !/^[a-f0-9]{64}$/.test(value.archiveBinding))) ||
    (value.viewGeneration !== undefined &&
      (!value.archiveBinding || !vaultID(value.viewGeneration)))
  )
    return undefined;
  const b = value.binding,
    t = value.target;
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
      'tunnelConfigId',
      'useExternalClient',
      'epoch',
    ]) ||
    b.workspaceId !== q.workspaceId ||
    b.nodeId !== q.nodeId ||
    b.sessionId !== q.sessionId ||
    b.requestId !== q.requestId ||
    b.epoch !== q.epoch ||
    (b.protocol !== 'http' && b.protocol !== 'https') ||
    b.useExternalClient !== false ||
    !vaultMetadataText(b.host, 1024, true) ||
    /[\p{White_Space}\p{Cc}]/u.test(b.host) ||
    !Number.isInteger(b.port) ||
    (b.port as number) < 1 ||
    (b.port as number) > 65535 ||
    (b.tunnelConfigId !== '' && !vaultID(b.tunnelConfigId)) ||
    !vaultRecord(t) ||
    !vaultFields(t, [
      'url',
      'protocol',
      'host',
      'port',
      'ignoreCertErrors',
      ...(t.tunnelConfigId !== undefined ? ['tunnelConfigId'] : []),
    ]) ||
    !vaultMetadataText(t.url, 8192, true) ||
    t.protocol !== b.protocol ||
    t.host !== b.host ||
    t.port !== b.port ||
    (t.tunnelConfigId !== undefined && !vaultID(t.tunnelConfigId)) ||
    (t.tunnelConfigId ?? '') !== b.tunnelConfigId ||
    typeof t.ignoreCertErrors !== 'boolean' ||
    (b.protocol === 'http' && t.ignoreCertErrors)
  )
    return undefined;
  const binding: VaultWebBinding = {
    workspaceId: q.workspaceId,
    sessionId: q.sessionId,
    requestId: q.requestId,
    nodeId: q.nodeId,
    epoch: q.epoch,
    protocol: b.protocol,
    host: b.host,
    port: b.port as number,
    tunnelConfigId: b.tunnelConfigId as string,
    useExternalClient: false,
  };
  let route: VaultRouteBinding | null = null;
  if (binding.tunnelConfigId) {
    const checked = parseVaultRouteBinding(value.route, q);
    if (
      !checked ||
      Object.entries(binding).some(([key, v]) => checked[key as keyof VaultWebBinding] !== v)
    )
      return undefined;
    route = checked;
  } else if (value.route !== null) return undefined;
  const target: VaultWebTarget = {
    url: t.url,
    protocol: binding.protocol,
    host: binding.host,
    port: binding.port,
    ignoreCertErrors: t.ignoreCertErrors,
    ...(binding.tunnelConfigId ? { tunnelConfigId: binding.tunnelConfigId } : {}),
  };
  try {
    const url = new URL(target.url);
    // Go identifies an owner-scoped temporary stage. Saved paths continue to
    // exclude query/fragment; an ordinary caller cannot promote a saved row.
    if ((!value.temporary && (url.search || url.hash)) || !webTargetURLMatchesEndpoint(url, target))
      return undefined;
  } catch {
    return undefined;
  }
  return {
    binding,
    route,
    target,
    ...(value.temporary ? { temporary: true } : {}),
    ...(typeof value.archiveBinding === 'string' ? { archiveBinding: value.archiveBinding } : {}),
    ...(vaultID(value.viewGeneration) ? { viewGeneration: value.viewGeneration } : {}),
  };
}
