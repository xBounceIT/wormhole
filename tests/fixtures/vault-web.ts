import { randomUUID } from 'node:crypto';
import type { VaultRoutePlanRequest } from '../../electron/vault-route.ts';
import type { VaultWebPlan } from '../../electron/vault-web.ts';
export function webRequest(): VaultRoutePlanRequest {
  return {
    workspaceId: randomUUID(),
    nodeId: randomUUID(),
    sessionId: randomUUID(),
    requestId: randomUUID(),
    epoch: 1,
    credentialOverride: '',
  };
}
export function webPlan(q: VaultRoutePlanRequest, routed = false): VaultWebPlan {
  const binding: VaultWebPlan['binding'] = {
    workspaceId: q.workspaceId,
    nodeId: q.nodeId,
    sessionId: q.sessionId,
    requestId: q.requestId,
    epoch: q.epoch,
    protocol: 'https',
    host: 'web.example',
    port: 8443,
    tunnelConfigId: routed ? randomUUID() : '',
    useExternalClient: false,
  };
  return {
    binding,
    route: routed
      ? {
          ...binding,
          fileId: randomUUID(),
          kind: 6,
          rowVersion: '9223372036854775807',
          configurationVersion: '9223372036854775806',
        }
      : null,
    target: {
      url: 'https://web.example:8443/native%2Fpath',
      protocol: 'https',
      host: binding.host,
      port: binding.port,
      ignoreCertErrors: false,
      ...(routed ? { tunnelConfigId: binding.tunnelConfigId } : {}),
    },
  };
}
