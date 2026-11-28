import type {
  VaultTunnelFallbackPlanRequest,
  VaultTunnelFallbackRequest,
  VaultTunnelFallbackBundle,
} from '../../electron/vault-tunnel-fallback.ts';

export const fallbackPlan: VaultTunnelFallbackPlanRequest = {
  workspaceId: '11111111-1111-4111-8111-111111111111',
  nodeId: '22222222-2222-4222-8222-222222222222',
  sessionId: '33333333-3333-4333-8333-333333333333',
  requestId: '44444444-4444-4444-8444-444444444444',
  credentialOverride: '',
  epoch: 1,
  fallbackRequestId: '55555555-5555-4555-8555-555555555555',
  primary: {
    workspaceId: '11111111-1111-4111-8111-111111111111',
    fileId: '66666666-6666-4666-8666-666666666666',
    nodeId: '22222222-2222-4222-8222-222222222222',
    sessionId: '33333333-3333-4333-8333-333333333333',
    requestId: '44444444-4444-4444-8444-444444444444',
    protocol: 'https',
    host: 'destination.example',
    port: 443,
    epoch: 1,
    tunnelConfigId: '77777777-7777-4777-8777-777777777777',
    useExternalClient: false,
    kind: 9,
    rowVersion: '9223372036854775807',
    configurationVersion: '9223372036854775806',
  },
};
export const fallbackRequest: VaultTunnelFallbackRequest = {
  workspaceId: fallbackPlan.workspaceId,
  nodeId: fallbackPlan.nodeId,
  sessionId: fallbackPlan.sessionId,
  requestId: fallbackPlan.requestId,
  credentialOverride: '',
  epoch: 1,
  publicKey: Buffer.alloc(32, 1).toString('base64'),
  binding: {
    primary: { ...fallbackPlan.primary },
    fallback: {
      ...fallbackPlan.primary,
      requestId: fallbackPlan.fallbackRequestId,
      tunnelConfigId: '88888888-8888-4888-8888-888888888888',
      kind: 2,
      rowVersion: '8',
      configurationVersion: '7',
    },
  },
};
export const fallbackBundle: VaultTunnelFallbackBundle = {
  binding: structuredClone(fallbackRequest.binding),
  bundle: {
    formatVersion: 1,
    suiteId: 2,
    enc: fallbackRequest.publicKey,
    ciphertext: Buffer.alloc(32, 2).toString('base64'),
  },
};
