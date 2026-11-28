import { randomUUID } from 'node:crypto';
import type { VaultTunnelAuthenticationContext } from '../../electron/vault-tunnel-authentication.ts';
export function tunnelAuthenticationContext(): VaultTunnelAuthenticationContext {
  return {
    binding: {
      workspaceId: randomUUID(),
      fileId: randomUUID(),
      nodeId: randomUUID(),
      sessionId: randomUUID(),
      requestId: randomUUID(),
      epoch: 1,
      protocol: 'ssh',
      host: 'café.example',
      port: 22,
      tunnelConfigId: randomUUID(),
      useExternalClient: false,
      kind: 9,
      rowVersion: '9223372036854775807',
      configurationVersion: '9223372036854775806',
    },
    challengeId: randomUUID(),
    publicKey: Buffer.alloc(32, 7).toString('base64'),
    usernameRequired: true,
  };
}
export function tunnelAuthenticationEnvelope() {
  return {
    formatVersion: 1 as const,
    suiteId: 2 as const,
    enc: Buffer.alloc(32, 3).toString('base64'),
    ciphertext: Buffer.alloc(27, 4).toString('base64'),
  };
}
