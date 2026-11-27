import { randomUUID } from 'node:crypto';
import type { VaultSshRequest, VaultSshBundle } from '../../electron/vault-ssh.ts';
export function sshRequest(): VaultSshRequest {
  return {
    workspaceId: randomUUID(),
    nodeId: randomUUID(),
    credentialOverride: '',
    sessionId: randomUUID(),
    requestId: randomUUID(),
    epoch: 1,
    publicKey: Buffer.alloc(32, 2).toString('base64'),
  };
}
export function sshBundle(q: VaultSshRequest): VaultSshBundle {
  return {
    ...(q.sftpOnly ? { sftpOnly: true } : {}),
    binding: {
      workspaceId: q.workspaceId,
      nodeId: q.nodeId,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: q.epoch,
      protocol: 'ssh',
      host: 'host.example',
      port: 22,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.alloc(32, 3).toString('base64'),
      ciphertext: Buffer.alloc(20, 4).toString('base64'),
    },
  };
}
