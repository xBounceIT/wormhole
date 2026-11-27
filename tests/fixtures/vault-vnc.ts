import { randomUUID } from 'node:crypto';
import type {
  VaultVncRequest,
  VaultVncBundle,
  VaultRoutedVncRequest,
  VaultRoutedVncBundle,
} from '../../electron/vault-vnc.ts';
export function vncRequest(): VaultVncRequest {
  return {
    workspaceId: randomUUID(),
    nodeId: randomUUID(),
    sessionId: randomUUID(),
    requestId: randomUUID(),
    credentialOverride: '',
    epoch: 1,
    publicKey: Buffer.alloc(32, 7).toString('base64'),
  };
}
export function vncBundle(q: VaultVncRequest): VaultVncBundle {
  return {
    binding: {
      workspaceId: q.workspaceId,
      nodeId: q.nodeId,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: q.epoch,
      protocol: 'vnc',
      host: 'host.example',
      port: 5900,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.alloc(32, 3).toString('base64'),
      ciphertext: Buffer.alloc(22, 4).toString('base64'),
    },
  };
}
export function routedVncRequest(): VaultRoutedVncRequest {
  const q = vncRequest();
  return {
    ...q,
    route: {
      ...vncBundle(q).binding,
      fileId: randomUUID(),
      tunnelConfigId: randomUUID(),
      kind: 6,
      rowVersion: '2',
      configurationVersion: '1',
    },
    endpoint: '127.0.0.1:2345',
  };
}
export function routedVncBundle(q: VaultRoutedVncRequest): VaultRoutedVncBundle {
  return { binding: { ...q.route }, bundle: { ...vncBundle(q).bundle }, endpoint: q.endpoint };
}
