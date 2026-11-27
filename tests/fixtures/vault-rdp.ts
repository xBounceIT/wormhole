import { randomUUID } from 'node:crypto';
import type {
  VaultRdpRequest,
  VaultRdpBundle,
  VaultRoutedRdpRequest,
  VaultRoutedRdpBundle,
} from '../../electron/vault-rdp.ts';
export function rdpRequest(): VaultRdpRequest {
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
export function rdpBundle(q: VaultRdpRequest): VaultRdpBundle {
  return {
    binding: {
      workspaceId: q.workspaceId,
      nodeId: q.nodeId,
      sessionId: q.sessionId,
      requestId: q.requestId,
      epoch: q.epoch,
      protocol: 'rdp',
      host: 'host.example',
      port: 3389,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.alloc(32, 3).toString('base64'),
      ciphertext: Buffer.alloc(42, 4).toString('base64'),
    },
  };
}
export function routedRdpRequest(): VaultRoutedRdpRequest {
  const q = rdpRequest();
  return {
    ...q,
    route: {
      ...rdpBundle(q).binding,
      fileId: randomUUID(),
      tunnelConfigId: randomUUID(),
      kind: 6,
      rowVersion: '2',
      configurationVersion: '1',
    },
    endpoint: '127.0.0.1:2345',
  };
}
export function routedRdpBundle(q: VaultRoutedRdpRequest): VaultRoutedRdpBundle {
  return { binding: { ...q.route }, bundle: { ...rdpBundle(q).bundle }, endpoint: q.endpoint };
}
