import { createHash, randomUUID } from 'node:crypto';
import type {
  VPNSSOBegin,
  VPNSSOContext,
  VPNSSOOffer,
  VPNSSOPacket,
} from '../../electron/vault-vpn-sso.ts';

export function vpnSSOFixture() {
  const request = {
    workspaceId: randomUUID(),
    nodeId: randomUUID(),
    credentialOverride: randomUUID(),
    sessionId: randomUUID(),
    requestId: randomUUID(),
    epoch: 7,
  };
  const q: VPNSSOBegin = {
    request,
    binding: {
      workspaceId: request.workspaceId,
      fileId: randomUUID(),
      nodeId: request.nodeId,
      sessionId: request.sessionId,
      requestId: request.requestId,
      epoch: request.epoch,
      protocol: 'ssh',
      host: 'target.test',
      port: 22,
      tunnelConfigId: randomUUID(),
      useExternalClient: false,
      kind: 2,
      rowVersion: '4',
      configurationVersion: '2',
    },
    profileId: randomUUID(),
    challengeId: randomUUID(),
    startURL: 'https://vpn.test:443/remote/saml/start?realm=staff',
    ignoreCertificateErrors: false,
    restorePublicKey: Buffer.alloc(32, 1).toString('base64'),
  };
  const c: VPNSSOContext = {
    workspaceId: request.workspaceId,
    fileId: q.binding.fileId,
    profileId: q.profileId,
    requestId: request.requestId,
    transferId: randomUUID(),
    sessionId: request.sessionId,
    challengeId: q.challengeId,
    epoch: request.epoch,
    policySequence: '3',
    sourceRevision: '0',
    sourceDeleted: false,
    sourceDigest: Buffer.alloc(32).toString('base64'),
    bindingDigest: Buffer.alloc(32, 3).toString('base64'),
    capturePublicKey: Buffer.alloc(32, 2).toString('base64'),
    restorePublicKey: q.restorePublicKey,
  };
  const offer: VPNSSOOffer = {
    context: c,
    manifest: { bytes: 0, digest: createHash('sha256').digest('base64') },
    floor: {
      checkpoint: { revision: '0', deleted: false, digest: Array(32).fill(0) },
      rowVersion: '0',
    },
  };
  const packet: VPNSSOPacket = {
    context: c,
    direction: 'capture',
    manifest: {
      bytes: 19,
      digest: createHash('sha256').update('browser storage xyz').digest('base64'),
    },
    index: 0,
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.alloc(32, 4).toString('base64'),
      ciphertext: Buffer.alloc(35, 5).toString('base64'),
    },
  };
  return { q, c, offer, packet };
}
