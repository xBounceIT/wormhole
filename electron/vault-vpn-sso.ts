import { createHash } from 'node:crypto';
import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';
import { browserTransferDecimal } from './vault-bitwarden-transfer.ts';
import {
  parseBrowserTransferAccepted,
  parseBrowserTransferCancelled,
} from './vault-bitwarden-native.ts';
import {
  parseVaultRouteBinding,
  parseVaultRoutePlanRequest,
  type VaultRouteBinding,
  type VaultRoutePlanRequest,
} from './vault-route.ts';
import {
  parseVaultTunnelFallbackBinding,
  type VaultTunnelFallbackBinding,
} from './vault-tunnel-fallback.ts';

// Main-only native transport. These DTOs carry metadata and ciphertext, never
// browser storage, completion credentials or a private recipient key.
export const vpnSSOChunkBytes = 4 * 1024 * 1024;
export const vpnSSOArchiveBytes = 64 * 1024 * 1024 - 48;
const zeroDigest = Buffer.alloc(32).toString('base64');
const emptyDigest = createHash('sha256').digest('base64');
const nonzeroDigest = (v: unknown): v is string => canonicalBase64(v, 32, 32) && v !== zeroDigest;
export type VPNSSOContext = {
  workspaceId: string;
  fileId: string;
  profileId: string;
  requestId: string;
  transferId: string;
  sessionId: string;
  challengeId: string;
  epoch: number;
  policySequence: string;
  sourceRevision: string;
  sourceDeleted: boolean;
  sourceDigest: string;
  bindingDigest: string;
  capturePublicKey: string;
  restorePublicKey: string;
};
export type VPNSSOManifest = { bytes: number; digest: string };
export type VPNSSOPacket = {
  context: VPNSSOContext;
  direction: 'restore' | 'capture';
  manifest: VPNSSOManifest;
  index: number;
  bundle: { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
};
export type VPNSSOCheckpoint = { revision: string; deleted: boolean; digest: number[] };
export type VPNSSOOffer = {
  context: VPNSSOContext;
  manifest: VPNSSOManifest;
  floor: { checkpoint: VPNSSOCheckpoint; rowVersion: string };
};
export type VPNSSOBegin = {
  request: VaultRoutePlanRequest;
  binding: VaultRouteBinding;
  profileId: string;
  challengeId: string;
  startURL: string;
  ignoreCertificateErrors: boolean;
  restorePublicKey: string;
  // Authenticated native device selection; the shared source keeps its own ID.
  custody?: { workspaceId: string; fileId: string };
  fallback?: VaultTunnelFallbackBinding;
};
export function parseVPNSSOContext(value: unknown): VPNSSOContext | undefined {
  const ids = [
    'workspaceId',
    'fileId',
    'profileId',
    'requestId',
    'transferId',
    'sessionId',
    'challengeId',
  ];
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      ...ids,
      'epoch',
      'policySequence',
      'sourceRevision',
      'sourceDeleted',
      'sourceDigest',
      'bindingDigest',
      'capturePublicKey',
      'restorePublicKey',
    ]) ||
    !ids.every((key) => vaultID(value[key])) ||
    !Number.isSafeInteger(value.epoch) ||
    (value.epoch as number) < 1 ||
    !browserTransferDecimal(value.policySequence, false) ||
    !browserTransferDecimal(value.sourceRevision) ||
    typeof value.sourceDeleted !== 'boolean' ||
    !canonicalBase64(value.sourceDigest, 32, 32) ||
    !nonzeroDigest(value.bindingDigest) ||
    !canonicalBase64(value.capturePublicKey, 32, 32) ||
    !canonicalBase64(value.restorePublicKey, 32, 32) ||
    (value.sourceRevision === '0'
      ? value.sourceDeleted || value.sourceDigest !== zeroDigest
      : value.sourceDigest === zeroDigest)
  )
    return undefined;
  return { ...value } as VPNSSOContext;
}
export function parseVPNSSOManifest(
  value: unknown,
  expected: unknown,
  direction: 'restore' | 'capture',
): VPNSSOManifest | undefined {
  const c = parseVPNSSOContext(expected);
  if (
    !c ||
    !vaultRecord(value) ||
    !vaultFields(value, ['bytes', 'digest']) ||
    !Number.isSafeInteger(value.bytes) ||
    (value.bytes as number) < 0 ||
    (value.bytes as number) > vpnSSOArchiveBytes ||
    !nonzeroDigest(value.digest)
  )
    return undefined;
  if (direction === 'restore') {
    const empty = c.sourceRevision === '0' || c.sourceDeleted;
    if (empty !== (value.bytes === 0) || (empty && value.digest !== emptyDigest)) return undefined;
  } else if (direction !== 'capture' || value.bytes === 0) return undefined;
  return { bytes: value.bytes as number, digest: value.digest };
}
export function vpnSSOChunkCount(m: VPNSSOManifest): number {
  if (!Number.isSafeInteger(m.bytes) || m.bytes < 0 || m.bytes > vpnSSOArchiveBytes)
    throw Error('Invalid VPN SSO archive size.');
  return Math.ceil(m.bytes / vpnSSOChunkBytes);
}
export function parseVPNSSOPacket(
  value: unknown,
  expected: unknown,
  direction: 'restore' | 'capture',
): VPNSSOPacket | undefined {
  const base = parseVPNSSOContext(expected);
  if (
    !base ||
    !vaultRecord(value) ||
    !vaultFields(value, ['context', 'direction', 'manifest', 'index', 'bundle']) ||
    value.direction !== direction
  )
    return undefined;
  const c = parseVPNSSOContext(value.context);
  if (!c || Object.entries(base).some(([key, v]) => c[key as keyof VPNSSOContext] !== v))
    return undefined;
  const m = parseVPNSSOManifest(value.manifest, c, direction),
    b = value.bundle;
  if (
    !m ||
    !Number.isInteger(value.index) ||
    (value.index as number) < 0 ||
    (value.index as number) >= vpnSSOChunkCount(m) ||
    !vaultRecord(b) ||
    !vaultFields(b, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    b.formatVersion !== 1 ||
    b.suiteId !== 2 ||
    !canonicalBase64(b.enc, 32, 32) ||
    !canonicalBase64(
      b.ciphertext,
      Math.min(vpnSSOChunkBytes, m.bytes - (value.index as number) * vpnSSOChunkBytes) + 16,
      Math.min(vpnSSOChunkBytes, m.bytes - (value.index as number) * vpnSSOChunkBytes) + 16,
    )
  )
    return undefined;
  return {
    context: c,
    manifest: m,
    direction,
    index: value.index as number,
    bundle: { formatVersion: 1, suiteId: 2, enc: b.enc, ciphertext: b.ciphertext },
  };
}
export function parseVPNSSOCheckpoint(value: unknown): VPNSSOCheckpoint | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['revision', 'deleted', 'digest']) ||
    !browserTransferDecimal(value.revision) ||
    typeof value.deleted !== 'boolean' ||
    !Array.isArray(value.digest) ||
    value.digest.length !== 32 ||
    !Array.from(value.digest).every(
      (n: unknown) => Number.isInteger(n) && (n as number) >= 0 && (n as number) <= 255,
    ) ||
    (value.revision === '0'
      ? value.deleted || value.digest.some((n) => n !== 0)
      : value.digest.every((n) => n === 0))
  )
    return undefined;
  return { revision: value.revision, deleted: value.deleted, digest: [...value.digest] };
}
export function parseVPNSSOBegin(value: unknown): VPNSSOBegin | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'request',
      'binding',
      'profileId',
      'challengeId',
      'startURL',
      'ignoreCertificateErrors',
      'restorePublicKey',
      ...(Object.hasOwn(value, 'custody') ? ['custody'] : []),
      ...(Object.hasOwn(value, 'fallback') ? ['fallback'] : []),
    ]) ||
    !vaultID(value.profileId) ||
    !vaultID(value.challengeId) ||
    typeof value.startURL !== 'string' ||
    value.startURL.length > 4096 ||
    typeof value.ignoreCertificateErrors !== 'boolean' ||
    !canonicalBase64(value.restorePublicKey, 32, 32)
  )
    return undefined;
  const request = parseVaultRoutePlanRequest(value.request);
  let fallback: VaultTunnelFallbackBinding | undefined;
  if (Object.hasOwn(value, 'fallback')) {
    if (!request || !vaultRecord(value.fallback) || !vaultRecord(value.fallback.fallback))
      return undefined;
    fallback = parseVaultTunnelFallbackBinding(value.fallback, {
      ...request,
      primary: value.fallback.primary,
      fallbackRequestId: value.fallback.fallback.requestId,
    } as Parameters<typeof parseVaultTunnelFallbackBinding>[1]);
    if (!fallback) return undefined;
  }
  const binding =
    request &&
    parseVaultRouteBinding(value.binding, {
      ...request,
      requestId: fallback?.fallback.requestId ?? request.requestId,
    });
  if (!request || !binding || ![2, 9].includes(binding.kind)) return undefined;
  if (fallback && JSON.stringify(binding) !== JSON.stringify(fallback.fallback)) return undefined;
  const custody = value.custody;
  if (
    Object.hasOwn(value, 'custody') &&
    (!vaultRecord(custody) ||
      !vaultFields(custody, ['workspaceId', 'fileId']) ||
      !vaultID(custody.workspaceId) ||
      !vaultID(custody.fileId) ||
      custody.fileId !== binding.fileId)
  )
    return undefined;
  try {
    const url = new URL(value.startURL);
    if (
      url.protocol !== 'https:' ||
      url.username ||
      url.password ||
      url.hash ||
      /[\p{White_Space}\p{Cc}\\]/u.test(value.startURL)
    )
      return undefined;
  } catch {
    return undefined;
  }
  return {
    request,
    binding,
    profileId: value.profileId,
    challengeId: value.challengeId,
    startURL: value.startURL,
    ignoreCertificateErrors: value.ignoreCertificateErrors,
    restorePublicKey: value.restorePublicKey,
    ...(fallback ? { fallback } : {}),
    ...(vaultRecord(custody)
      ? {
          custody: { workspaceId: custody.workspaceId as string, fileId: custody.fileId as string },
        }
      : {}),
  };
}
export function parseVPNSSOOffer(value: unknown, q: VPNSSOBegin): VPNSSOOffer | undefined {
  if (!vaultRecord(value) || !vaultFields(value, ['context', 'manifest', 'floor']))
    return undefined;
  const c = parseVPNSSOContext(value.context),
    floor = value.floor;
  if (
    !c ||
    c.workspaceId !== (q.custody?.workspaceId ?? q.request.workspaceId) ||
    c.fileId !== q.binding.fileId ||
    c.profileId !== q.profileId ||
    c.sessionId !== q.request.sessionId ||
    c.requestId !== q.request.requestId ||
    c.epoch !== q.request.epoch ||
    c.challengeId !== q.challengeId ||
    c.restorePublicKey !== q.restorePublicKey ||
    !vaultRecord(floor) ||
    !vaultFields(floor, ['checkpoint', 'rowVersion'])
  )
    return undefined;
  const m = parseVPNSSOManifest(value.manifest, c, 'restore'),
    checkpoint = parseVPNSSOCheckpoint(floor.checkpoint);
  if (
    !m ||
    !checkpoint ||
    floor.rowVersion !== c.sourceRevision ||
    checkpoint.revision !== c.sourceRevision ||
    checkpoint.deleted !== c.sourceDeleted ||
    Buffer.from(checkpoint.digest).toString('base64') !== c.sourceDigest
  )
    return undefined;
  return { context: c, manifest: m, floor: { checkpoint, rowVersion: checkpoint.revision } };
}

export interface VPNSSOClient {
  beginVPNSSO(value: unknown): Promise<VPNSSOOffer>;
  takeVPNSSO(context: unknown, manifest: unknown, index: number): Promise<VPNSSOPacket>;
  acknowledgeVPNSSO(context: unknown, manifest: unknown): Promise<{ restored: true }>;
  pushVPNSSO(packet: unknown): Promise<{ accepted: true; index: number }>;
  commitVPNSSO(context: unknown): Promise<VPNSSOCheckpoint>;
  cancelVPNSSO(context: unknown): Promise<{ cancelled: true }>;
}
export interface VPNSSOCapability {
  readonly offer: VPNSSOOffer;
  take(index: number): Promise<VPNSSOPacket>;
  acknowledge(): Promise<void>;
  push(value: unknown): Promise<void>;
  commit(): Promise<VPNSSOCheckpoint>;
  cancel(): Promise<void>;
}

// Capture the exact process, route override, recipient and native authority.
// Late replies always cancel on this process, including after host replacement.
export async function beginNativeVPNSSO(
  client: VPNSSOClient,
  value: unknown,
  current: () => boolean,
  reserved?: (capability: VPNSSOCapability) => void,
  retireOriginal?: () => Promise<void>,
): Promise<VPNSSOCapability> {
  const q = parseVPNSSOBegin(value);
  const checkOwner = () => {
    if (!current()) throw Error('VPN SSO owner is unavailable.');
  };
  if (!q) throw Error('Invalid VPN SSO request.');
  checkOwner();
  const offer = parseVPNSSOOffer(await client.beginVPNSSO(structuredClone(q)), q);
  if (!offer) throw Error('Invalid VPN SSO offer.');
  const c = offer.context;
  let closed = false,
    busy = false,
    retired = false;
  const cancel = async () => {
    closed = true;
    if (retired) return;
    try {
      if (!parseBrowserTransferCancelled(await client.cancelVPNSSO(structuredClone(c))))
        throw Error('VPN SSO cleanup is unconfirmed.');
    } catch (error) {
      if (!retireOriginal) throw error;
      // A confirmed exit releases all stages of THIS process. A timeout or
      // termination request alone is insufficient; the native owner must join it.
      await retireOriginal();
      retired = true;
    }
  };
  const run = async <T>(action: () => Promise<T>): Promise<T> => {
    if (busy) throw Error('VPN SSO transfer is busy.');
    busy = true;
    try {
      if (closed) throw Error('VPN SSO transfer is closed.');
      checkOwner();
      const result = await action();
      checkOwner();
      if (closed) throw Error('VPN SSO transfer is closed.');
      return result;
    } catch (error) {
      try {
        await cancel();
      } catch (cleanup) {
        throw new AggregateError([error, cleanup], 'VPN SSO cleanup is unconfirmed.');
      }
      throw error;
    } finally {
      busy = false;
    }
  };
  const capability: VPNSSOCapability = {
    get offer() {
      return structuredClone(offer);
    },
    take: (index: number) =>
      run(async () => {
        if (!Number.isInteger(index) || index < 0 || index >= vpnSSOChunkCount(offer.manifest))
          throw Error('Invalid VPN SSO chunk.');
        const p = parseVPNSSOPacket(
          await client.takeVPNSSO(structuredClone(c), { ...offer.manifest }, index),
          c,
          'restore',
        );
        if (
          !p ||
          p.index !== index ||
          p.manifest.bytes !== offer.manifest.bytes ||
          p.manifest.digest !== offer.manifest.digest
        )
          throw Error('Invalid VPN SSO restore.');
        return p;
      }),
    acknowledge: () =>
      run(async () => {
        const result = await client.acknowledgeVPNSSO(structuredClone(c), { ...offer.manifest });
        if (!vaultRecord(result) || !vaultFields(result, ['restored']) || result.restored !== true)
          throw Error('Invalid VPN SSO acknowledgement.');
      }),
    push: (value: unknown) =>
      run(async () => {
        const p = parseVPNSSOPacket(value, c, 'capture');
        if (!p || !parseBrowserTransferAccepted(await client.pushVPNSSO(p), p.index))
          throw Error('Invalid VPN SSO capture.');
      }),
    commit: async () => {
      const receipt = await run(async () => {
        const receipt = parseVPNSSOCheckpoint(await client.commitVPNSSO(structuredClone(c)));
        if (
          !receipt ||
          receipt.deleted ||
          BigInt(receipt.revision) !== BigInt(c.sourceRevision) + 1n
        )
          throw Error('Invalid VPN SSO commit.');
        return receipt;
      });
      closed = true;
      return receipt;
    },
    cancel,
  };
  // Register cleanup ownership before the final admission gate can fail. The
  // owning actor must retain this handle even when its begin promise rejects.
  try {
    reserved?.(capability);
  } catch (error) {
    try {
      await cancel();
    } catch (cleanup) {
      throw new AggregateError([error, cleanup], 'VPN SSO cleanup is unconfirmed.');
    }
    throw error;
  }
  await run(async () => undefined);
  return capability;
}
