import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';

export const browserTransferAreaBytes = 8 * 1024 * 1024;
export const browserTransferChunkBytes = 4 * 1024 * 1024;
export const browserTransferFrameBytes = 10 + 2 * browserTransferAreaBytes;
export type BrowserTransferContext = {
  workspaceId: string;
  fileId: string;
  profileId: string;
  requestId: string;
  transferId: string;
  epoch: number;
  policySequence: string;
  action: 'hydrate' | 'capture';
  sourceRevision: string;
  capturePublicKey: string;
  restorePublicKey: string;
};
export type BrowserTransferManifest = { bytes: number; revision: string; restore: boolean };
export type BrowserTransferPacket = {
  context: BrowserTransferContext;
  direction: 'capture' | 'restore';
  manifest: BrowserTransferManifest;
  index: number;
  bundle: { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
};
export function browserTransferDecimal(value: unknown, zero = true): value is string {
  return (
    typeof value === 'string' &&
    /^(0|[1-9][0-9]{0,18})$/.test(value) &&
    (zero || value !== '0') &&
    BigInt(value) <= 9223372036854775807n
  );
}
export function parseBrowserTransferContext(value: unknown): BrowserTransferContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'workspaceId',
      'fileId',
      'profileId',
      'requestId',
      'transferId',
      'epoch',
      'policySequence',
      'action',
      'sourceRevision',
      'capturePublicKey',
      'restorePublicKey',
    ]) ||
    ![value.workspaceId, value.fileId, value.profileId, value.requestId, value.transferId].every(
      vaultID,
    ) ||
    !Number.isSafeInteger(value.epoch) ||
    (value.epoch as number) < 1 ||
    !browserTransferDecimal(value.policySequence, false) ||
    !browserTransferDecimal(value.sourceRevision) ||
    (value.action !== 'hydrate' && value.action !== 'capture') ||
    !enrollmentBytes(value.capturePublicKey, 32) ||
    !enrollmentBytes(value.restorePublicKey, 32)
  )
    return undefined;
  return {
    workspaceId: value.workspaceId as string,
    fileId: value.fileId as string,
    profileId: value.profileId as string,
    requestId: value.requestId as string,
    transferId: value.transferId as string,
    epoch: value.epoch as number,
    policySequence: value.policySequence,
    action: value.action,
    sourceRevision: value.sourceRevision,
    capturePublicKey: value.capturePublicKey as string,
    restorePublicKey: value.restorePublicKey as string,
  };
}
export function parseBrowserTransferManifest(
  value: unknown,
  expected: unknown,
  direction: unknown,
): BrowserTransferManifest | undefined {
  const context = parseBrowserTransferContext(expected);
  if (!context) return undefined;
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['bytes', 'revision', 'restore']) ||
    !Number.isSafeInteger(value.bytes) ||
    (value.bytes as number) < 14 ||
    (value.bytes as number) > browserTransferFrameBytes ||
    !browserTransferDecimal(value.revision) ||
    typeof value.restore !== 'boolean' ||
    (direction === 'capture'
      ? value.revision !== context.sourceRevision || value.restore
      : direction !== 'restore' || BigInt(value.revision) < BigInt(context.sourceRevision))
  )
    return undefined;
  return { bytes: value.bytes as number, revision: value.revision, restore: value.restore };
}
export function browserTransferChunkCount(manifest: BrowserTransferManifest): number {
  if (
    !Number.isSafeInteger(manifest.bytes) ||
    manifest.bytes < 14 ||
    manifest.bytes > browserTransferFrameBytes
  )
    throw Error('Invalid browser transfer size.');
  return Math.ceil(manifest.bytes / browserTransferChunkBytes);
}
export function browserTransferChunkSize(manifest: BrowserTransferManifest, index: number): number {
  if (!Number.isInteger(index) || index < 0 || index >= browserTransferChunkCount(manifest))
    throw Error('Invalid browser transfer chunk.');
  return Math.min(browserTransferChunkBytes, manifest.bytes - index * browserTransferChunkBytes);
}
export function browserTransferInfo(
  value: unknown,
  direction: unknown,
  manifest: unknown,
  index: number,
): Uint8Array {
  const c = parseBrowserTransferContext(value),
    m = c && parseBrowserTransferManifest(manifest, c, direction);
  if (!c || !m) throw Error('Invalid browser transfer context.');
  browserTransferChunkSize(m, index);
  const fields = [
    c.workspaceId,
    c.fileId,
    c.profileId,
    c.requestId,
    c.transferId,
    String(c.epoch),
    c.policySequence,
    c.action,
    c.sourceRevision,
    c.capturePublicKey,
    c.restorePublicKey,
    String(direction),
    String(m.bytes),
    m.revision,
    m.restore ? '1' : '0',
    String(index),
  ];
  const encoder = new TextEncoder(),
    prefix = encoder.encode('wormhole/v1/bitwarden-browser-transfer'),
    parts = fields.map((x) => encoder.encode(x));
  const out = new Uint8Array(prefix.length + parts.reduce((sum, x) => sum + 4 + x.length, 0));
  out.set(prefix);
  let offset = prefix.length;
  for (const p of parts) {
    new DataView(out.buffer).setUint32(offset, p.length);
    out.set(p, offset + 4);
    offset += 4 + p.length;
  }
  return out;
}
export function parseBrowserTransferPacket(
  value: unknown,
  expected: BrowserTransferContext,
  direction: 'capture' | 'restore',
): BrowserTransferPacket | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['context', 'direction', 'manifest', 'index', 'bundle']) ||
    value.direction !== direction
  )
    return undefined;
  const context = parseBrowserTransferContext(value.context),
    base = parseBrowserTransferContext(expected);
  if (
    !context ||
    !base ||
    Object.entries(base).some(([key, v]) => context[key as keyof BrowserTransferContext] !== v)
  )
    return undefined;
  const manifest = parseBrowserTransferManifest(value.manifest, context, direction),
    b = value.bundle;
  if (
    !manifest ||
    !Number.isInteger(value.index) ||
    (value.index as number) < 0 ||
    (value.index as number) >= browserTransferChunkCount(manifest) ||
    !vaultRecord(b) ||
    !vaultFields(b, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    b.formatVersion !== 1 ||
    b.suiteId !== 2 ||
    !enrollmentBytes(b.enc, 32) ||
    !enrollmentBytes(b.ciphertext, browserTransferChunkSize(manifest, value.index as number) + 16)
  )
    return undefined;
  return {
    context,
    direction,
    manifest,
    index: value.index as number,
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: b.enc as string,
      ciphertext: b.ciphertext as string,
    },
  };
}
function validJSON(raw: Uint8Array): boolean {
  if (!(raw instanceof Uint8Array) || raw.length < 2 || raw.length > browserTransferAreaBytes)
    return false;
  try {
    const value = JSON.parse(
      new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw),
    );
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  } catch {
    return false;
  }
}
// Isolated native context only. No ordinary renderer/preload exports these bytes.
export function encodeBrowserTransferFrame(local: Uint8Array, session: Uint8Array): Uint8Array {
  if (!validJSON(local) || !validJSON(session)) throw Error('Invalid browser storage capture.');
  const out = new Uint8Array(10 + local.length + session.length),
    view = new DataView(out.buffer);
  out[0] = 1;
  view.setUint32(2, local.length);
  view.setUint32(6, session.length);
  out.set(local, 10);
  out.set(session, 10 + local.length);
  return out;
}
export function decodeBrowserTransferFrame(raw: Uint8Array): {
  localJSON: Uint8Array;
  sessionJSON: Uint8Array;
} {
  if (
    !(raw instanceof Uint8Array) ||
    raw.length < 14 ||
    raw.length > browserTransferFrameBytes ||
    raw[0] !== 1 ||
    raw[1] !== 0
  )
    throw Error('Invalid browser storage frame.');
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength),
    local = view.getUint32(2),
    session = view.getUint32(6);
  if (
    local < 2 ||
    session < 2 ||
    local > browserTransferAreaBytes ||
    session > browserTransferAreaBytes ||
    10 + local + session !== raw.length
  )
    throw Error('Invalid browser storage frame.');
  const localJSON = raw.subarray(10, 10 + local),
    sessionJSON = raw.subarray(10 + local);
  if (!validJSON(localJSON) || !validJSON(sessionJSON))
    throw Error('Invalid browser storage frame.');
  return { localJSON, sessionJSON };
}
