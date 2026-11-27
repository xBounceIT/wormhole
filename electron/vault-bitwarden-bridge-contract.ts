import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import {
  browserTransferDecimal,
  type BrowserTransferManifest,
  type BrowserTransferPacket,
} from './vault-bitwarden-transfer.ts';
import type { BrowserTransferRequest } from './vault-bitwarden-native.ts';

export type BitwardenBridgeOwner = { workspaceId: string; profileId: string; epoch: number };
export type BitwardenBridgeCapture = { chunks: number; manifest: BrowserTransferManifest };
export type BitwardenBridgeReceipt =
  | { complete: false }
  | { complete: true; revision: string; restore: boolean };
export interface BitwardenExtensionBridge {
  prepare(): Promise<BrowserTransferRequest>;
  bind(context: unknown): Promise<BitwardenBridgeCapture>;
  next(): Promise<BrowserTransferPacket>;
  accept(packet: unknown): Promise<BitwardenBridgeReceipt>;
  cancel(): Promise<{ cancelled: true }>;
  dispose(): Promise<{ closed: true }>;
}
export function parseBitwardenBridgeOwner(value: unknown): BitwardenBridgeOwner | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'profileId', 'epoch']) ||
    !vaultID(value.workspaceId) ||
    !vaultID(value.profileId) ||
    !Number.isSafeInteger(value.epoch) ||
    (value.epoch as number) < 1
  )
    return undefined;
  return {
    workspaceId: value.workspaceId,
    profileId: value.profileId,
    epoch: value.epoch as number,
  };
}
export function parseBitwardenBridgeReceipt(value: unknown): BitwardenBridgeReceipt | undefined {
  if (!vaultRecord(value)) return undefined;
  if (value.complete === false && vaultFields(value, ['complete'])) return { complete: false };
  return value.complete === true &&
    vaultFields(value, ['complete', 'revision', 'restore']) &&
    browserTransferDecimal(value.revision) &&
    typeof value.restore === 'boolean'
    ? { complete: true, revision: value.revision, restore: value.restore }
    : undefined;
}

export const bitwardenDocumentTimeoutMs = 30_000;
export const bitwardenDocumentPacketBytes = 6 * 1024 * 1024;
export type BitwardenDocumentOperation =
  | 'prepare'
  | 'bind'
  | 'next'
  | 'accept'
  | 'cancel'
  | 'dispose';
