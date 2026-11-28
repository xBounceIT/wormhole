import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import {
  browserTransferDecimal,
  parseBrowserTransferContext,
  parseBrowserTransferManifest,
  parseBrowserTransferPacket,
  type BrowserTransferContext,
  type BrowserTransferManifest,
  type BrowserTransferPacket,
} from './vault-bitwarden-transfer.ts';

// Main-process metadata only. This module is intentionally absent from preload.
export type BrowserTransferRequest = Pick<
  BrowserTransferContext,
  | 'workspaceId'
  | 'profileId'
  | 'requestId'
  | 'epoch'
  | 'action'
  | 'sourceRevision'
  | 'restorePublicKey'
>;
export function parseBrowserTransferRequest(value: unknown): BrowserTransferRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'workspaceId',
      'profileId',
      'requestId',
      'epoch',
      'action',
      'sourceRevision',
      'restorePublicKey',
    ]) ||
    ![value.workspaceId, value.profileId, value.requestId].every(vaultID) ||
    !Number.isSafeInteger(value.epoch) ||
    (value.epoch as number) < 1 ||
    (value.action !== 'hydrate' && value.action !== 'capture') ||
    !browserTransferDecimal(value.sourceRevision) ||
    !enrollmentBytes(value.restorePublicKey, 32)
  )
    return undefined;
  return {
    workspaceId: value.workspaceId as string,
    profileId: value.profileId as string,
    requestId: value.requestId as string,
    epoch: value.epoch as number,
    action: value.action,
    sourceRevision: value.sourceRevision,
    restorePublicKey: value.restorePublicKey as string,
  };
}
export function parseBrowserTransferBegun(
  value: unknown,
  q: BrowserTransferRequest,
): BrowserTransferContext | undefined {
  const c = parseBrowserTransferContext(value);
  return c && Object.entries(q).every(([key, v]) => c[key as keyof BrowserTransferContext] === v)
    ? c
    : undefined;
}
export function parseBrowserTransferAccepted(
  value: unknown,
  index: number,
): { accepted: true; index: number } | undefined {
  return vaultRecord(value) &&
    vaultFields(value, ['accepted', 'index']) &&
    value.accepted === true &&
    value.index === index
    ? { accepted: true, index }
    : undefined;
}
export function parseBrowserTransferCommitted(
  value: unknown,
  c: BrowserTransferContext,
): BrowserTransferManifest | undefined {
  return vaultRecord(value) && vaultFields(value, ['manifest'])
    ? parseBrowserTransferManifest(value.manifest, c, 'restore')
    : undefined;
}
export function parseBrowserTransferCancelled(value: unknown): { cancelled: true } | undefined {
  return vaultRecord(value) && vaultFields(value, ['cancelled']) && value.cancelled === true
    ? { cancelled: true }
    : undefined;
}
export function parseBrowserProfileClosed(value: unknown): { closed: true } | undefined {
  return vaultRecord(value) && vaultFields(value, ['closed']) && value.closed === true
    ? { closed: true }
    : undefined;
}
export interface BrowserTransferClient {
  beginBitwardenTransfer(value: unknown): Promise<BrowserTransferContext>;
  pushBitwardenTransfer(value: unknown): Promise<{ accepted: true; index: number }>;
  commitBitwardenTransfer(value: unknown): Promise<BrowserTransferManifest>;
  takeBitwardenTransfer(value: unknown, index: number): Promise<BrowserTransferPacket>;
  cancelBitwardenTransfer(value: unknown): Promise<{ cancelled: true }>;
  closeBitwardenProfile(profileId: string): Promise<{ closed: true }>;
}

// A capability captures one exact backend process and one browser authority.
// Losing either cancels on that original process, never on its replacement.
export async function beginNativeBrowserTransfer(
  client: BrowserTransferClient,
  q: BrowserTransferRequest,
  current: () => boolean,
) {
  if (!current()) throw Error('Vault is locked.');
  const c = await client.beginBitwardenTransfer(q);
  let closed = false,
    busy = false;
  const cancel = async () => {
    closed = true;
    await client.cancelBitwardenTransfer(c);
  };
  const check = () => {
    if (closed || !current()) throw Error('Vault is locked.');
  };
  const run = async <T>(action: () => Promise<T>): Promise<T> => {
    if (busy) throw Error('Browser transfer is busy.');
    busy = true;
    try {
      check();
      const value = await action();
      check();
      return value;
    } catch (error) {
      try {
        await cancel();
      } catch (cleanup) {
        throw new AggregateError([error, cleanup], 'Browser transfer cleanup was not confirmed.');
      }
      throw error;
    } finally {
      busy = false;
    }
  };
  await run(async () => undefined);
  return {
    get context() {
      return { ...c };
    },
    push: (packet: unknown) =>
      run(() => {
        const parsed = parseBrowserTransferPacket(packet, c, 'capture');
        if (!parsed) return Promise.reject(Error('Invalid browser transfer packet.'));
        return client.pushBitwardenTransfer(parsed);
      }),
    commit: () => run(() => client.commitBitwardenTransfer(c)),
    take: (index: number) => run(() => client.takeBitwardenTransfer(c, index)),
    closeProfile: async () => {
      closed = true;
      return client.closeBitwardenProfile(c.profileId);
    },
    cancel,
  };
}
