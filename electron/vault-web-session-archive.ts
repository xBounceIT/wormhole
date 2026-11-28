import { Buffer } from 'node:buffer';
import { vaultFields, vaultRecord, vaultRevision } from './vault-contract.ts';
import { createVaultDisplayRecipient } from './vault-display-recipient.ts';
import type { VaultWebPlan } from './vault-web.ts';

export const maxWebSessionArchiveBytes = 1024 * 1024;
export const maxWebSessionArchiveReply = Math.ceil((maxWebSessionArchiveBytes + 16) / 3) * 4 + 4096;

export function webSessionArchiveCoordinates(plan: VaultWebPlan) {
  if (!plan.archiveBinding || plan.temporary) return undefined;
  const { workspaceId, nodeId, sessionId, requestId, epoch } = plan.binding;
  return {
    workspaceId,
    payload: {
      nodeId,
      sessionId,
      requestId,
      epoch: String(epoch),
      archiveBinding: plan.archiveBinding,
    },
  };
}

export type WebSessionArchiveCoordinates = NonNullable<
  ReturnType<typeof webSessionArchiveCoordinates>
>;

function parseArchiveBundle(value: unknown) {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    typeof value.enc !== 'string' ||
    value.enc.length !== 44 ||
    typeof value.ciphertext !== 'string' ||
    value.ciphertext.length < 24 ||
    value.ciphertext.length > Math.ceil((maxWebSessionArchiveBytes + 16) / 3) * 4
  )
    return undefined;
  const enc = Buffer.from(value.enc, 'base64');
  const ciphertext = Buffer.from(value.ciphertext, 'base64');
  if (
    enc.length !== 32 ||
    ciphertext.length <= 16 ||
    ciphertext.length > maxWebSessionArchiveBytes + 16 ||
    enc.toString('base64') !== value.enc ||
    ciphertext.toString('base64') !== value.ciphertext
  )
    return undefined;
  return { enc, ciphertext };
}

export function parseWebSessionArchiveReply(value: unknown) {
  if (!vaultRecord(value)) return undefined;
  const { revision } = value;
  if (vaultFields(value, ['revision']) && (revision === '0' || vaultRevision(revision)))
    return { revision };
  if (!vaultFields(value, ['revision', 'bundle']) || !vaultRevision(revision)) return undefined;
  const bundle = parseArchiveBundle(value.bundle);
  return bundle ? { revision, bundle } : undefined;
}

export function webSessionArchiveWriteRevision(value: string) {
  return (value === '0' || vaultRevision(value)) && value !== '9223372036854775807';
}

export function parseWebSessionArchiveWrite(value: unknown, current: string) {
  if (!vaultRecord(value) || !vaultFields(value, ['revision'])) return undefined;
  const next = (BigInt(current) + 1n).toString();
  return value.revision === next ? next : undefined;
}

export type WebSessionArchive = { revision: string; bytes?: Uint8Array };
export type WebSessionArchiveStore = {
  read(): Promise<WebSessionArchive>;
  save(revision: string, bytes: Uint8Array): Promise<string>;
  forget(revision: string): Promise<string>;
};

export function webSessionArchiveRecipient({ workspaceId, payload }: WebSessionArchiveCoordinates) {
  return createVaultDisplayRecipient(
    'wormhole/v1/web-session-archive',
    [workspaceId, payload.nodeId, payload.requestId],
    // The native-reply parser already validated and decoded these bytes.
    (value) => value as NonNullable<ReturnType<typeof parseArchiveBundle>>,
  );
}
