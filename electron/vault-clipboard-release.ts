import { isUtf8 } from 'node:buffer';
import { createVaultDisplayRecipient } from './vault-display-recipient.ts';
import { vaultFields, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import { vaultClipboardField, type VaultClipboardField } from './vault-clipboard.ts';
import {
  parseVaultNotesRequest,
  parseVaultNotesContext,
  parseVaultNotesDisplay,
  notesCiphertext,
  type VaultNotesRequest,
  type VaultNotesContext,
} from './vault-notes.ts';

export type VaultClipboardReleaseContext = VaultNotesContext & { field: VaultClipboardField };
export type VaultClipboardReleaseRequest = VaultNotesRequest & { field: VaultClipboardField };

export function parseClipboardReleaseRequest(
  value: unknown,
): VaultClipboardReleaseRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'workspaceId',
      'nodeId',
      'rowVersion',
      'requestId',
      'publicKey',
      'field',
    ]) ||
    !vaultClipboardField(value.field)
  )
    return undefined;
  const { field, ...rest } = value;
  const request = parseVaultNotesRequest(rest);
  return request ? { ...request, field } : undefined;
}

// Main only: this recipient must never be exposed by the application preload.
// The field-specific domain prevents substituting a password for an identity.
export async function createClipboardRecipient(context: VaultClipboardReleaseContext) {
  const { field, ...rest } = context;
  const expected = parseVaultNotesContext(rest);
  if (!expected || !vaultClipboardField(field)) throw Error('Invalid clipboard context.');
  return createVaultDisplayRecipient(
    'wormhole/v1/clipboard/' + field,
    [expected.workspaceId, expected.nodeId, expected.requestId, expected.rowVersion],
    (value) => {
      const result = parseVaultNotesDisplay(value, expected);
      if (!result) return undefined;
      const ciphertext = notesCiphertext(result.bundle.ciphertext)!;
      return ciphertext.length <= 16402
        ? { enc: enrollmentBytes(result.bundle.enc, 32)!, ciphertext }
        : undefined;
    },
  );
}

// Borrow a view into the decrypted buffer. The owner wipes that buffer after
// synchronous clipboard publication; no plaintext string is retained here.
export function decodeClipboardRelease(raw: Uint8Array): {
  expiresInSeconds: 20 | 30;
  value: Uint8Array;
} {
  if (raw.length < 3 || raw.length > 16386 || raw[0] !== 1 || (raw[1] !== 20 && raw[1] !== 30))
    throw Error('Invalid clipboard response.');
  const value = raw.subarray(2);
  if (!isUtf8(value) || value.includes(0)) throw Error('Invalid clipboard response.');
  return { expiresInSeconds: raw[1], value };
}
