import { createVaultDisplayRecipient } from '../electron/vault-display-recipient.ts';
import {
  parseVaultNotesContext,
  parseVaultNotesDisplay,
  notesCiphertext,
  type VaultNotesContext,
} from '../electron/vault-notes.ts';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';

// This module is loaded only by the isolated credentials display document.
export async function createCredentialsRecipient(context: VaultNotesContext) {
  const expected = parseVaultNotesContext(context);
  if (!expected) throw Error('Invalid credentials context.');
  return createVaultDisplayRecipient(
    'wormhole/v1/credential-display',
    [expected.workspaceId, expected.nodeId, expected.requestId, expected.rowVersion],
    (value) => {
      const result = parseVaultNotesDisplay(value, expected);
      return result
        ? {
            enc: enrollmentBytes(result.bundle.enc, 32)!,
            ciphertext: notesCiphertext(result.bundle.ciphertext)!,
          }
        : undefined;
    },
  );
}

export function decodeCredentialDisplay(raw: Uint8Array): {
  username: string;
  domain: string;
  secret: string;
  label: string;
} {
  if (raw.length < 14 || raw.length > 20494 || raw[0] !== 1 || raw[1] > 1)
    throw Error('Invalid credentials response.');
  const reader = new DataView(raw.buffer, raw.byteOffset, raw.byteLength),
    fields: string[] = [];
  let offset = 2;
  for (const limit of [2048, 2048, 16384]) {
    if (offset + 4 > raw.length) throw Error('Invalid credentials response.');
    const length = reader.getUint32(offset);
    offset += 4;
    if (length > limit || offset + length > raw.length)
      throw Error('Invalid credentials response.');
    fields.push(
      new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
        raw.subarray(offset, offset + length),
      ),
    );
    offset += length;
  }
  if (offset !== raw.length) throw Error('Invalid credentials response.');
  return {
    username: fields[0],
    domain: fields[1],
    secret: fields[2],
    label: raw[1] === 1 ? 'Passphrase' : 'Password',
  };
}
