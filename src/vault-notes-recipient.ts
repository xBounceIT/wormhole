import { createVaultDisplayRecipient } from '../electron/vault-display-recipient.ts';
import {
  parseVaultNotesContext,
  parseVaultNotesDisplay,
  notesCiphertext,
  type VaultNotesContext,
} from '../electron/vault-notes.ts';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';

// The private key and plaintext live only in the isolated display document.
export async function createNotesRecipient(context: VaultNotesContext) {
  const expected = parseVaultNotesContext(context);
  if (!expected) throw Error('Invalid notes context.');
  const recipient = await createVaultDisplayRecipient(
    'wormhole/v1/notes-display',
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
  let disposed = false;
  return {
    publicKey: recipient.publicKey,
    dispose() {
      disposed = true;
      recipient.dispose();
    },
    async open(value: unknown): Promise<Uint8Array> {
      const notes = await recipient.open(value);
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(notes);
        if (disposed || text.length > 16384 || text.includes('\0'))
          throw Error('Invalid notes response.');
        return notes;
      } catch {
        notes.fill(0);
        throw Error('Invalid notes response.');
      }
    },
  };
}
