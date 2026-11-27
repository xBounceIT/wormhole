import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import {
  enrollmentBytes,
  parseRecoveryDisplay,
  type RecoveryDisplayReceipt,
} from '../electron/vault-enrollment-contract.ts';

export type RecoveryRecipient = {
  publicKey: Uint8Array;
  open(value: RecoveryDisplayReceipt): Promise<Uint8Array>;
  dispose(): void;
};

// Runs only in the isolated recovery dialog. Its non-exportable private key and
// plaintext recovery code never cross the preload bridge or enter React state.
export async function createRecoveryRecipient(): Promise<RecoveryRecipient> {
  let pair: CryptoKeyPair | undefined = (await crypto.subtle.generateKey(
    { name: 'X25519' },
    false,
    ['deriveBits'],
  )) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  let disposed = false;
  return {
    publicKey,
    dispose() {
      disposed = true;
      pair = undefined;
      publicKey.fill(0);
    },
    async open(value) {
      const key = pair;
      pair = undefined;
      if (!key || disposed) throw Error('Recovery recipient is closed.');
      const result = parseRecoveryDisplay({
        enrollmentId: value?.enrollmentId,
        vaultId: value?.vaultId,
        bundle: value?.bundle,
      });
      if (!result) throw Error('Invalid recovery response.');
      const encoder = new TextEncoder();
      const domain = encoder.encode('wormhole/v1/recovery-display');
      const info = new Uint8Array(domain.length + 4 + 36 + 4 + 36);
      info.set(domain);
      let offset = domain.length;
      for (const id of [result.vaultId, result.enrollmentId]) {
        new DataView(info.buffer).setUint32(offset, 36);
        info.set(encoder.encode(id), offset + 4);
        offset += 40;
      }
      const code = new Uint8Array(
        await suite.open(
          { recipientKey: key, enc: enrollmentBytes(result.bundle.enc, 32)!, info },
          enrollmentBytes(result.bundle.ciphertext, 92)!,
        ),
      );
      if (
        disposed ||
        !/^WHREC1-(?:[A-Z2-7]{5}-){11}[A-Z2-7]{3}$/.test(new TextDecoder().decode(code))
      ) {
        code.fill(0);
        throw Error('Invalid recovery response.');
      }
      return code;
    },
  };
}
