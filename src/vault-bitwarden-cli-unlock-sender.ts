import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import {
  bitwardenCLIPasswordInfo,
  maxBitwardenCLIPassword,
  type VaultBitwardenCLIEnvelope,
  type VaultBitwardenCLIUnlockContext,
} from '../electron/vault-bitwarden-cli-unlock.ts';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';

export async function sealBitwardenCLIPassword(
  context: VaultBitwardenCLIUnlockContext,
  password: Uint8Array,
  signal: AbortSignal,
): Promise<VaultBitwardenCLIEnvelope> {
  try {
    if (
      password.length === 0 ||
      password.length > maxBitwardenCLIPassword ||
      password.some((byte) => byte === 0 || byte === 10 || byte === 13)
    )
      throw Error('Invalid password.');
    signal.throwIfAborted();
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const recipientPublicKey = await suite.kem.deserializePublicKey(
      enrollmentBytes(context.publicKey, 32)!,
    );
    signal.throwIfAborted();
    const result = await suite.seal(
      { recipientPublicKey, info: bitwardenCLIPasswordInfo(context.binding) },
      password,
    );
    signal.throwIfAborted();
    return {
      formatVersion: 1,
      suiteId: 2,
      enc: btoa(String.fromCharCode(...new Uint8Array(result.enc))),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(result.ct))),
    };
  } finally {
    password.fill(0);
  }
}
