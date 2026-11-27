import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';
import {
  maxVncTemporaryPasswordBytes,
  parseVaultVncPasswordContext,
  vncPasswordInfo,
  type VaultVncPasswordEnvelope,
} from '../electron/vault-vnc-password.ts';

// Imported only by the isolated password document. The caller-owned input is
// consumed before asynchronous crypto work; its encoded frame is cleared on all
// outcomes. Main receives the returned envelope only, never this byte buffer.
export async function sealVncTemporaryPassword(
  value: unknown,
  password: Uint8Array,
  signal?: AbortSignal,
): Promise<VaultVncPasswordEnvelope> {
  const input = password instanceof Uint8Array ? password : undefined;
  let frame: Uint8Array | undefined;
  try {
    const context = parseVaultVncPasswordContext(value);
    if (!context || !input || input.byteLength > maxVncTemporaryPasswordBytes)
      throw Error('Invalid password input.');
    if (signal?.aborted) throw Error('Cancelled.');
    frame = new Uint8Array(6 + input.byteLength);
    frame[0] = 1;
    frame[1] = 1;
    new DataView(frame.buffer).setUint32(2, input.byteLength);
    frame.set(input, 6);
    input.fill(0);
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const recipientPublicKey = await suite.kem.deserializePublicKey(
      enrollmentBytes(context.publicKey, 32)!,
    );
    if (signal?.aborted) throw Error('Cancelled.');
    const result = await suite.seal({ recipientPublicKey, info: vncPasswordInfo(context) }, frame);
    if (signal?.aborted) throw Error('Cancelled.');
    return {
      formatVersion: 1,
      suiteId: 2,
      enc: btoa(String.fromCharCode(...new Uint8Array(result.enc))),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(result.ct))),
    };
  } catch {
    throw Error(
      signal?.aborted
        ? 'VNC password entry was cancelled.'
        : 'VNC password could not be encrypted.',
    );
  } finally {
    input?.fill(0);
    frame?.fill(0);
  }
}
