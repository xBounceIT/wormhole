import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';
import {
  parseVaultRdpCredentialsContext,
  rdpCredentialsInfo,
  type VaultRdpCredentialsEnvelope,
} from '../electron/vault-rdp-credentials.ts';
export type RdpTemporaryCredentials = {
  username: Uint8Array;
  domain: Uint8Array;
  password: Uint8Array;
};
// Imported only by the isolated document. Consume every input buffer before
// asynchronous crypto; the ordinary app and main see the envelope only.
export async function sealRdpTemporaryCredentials(
  value: unknown,
  input: RdpTemporaryCredentials,
  signal?: AbortSignal,
): Promise<VaultRdpCredentialsEnvelope> {
  const fields = [input?.username, input?.domain, input?.password];
  let frame: Uint8Array | undefined;
  try {
    const context = parseVaultRdpCredentialsContext(value);
    if (!context || fields.some((f) => !(f instanceof Uint8Array)))
      throw Error('Invalid credentials.');
    if (signal?.aborted) throw Error('Cancelled.');
    for (let i = 0; i < fields.length; i++) {
      const bytes = fields[i];
      if (bytes.byteLength > (i === 2 ? 16384 : 2048)) throw Error('Invalid credentials.');
      const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
      if (
        (i === 0 && text.length === 0) ||
        text.includes('\r') ||
        text.includes('\n') ||
        text.includes('\0') ||
        Array.from(text).length > (i === 2 ? 4096 : 513)
      )
        throw Error('Invalid credentials.');
    }
    frame = new Uint8Array(14 + fields.reduce((n, f) => n + f.byteLength, 0));
    frame[0] = 1;
    frame[1] = 1;
    let offset = 2;
    for (const field of fields) {
      new DataView(frame.buffer).setUint32(offset, field.byteLength);
      frame.set(field, offset + 4);
      offset += 4 + field.byteLength;
    }
    for (const field of fields) field.fill(0);
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const recipientPublicKey = await suite.kem.deserializePublicKey(
      enrollmentBytes(context.publicKey, 32)!,
    );
    if (signal?.aborted) throw Error('Cancelled.');
    const result = await suite.seal(
      { recipientPublicKey, info: rdpCredentialsInfo(context) },
      frame,
    );
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
        ? 'RDP credential entry was cancelled.'
        : 'RDP credentials could not be encrypted.',
    );
  } finally {
    for (const field of fields) if (field instanceof Uint8Array) field.fill(0);
    frame?.fill(0);
  }
}
