import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';
import {
  parseVaultSshManualContext,
  sshManualInfo,
  type VaultSshManualEnvelope,
} from '../electron/vault-ssh-manual.ts';

export type SshTemporaryCredentials = {
  username: Uint8Array;
  password: Uint8Array;
  privateKey: Uint8Array;
  passphrase: Uint8Array;
  certificate: Uint8Array;
};
function base64(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += 16384)
    parts.push(String.fromCharCode(...bytes.subarray(i, i + 16384)));
  return btoa(parts.join(''));
}

// Import only in the protected credential document. Caller buffers and the
// complete encoded secret frame are consumed on success, cancellation or error.
export async function sealSshTemporaryCredentials(
  value: unknown,
  input: SshTemporaryCredentials,
  signal?: AbortSignal,
): Promise<VaultSshManualEnvelope> {
  const fields = [
    input?.username,
    input?.password,
    input?.privateKey,
    input?.passphrase,
    input?.certificate,
  ];
  let frame: Uint8Array | undefined;
  try {
    const c = parseVaultSshManualContext(value);
    if (!c || fields.some((f) => !(f instanceof Uint8Array)) || signal?.aborted)
      throw Error('Invalid input.');
    const [username, password, key, passphrase, certificate] = fields;
    const limits = [2048, 16384, 1024 * 1024, 16384, 1024 * 1024];
    if (fields.some((f, i) => f.byteLength > limits[i])) throw Error('Invalid input.');
    if (c.plan.mode === 'passphrase') {
      if (username.length || password.length || key.length || certificate.length)
        throw Error('Invalid input.');
      frame = new Uint8Array(6 + passphrase.length);
      frame[0] = 1;
      frame[1] = 2;
      new DataView(frame.buffer).setUint32(2, passphrase.length);
      frame.set(passphrase, 6);
    } else {
      const name = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(username);
      if (
        !name ||
        /\p{Cc}/u.test(name) ||
        (!key.length && (!password.length || passphrase.length || certificate.length)) ||
        (key.length && password.length)
      )
        throw Error('Invalid input.');
      const ordered = [
        username,
        new TextEncoder().encode(c.plan.host.fingerprint),
        password,
        key,
        passphrase,
        certificate,
      ];
      frame = new Uint8Array(26 + ordered.reduce((size, f) => size + f.length, 0));
      frame[0] = 1;
      let offset = 2;
      for (const field of ordered) {
        new DataView(frame.buffer).setUint32(offset, field.length);
        frame.set(field, offset + 4);
        offset += 4 + field.length;
      }
    }
    for (const field of fields) field.fill(0);
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const recipientPublicKey = await suite.kem.deserializePublicKey(
      enrollmentBytes(c.publicKey, 32)!,
    );
    if (signal?.aborted) throw Error('Cancelled.');
    const result = await suite.seal({ recipientPublicKey, info: sshManualInfo(c) }, frame);
    if (signal?.aborted) throw Error('Cancelled.');
    return {
      formatVersion: 1,
      suiteId: 2,
      enc: base64(new Uint8Array(result.enc)),
      ciphertext: base64(new Uint8Array(result.ct)),
    };
  } catch {
    throw Error(
      signal?.aborted
        ? 'SSH credential entry was cancelled.'
        : 'SSH credentials could not be encrypted.',
    );
  } finally {
    for (const field of fields) if (field instanceof Uint8Array) field.fill(0);
    frame?.fill(0);
  }
}
