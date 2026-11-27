import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';
import {
  parseVaultTunnelAuthenticationContext,
  tunnelAuthenticationInfo,
  maxTunnelAuthenticationField,
  type VaultTunnelAuthenticationEnvelope,
} from '../electron/vault-tunnel-authentication.ts';

function validFactor(value: Uint8Array, username: boolean): boolean {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(value);
  if (username && !text.replace(/\p{White_Space}/gu, '')) return false;
  return !value.some((b) => b < 32 || b === 127);
}

// Protected document only. The caller's factors are consumed before awaiting
// crypto, and main receives only the purpose-bound native recipient envelope.
export async function sealTunnelAuthentication(
  value: unknown,
  username: Uint8Array,
  password: Uint8Array,
  signal?: AbortSignal,
): Promise<VaultTunnelAuthenticationEnvelope> {
  let frame: Uint8Array | undefined;
  try {
    const c = parseVaultTunnelAuthenticationContext(value);
    if (
      !c ||
      !(username instanceof Uint8Array) ||
      !(password instanceof Uint8Array) ||
      !(username.buffer instanceof ArrayBuffer) ||
      !(password.buffer instanceof ArrayBuffer) ||
      signal?.aborted ||
      username.length > maxTunnelAuthenticationField ||
      !password.length ||
      password.length > maxTunnelAuthenticationField ||
      username.length > 0 !== c.usernameRequired
    )
      throw Error('Invalid VPN input.');
    if ((c.usernameRequired && !validFactor(username, true)) || !validFactor(password, false))
      throw Error('Invalid VPN input.');
    frame = new Uint8Array(10 + username.length + password.length);
    frame[0] = 1;
    frame[1] = 1;
    new DataView(frame.buffer).setUint32(2, username.length);
    new DataView(frame.buffer).setUint32(6, password.length);
    frame.set(username, 10);
    frame.set(password, 10 + username.length);
    username.fill(0);
    password.fill(0);
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const recipientPublicKey = await suite.kem.deserializePublicKey(
      enrollmentBytes(c.publicKey, 32)!,
    );
    if (signal?.aborted) throw Error('Cancelled.');
    const result = await suite.seal(
      { recipientPublicKey, info: tunnelAuthenticationInfo(c) },
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
    throw Error('VPN credentials could not be encrypted.');
  } finally {
    if (username instanceof Uint8Array) username.fill(0);
    if (password instanceof Uint8Array) password.fill(0);
    frame?.fill(0);
  }
}
