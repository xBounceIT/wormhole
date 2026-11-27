import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { vaultFields, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import {
  parseVaultTunnelAuthenticationContext,
  type VaultTunnelAuthenticationEnvelope,
} from './vault-tunnel-authentication.ts';
import type { VaultRouteBinding } from './vault-route.ts';

export type VaultTunnelBrowserContext = {
  binding: VaultRouteBinding;
  challengeId: string;
  publicKey: string;
  startURL: string;
  callbackURL: string;
  ignoreCertificateErrors: boolean;
};
function unsafeURL(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0)!;
    if (code <= 32 || code === 127) return true;
  }
  return false;
}
export function parseVaultTunnelBrowserContext(
  value: unknown,
): VaultTunnelBrowserContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'binding',
      'challengeId',
      'publicKey',
      'startURL',
      'callbackURL',
      'ignoreCertificateErrors',
    ]) ||
    typeof value.startURL !== 'string' ||
    value.startURL.length > 4096 ||
    unsafeURL(value.startURL) ||
    typeof value.callbackURL !== 'string' ||
    typeof value.ignoreCertificateErrors !== 'boolean'
  )
    return;
  const base = parseVaultTunnelAuthenticationContext({
    binding: value.binding,
    challengeId: value.challengeId,
    publicKey: value.publicKey,
    usernameRequired: false,
  });
  if (!base) return;
  try {
    const start = new URL(value.startURL),
      callback = new URL(value.callbackURL);
    if (
      start.protocol !== 'https:' ||
      !start.hostname ||
      start.username ||
      start.password ||
      start.pathname !== '/saml' ||
      start.hash ||
      callback.protocol !== 'http:' ||
      callback.hostname !== '127.0.0.1' ||
      !/^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/$/.test(value.callbackURL) ||
      callback.pathname !== '/' ||
      callback.search ||
      callback.hash ||
      callback.username ||
      callback.password ||
      Number(value.callbackURL.split(':')[2].slice(0, -1)) > 65535
    )
      return;
  } catch {
    return;
  }
  return {
    binding: base.binding,
    challengeId: base.challengeId,
    publicKey: base.publicKey,
    startURL: value.startURL,
    callbackURL: value.callbackURL,
    ignoreCertificateErrors: value.ignoreCertificateErrors,
  };
}
export function parseVaultTunnelBrowserChallenge(value: unknown, binding: VaultRouteBinding) {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'type',
      'sessionId',
      'challengeId',
      'publicKey',
      'startURL',
      'callbackURL',
      'ignoreCertificateErrors',
    ]) ||
    value.type !== 'browser-authentication-required' ||
    value.sessionId !== binding.sessionId
  )
    return;
  return parseVaultTunnelBrowserContext({
    binding,
    challengeId: value.challengeId,
    publicKey: value.publicKey,
    startURL: value.startURL,
    callbackURL: value.callbackURL,
    ignoreCertificateErrors: value.ignoreCertificateErrors,
  });
}
export function parseVaultTunnelBrowserEnvelope(
  value: unknown,
): VaultTunnelAuthenticationEnvelope | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    !enrollmentBytes(value.enc, 32) ||
    !enrollmentBytes(value.ciphertext, 50)
  )
    return;
  return {
    formatVersion: 1,
    suiteId: 2,
    enc: value.enc as string,
    ciphertext: value.ciphertext as string,
  };
}
export function tunnelBrowserInfo(value: unknown): Uint8Array {
  const c = parseVaultTunnelBrowserContext(value);
  if (!c) throw Error('Invalid VPN browser context.');
  const b = c.binding,
    encoder = new TextEncoder(),
    fields = [
      b.workspaceId,
      b.fileId,
      b.nodeId,
      b.sessionId,
      b.requestId,
      b.protocol,
      b.host,
      String(b.port),
      String(b.epoch),
      b.tunnelConfigId,
      String(b.kind),
      b.rowVersion,
      b.configurationVersion,
      c.challengeId,
      c.startURL,
      c.callbackURL,
      String(c.ignoreCertificateErrors),
    ].map((s) => encoder.encode(s));
  const prefix = encoder.encode('wormhole/v1/tunnel-browser-authentication'),
    info = new Uint8Array(prefix.length + fields.reduce((n, f) => n + 4 + f.length, 0));
  info.set(prefix);
  let offset = prefix.length;
  for (const f of fields) {
    new DataView(info.buffer).setUint32(offset, f.length);
    info.set(f, offset + 4);
    offset += 4 + f.length;
  }
  return info;
}
export function tunnelBrowserCallbackToken(
  value: unknown,
  context: VaultTunnelBrowserContext,
): Uint8Array | undefined {
  if (typeof value !== 'string' || value.length > 4096) return;
  try {
    const u = new URL(value),
      expected = new URL(context.callbackURL),
      all = [...u.searchParams.entries()];
    if (
      u.origin !== expected.origin ||
      u.pathname !== '/' ||
      u.username ||
      u.password ||
      u.hash ||
      all.length !== 1 ||
      all[0][0] !== 'tokenid' ||
      !/^[a-fA-F0-9]{32}$/.test(all[0][1])
    )
      return;
    return new TextEncoder().encode(all[0][1]);
  } catch {
    return;
  }
}
// Native browser adapter only; no remote document has a preload or app bridge.
export async function sealTunnelBrowserToken(
  value: unknown,
  token: Uint8Array,
  signal?: AbortSignal,
): Promise<VaultTunnelAuthenticationEnvelope> {
  let frame: Uint8Array | undefined;
  try {
    const c = parseVaultTunnelBrowserContext(value);
    if (
      !c ||
      !(token instanceof Uint8Array) ||
      !(token.buffer instanceof ArrayBuffer) ||
      token.length !== 32 ||
      signal?.aborted ||
      token.some((b) => !((b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102)))
    )
      throw Error('Invalid token.');
    frame = new Uint8Array(34);
    frame.set([1, 1]);
    frame.set(token, 2);
    token.fill(0);
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const recipientPublicKey = await suite.kem.deserializePublicKey(
      enrollmentBytes(c.publicKey, 32)!,
    );
    if (signal?.aborted) throw Error('Cancelled.');
    const sealed = await suite.seal({ recipientPublicKey, info: tunnelBrowserInfo(c) }, frame);
    if (signal?.aborted) throw Error('Cancelled.');
    return {
      formatVersion: 1,
      suiteId: 2,
      enc: btoa(String.fromCharCode(...new Uint8Array(sealed.enc))),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(sealed.ct))),
    };
  } catch {
    throw Error('VPN browser authentication could not complete.');
  } finally {
    if (token instanceof Uint8Array) token.fill(0);
    frame?.fill(0);
  }
}
