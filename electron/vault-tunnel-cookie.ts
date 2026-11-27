import { createHash } from 'node:crypto';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { vaultRecord, vaultFields, vaultID } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import { parseVaultRouteBinding, type VaultRouteBinding } from './vault-route.ts';
import type { VaultTunnelAuthenticationEnvelope } from './vault-tunnel-authentication.ts';
export const maxTunnelCookieBytes = 16384;
export type VaultTunnelCookieContext = {
  binding: VaultRouteBinding;
  challengeId: string;
  publicKey: string;
  startURL: string;
  ignoreCertificateErrors: boolean;
} & ({ cookieName: 'SVPNCOOKIE' } | { completion: 'fortinet-ssl' });
export function parseVaultTunnelCookieContext(
  value: unknown,
): VaultTunnelCookieContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'binding',
      'challengeId',
      'publicKey',
      'startURL',
      'ignoreCertificateErrors',
      'completion' in value ? 'completion' : 'cookieName',
    ]) ||
    !vaultRecord(value.binding) ||
    !vaultID(value.challengeId) ||
    !enrollmentBytes(value.publicKey, 32) ||
    typeof value.startURL !== 'string' ||
    value.startURL.length > 4096 ||
    typeof value.ignoreCertificateErrors !== 'boolean' ||
    ('completion' in value
      ? value.completion !== 'fortinet-ssl'
      : value.cookieName !== 'SVPNCOOKIE')
  )
    return;
  const b = value.binding,
    binding = parseVaultRouteBinding(b, {
      workspaceId: b.workspaceId,
      nodeId: b.nodeId,
      sessionId: b.sessionId,
      requestId: b.requestId,
      epoch: b.epoch,
      credentialOverride: '',
    } as Parameters<typeof parseVaultRouteBinding>[1]);
  if (binding?.kind !== 2) return;
  for (const ch of value.startURL) {
    const n = ch.codePointAt(0)!;
    if (n <= 32 || n === 127) return;
  }
  try {
    const url = new URL(value.startURL);
    if (
      url.protocol !== 'https:' ||
      !url.hostname ||
      url.username ||
      url.password ||
      url.pathname !== '/remote/saml/start' ||
      url.hash ||
      ('completion' in value ? url.search !== '?redirect=1' : url.searchParams.has('redirect'))
    )
      return;
  } catch {
    return;
  }
  return {
    binding,
    challengeId: value.challengeId,
    publicKey: value.publicKey as string,
    startURL: value.startURL,
    ignoreCertificateErrors: value.ignoreCertificateErrors,
    ...('completion' in value
      ? { completion: 'fortinet-ssl' as const }
      : { cookieName: 'SVPNCOOKIE' as const }),
  };
}
export function parseVaultTunnelCookieChallenge(value: unknown, binding: VaultRouteBinding) {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'type',
      'sessionId',
      'challengeId',
      'publicKey',
      'startURL',
      'ignoreCertificateErrors',
      'completion' in value ? 'completion' : 'cookieName',
    ]) ||
    value.type !== 'cookie-authentication-required' ||
    value.sessionId !== binding.sessionId
  )
    return;
  return parseVaultTunnelCookieContext({
    binding,
    challengeId: value.challengeId,
    publicKey: value.publicKey,
    startURL: value.startURL,
    ignoreCertificateErrors: value.ignoreCertificateErrors,
    ...('completion' in value
      ? { completion: value.completion }
      : { cookieName: value.cookieName }),
  });
}
export function parseVaultTunnelCookieEnvelope(
  value: unknown,
): VaultTunnelAuthenticationEnvelope | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    !enrollmentBytes(value.enc, 32) ||
    typeof value.ciphertext !== 'string' ||
    value.ciphertext.length > 21876
  )
    return;
  const size =
    (value.ciphertext.length / 4) * 3 -
    (value.ciphertext.endsWith('==') ? 2 : value.ciphertext.endsWith('=') ? 1 : 0);
  if (size < 23 || size > 16406 || !enrollmentBytes(value.ciphertext, size)) return;
  return { formatVersion: 1, suiteId: 2, enc: value.enc as string, ciphertext: value.ciphertext };
}
export function validTunnelCookie(value: Uint8Array): boolean {
  return (
    value.length > 0 &&
    value.length <= maxTunnelCookieBytes &&
    value.every(
      (b) =>
        b === 0x21 ||
        (b >= 0x23 && b <= 0x2b) ||
        (b >= 0x2d && b <= 0x3a) ||
        (b >= 0x3c && b <= 0x5b) ||
        (b >= 0x5d && b <= 0x7e),
    )
  );
}
export function tunnelCookieDigest(value: string): string | undefined {
  const bytes = new TextEncoder().encode(value);
  try {
    if (!validTunnelCookie(bytes)) return;
    return createHash('sha256').update(bytes).digest('hex');
  } finally {
    bytes.fill(0);
  }
}
// Only a fresh HttpOnly cookie issued by the exact gateway response is eligible.
// Keep its digest, not the bearer value, while the native cookie store commits.
export function tunnelCookieResponseDigest(headers: unknown): string | null | undefined {
  if (!vaultRecord(headers) || Object.keys(headers).length > 256) return;
  let digest: string | null | undefined;
  for (const [name, values] of Object.entries(headers)) {
    if (name.toLowerCase() !== 'set-cookie') continue;
    if (!Array.isArray(values) || values.length > 64) return;
    for (const raw of values) {
      if (typeof raw !== 'string' || raw.length > 32768) return;
      const parts = raw.split(';'),
        pair = parts.shift()!.trim(),
        equals = pair.indexOf('=');
      if (equals < 1 || pair.slice(0, equals) !== 'SVPNCOOKIE') continue;
      const expired = parts.some((part) => {
        const match = /^\s*max-age\s*=\s*(-?\d+)\s*$/i.exec(part);
        return match !== null && Number(match[1]) <= 0;
      });
      digest =
        parts.some((v) => v.trim().toLowerCase() === 'httponly') && !expired
          ? (tunnelCookieDigest(pair.slice(equals + 1).trim()) ?? null)
          : null;
    }
  }
  return digest;
}
export function tunnelCookieInfo(value: unknown): Uint8Array {
  const c = parseVaultTunnelCookieContext(value);
  if (!c) throw Error('Invalid VPN cookie context.');
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
      String(c.ignoreCertificateErrors),
      'completion' in c ? c.completion : c.cookieName,
    ].map((s) => encoder.encode(s));
  const prefix = encoder.encode('wormhole/v1/tunnel-cookie-authentication'),
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
export async function sealTunnelCookie(
  value: unknown,
  cookie: Uint8Array,
  signal?: AbortSignal,
): Promise<VaultTunnelAuthenticationEnvelope> {
  let frame: Uint8Array | undefined;
  try {
    const c = parseVaultTunnelCookieContext(value);
    if (
      !c ||
      !(cookie instanceof Uint8Array) ||
      !(cookie.buffer instanceof ArrayBuffer) ||
      !('completion' in c
        ? cookie.length > 0 && cookie.length <= 4096 && cookie.every((b) => b >= 0x21 && b <= 0x7e)
        : validTunnelCookie(cookie)) ||
      signal?.aborted
    )
      throw Error('Invalid cookie.');
    frame = new Uint8Array(6 + cookie.length);
    frame.set([1, 1]);
    new DataView(frame.buffer).setUint32(2, cookie.length);
    frame.set(cookie, 6);
    cookie.fill(0);
    const suite = new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes256Gcm(),
      }),
      recipientPublicKey = await suite.kem.deserializePublicKey(enrollmentBytes(c.publicKey, 32)!);
    if (signal?.aborted) throw Error('Cancelled.');
    const sealed = await suite.seal({ recipientPublicKey, info: tunnelCookieInfo(c) }, frame);
    if (signal?.aborted) throw Error('Cancelled.');
    return {
      formatVersion: 1,
      suiteId: 2,
      enc: btoa(String.fromCharCode(...new Uint8Array(sealed.enc))),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(sealed.ct))),
    };
  } catch {
    throw Error('VPN cookie authentication could not complete.');
  } finally {
    if (cookie instanceof Uint8Array) cookie.fill(0);
    frame?.fill(0);
  }
}
