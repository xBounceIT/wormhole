import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import { parseVaultRouteBinding, type VaultRouteBinding } from './vault-route.ts';

export type VaultTunnelAuthenticationContext = {
  binding: VaultRouteBinding;
  challengeId: string;
  publicKey: string;
  usernameRequired: boolean;
};
export type VaultTunnelAuthenticationEnvelope = {
  formatVersion: 1;
  suiteId: 2;
  enc: string;
  ciphertext: string;
};
export const maxTunnelAuthenticationField = 4096;
export function parseVaultTunnelAuthenticationContext(
  value: unknown,
): VaultTunnelAuthenticationContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['binding', 'challengeId', 'publicKey', 'usernameRequired']) ||
    !vaultID(value.challengeId) ||
    !enrollmentBytes(value.publicKey, 32) ||
    typeof value.usernameRequired !== 'boolean' ||
    !vaultRecord(value.binding)
  )
    return undefined;
  const b = value.binding;
  const binding = parseVaultRouteBinding(b, {
    workspaceId: b.workspaceId,
    nodeId: b.nodeId,
    sessionId: b.sessionId,
    requestId: b.requestId,
    epoch: b.epoch,
    credentialOverride: '',
  } as Parameters<typeof parseVaultRouteBinding>[1]);
  return binding?.kind === 9
    ? {
        binding,
        challengeId: value.challengeId,
        publicKey: value.publicKey as string,
        usernameRequired: value.usernameRequired,
      }
    : undefined;
}
export function parseVaultTunnelAuthenticationChallenge(
  value: unknown,
  binding: VaultRouteBinding,
): VaultTunnelAuthenticationContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['type', 'sessionId', 'challengeId', 'publicKey', 'usernameRequired']) ||
    value.type !== 'authentication-required' ||
    value.sessionId !== binding.sessionId
  )
    return undefined;
  return parseVaultTunnelAuthenticationContext({
    binding,
    challengeId: value.challengeId,
    publicKey: value.publicKey,
    usernameRequired: value.usernameRequired,
  });
}
export function parseVaultTunnelAuthenticationEnvelope(
  value: unknown,
): VaultTunnelAuthenticationEnvelope | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    !enrollmentBytes(value.enc, 32) ||
    typeof value.ciphertext !== 'string' ||
    value.ciphertext.length > 10960
  )
    return undefined;
  const size =
    (value.ciphertext.length / 4) * 3 -
    (value.ciphertext.endsWith('==') ? 2 : value.ciphertext.endsWith('=') ? 1 : 0);
  return size >= 27 && size <= 8218 && enrollmentBytes(value.ciphertext, size)
    ? { formatVersion: 1, suiteId: 2, enc: value.enc as string, ciphertext: value.ciphertext }
    : undefined;
}
export function tunnelAuthenticationInfo(value: unknown): Uint8Array {
  const c = parseVaultTunnelAuthenticationContext(value);
  if (!c) throw Error('Invalid VPN authentication context.');
  const b = c.binding,
    encoder = new TextEncoder();
  const fields = [
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
    String(c.usernameRequired),
  ].map((s) => encoder.encode(s));
  const prefix = encoder.encode('wormhole/v1/tunnel-authentication');
  const info = new Uint8Array(prefix.length + fields.reduce((n, f) => n + 4 + f.length, 0));
  info.set(prefix);
  let offset = prefix.length;
  for (const f of fields) {
    new DataView(info.buffer).setUint32(offset, f.length);
    info.set(f, offset + 4);
    offset += 4 + f.length;
  }
  return info;
}
