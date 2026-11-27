import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import {
  parseVaultRouteBinding,
  validVaultRouteEndpoint,
  type VaultRouteBinding,
} from './vault-route.ts';
import type { VaultRdpBundle } from './vault-rdp.ts';

export type VaultRdpCredentialsContext = {
  binding: VaultRdpBundle['binding'] | VaultRouteBinding;
  publicKey: string;
  endpoint?: string;
};
export type VaultRdpCredentialsEnvelope = VaultRdpBundle['bundle'];
export const maxRdpTemporaryPasswordBytes = 16384;
export const maxRdpManualCiphertext = 14 + 2048 + 2048 + maxRdpTemporaryPasswordBytes + 16;
export function parseVaultRdpCredentialsContext(
  value: unknown,
): VaultRdpCredentialsContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'binding',
      'publicKey',
      ...(value.endpoint !== undefined ? ['endpoint'] : []),
    ]) ||
    !enrollmentBytes(value.publicKey, 32)
  )
    return undefined;
  const b = value.binding;
  if (
    !vaultRecord(b) ||
    ![b.workspaceId, b.nodeId, b.sessionId, b.requestId].every(vaultID) ||
    b.protocol !== 'rdp' ||
    b.useExternalClient !== false ||
    !Number.isSafeInteger(b.epoch) ||
    (b.epoch as number) < 1 ||
    !Number.isInteger(b.port) ||
    (b.port as number) < 1 ||
    (b.port as number) > 65535 ||
    !vaultMetadataText(b.host, 1024, true) ||
    /[\p{White_Space}\p{Cc}]/u.test(b.host) ||
    Array.from(b.host).length > 253
  )
    return undefined;
  if (value.endpoint !== undefined) {
    if (!validVaultRouteEndpoint(value.endpoint)) return undefined;
    const binding = parseVaultRouteBinding(b, {
      workspaceId: b.workspaceId as string,
      nodeId: b.nodeId as string,
      sessionId: b.sessionId as string,
      requestId: b.requestId as string,
      credentialOverride: '',
      epoch: b.epoch as number,
    });
    return binding
      ? { binding, publicKey: value.publicKey as string, endpoint: value.endpoint }
      : undefined;
  }
  if (
    !vaultFields(b, [
      'workspaceId',
      'nodeId',
      'sessionId',
      'requestId',
      'protocol',
      'host',
      'port',
      'epoch',
      'tunnelConfigId',
      'useExternalClient',
    ]) ||
    b.tunnelConfigId !== ''
  )
    return undefined;
  return {
    binding: {
      workspaceId: b.workspaceId as string,
      nodeId: b.nodeId as string,
      sessionId: b.sessionId as string,
      requestId: b.requestId as string,
      epoch: b.epoch as number,
      protocol: 'rdp',
      host: b.host,
      port: b.port as number,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    publicKey: value.publicKey as string,
  };
}
export function parseVaultRdpCredentialsEnvelope(
  value: unknown,
): VaultRdpCredentialsEnvelope | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    !enrollmentBytes(value.enc, 32) ||
    typeof value.ciphertext !== 'string' ||
    value.ciphertext.length % 4 !== 0 ||
    value.ciphertext.length > 4 * Math.ceil(maxRdpManualCiphertext / 3)
  )
    return undefined;
  const size =
    (value.ciphertext.length / 4) * 3 -
    (value.ciphertext.endsWith('==') ? 2 : value.ciphertext.endsWith('=') ? 1 : 0);
  if (size < 30 || size > maxRdpManualCiphertext || !enrollmentBytes(value.ciphertext, size))
    return undefined;
  return { formatVersion: 1, suiteId: 2, enc: value.enc as string, ciphertext: value.ciphertext };
}
export function rdpCredentialsInfo(value: unknown): Uint8Array {
  const context = parseVaultRdpCredentialsContext(value);
  if (!context) throw Error('Invalid RDP credentials context.');
  const b = context.binding,
    route = 'fileId' in b ? b : undefined,
    encoder = new TextEncoder();
  const fields = [
    b.workspaceId,
    b.nodeId,
    b.sessionId,
    b.requestId,
    'rdp',
    b.host,
    String(b.port),
    b.tunnelConfigId,
    String(b.epoch),
    route?.fileId ?? '',
    route ? String(route.kind) : '',
    route?.rowVersion ?? '',
    route?.configurationVersion ?? '',
    context.endpoint ?? '',
  ].map((v) => encoder.encode(v));
  const prefix = encoder.encode('wormhole/v1/rdp-manual-credentials');
  const info = new Uint8Array(
    prefix.length + fields.reduce((size, field) => size + 4 + field.length, 0),
  );
  info.set(prefix);
  let offset = prefix.length;
  for (const field of fields) {
    new DataView(info.buffer).setUint32(offset, field.length);
    info.set(field, offset + 4);
    offset += 4 + field.length;
  }
  return info;
}
