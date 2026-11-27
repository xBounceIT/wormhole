import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';
import {
  parseVaultRouteBinding,
  validVaultRouteEndpoint,
  type VaultRouteBinding,
} from './vault-route.ts';
import type { VaultVncBundle } from './vault-vnc.ts';

export type VaultVncPasswordContext = {
  binding: VaultVncBundle['binding'] | VaultRouteBinding;
  publicKey: string;
  endpoint?: string;
};
export type VaultVncPasswordEnvelope = VaultVncBundle['bundle'];
export const maxVncTemporaryPasswordBytes = 16384;
export function parseVaultVncPasswordContext(value: unknown): VaultVncPasswordContext | undefined {
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
    b.protocol !== 'vnc' ||
    b.useExternalClient !== false ||
    !Number.isSafeInteger(b.epoch) ||
    (b.epoch as number) < 1 ||
    !Number.isInteger(b.port) ||
    (b.port as number) < 1 ||
    (b.port as number) > 65535 ||
    !vaultMetadataText(b.host, 1024, true) ||
    /[\p{White_Space}\p{Cc}]/u.test(b.host)
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
      protocol: 'vnc',
      host: b.host,
      port: b.port as number,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    publicKey: value.publicKey as string,
  };
}
export function parseVaultVncPasswordEnvelope(
  value: unknown,
): VaultVncPasswordEnvelope | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    !enrollmentBytes(value.enc, 32) ||
    typeof value.ciphertext !== 'string' ||
    value.ciphertext.length % 4 !== 0 ||
    value.ciphertext.length > 4 * Math.ceil((maxVncTemporaryPasswordBytes + 22) / 3)
  )
    return undefined;
  const size =
    (value.ciphertext.length / 4) * 3 -
    (value.ciphertext.endsWith('==') ? 2 : value.ciphertext.endsWith('=') ? 1 : 0);
  if (
    size < 22 ||
    size > maxVncTemporaryPasswordBytes + 22 ||
    !enrollmentBytes(value.ciphertext, size)
  )
    return undefined;
  return { formatVersion: 1, suiteId: 2, enc: value.enc as string, ciphertext: value.ciphertext };
}
export function vncPasswordInfo(value: unknown): Uint8Array {
  const context = parseVaultVncPasswordContext(value);
  if (!context) throw Error('Invalid VNC password context.');
  const b = context.binding,
    route = 'fileId' in b ? b : undefined,
    encoder = new TextEncoder();
  const fields = [
    b.workspaceId,
    b.nodeId,
    b.sessionId,
    b.requestId,
    'vnc',
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
  const prefix = encoder.encode('wormhole/v1/vnc-manual-password');
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
