import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { enrollmentBytes } from './vault-enrollment-contract.ts';

export const maxBitwardenCLIPassword = 4096;
const maxSessionBytes = 64 * 1024;

export type VaultBitwardenCLIUnlockBinding = {
  workspaceId: string;
  requestId: string;
  configuration: string;
  vaultKey: string;
  expiresAt: number;
};
export type VaultBitwardenCLIUnlockContext = {
  binding: VaultBitwardenCLIUnlockBinding;
  publicKey: string;
};
export type VaultBitwardenCLIEnvelope = {
  formatVersion: 1;
  suiteId: 2;
  enc: string;
  ciphertext: string;
};

export function parseVaultBitwardenCLIUnlockBinding(
  value: unknown,
): VaultBitwardenCLIUnlockBinding | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['workspaceId', 'requestId', 'configuration', 'vaultKey', 'expiresAt']) ||
    !vaultID(value.workspaceId) ||
    !vaultID(value.requestId) ||
    typeof value.configuration !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.configuration) ||
    typeof value.vaultKey !== 'string' ||
    !enrollmentBytes(value.vaultKey, 32) ||
    typeof value.expiresAt !== 'number' ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt <= 0
  )
    return undefined;
  return {
    workspaceId: value.workspaceId,
    requestId: value.requestId,
    configuration: value.configuration,
    vaultKey: value.vaultKey,
    expiresAt: value.expiresAt,
  };
}

export function parseVaultBitwardenCLIUnlockContext(
  value: unknown,
): VaultBitwardenCLIUnlockContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['binding', 'publicKey']) ||
    typeof value.publicKey !== 'string' ||
    !enrollmentBytes(value.publicKey, 32)
  )
    return undefined;
  const binding = parseVaultBitwardenCLIUnlockBinding(value.binding);
  return binding && binding.vaultKey !== value.publicKey
    ? { binding, publicKey: value.publicKey }
    : undefined;
}

function parseEnvelope(value: unknown, maxBytes: number): VaultBitwardenCLIEnvelope | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    typeof value.enc !== 'string' ||
    !enrollmentBytes(value.enc, 32) ||
    typeof value.ciphertext !== 'string' ||
    value.ciphertext.length > 4 * Math.ceil((maxBytes + 16) / 3)
  )
    return undefined;
  const ciphertext = value.ciphertext;
  const size =
    (ciphertext.length / 4) * 3 -
    (ciphertext.endsWith('==') ? 2 : ciphertext.endsWith('=') ? 1 : 0);
  if (
    !Number.isInteger(size) ||
    size < 17 ||
    size > maxBytes + 16 ||
    !enrollmentBytes(ciphertext, size)
  )
    return undefined;
  return { formatVersion: 1, suiteId: 2, enc: value.enc, ciphertext };
}

export function parseVaultBitwardenCLIPassword(value: unknown) {
  return parseEnvelope(value, maxBitwardenCLIPassword);
}

export function parseVaultBitwardenCLISession(value: unknown) {
  return parseEnvelope(value, maxSessionBytes);
}

export function bitwardenCLIPasswordInfo(binding: VaultBitwardenCLIUnlockBinding): Uint8Array {
  const encoder = new TextEncoder();
  const prefix = encoder.encode('wormhole/v1/bitwarden-cli-password');
  const fields = [
    encoder.encode(binding.workspaceId),
    encoder.encode(binding.requestId),
    encoder.encode(binding.configuration),
    enrollmentBytes(binding.vaultKey, 32)!,
    encoder.encode(String(binding.expiresAt)),
  ];
  const info = new Uint8Array(
    prefix.length + fields.reduce((sum, field) => sum + 4 + field.length, 0),
  );
  info.set(prefix);
  const lengths = new DataView(info.buffer);
  let offset = prefix.length;
  for (const field of fields) {
    lengths.setUint32(offset, field.length);
    info.set(field, offset + 4);
    offset += 4 + field.length;
  }
  return info;
}
