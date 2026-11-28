import { Buffer } from 'node:buffer';
import {
  vaultFields,
  vaultID,
  vaultMetadataText,
  vaultRecord,
  vaultRevision,
} from './vault-contract.ts';

type Metadata = {
  id: string;
  name: string;
  protocol: 'ssh' | 'rdp' | 'vnc';
  kind: 'password' | 'sshKey';
  username: string;
  domain: string;
  provider: 'Local' | 'Bitwarden';
  bitwardenItemId: string;
  bitwardenItemName: string;
  clearPassphrase: boolean;
  clearCertificate: boolean;
};
type Values = { rowVersion: string; password: Uint8Array; passphrase: Uint8Array };
export type VaultCredentialRequest = Values & {
  metadata: Metadata & { privateKeySelectionId: string; certificateSelectionId: string };
};
export type VaultCredentialInput = Values & {
  metadata: Metadata & { privateKeyPath: string; certificatePath: string };
};
export type VaultCredentialSelection = { id: string; rowVersion: string };
export type VaultCredentialResult = VaultCredentialSelection & { updated: true };
export type VaultCredentialDeleteResult = VaultCredentialSelection & { deleted: true };

export function parseVaultCredentialSelection(
  value: unknown,
): VaultCredentialSelection | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['id', 'rowVersion']) ||
    !vaultID(value.id) ||
    !vaultRevision(value.rowVersion) ||
    value.rowVersion === '9223372036854775807'
  )
    return undefined;
  return { id: value.id, rowVersion: value.rowVersion };
}

function consume(value: unknown, native: boolean): VaultCredentialRequest | VaultCredentialInput {
  const object = vaultRecord(value) ? value : undefined;
  const password = object?.password,
    passphrase = object?.passphrase,
    m = object?.metadata;
  try {
    const keys = native
      ? ['privateKeyPath', 'certificatePath']
      : ['privateKeySelectionId', 'certificateSelectionId'];
    if (
      !object ||
      !vaultFields(object, ['metadata', 'rowVersion', 'password', 'passphrase']) ||
      !vaultRecord(m) ||
      !vaultFields(m, [
        'id',
        'name',
        'protocol',
        'kind',
        'username',
        'domain',
        'provider',
        'bitwardenItemId',
        'bitwardenItemName',
        'clearPassphrase',
        'clearCertificate',
        ...keys,
      ]) ||
      !(
        (m.id === '' && object.rowVersion === '0') ||
        parseVaultCredentialSelection({ id: m.id, rowVersion: object.rowVersion })
      ) ||
      !vaultMetadataText(m.name, 1024, true) ||
      !vaultMetadataText(m.username, 2048) ||
      !vaultMetadataText(m.domain, 2048) ||
      !vaultMetadataText(m.bitwardenItemId, 2048) ||
      !vaultMetadataText(m.bitwardenItemName, 4096) ||
      !['ssh', 'rdp', 'vnc'].includes(m.protocol as string) ||
      !['password', 'sshKey'].includes(m.kind as string) ||
      !['Local', 'Bitwarden'].includes(m.provider as string) ||
      typeof m.clearPassphrase !== 'boolean' ||
      typeof m.clearCertificate !== 'boolean' ||
      keys.some((k) =>
        native ? !vaultMetadataText(m[k], 32768) : !(m[k] === '' || vaultID(m[k])),
      ) ||
      !(password instanceof Uint8Array) ||
      !(password.buffer instanceof ArrayBuffer) ||
      password.length > 16384 ||
      !(passphrase instanceof Uint8Array) ||
      !(passphrase.buffer instanceof ArrayBuffer) ||
      passphrase.length > 16384 ||
      (m.kind === 'sshKey'
        ? m.protocol !== 'ssh' || m.provider !== 'Local' || password.length !== 0
        : passphrase.length !== 0 ||
          m.clearPassphrase ||
          m.clearCertificate ||
          keys.some((k) => m[k] !== '')) ||
      (m.clearPassphrase && passphrase.length !== 0) ||
      (m.clearCertificate && m[keys[1]] !== '')
    )
      throw Error('Invalid vault credential request.');
    return {
      metadata: { ...m },
      rowVersion: object.rowVersion,
      password: Buffer.from(password),
      passphrase: Buffer.from(passphrase),
    } as unknown as VaultCredentialRequest | VaultCredentialInput;
  } finally {
    if (password instanceof Uint8Array) password.fill(0);
    if (passphrase instanceof Uint8Array) passphrase.fill(0);
  }
}
export function consumeVaultCredentialRequest(value: unknown): VaultCredentialRequest {
  return consume(value, false) as VaultCredentialRequest;
}
// Main/native boundary only; never call this consumer directly on renderer IPC.
export function consumeVaultCredentialInput(value: unknown): VaultCredentialInput {
  return consume(value, true) as VaultCredentialInput;
}
export function parseVaultCredentialResult(value: unknown): VaultCredentialResult | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['id', 'rowVersion', 'updated']) ||
    !vaultID(value.id) ||
    !vaultRevision(value.rowVersion) ||
    value.updated !== true
  )
    return undefined;
  return { id: value.id, rowVersion: value.rowVersion, updated: true };
}
export function parseVaultCredentialDeleteResult(
  value: unknown,
): VaultCredentialDeleteResult | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['id', 'rowVersion', 'deleted']) ||
    !vaultID(value.id) ||
    !vaultRevision(value.rowVersion) ||
    value.deleted !== true
  )
    return undefined;
  return { id: value.id, rowVersion: value.rowVersion, deleted: true };
}
