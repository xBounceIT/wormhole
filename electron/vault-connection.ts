import { Buffer } from 'node:buffer';
import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';
import { parseVaultFolder, type VaultFolderRequest } from './vault-folder.ts';
import { parseWorkspaceRdpSettings, type WorkspaceRdpSettings } from './workspace-rdp-contract.ts';

export type VaultConnectionMetadata = Omit<VaultFolderRequest, 'rowVersion'> & {
  protocol: 'ssh' | 'sftp' | 'rdp' | 'vnc' | 'http' | 'https' | 'serial';
  host: string;
  port: number;
  username: string;
  inlinePasswordAction: 'preserve' | 'set' | 'clear';
  httpIgnoreCertErrors: boolean | null;
  serialBaudRate: number;
  serialDataBits: number;
  serialStopBits: number;
  serialParity: number;
  serialFlowControl: number;
  rdp: WorkspaceRdpSettings | null;
};
export type VaultConnectionInput = {
  metadata: VaultConnectionMetadata;
  rowVersion: string;
  notesAction: 'preserve' | 'set' | 'clear';
  password: Uint8Array;
  notes: Uint8Array;
};

function connectionMetadata(
  value: unknown,
  rowVersion: unknown,
): VaultConnectionMetadata | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'id',
      'parentId',
      'name',
      'sshAutoSudo',
      'tunnelEnabled',
      'tunnelConfigId',
      'credentialMode',
      'credentialId',
      'protocol',
      'host',
      'port',
      'username',
      'inlinePasswordAction',
      'httpIgnoreCertErrors',
      'serialBaudRate',
      'serialDataBits',
      'serialStopBits',
      'serialParity',
      'serialFlowControl',
      'rdp',
    ])
  )
    return undefined;
  const folder = parseVaultFolder({
    id: value.id,
    rowVersion,
    parentId: value.parentId,
    name: value.name,
    sshAutoSudo: value.sshAutoSudo,
    tunnelEnabled: value.tunnelEnabled,
    tunnelConfigId: value.tunnelConfigId,
    credentialMode: value.credentialMode,
    credentialId: value.credentialId,
  });
  if (
    !folder ||
    !['ssh', 'sftp', 'rdp', 'vnc', 'http', 'https', 'serial'].includes(value.protocol as string) ||
    !vaultMetadataText(value.host, 16384, true) ||
    /[\r\n]/.test(value.host) ||
    !Number.isSafeInteger(value.port) ||
    (value.port as number) < 0 ||
    (value.port as number) > 65535 ||
    !vaultMetadataText(value.username, 2048) ||
    /[\r\n]/.test(value.username) ||
    !['preserve', 'set', 'clear'].includes(value.inlinePasswordAction as string) ||
    !(value.httpIgnoreCertErrors === null || typeof value.httpIgnoreCertErrors === 'boolean')
  )
    return undefined;
  for (const key of [
    'serialBaudRate',
    'serialDataBits',
    'serialStopBits',
    'serialParity',
    'serialFlowControl',
  ])
    if (
      !Number.isSafeInteger(value[key]) ||
      (value[key] as number) < 0 ||
      (value[key] as number) > 2147483647
    )
      return undefined;
  let rdp: WorkspaceRdpSettings | null = null;
  if (value.protocol === 'rdp') {
    try {
      rdp = parseWorkspaceRdpSettings(value.rdp);
      if (
        !vaultRecord(value.rdp) ||
        !vaultFields(value.rdp, Object.keys(rdp)) ||
        (rdp.gatewayCredentialId !== '' && !vaultID(rdp.gatewayCredentialId))
      )
        return undefined;
    } catch {
      return undefined;
    }
  } else if (value.rdp !== null) return undefined;
  return { ...value, rdp } as VaultConnectionMetadata;
}

// IPC bytes are consumed even on rejection. Only mutable owned copies survive
// until the bounded stdin write, and the backend independently validates UTF-8.
export function consumeVaultConnectionInput(value: unknown): VaultConnectionInput {
  const object = vaultRecord(value) ? value : undefined;
  const password = object?.password,
    notes = object?.notes;
  try {
    const metadata = connectionMetadata(object?.metadata, object?.rowVersion);
    if (
      !object ||
      !vaultFields(object, ['metadata', 'rowVersion', 'notesAction', 'password', 'notes']) ||
      !metadata ||
      !['preserve', 'set', 'clear'].includes(object.notesAction as string) ||
      !(password instanceof Uint8Array) ||
      !(password.buffer instanceof ArrayBuffer) ||
      password.length > 16384 ||
      !(notes instanceof Uint8Array) ||
      !(notes.buffer instanceof ArrayBuffer) ||
      notes.length > 65536 ||
      (metadata.inlinePasswordAction === 'set') !== password.length > 0 ||
      (object.notesAction !== 'set' && notes.length !== 0)
    )
      throw new Error('Invalid vault connection request.');
    return {
      metadata,
      rowVersion: object.rowVersion as string,
      notesAction: object.notesAction as VaultConnectionInput['notesAction'],
      password: Buffer.from(password),
      notes: Buffer.from(notes),
    };
  } finally {
    if (password instanceof Uint8Array) password.fill(0);
    if (notes instanceof Uint8Array) notes.fill(0);
  }
}
