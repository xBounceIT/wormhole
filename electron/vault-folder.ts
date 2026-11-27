import {
  vaultFields,
  vaultID,
  vaultMetadataText,
  vaultRecord,
  vaultRevision,
} from './vault-contract.ts';

export type VaultFolderRequest = {
  id: string;
  rowVersion: string;
  parentId: string;
  name: string;
  sshAutoSudo: boolean | null;
  tunnelEnabled: boolean | null;
  tunnelConfigId: string;
  credentialMode: 0 | 1 | 2;
  credentialId: string;
};
export type VaultFolderResult = { nodeId: string; rowVersion: string; updated: true };

export function parseVaultFolder(value: unknown): VaultFolderRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'id',
      'rowVersion',
      'parentId',
      'name',
      'sshAutoSudo',
      'tunnelEnabled',
      'tunnelConfigId',
      'credentialMode',
      'credentialId',
    ]) ||
    !(
      (value.id === '' && value.rowVersion === '0') ||
      (vaultID(value.id) &&
        vaultRevision(value.rowVersion) &&
        value.rowVersion !== '9223372036854775807')
    ) ||
    !(value.parentId === '' || vaultID(value.parentId)) ||
    !vaultMetadataText(value.name, 1024, true) ||
    [...value.name.trim()].length > 256 ||
    /\p{Cc}/u.test(value.name) ||
    !(value.sshAutoSudo === null || typeof value.sshAutoSudo === 'boolean') ||
    !(value.tunnelEnabled === null || typeof value.tunnelEnabled === 'boolean') ||
    !(value.tunnelConfigId === '' || vaultID(value.tunnelConfigId)) ||
    ![0, 1, 2].includes(value.credentialMode as number) ||
    !(value.credentialMode === 2 ? vaultID(value.credentialId) : value.credentialId === '')
  )
    return undefined;
  return { ...value } as VaultFolderRequest;
}

export function parseVaultFolderResult(value: unknown): VaultFolderResult | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodeId', 'rowVersion', 'updated']) ||
    !vaultID(value.nodeId) ||
    !vaultRevision(value.rowVersion) ||
    value.updated !== true
  )
    return undefined;
  return { nodeId: value.nodeId, rowVersion: value.rowVersion, updated: true };
}
