import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';
import {
  parseVaultCredentialSelection,
  type VaultCredentialSelection,
} from './vault-credential.ts';
export type VaultNodeDuplicateRequest = VaultCredentialSelection;
export type VaultNodeDuplicateResult = { nodeId: string; name: string; rowVersion: '1' };
export const parseVaultNodeDuplicate = parseVaultCredentialSelection;
export function parseVaultNodeDuplicateResult(
  value: unknown,
): VaultNodeDuplicateResult | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodeId', 'name', 'rowVersion']) ||
    !vaultID(value.nodeId) ||
    !vaultMetadataText(value.name, 1024, true) ||
    [...value.name].length > 256 ||
    /\p{Cc}/u.test(value.name) ||
    value.rowVersion !== '1'
  )
    return undefined;
  return { nodeId: value.nodeId, name: value.name, rowVersion: '1' };
}
