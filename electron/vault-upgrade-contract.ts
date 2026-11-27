import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';

export type VaultUpgradeContext = { vaultId: string };

export function parseVaultUpgradeContext(value: unknown): VaultUpgradeContext | undefined {
  return vaultRecord(value) && vaultFields(value, ['vaultId']) && vaultID(value.vaultId)
    ? { vaultId: value.vaultId }
    : undefined;
}
