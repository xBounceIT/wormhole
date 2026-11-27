import { vaultFields, vaultRecord, vaultID } from './vault-contract.ts';
import { parseVaultSecurity, type VaultSecurity } from './vault-security.ts';
import { parseSharedVaultTransport, type SharedVaultTransport } from './vault-shared-transport.ts';

// Main-only public projection. vaultId selects the protected device slot file;
// workspaceId scopes shared protocol requests to the admitted PostgreSQL workspace.
export type SharedVaultRuntime = {
  vaultId: string;
  workspaceId: string;
  security: VaultSecurity;
  tls: SharedVaultTransport;
  recoveryBackup?: true;
  administrator?: true;
};

export function parseSharedVaultRuntime(value: unknown): SharedVaultRuntime | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'vaultId',
      'workspaceId',
      'security',
      'tls',
      ...(Object.hasOwn(value, 'recoveryBackup') ? ['recoveryBackup'] : []),
      ...(Object.hasOwn(value, 'administrator') ? ['administrator'] : []),
    ]) ||
    !vaultID(value.vaultId) ||
    !vaultID(value.workspaceId)
  )
    return undefined;
  const security = parseVaultSecurity(value.security);
  const tls = parseSharedVaultTransport(value.tls);
  if (
    !security ||
    (security.canTightenToStandard && tls !== 'verified') ||
    !tls ||
    (Object.hasOwn(value, 'administrator') &&
      (value.administrator !== true || tls !== 'verified')) ||
    (security.effective !== 'default' && tls !== 'verified') ||
    (Object.hasOwn(value, 'recoveryBackup') &&
      (value.recoveryBackup !== true ||
        tls !== 'verified' ||
        (security.effective !== 'default' && security.effective !== 'standard')))
  )
    return undefined;
  return {
    vaultId: value.vaultId,
    workspaceId: value.workspaceId,
    security,
    tls,
    ...(value.recoveryBackup === true ? { recoveryBackup: true } : {}),
    ...(value.administrator === true ? { administrator: true } : {}),
  };
}
