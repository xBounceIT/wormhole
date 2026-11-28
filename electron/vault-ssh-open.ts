import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { parseVaultQuickTarget, type VaultQuickTarget } from './vault-quick-target.ts';

export type VaultSshOpen = {
  sessionId: string;
  columns: number;
  rows: number;
  mode?: 'terminal' | 'sftp';
  manualCredentials?: true;
  manualKeyPassphrase?: true;
} & (
  | { nodeId: string; credentialId?: string; quickTarget?: never }
  | { quickTarget: VaultQuickTarget; nodeId?: never; credentialId?: never }
);

/** Public intent only. Passwords, private keys and passphrases use isolated entry. */
export function parseVaultSshOpen(value: unknown): VaultSshOpen | undefined {
  if (
    !vaultRecord(value) ||
    !vaultID(value.sessionId) ||
    ![value.columns, value.rows].every(
      (n) => Number.isInteger(n) && (n as number) > 0 && (n as number) <= 500,
    ) ||
    (value.mode !== undefined && value.mode !== 'terminal' && value.mode !== 'sftp') ||
    (value.manualCredentials !== undefined && value.manualCredentials !== true) ||
    (value.manualKeyPassphrase !== undefined && value.manualKeyPassphrase !== true) ||
    (value.manualCredentials && value.manualKeyPassphrase) ||
    !vaultFields(value, [
      'sessionId',
      'columns',
      'rows',
      ...(value.mode !== undefined ? ['mode'] : []),
      ...(value.manualCredentials !== undefined ? ['manualCredentials'] : []),
      ...(value.manualKeyPassphrase !== undefined ? ['manualKeyPassphrase'] : []),
      ...(value.quickTarget !== undefined ? ['quickTarget'] : ['nodeId']),
      ...(value.credentialId !== undefined ? ['credentialId'] : []),
    ])
  )
    return undefined;
  const intent = {
    sessionId: value.sessionId,
    columns: value.columns as number,
    rows: value.rows as number,
    ...(value.mode ? { mode: value.mode as 'terminal' | 'sftp' } : {}),
    ...(value.manualCredentials ? { manualCredentials: true as const } : {}),
    ...(value.manualKeyPassphrase ? { manualKeyPassphrase: true as const } : {}),
  };
  if (value.quickTarget !== undefined) {
    const quickTarget = parseVaultQuickTarget(value.quickTarget);
    if (
      !quickTarget ||
      !['ssh', 'sftp'].includes(quickTarget.protocol) ||
      value.credentialId !== undefined ||
      (value.manualCredentials && quickTarget.credentialId !== '') ||
      (quickTarget.protocol === 'sftp' && value.mode !== 'sftp')
    )
      return undefined;
    return { ...intent, quickTarget };
  }
  if (
    !vaultID(value.nodeId) ||
    (value.credentialId !== undefined && !vaultID(value.credentialId)) ||
    (value.manualCredentials && value.credentialId !== undefined)
  )
    return undefined;
  return {
    ...intent,
    nodeId: value.nodeId,
    ...(value.credentialId ? { credentialId: value.credentialId as string } : {}),
  };
}
