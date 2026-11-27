import { vaultRecord, vaultFields, vaultID, vaultRevision } from './vault-contract.ts';

export type VaultMigrationSelection = { nodeId: string; rowVersion: string };
export const migrationPaths = ['rdp', 'rdp-gateway', 'reveal', 'sftp', 'ssh', 'vnc'] as const;
export type MigrationPath = (typeof migrationPaths)[number];
export type VaultMigrationChoice = { protocolPath: MigrationPath; choice: 'keep' | 'new' };
export type VaultMigrationEntry = VaultMigrationChoice & {
  nodeId: string;
  oldCredentialId: string;
  newCredentialId: string;
  credentialChanged: boolean;
  usernameChanged: boolean;
  domainChanged: boolean;
  sourceChanged: boolean;
};
export type VaultMigrationReport = VaultMigrationSelection & {
  canDecide: boolean;
  fingerprint: string | null;
  entries: VaultMigrationEntry[];
};
export type VaultMigrationDecision = VaultMigrationSelection & {
  fingerprint: string;
  choices: VaultMigrationChoice[];
};
const fingerprint = (value: unknown): value is string =>
  typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const path = (value: unknown): value is MigrationPath =>
  migrationPaths.includes(value as MigrationPath);
const choice = (value: unknown): value is 'keep' | 'new' => value === 'keep' || value === 'new';

export function parseVaultMigrationSelection(value: unknown): VaultMigrationSelection | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodeId', 'rowVersion']) ||
    !vaultID(value.nodeId) ||
    !vaultRevision(value.rowVersion)
  )
    return undefined;
  return { nodeId: value.nodeId, rowVersion: value.rowVersion };
}
export function parseVaultMigrationDecision(value: unknown): VaultMigrationDecision | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodeId', 'rowVersion', 'fingerprint', 'choices']) ||
    !fingerprint(value.fingerprint) ||
    !Array.isArray(value.choices) ||
    value.choices.length < 1 ||
    value.choices.length > 3
  )
    return undefined;
  const selected = parseVaultMigrationSelection({
    nodeId: value.nodeId,
    rowVersion: value.rowVersion,
  });
  if (!selected || selected.rowVersion === '9223372036854775807') return undefined;
  const choices: VaultMigrationChoice[] = [];
  for (const entry of value.choices) {
    if (
      !vaultRecord(entry) ||
      !vaultFields(entry, ['protocolPath', 'choice']) ||
      !path(entry.protocolPath) ||
      !choice(entry.choice) ||
      choices.some((v) => v.protocolPath === entry.protocolPath)
    )
      return undefined;
    choices.push({ protocolPath: entry.protocolPath, choice: entry.choice });
  }
  return { ...selected, fingerprint: value.fingerprint, choices };
}
export function parseVaultMigrationReport(
  value: unknown,
  expected: VaultMigrationSelection,
): VaultMigrationReport | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['nodeId', 'rowVersion', 'fingerprint', 'entries', 'canDecide']) ||
    typeof value.canDecide !== 'boolean' ||
    value.nodeId !== expected.nodeId ||
    value.rowVersion !== expected.rowVersion ||
    !Array.isArray(value.entries) ||
    value.entries.length > 3 ||
    !(value.entries.length ? fingerprint(value.fingerprint) : value.fingerprint === null)
  )
    return undefined;
  const entries: VaultMigrationEntry[] = [];
  for (const entry of value.entries) {
    if (
      !vaultRecord(entry) ||
      !vaultFields(entry, [
        'nodeId',
        'protocolPath',
        'oldCredentialId',
        'newCredentialId',
        'credentialChanged',
        'usernameChanged',
        'domainChanged',
        'sourceChanged',
        'choice',
      ]) ||
      entry.nodeId !== expected.nodeId ||
      !path(entry.protocolPath) ||
      !choice(entry.choice) ||
      !(entry.oldCredentialId === '' || vaultID(entry.oldCredentialId)) ||
      !(entry.newCredentialId === '' || vaultID(entry.newCredentialId)) ||
      ['credentialChanged', 'usernameChanged', 'domainChanged', 'sourceChanged'].some(
        (key) => typeof entry[key] !== 'boolean',
      ) ||
      !(
        entry.credentialChanged ||
        entry.usernameChanged ||
        entry.domainChanged ||
        entry.sourceChanged
      ) ||
      entry.credentialChanged !== (entry.oldCredentialId !== entry.newCredentialId) ||
      entries.some((v) => v.protocolPath === entry.protocolPath)
    )
      return undefined;
    entries.push({ ...entry } as VaultMigrationEntry);
  }
  return {
    nodeId: expected.nodeId,
    rowVersion: expected.rowVersion,
    canDecide: value.canDecide,
    fingerprint: value.fingerprint as string | null,
    entries,
  };
}
