import type {
  VaultMigrationReport,
  VaultMigrationDecision,
} from '../../electron/vault-migration.ts';
export const migrationNode = '11111111-1111-4111-8111-111111111111';
export const migrationSelection = { nodeId: migrationNode, rowVersion: '2' };
export function migrationReport(): VaultMigrationReport {
  return {
    ...migrationSelection,
    canDecide: true,
    fingerprint: 'a'.repeat(64),
    entries: [
      {
        nodeId: migrationNode,
        protocolPath: 'ssh',
        oldCredentialId: migrationNode,
        newCredentialId: migrationNode,
        credentialChanged: false,
        usernameChanged: true,
        domainChanged: false,
        sourceChanged: false,
        choice: 'keep',
      },
      {
        nodeId: migrationNode,
        protocolPath: 'sftp',
        oldCredentialId: '',
        newCredentialId: migrationNode,
        credentialChanged: true,
        usernameChanged: false,
        domainChanged: true,
        sourceChanged: true,
        choice: 'new',
      },
    ],
  };
}
export function migrationDecision(): VaultMigrationDecision {
  return {
    ...migrationSelection,
    fingerprint: 'a'.repeat(64),
    choices: [{ protocolPath: 'ssh', choice: 'new' }],
  };
}
