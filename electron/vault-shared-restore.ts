import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { validSharedRecoveryBackupPath, validSharedArtifactPath } from './vault-shared-unlock.ts';

type WorkspaceRecoverySummary = {
  workspaceId: string;
  roleTag: string;
  sourceSchemaVersion: number;
  profile: 'default' | 'standard';
  accounts: number;
  nodes: number;
};

export type SharedRecoveryInspection =
  | { status: 'ready' | 'saved' | 'save-failed'; summary: WorkspaceRecoverySummary }
  | { status: 'invalid-backup' | 'invalid-password' };
export type SharedRecoveryInspectionReceipt =
  | (Extract<SharedRecoveryInspection, { summary: WorkspaceRecoverySummary }> & {
      archiveDigest: string;
    })
  | Extract<SharedRecoveryInspection, { status: 'invalid-backup' | 'invalid-password' }>;

export type SharedRecoveryInspectionRequest = {
  password: Uint8Array;
  saveScript: boolean;
};

export type SharedRecoveryInspectionNative = {
  password: Uint8Array;
  path: string;
  scriptPath?: string;
};

export type SharedRecoveryRestoreRequest = {
  host: string;
  port: number;
  database: string;
  confirmed: true;
  password: Uint8Array;
  deployerPassword: Uint8Array;
};
export type SharedRecoveryRestoreNative = Omit<SharedRecoveryRestoreRequest, 'confirmed'> & {
  path: string;
  workspaceId: string;
  roleTag: string;
  archiveDigest: string;
};
export type SharedRecoveryRestoreStatus =
  | 'restored'
  | 'already-restored'
  | 'invalid-backup'
  | 'invalid-password'
  | 'archive-changed'
  | 'logging-enabled'
  | 'uncertain'
  | 'rejected';

export function parseSharedRecoveryRestoreStatus(
  value: unknown,
): SharedRecoveryRestoreStatus | undefined {
  if (
    value === 'restored' ||
    value === 'already-restored' ||
    value === 'invalid-backup' ||
    value === 'invalid-password' ||
    value === 'archive-changed' ||
    value === 'logging-enabled' ||
    value === 'uncertain' ||
    value === 'rejected'
  )
    return value;
}

export function wipeSharedRecoveryRestore(value: unknown): void {
  if (!vaultRecord(value)) return;
  for (const factor of [value.password, value.deployerPassword])
    if (factor instanceof Uint8Array) factor.fill(0);
}

function factor(value: unknown, min: number, max = min): value is Uint8Array {
  return (
    value instanceof Uint8Array &&
    value.buffer instanceof ArrayBuffer &&
    value.length >= min &&
    value.length <= max
  );
}

function restoreTarget(
  input: Record<string, unknown>,
): input is Record<string, unknown> &
  Pick<SharedRecoveryRestoreRequest, 'host' | 'port' | 'database'> {
  return (
    typeof input.host === 'string' &&
    input.host.length <= 253 &&
    /^[a-z0-9.:-]+$/i.test(input.host) &&
    typeof input.port === 'number' &&
    Number.isInteger(input.port) &&
    input.port >= 1 &&
    input.port <= 65535 &&
    typeof input.database === 'string' &&
    /^[a-zA-Z0-9_-]{1,63}$/.test(input.database)
  );
}

export function consumeSharedRecoveryRestore(value: unknown): SharedRecoveryRestoreRequest {
  try {
    if (
      !vaultRecord(value) ||
      !vaultFields(value, [
        'host',
        'port',
        'database',
        'confirmed',
        'password',
        'deployerPassword',
      ]) ||
      value.confirmed !== true ||
      !restoreTarget(value) ||
      !factor(value.password, 76) ||
      !factor(value.deployerPassword, 1, 1024)
    )
      throw Error('Invalid workspace restore request.');
    return {
      host: value.host,
      port: value.port,
      database: value.database,
      confirmed: true,
      password: new Uint8Array(value.password),
      deployerPassword: new Uint8Array(value.deployerPassword),
    };
  } finally {
    wipeSharedRecoveryRestore(value);
  }
}

export function validSharedRecoveryRestore(value: SharedRecoveryRestoreNative): boolean {
  return (
    restoreTarget(value) &&
    validSharedRecoveryBackupPath(value.path) &&
    vaultID(value.workspaceId) &&
    validRoleTag(value.roleTag) &&
    validArchiveDigest(value.archiveDigest) &&
    factor(value.password, 76) &&
    factor(value.deployerPassword, 1, 1024)
  );
}

export function consumeSharedRecoveryInspection(value: unknown): SharedRecoveryInspectionRequest {
  const password = vaultRecord(value) ? value.password : undefined;
  try {
    if (
      !vaultRecord(value) ||
      !vaultFields(value, ['password', 'saveScript']) ||
      typeof value.saveScript !== 'boolean' ||
      !factor(password, 76)
    )
      throw Error('Invalid workspace restore request.');
    return { password: new Uint8Array(password), saveScript: value.saveScript };
  } finally {
    if (password instanceof Uint8Array) password.fill(0);
  }
}

export function validSharedRecoveryInspection(input: SharedRecoveryInspectionNative): boolean {
  return (
    validSharedRecoveryBackupPath(input.path) &&
    input.password.length === 76 &&
    (input.scriptPath === undefined || validSharedArtifactPath(input.scriptPath, '.sql'))
  );
}

function recordCount(value: unknown, minimum: number): value is number {
  return (
    typeof value === 'number' && Number.isInteger(value) && value >= minimum && value <= 100_000
  );
}

function validRoleTag(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z2-7]{8,16}$/.test(value);
}

function validArchiveDigest(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

export function parseSharedRecoveryInspectionReceipt(
  value: unknown,
): SharedRecoveryInspectionReceipt | undefined {
  if (!vaultRecord(value)) return undefined;
  const { archiveDigest, ...display } = value;
  const result = parseSharedRecoveryInspection(display);
  if (!result) return undefined;
  return 'summary' in result
    ? validArchiveDigest(archiveDigest)
      ? { ...result, archiveDigest }
      : undefined
    : Object.hasOwn(value, 'archiveDigest')
      ? undefined
      : result;
}

export function parseSharedRecoveryInspection(
  value: unknown,
): SharedRecoveryInspection | undefined {
  if (!vaultRecord(value)) return undefined;
  if (value.status === 'invalid-backup' || value.status === 'invalid-password')
    return vaultFields(value, ['status']) ? { status: value.status } : undefined;
  if (value.status !== 'ready' && value.status !== 'saved' && value.status !== 'save-failed')
    return undefined;
  const summary = value.summary;
  if (
    !vaultFields(value, ['status', 'summary']) ||
    !vaultRecord(summary) ||
    !vaultFields(summary, [
      'workspaceId',
      'roleTag',
      'sourceSchemaVersion',
      'profile',
      'accounts',
      'nodes',
    ]) ||
    !vaultID(summary.workspaceId) ||
    !validRoleTag(summary.roleTag) ||
    typeof summary.sourceSchemaVersion !== 'number' ||
    !Number.isInteger(summary.sourceSchemaVersion) ||
    summary.sourceSchemaVersion < 49 ||
    summary.sourceSchemaVersion > 96 ||
    (summary.profile !== 'default' && summary.profile !== 'standard') ||
    !recordCount(summary.accounts, 1) ||
    !recordCount(summary.nodes, 0)
  )
    return undefined;
  return {
    status: value.status,
    summary: {
      workspaceId: summary.workspaceId,
      roleTag: summary.roleTag,
      sourceSchemaVersion: summary.sourceSchemaVersion,
      profile: summary.profile,
      accounts: summary.accounts,
      nodes: summary.nodes,
    },
  };
}
