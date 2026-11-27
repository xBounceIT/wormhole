import { parseVaultEnrollment, type VaultEnrollment } from './vault-enrollment-contract.ts';
import type { SharedVaultSessionAdmission } from './vault-shared-unlock.ts';
import {
  parseImportReviewRequest,
  parseWorkspaceImportPreview,
  type WorkspaceImportPreview,
  type WorkspaceImportReviewRequest,
} from './vault-shared-import.ts';

export type SharedSetupTarget = {
  hosting: 'self-hosted' | 'managed';
  host: string;
  port: number;
  database: string;
};

export type SharedSetupPlan = SharedSetupTarget & {
  workspaceId: string;
  roleTag: string;
  state: 'prepared' | 'exported' | 'submitted';
};

export type SharedSetupNetworkAction = 'preflight' | 'check' | 'run';
export type SharedSetupNetworkOperation = `shared-setup-${SharedSetupNetworkAction}`;
export type SharedSetupAction =
  | SharedSetupNetworkAction
  | 'plan'
  | 'prepare'
  | 'prepare-tls'
  | 'prepare-generated-tls'
  | 'save-server-kit'
  | 'delete-server-key'
  | 'discard'
  | 'export'
  | 'export-hba'
  | 'import-review'
  | SharedAdminSetupRequest['action'];
type SharedAdminSetupFactors = {
  workspaceId: string;
  accountPassword: Uint8Array;
  ask?: Uint8Array;
};
export type SharedAdminSetupRequest = SharedAdminSetupFactors &
  (
    | {
        action: 'admin-prepare';
        loginName: string;
        profile: 'default' | 'standard';
        directConnectionDevices?: number;
        role: string;
        password: Uint8Array;
      }
    | { action: 'admin-open' }
    | { action: 'admin-import-start' }
    | { action: 'admin-recovery'; recipient: Uint8Array }
    | { action: 'admin-confirm'; enrollmentId: string; groups: Uint8Array }
    | { action: 'admin-publish'; role: string; password: Uint8Array }
    | { action: 'admin-join'; deviceName: string; importConfirmation?: string }
  );
export type SharedAdminSetupOperation = `shared-setup-${SharedAdminSetupRequest['action']}`;
export type SharedSetupTLSRequest = Omit<SharedSetupTarget, 'hosting'> & {
  approvedHosts: string[];
  accountPassword: Uint8Array;
  ask?: Uint8Array;
} & (
    | { action: 'prepare-tls'; csr: string }
    | { action: 'prepare-generated-tls'; keyPassphrase: Uint8Array }
  );
export type SharedSetupRequest =
  | { action: 'plan' }
  | (SharedSetupTarget & { action: 'prepare'; caPem: string })
  | SharedSetupTLSRequest
  | { action: 'discard'; workspaceId: string }
  | { action: 'export'; workspaceId: string }
  | { action: 'export-hba'; workspaceId: string; networks: string[] }
  | { action: 'save-server-kit' | 'delete-server-key'; workspaceId: string }
  | { action: SharedSetupNetworkAction; workspaceId: string; role: string; password: Uint8Array }
  | WorkspaceImportReviewRequest
  | SharedAdminSetupRequest;
export type SharedSetupNativeRequest =
  | Exclude<
      SharedSetupRequest,
      { action: 'export' | 'export-hba' | 'admin-recovery' | 'admin-join' }
    >
  | (Extract<SharedSetupRequest, { action: 'export' | 'export-hba' }> & { path: string })
  | (Extract<SharedAdminSetupRequest, { action: 'admin-recovery' }> & { path: string });

export type SharedSetupPreflight = {
  serverVersion: number;
  maxConnections: number;
  tls: 'verified';
  canCreateRoles: boolean;
  ownsDatabase: boolean;
  ownsPublicSchema: boolean;
  canGrantStatistics: boolean;
  emptyDatabase: boolean;
  logsStatements: boolean;
  logsParameters: boolean;
  statementTracking: 'none' | 'top' | 'all' | 'unavailable';
};

export type SharedSetupDeployment = {
  version: number;
  provisioning: boolean;
  requiresTls: boolean;
};
export type SharedSetupChecks = Pick<
  SharedSetupPreflight,
  'maxConnections' | 'logsStatements' | 'logsParameters' | 'statementTracking'
> & {
  plainStartup: 'offered' | 'refused' | 'unconfirmed';
};

const failureCodes = [
  'dns',
  'tcp',
  'tls',
  'scram',
  'channel-binding',
  'database',
  'read-write',
  'connection-limit',
  'rejected',
  'mismatch',
  'configuration',
  'csr',
  'unavailable',
  'check-required',
  'export-failed',
] as const;
type SharedSetupFailure = (typeof failureCodes)[number] | 'invalid-networks';

export type SharedSetupReply = {
  plan: SharedSetupPlan | null;
  preflight?: SharedSetupPreflight;
  deployment?: SharedSetupDeployment;
  checks?: SharedSetupChecks;
  tls?: SharedSetupTLSCertificates;
  serverKit?: SharedSetupServerKit;
  failure?: SharedSetupFailure;
  adminPending?: true;
  administrator?: SharedAdminSetupStatus;
  recovery?: VaultEnrollment;
  joinAvailable?: true;
  joinSwitchesOnRestart?: true;
  importPreview?: WorkspaceImportPreview;
};

export type SharedSetupTLSCertificates = { caPem: string; serverPem: string };
export type SharedCertificateRenewalRequest = { csr: string };
export type SharedCertificateRenewalResult =
  | { status: 'issued'; serverPem: string }
  | { status: 'unavailable' | 'invalid-csr' };
export type SharedWorkspaceCARequest =
  | { action: 'status' | 'retire' }
  | { action: 'rotate'; csr: string };
export type SharedWorkspaceCAResult =
  | { status: 'staged'; serverPem: string; reconnect?: true }
  | { status: 'retired'; reconnect: true }
  | { status: 'ready' | 'unavailable' | 'invalid-csr' | 'installation-required' };
export type SharedSetupServerKit = {
  folder: string;
  state: 'pending' | 'saved' | 'verified' | 'removed';
};

export type SharedWorkspaceSwitch = { switchOnRestart: true };
export type SharedSetupCompletion = SharedWorkspaceSwitch | SharedVaultSessionAdmission;

export type SharedAdminSetupStatus = {
  enrollmentId: string;
  loginName: string;
  stage: 'prepared' | 'recovery-exported' | 'recovery-confirmed' | 'published';
};

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return (
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key))
  );
}

export function parseSharedWorkspaceSwitch(value: unknown): SharedWorkspaceSwitch | undefined {
  const raw = object(value);
  return raw && exact(raw, ['switchOnRestart']) && raw.switchOnRestart === true
    ? { switchOnRestart: true }
    : undefined;
}

function uuid(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value)
  );
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && /^[\w-]{1,63}$/.test(value);
}

function factor(value: unknown, min: number, max = min): value is Uint8Array {
  return (
    value instanceof Uint8Array &&
    value.buffer instanceof ArrayBuffer &&
    value.length >= min &&
    value.length <= max
  );
}

function checkedText(value: unknown, max: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= max &&
    !/\p{Cc}/u.test(value) &&
    new TextEncoder().encode(value).length <= max
  );
}

export function wipeSharedSetupRequest(value: unknown): void {
  const raw = object(value);
  if (!raw) return;
  for (const field of [
    'password',
    'accountPassword',
    'ask',
    'groups',
    'recipient',
    'keyPassphrase',
  ]) {
    const entry = raw[field];
    if (entry instanceof Uint8Array) entry.fill(0);
  }
}

function consumeSharedAdministrator(
  raw: Record<string, unknown>,
  workspaceId: string,
): SharedAdminSetupRequest | undefined {
  const { action, accountPassword, ask } = raw;
  if (!factor(accountPassword, 1, 1024) || (Object.hasOwn(raw, 'ask') && !factor(ask, 32)))
    return undefined;
  const keys = ['action', 'workspaceId', 'accountPassword', ...(ask ? ['ask'] : [])];
  const own = () => ({
    workspaceId,
    accountPassword: Uint8Array.from(accountPassword),
    ...(ask instanceof Uint8Array ? { ask: Uint8Array.from(ask) } : {}),
  });
  if ((action === 'admin-open' || action === 'admin-import-start') && exact(raw, keys))
    return { action, ...own() };
  if (
    action === 'admin-recovery' &&
    exact(raw, [...keys, 'recipient']) &&
    factor(raw.recipient, 32)
  )
    return { action, ...own(), recipient: Uint8Array.from(raw.recipient) };
  if (
    action === 'admin-confirm' &&
    exact(raw, [...keys, 'enrollmentId', 'groups']) &&
    uuid(raw.enrollmentId) &&
    factor(raw.groups, 10)
  )
    return {
      action,
      ...own(),
      enrollmentId: raw.enrollmentId,
      groups: Uint8Array.from(raw.groups),
    };
  if (
    action === 'admin-join' &&
    exact(raw, [
      ...keys,
      'deviceName',
      ...(Object.hasOwn(raw, 'importConfirmation') ? ['importConfirmation'] : []),
    ]) &&
    checkedText(raw.deviceName, 4096) &&
    (!Object.hasOwn(raw, 'importConfirmation') || uuid(raw.importConfirmation))
  )
    return {
      action,
      ...own(),
      deviceName: raw.deviceName,
      ...(typeof raw.importConfirmation === 'string'
        ? { importConfirmation: raw.importConfirmation }
        : {}),
    };
  if (!identifier(raw.role) || !factor(raw.password, 1, 1024) || raw.password.includes(0))
    return undefined;
  const credentials = ['role', 'password'];
  if (action === 'admin-publish' && exact(raw, [...keys, ...credentials]))
    return { action, ...own(), role: raw.role, password: Uint8Array.from(raw.password) };
  const hasDevices = Object.hasOwn(raw, 'directConnectionDevices');
  const devices = hasDevices ? raw.directConnectionDevices : undefined;
  if (
    action === 'admin-prepare' &&
    exact(raw, [
      ...keys,
      ...credentials,
      'loginName',
      'profile',
      ...(hasDevices ? ['directConnectionDevices'] : []),
    ]) &&
    (!hasDevices ||
      (typeof devices === 'number' &&
        Number.isInteger(devices) &&
        devices >= 0 &&
        devices <= 0xffffffff)) &&
    checkedText(raw.loginName, 256) &&
    (raw.profile === 'default' || raw.profile === 'standard')
  )
    return {
      action,
      ...own(),
      role: raw.role,
      password: Uint8Array.from(raw.password),
      loginName: raw.loginName,
      profile: raw.profile,
      ...(typeof devices === 'number' ? { directConnectionDevices: devices } : {}),
    };
  return undefined;
}

const targetKeys = ['hosting', 'host', 'port', 'database'] as const;
const hostText = (value: unknown): value is string =>
  typeof value === 'string' && value.length <= 253 && /^[a-zA-Z0-9.:-]+$/.test(value);

function pem(value: unknown, type: 'CERTIFICATE REQUEST' | 'CERTIFICATE'): value is string {
  if (typeof value !== 'string' || value.length > 64 * 1024) return false;
  const begin = `-----BEGIN ${type}-----`;
  const end = `-----END ${type}-----`;
  const normalized = value.trimEnd();
  const body = normalized.slice(begin.length, -end.length);
  return (
    normalized.startsWith(begin) && normalized.endsWith(end) && /^[\r\nA-Za-z0-9+/=]+$/.test(body)
  );
}

export function parseSharedCertificateRenewalRequest(
  raw: unknown,
): SharedCertificateRenewalRequest | undefined {
  const value = object(raw);
  if (!value || !exact(value, ['csr'])) return undefined;
  const { csr } = value;
  if (pem(csr, 'CERTIFICATE REQUEST') && csr.length <= 32 * 1024) return { csr };
}

export function parseSharedCertificateRenewalResult(
  raw: unknown,
): SharedCertificateRenewalResult | undefined {
  const value = object(raw);
  if (!value) return undefined;
  const { status, serverPem } = value;
  if (status === 'issued' && exact(value, ['status', 'serverPem']) && pem(serverPem, 'CERTIFICATE'))
    return { status, serverPem };
  if ((status === 'unavailable' || status === 'invalid-csr') && exact(value, ['status']))
    return { status };
}

export function parseSharedWorkspaceCARequest(raw: unknown): SharedWorkspaceCARequest | undefined {
  const value = object(raw);
  if (!value) return undefined;
  if ((value.action === 'status' || value.action === 'retire') && exact(value, ['action']))
    return { action: value.action };
  if (value.action === 'rotate' && exact(value, ['action', 'csr'])) {
    const request = parseSharedCertificateRenewalRequest({ csr: value.csr });
    if (request) return { action: 'rotate', csr: request.csr };
  }
}

export function parseSharedWorkspaceCAResult(
  raw: unknown,
  action: SharedWorkspaceCARequest['action'],
): SharedWorkspaceCAResult | undefined {
  const value = object(raw);
  if (!value) return undefined;
  const { status, serverPem, reconnect } = value;
  if (status === 'staged' && pem(serverPem, 'CERTIFICATE')) {
    if (action === 'status' && exact(value, ['status', 'serverPem'])) return { status, serverPem };
    if (
      action === 'rotate' &&
      reconnect === true &&
      exact(value, ['status', 'serverPem', 'reconnect'])
    )
      return { status, serverPem, reconnect };
  }
  if (
    status === 'retired' &&
    action === 'retire' &&
    reconnect === true &&
    exact(value, ['status', 'reconnect'])
  )
    return { status, reconnect };
  if (
    exact(value, ['status']) &&
    (status === 'unavailable' ||
      (status === 'ready' && action === 'status') ||
      (status === 'invalid-csr' && action === 'rotate') ||
      (status === 'installation-required' && action === 'retire'))
  )
    return { status };
}

function parseTarget(value: Record<string, unknown>): SharedSetupTarget | undefined {
  const { hosting, host, port, database } = value;
  if (
    (hosting !== 'self-hosted' && hosting !== 'managed') ||
    !hostText(host) ||
    typeof port !== 'number' ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535 ||
    !identifier(database)
  )
    return undefined;
  return { hosting, host, port, database };
}

function consumeSharedTLSRequest(raw: Record<string, unknown>): SharedSetupTLSRequest | undefined {
  const { approvedHosts, csr, accountPassword, ask, keyPassphrase } = raw;
  const generate = raw.action === 'prepare-generated-tls';
  const hasAsk = Object.hasOwn(raw, 'ask');
  const target = parseTarget({ ...raw, hosting: 'self-hosted' });
  if (
    !target ||
    !exact(raw, [
      'action',
      'host',
      'port',
      'database',
      'approvedHosts',
      generate ? 'keyPassphrase' : 'csr',
      'accountPassword',
      ...(hasAsk ? ['ask'] : []),
    ]) ||
    !Array.isArray(approvedHosts) ||
    approvedHosts.length < 1 ||
    approvedHosts.length > 64 ||
    !approvedHosts.every(hostText) ||
    !factor(accountPassword, 1, 1024) ||
    (hasAsk && !factor(ask, 32))
  )
    return undefined;
  const own = () => ({
    host: target.host,
    port: target.port,
    database: target.database,
    approvedHosts: [...approvedHosts],
    accountPassword: Uint8Array.from(accountPassword),
    ...(ask instanceof Uint8Array ? { ask: Uint8Array.from(ask) } : {}),
  });
  if (generate) {
    if (
      !factor(keyPassphrase, 16, 1024) ||
      keyPassphrase.some((byte) => byte === 0 || byte === 10 || byte === 13)
    )
      return undefined;
    return {
      action: 'prepare-generated-tls',
      keyPassphrase: Uint8Array.from(keyPassphrase),
      ...own(),
    };
  }
  return pem(csr, 'CERTIFICATE REQUEST') && csr.length <= 32 * 1024
    ? { action: 'prepare-tls', csr, ...own() }
    : undefined;
}

export function validSharedHBANetworks(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 32 &&
    Array.from(value).every(
      (entry) => typeof entry === 'string' && /^[0-9a-fA-F.:/]{1,64}$/.test(entry),
    )
  );
}

export function consumeSharedSetupRequest(value: unknown): SharedSetupRequest | undefined {
  const raw = object(value);
  if (!raw) return undefined;
  const password = raw.password;
  try {
    const action = raw.action;
    if (action === 'plan' && exact(raw, ['action'])) return { action };
    if (action === 'prepare-tls' || action === 'prepare-generated-tls')
      return consumeSharedTLSRequest(raw);
    if (action === 'prepare' && exact(raw, ['action', 'caPem', ...targetKeys])) {
      const target = parseTarget(raw);
      const caPem = raw.caPem;
      if (
        target &&
        typeof caPem === 'string' &&
        caPem.length > 0 &&
        caPem.length <= 256 * 1024 &&
        /^[\t\r\n -~]+$/.test(caPem)
      )
        return { action, ...target, caPem };
    }
    const workspaceId = raw.workspaceId;
    if (!uuid(workspaceId)) return undefined;
    if (
      action === 'export-hba' &&
      exact(raw, ['action', 'workspaceId', 'networks']) &&
      validSharedHBANetworks(raw.networks)
    )
      return { action, workspaceId, networks: [...raw.networks] };
    if (action === 'import-review') return parseImportReviewRequest(raw);
    if (typeof action === 'string' && action.startsWith('admin-'))
      return consumeSharedAdministrator(raw, workspaceId);
    if (
      (action === 'discard' ||
        action === 'export' ||
        action === 'save-server-kit' ||
        action === 'delete-server-key') &&
      exact(raw, ['action', 'workspaceId'])
    )
      return { action, workspaceId };
    if (
      (action === 'preflight' || action === 'check' || action === 'run') &&
      exact(raw, ['action', 'workspaceId', 'role', 'password']) &&
      identifier(raw.role) &&
      password instanceof Uint8Array &&
      password.buffer instanceof ArrayBuffer &&
      password.length > 0 &&
      password.length <= 1024 &&
      !password.includes(0)
    )
      return { action, workspaceId, role: raw.role, password: Uint8Array.from(password) };
    return undefined;
  } finally {
    wipeSharedSetupRequest(raw);
  }
}

function parseServerKit(value: unknown, plan: SharedSetupPlan): SharedSetupServerKit | undefined {
  const raw = object(value);
  if (!raw || plan.hosting !== 'self-hosted' || !exact(raw, ['folder', 'state'])) return undefined;
  const { folder, state } = raw;
  if (
    !checkedText(folder, 4096) ||
    !/^(?:[a-zA-Z]:[\\/]|\/)/.test(folder) ||
    folder.split(/[\\/]/).at(-1) !== plan.workspaceId ||
    (state !== 'pending' && state !== 'saved' && state !== 'verified' && state !== 'removed')
  )
    return undefined;
  return { folder, state };
}

function parsePlan(value: unknown): SharedSetupPlan | undefined {
  const raw = object(value);
  if (!raw || !exact(raw, [...targetKeys, 'workspaceId', 'roleTag', 'state'])) return undefined;
  const target = parseTarget(raw);
  const { workspaceId, roleTag, state } = raw;
  if (
    !target ||
    !uuid(workspaceId) ||
    typeof roleTag !== 'string' ||
    !/^[a-z2-7]{16}$/.test(roleTag) ||
    (state !== 'prepared' && state !== 'exported' && state !== 'submitted')
  )
    return undefined;
  return { ...target, workspaceId, roleTag, state };
}

const preflightFlags = [
  'canCreateRoles',
  'ownsDatabase',
  'ownsPublicSchema',
  'canGrantStatistics',
  'emptyDatabase',
  'logsStatements',
  'logsParameters',
] as const;
function validTracking(value: unknown): boolean {
  return value === 'none' || value === 'top' || value === 'all' || value === 'unavailable';
}

function validConnectionLimit(value: unknown): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= 0x7fff_ffff;
}

function parsePreflight(value: unknown): SharedSetupPreflight | undefined {
  const raw = object(value);
  if (
    !raw ||
    !exact(raw, [
      'serverVersion',
      'maxConnections',
      'tls',
      'statementTracking',
      ...preflightFlags,
    ]) ||
    !validConnectionLimit(raw.maxConnections) ||
    typeof raw.serverVersion !== 'number' ||
    !Number.isSafeInteger(raw.serverVersion) ||
    raw.serverVersion <= 0 ||
    raw.tls !== 'verified' ||
    !validTracking(raw.statementTracking) ||
    !preflightFlags.every((flag) => typeof raw[flag] === 'boolean')
  )
    return undefined;
  return raw as SharedSetupPreflight;
}

function parseDeploymentChecks(value: unknown): SharedSetupChecks | undefined {
  const raw = object(value);
  if (
    !raw ||
    !exact(raw, [
      'plainStartup',
      'maxConnections',
      'logsStatements',
      'logsParameters',
      'statementTracking',
    ]) ||
    !validConnectionLimit(raw.maxConnections) ||
    !validTracking(raw.statementTracking) ||
    typeof raw.logsStatements !== 'boolean' ||
    typeof raw.logsParameters !== 'boolean' ||
    (raw.plainStartup !== 'offered' &&
      raw.plainStartup !== 'refused' &&
      raw.plainStartup !== 'unconfirmed')
  )
    return undefined;
  return raw as SharedSetupChecks;
}

function parseDeployment(value: unknown): SharedSetupDeployment | undefined {
  const raw = object(value);
  if (
    !raw ||
    !exact(raw, ['version', 'provisioning', 'requiresTls']) ||
    typeof raw.version !== 'number' ||
    !Number.isSafeInteger(raw.version) ||
    raw.version <= 0 ||
    typeof raw.provisioning !== 'boolean' ||
    typeof raw.requiresTls !== 'boolean'
  )
    return undefined;
  return { version: raw.version, provisioning: raw.provisioning, requiresTls: raw.requiresTls };
}

// Match the receipt to its originating action and (when present) plan identity.
export function parseSharedSetupReply(
  value: unknown,
  action: SharedSetupAction,
  workspaceId?: string,
): SharedSetupReply | undefined {
  const raw = object(value);
  if (!raw) return undefined;
  if (raw.plan === null) {
    if (action === 'prepare-tls' && exact(raw, ['plan', 'failure']) && raw.failure === 'csr')
      return { plan: null, failure: 'csr' };
    return exact(raw, ['plan']) && (action === 'plan' || action === 'discard')
      ? { plan: null }
      : undefined;
  }
  const plan = parsePlan(raw.plan);
  if (!plan || (workspaceId !== undefined && workspaceId !== plan.workspaceId)) return undefined;
  if (action === 'export-hba') {
    if (plan.hosting !== 'self-hosted') return undefined;
    if (exact(raw, ['plan'])) return { plan };
    return exact(raw, ['plan', 'failure']) &&
      (raw.failure === 'invalid-networks' || raw.failure === 'export-failed')
      ? { plan, failure: raw.failure }
      : undefined;
  }
  if (action === 'admin-import-start' || action === 'import-review') {
    if (plan.state === 'prepared' || !exact(raw, ['plan', 'importPreview'])) return undefined;
    const importPreview = parseWorkspaceImportPreview(raw.importPreview);
    return importPreview ? { plan, importPreview } : undefined;
  }
  if (
    action === 'plan' ||
    action === 'prepare-tls' ||
    action === 'prepare-generated-tls' ||
    action === 'save-server-kit' ||
    action === 'delete-server-key'
  ) {
    const keys = ['plan'];
    let tls: SharedSetupTLSCertificates | undefined;
    if (Object.hasOwn(raw, 'tls')) {
      const material = object(raw.tls);
      if (
        plan.hosting !== 'self-hosted' ||
        !material ||
        !exact(material, ['caPem', 'serverPem']) ||
        !pem(material.caPem, 'CERTIFICATE') ||
        !pem(material.serverPem, 'CERTIFICATE')
      )
        return undefined;
      tls = { caPem: material.caPem, serverPem: material.serverPem };
      keys.push('tls');
    }
    if (
      (action === 'prepare-tls' || action === 'prepare-generated-tls') &&
      (!tls || plan.state !== 'prepared')
    )
      return undefined;
    const kit = Object.hasOwn(raw, 'serverKit') ? parseServerKit(raw.serverKit, plan) : undefined;
    if (kit && tls && action !== 'prepare-tls') keys.push('serverKit');
    if (
      (action === 'prepare-generated-tls' && kit?.state !== 'pending') ||
      (action === 'save-server-kit' && kit?.state !== 'saved') ||
      (action === 'delete-server-key' && kit?.state !== 'removed')
    )
      return undefined;
    const pending = action === 'plan' && raw.adminPending === true && plan.state !== 'prepared';
    if (pending) keys.push('adminPending');
    return exact(raw, keys)
      ? {
          plan,
          ...(tls ? { tls } : {}),
          ...(kit ? { serverKit: kit } : {}),
          ...(pending ? { adminPending: true } : {}),
        }
      : undefined;
  }
  if (action.startsWith('admin-')) return parseAdministratorReply(raw, plan, action);
  if (action === 'prepare')
    return exact(raw, ['plan']) && plan.state === 'prepared' ? { plan } : undefined;
  if (action === 'export')
    return plan.state !== 'exported'
      ? undefined
      : exact(raw, ['plan'])
        ? { plan }
        : exact(raw, ['plan', 'failure']) && raw.failure === 'export-failed'
          ? { plan, failure: raw.failure }
          : undefined;
  if (action === 'discard') return undefined;
  if (
    exact(raw, ['plan', 'failure']) &&
    raw.failure !== 'export-failed' &&
    raw.failure !== 'csr' &&
    failureCodes.some((code) => code === raw.failure)
  )
    return { plan, failure: raw.failure as SharedSetupFailure };
  if (action === 'preflight' && exact(raw, ['plan', 'preflight'])) {
    const preflight = parsePreflight(raw.preflight);
    return preflight ? { plan, preflight } : undefined;
  }
  if (action === 'run' || action === 'check') {
    const deployment = parseDeployment(raw.deployment);
    if (
      !deployment ||
      (action === 'run' &&
        (plan.state !== 'submitted' || !deployment.provisioning || !deployment.requiresTls))
    )
      return undefined;
    const kit =
      action === 'check' && deployment.requiresTls
        ? parseServerKit(raw.serverKit, plan)
        : undefined;
    const keys = ['plan', 'deployment'];
    const checks = action === 'check' ? parseDeploymentChecks(raw.checks) : undefined;
    if (action === 'check' && !checks) return undefined;
    if (checks) keys.push('checks');
    if (kit?.state === 'verified') keys.push('serverKit');
    return exact(raw, keys)
      ? {
          plan,
          deployment,
          ...(checks ? { checks } : {}),
          ...(kit?.state === 'verified' ? { serverKit: kit } : {}),
        }
      : undefined;
  }
  return undefined;
}
function parseAdministratorReply(
  raw: Record<string, unknown>,
  plan: SharedSetupPlan,
  action: SharedSetupAction,
): SharedSetupReply | undefined {
  if (plan.state === 'prepared' || action === 'admin-join') return undefined;
  const failure = raw.failure as (typeof failureCodes)[number];
  const failed = failure !== 'export-failed' && failure !== 'csr' && failureCodes.includes(failure);
  if (action === 'admin-prepare' && failed && exact(raw, ['plan', 'failure']))
    return { plan, failure };
  const status = object(raw.administrator);
  const stage = status?.stage;
  if (
    raw.adminPending !== true ||
    !status ||
    !exact(status, ['enrollmentId', 'loginName', 'stage']) ||
    !uuid(status.enrollmentId) ||
    !checkedText(status.loginName, 256) ||
    (stage !== 'prepared' &&
      stage !== 'recovery-exported' &&
      stage !== 'recovery-confirmed' &&
      stage !== 'published')
  )
    return undefined;
  const administrator: SharedAdminSetupStatus = {
    enrollmentId: status.enrollmentId,
    loginName: status.loginName,
    stage,
  };
  const reply: SharedSetupReply = { plan, adminPending: true, administrator };
  const keys = ['plan', 'adminPending', 'administrator'];
  if (action === 'admin-recovery') {
    const recovery = parseVaultEnrollment(raw.recovery);
    return stage === 'recovery-exported' &&
      exact(raw, [...keys, 'recovery']) &&
      recovery?.vaultId === plan.workspaceId &&
      recovery.enrollmentId === administrator.enrollmentId
      ? { ...reply, recovery }
      : undefined;
  }
  if (
    action === 'admin-publish' &&
    failed &&
    (stage === 'recovery-confirmed' || stage === 'published') &&
    exact(raw, [...keys, 'failure'])
  )
    return { ...reply, failure };
  if (!exact(raw, keys)) return undefined;
  if (
    action === 'admin-open' ||
    (action === 'admin-prepare' && stage === 'prepared') ||
    (action === 'admin-confirm' && stage === 'recovery-confirmed') ||
    (action === 'admin-publish' && stage === 'published')
  )
    return reply;
  return undefined;
}
