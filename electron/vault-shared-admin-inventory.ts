import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';

export type AdminInventoryKind =
  | 'accounts'
  | 'devices'
  | 'my-devices'
  | 'unencrypted-clients'
  | 'sessions'
  | 'slots'
  | 'audit';
type Cursor = { id: string; at?: string };
export type AdminInventoryRequest = { kind: AdminInventoryKind; next?: Cursor };
export type CredentialSlot = {
  id: string;
  name: string;
  protocol: 'ssh' | 'rdp' | 'vnc';
  allowSelfService: boolean;
};
export type CreateSlotReply = {
  status: 'saved' | 'busy' | 'stale' | 'unsupported' | 'unavailable';
};
export type CreateSlotPort = (request: CredentialSlot) => Promise<CreateSlotReply>;

type Entry = {
  id: string;
  login?: string;
  protocol?: 'ssh' | 'rdp' | 'vnc';
  allowSelfService?: boolean;
  name?: string;
  role?: string;
  status?: string;
  at?: string;
  deviceId?: string;
  appVersion?: string;
  transport?: string;
  actorId?: string;
  sessionId?: string;
  action?: string;
  source?: string;
};
type Page = { kind: AdminInventoryKind; entries: Entry[]; next?: Cursor };
export type CredentialSlotPage = {
  kind: 'slots';
  entries: CredentialSlot[];
  next?: { id: string };
};
export type AdminInventoryReply<T extends Page = Page> =
  | { status: 'ready'; page: T }
  | { status: 'unavailable' | 'unsupported' };

const date = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^(?!0000)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value.slice(0, 23) + 'Z';
const timeline = (kind: AdminInventoryKind) => kind === 'sessions' || kind === 'audit';
const text = (value: unknown, max: number): value is string =>
  typeof value === 'string' && value.length <= max && !/\p{Cc}/u.test(value);
const eventCode = (value: unknown) =>
  typeof value === 'string' && /^[a-z][a-z0-9_-]{0,63}$/.test(value);

export function parseAdminInventoryRequest(value: unknown): AdminInventoryRequest | undefined {
  if (!vaultRecord(value)) return;
  const { kind, next } = value;
  if (
    kind !== 'accounts' &&
    kind !== 'devices' &&
    kind !== 'my-devices' &&
    kind !== 'unencrypted-clients' &&
    kind !== 'sessions' &&
    kind !== 'audit' &&
    kind !== 'slots'
  )
    return;
  if (!Object.hasOwn(value, 'next')) return vaultFields(value, ['kind']) ? { kind } : undefined;
  if (
    !vaultFields(value, ['kind', 'next']) ||
    !vaultRecord(next) ||
    !vaultID(next.id) ||
    !vaultFields(next, timeline(kind) ? ['id', 'at'] : ['id']) ||
    (timeline(kind) && !date(next.at))
  )
    return;
  return { kind, next: { id: next.id, ...(typeof next.at === 'string' ? { at: next.at } : {}) } };
}

function isSlot(value: unknown): value is CredentialSlot {
  return (
    vaultRecord(value) &&
    vaultID(value.id) &&
    vaultFields(value, ['id', 'name', 'protocol', 'allowSelfService']) &&
    typeof value.name === 'string' &&
    value.name.trim().length > 0 &&
    value.name.length <= 1024 &&
    new TextEncoder().encode(value.name).byteLength <= 1024 &&
    !value.name.includes('\0') &&
    (value.protocol === 'ssh' || value.protocol === 'rdp' || value.protocol === 'vnc') &&
    typeof value.allowSelfService === 'boolean'
  );
}

export function parseCreateSlot(value: unknown): CredentialSlot | undefined {
  if (isSlot(value) && !/\p{Cc}|\p{Cs}/u.test(value.name)) return value;
}

export function parseCreateSlotReply(value: unknown): CreateSlotReply | undefined {
  if (!vaultRecord(value) || !vaultFields(value, ['status'])) return;
  const { status } = value;
  if (
    status === 'saved' ||
    status === 'busy' ||
    status === 'stale' ||
    status === 'unsupported' ||
    status === 'unavailable'
  )
    return { status };
}

function validEntry(value: unknown, kind: AdminInventoryKind): value is Entry {
  if (kind === 'slots') return isSlot(value);
  if (!vaultRecord(value) || !vaultID(value.id)) return false;
  if (!text(value.login, 256) || (!value.login && kind !== 'audit')) return false;
  const names = ['id', 'login', ...(Object.hasOwn(value, 'name') ? ['name'] : [])];
  switch (kind) {
    case 'accounts':
      return (
        vaultFields(value, [...names, 'role', 'status']) &&
        (!Object.hasOwn(value, 'name') || text(value.name, 4096)) &&
        (value.role === 'administrator' || value.role === 'member') &&
        (value.status === 'enabled' || value.status === 'disabled')
      );
    case 'devices':
    case 'my-devices':
    case 'unencrypted-clients':
      return (
        vaultFields(value, [...names, 'status', 'at']) &&
        (!Object.hasOwn(value, 'name') || text(value.name, 4096)) &&
        (value.status === 'active' || value.status === 'pending' || value.status === 'revoked') &&
        date(value.at)
      );
    case 'sessions':
      return (
        vaultFields(value, ['id', 'login', 'deviceId', 'appVersion', 'transport', 'at']) &&
        vaultID(value.deviceId) &&
        text(value.appVersion, 64) &&
        /^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$/.test(value.appVersion) &&
        (value.transport === 'tls' || value.transport === 'unencrypted') &&
        date(value.at)
      );
    case 'audit':
      return (
        vaultFields(value, [
          'id',
          'login',
          'actorId',
          'sessionId',
          'action',
          'status',
          'source',
          'at',
        ]) &&
        vaultID(value.actorId) &&
        vaultID(value.sessionId) &&
        eventCode(value.action) &&
        eventCode(value.status) &&
        (value.source === 'ui' || value.source === 'mcp') &&
        date(value.at)
      );
  }
}

export function parseAdminInventoryReply(
  value: unknown,
  request: AdminInventoryRequest & { kind: 'slots' },
): AdminInventoryReply<CredentialSlotPage> | undefined;
export function parseAdminInventoryReply(
  value: unknown,
  request: AdminInventoryRequest,
): AdminInventoryReply | undefined;
export function parseAdminInventoryReply(
  value: unknown,
  request: AdminInventoryRequest,
): AdminInventoryReply | undefined {
  if (!vaultRecord(value)) return;
  if (value.status === 'unavailable' || value.status === 'unsupported')
    return vaultFields(value, ['status']) ? { status: value.status } : undefined;
  const { kind } = request;
  const page = value.page;
  if (
    value.status !== 'ready' ||
    !vaultFields(value, ['status', 'page']) ||
    !vaultRecord(page) ||
    page.kind !== kind ||
    !vaultFields(page, ['kind', 'entries', ...(Object.hasOwn(page, 'next') ? ['next'] : [])]) ||
    !Array.isArray(page.entries) ||
    page.entries.length > 25
  )
    return;
  const entries: Entry[] = [];
  let before = request.next;
  const byTime = timeline(kind);
  for (const entry of page.entries) {
    if (!validEntry(entry, kind)) return;
    if (
      before &&
      (byTime
        ? entry.at! > before.at! || (entry.at === before.at && entry.id >= before.id)
        : entry.id <= before.id)
    )
      return;
    entries.push(entry);
    before = entry;
  }
  let next: Cursor | undefined;
  if (Object.hasOwn(page, 'next')) {
    next = parseAdminInventoryRequest({ kind, next: page.next })?.next;
    if (
      !next ||
      (kind === 'slots' ? entries.length === 0 : entries.length !== 25) ||
      next.id !== before?.id ||
      (byTime && next.at !== before.at)
    )
      return;
  }
  return { status: 'ready', page: { kind, entries, ...(next ? { next } : {}) } };
}
