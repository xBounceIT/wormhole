import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';

export type AdminInventoryKind =
  | 'accounts'
  | 'devices'
  | 'my-devices'
  | 'unencrypted-clients'
  | 'sessions'
  | 'audit';
type Cursor = { id: string; at?: string };
export type AdminInventoryRequest = { kind: AdminInventoryKind; next?: Cursor };

type Entry = {
  id: string;
  login: string;
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
export type AdminInventoryReply =
  | { status: 'ready'; page: Page }
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
    kind !== 'audit'
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

function validEntry(value: unknown, kind: AdminInventoryKind): value is Entry {
  if (
    !vaultRecord(value) ||
    !vaultID(value.id) ||
    !text(value.login, 256) ||
    (!value.login && kind !== 'audit')
  )
    return false;
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
      entries.length !== 25 ||
      next.id !== before?.id ||
      (byTime && next.at !== before.at)
    )
      return;
  }
  return { status: 'ready', page: { kind, entries, ...(next ? { next } : {}) } };
}
