import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';

type GroupRef = { groupId: string; revision: string };
export type GroupRequest =
  | { action: 'list'; after?: string }
  | ({ action: 'members'; after?: string } & GroupRef)
  | { action: 'create'; groupId: string; name: string }
  | ({ action: 'rename'; name: string } & GroupRef)
  | ({ action: 'add-member'; login: string } & GroupRef)
  | ({ action: 'remove-member'; memberId: string } & GroupRef)
  | ({ action: 'delete' } & GroupRef);
export type GroupEntry = { id: string; name: string; revision: string };
export type GroupMember = { id: string; login: string; status: 'enabled' | 'disabled' };
type GroupStatus =
  | 'changed'
  | 'unchanged'
  | 'stale'
  | 'busy'
  | 'unsupported'
  | 'unavailable'
  | 'group-in-use'
  | 'key-change-required'
  | 'account-unavailable';
export type GroupReply =
  | { status: 'ready'; page: { entries: (GroupEntry | GroupMember)[]; after?: string } }
  | { status: GroupStatus };

const fields = {
  list: [],
  members: ['groupId', 'revision'],
  create: ['groupId', 'name'],
  rename: ['groupId', 'revision', 'name'],
  'add-member': ['groupId', 'revision', 'login'],
  'remove-member': ['groupId', 'revision', 'memberId'],
  delete: ['groupId', 'revision'],
} as const;

const revision = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^[1-9]\d{0,18}$/.test(value) &&
  (value.length < 19 || value <= '9223372036854775807');
const text = (value: unknown, max: number): value is string =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.length <= max &&
  !/\p{Cc}/u.test(value) &&
  new TextEncoder().encode(value).length <= max;
const reading = (action: GroupRequest['action']) => action === 'list' || action === 'members';

export function parseGroupRequest(value: unknown): GroupRequest | undefined {
  if (
    !vaultRecord(value) ||
    typeof value.action !== 'string' ||
    !Object.hasOwn(fields, value.action)
  )
    return;
  const action = value.action as GroupRequest['action'];
  const required = fields[action] as readonly string[];
  const after = reading(action) && Object.hasOwn(value, 'after');
  if (
    !vaultFields(value, ['action', ...required, ...(after ? ['after'] : [])]) ||
    (after && !vaultID(value.after))
  )
    return;
  for (const field of required) {
    const item = value[field];
    if (
      field === 'revision'
        ? !revision(item)
        : field === 'name'
          ? !text(item, 256) || item.trim() !== item
          : field === 'login'
            ? !text(item, 256)
            : !vaultID(item)
    )
      return;
  }
  return value as GroupRequest;
}

export function parseGroupReply(value: unknown, request: GroupRequest): GroupReply | undefined {
  if (!vaultRecord(value)) return;
  const { status, page } = value;
  if (status !== 'ready') {
    if (!vaultFields(value, ['status'])) return;
    if (
      status === 'unavailable' ||
      status === 'unsupported' ||
      status === 'stale' ||
      status === 'busy' ||
      (!reading(request.action) && (status === 'changed' || status === 'unchanged')) ||
      (request.action === 'delete' && status === 'group-in-use') ||
      (request.action === 'add-member' && status === 'account-unavailable') ||
      (status === 'key-change-required' &&
        ['add-member', 'remove-member', 'delete'].includes(request.action))
    )
      return { status };
    return;
  }
  if (
    !reading(request.action) ||
    !vaultFields(value, ['status', 'page']) ||
    !vaultRecord(page) ||
    !vaultFields(page, ['entries', ...(Object.hasOwn(page, 'after') ? ['after'] : [])]) ||
    !Array.isArray(page.entries) ||
    page.entries.length > 25
  )
    return;
  const entries: (GroupEntry | GroupMember)[] = [];
  let after = 'after' in request ? (request.after ?? '') : '';
  for (const row of page.entries) {
    if (!vaultRecord(row) || !vaultID(row.id) || row.id <= after) return;
    after = row.id;
    if (request.action === 'list') {
      if (
        !vaultFields(row, ['id', 'name', 'revision']) ||
        !text(row.name, 1024) ||
        !revision(row.revision)
      )
        return;
      entries.push({ id: row.id, name: row.name, revision: row.revision });
    } else {
      if (
        !vaultFields(row, ['id', 'login', 'status']) ||
        !text(row.login, 256) ||
        (row.status !== 'enabled' && row.status !== 'disabled')
      )
        return;
      entries.push({ id: row.id, login: row.login, status: row.status });
    }
  }
  if (Object.hasOwn(page, 'after') && (page.entries.length !== 25 || page.after !== after)) return;
  return { status, page: { entries, ...(page.after === after ? { after } : {}) } };
}
