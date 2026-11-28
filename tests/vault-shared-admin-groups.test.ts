import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseGroupReply,
  parseGroupRequest,
  type GroupRequest,
} from '../electron/vault-shared-admin-groups.ts';

const id = (n: number) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`;
const group = { groupId: id(10), revision: '3' };
const create = { action: 'create', groupId: id(10), name: 'Operations' } as const;
const rename = { action: 'rename', ...group, name: 'Incident response' } as const;
const add = { action: 'add-member', ...group, login: 'exact account' } as const;
const remove = { action: 'remove-member', ...group, memberId: id(4) } as const;
const del = { action: 'delete', ...group } as const;
const list = { action: 'list' } as const;
const members = { action: 'members', ...group } as const;

test('group requests require the selected canonical target and revision', () => {
  for (const request of [
    create,
    rename,
    add,
    remove,
    del,
    list,
    members,
    { ...list, after: id(9) },
  ])
    assert.deepEqual(parseGroupRequest(request), request);
  for (const bad of [
    null,
    { action: 'constructor' },
    { ...list, after: id(0) },
    { ...list, groupId: id(3) },
    { ...create, revision: '1' },
    { ...create, name: ' Operations ' },
    { ...create, name: 'è'.repeat(140) },
    { ...create, name: 'line\nbreak' },
    { ...add, login: '' },
    { ...rename, revision: '03' },
    { ...rename, revision: '9223372036854775808' },
    { ...remove, memberId: id(0) },
    { ...del, after: id(4) },
    { ...del, groupId: 'unknown' },
  ])
    assert.equal(parseGroupRequest(bad), undefined);
});

test('group replies validate page and cursor identity and action-specific status', () => {
  const rows = Array.from({ length: 25 }, (_, pos) => ({
    id: id(pos + 1),
    name: 'Operations',
    revision: '9223372036854775807',
  }));
  const page = { status: 'ready', page: { entries: rows, after: id(25) } };
  assert.deepEqual(parseGroupReply(page, list), page);
  const member = {
    status: 'ready',
    page: { entries: [{ id: id(4), login: 'alice', status: 'disabled' }] },
  };
  assert.deepEqual(parseGroupReply(member, members), member);
  for (const [reply, req] of [
    [page, { ...list, after: id(2) }],
    [page, create],
    [page, members],
    [member, list],
    [{ ...page, page: { ...page.page, after: id(29) } }, list],
    [{ ...page, page: { entries: [...rows, rows[0]] } }, list],
    [{ ...page, page: { entries: [rows[0], rows[0]] } }, list],
    [{ ...member, page: { entries: [{ ...member.page.entries[0], status: 'pending' }] } }, members],
    [{ status: 'changed' }, list],
    [{ status: 'group-in-use' }, remove],
    [{ status: 'account-unavailable' }, del],
    [{ status: 'key-change-required' }, rename],
    [{ status: 'unavailable', page: {} }, members],
  ] as [unknown, GroupRequest][])
    assert.equal(parseGroupReply(reply, req), undefined);
  for (const [status, request] of [
    ['busy', list],
    ['stale', members],
    ['changed', create],
    ['unchanged', rename],
    ['unavailable', remove],
    ['group-in-use', del],
    ['key-change-required', remove],
    ['account-unavailable', add],
    ['unsupported', list],
  ] as const)
    assert.deepEqual(parseGroupReply({ status }, request), { status });
});
