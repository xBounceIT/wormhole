import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseGroupBoundaryGrantReply,
  parseGroupBoundaryGrantRequest,
} from '../electron/vault-shared-group-boundary-grant.ts';
import {
  parseNodeGrantReply,
  parseNodeGrantRequest,
  type NodeGrantRequest,
} from '../electron/vault-shared-node-grants.ts';

const id = (n: number) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`;
const target = { nodeId: id(50), nodeRevision: '1', kind: 'group' } as const;
const snapshot = { epoch: '1', changeSeq: '4' };
const add = { ...target, ...snapshot, subjectId: id(2), grantRevision: '0', mask: 31 };
const revoke = { ...add, grantRevision: '2', mask: 0 };

test('node grant changes require a target and complete reviewed version tuple', () => {
  for (const value of [
    target,
    { ...target, ...snapshot, after: id(5) },
    add,
    revoke,
    { ...target, ...snapshot, kind: 'account', login: 'exact-Login', grantRevision: '0', mask: 1 },
  ])
    assert.deepEqual(parseNodeGrantRequest(value), value);
  for (const value of [
    null,
    { ...target, nodeId: id(0) },
    { ...target, nodeRevision: '00' },
    { ...target, kind: 'admin' },
    { ...target, ...snapshot },
    { ...target, after: id(1) },
    { ...target, ...snapshot, changeSeq: '-1', after: id(9) },
    { ...add, mask: 0 },
    { ...add, mask: 32 },
    { ...add, mask: 2.1 },
    { ...add, after: id(9) },
    { ...add, grantRevision: '-1' },
    { ...add, login: 'ignored' },
    { ...add, epoch: '0' },
    { ...target, ...snapshot, login: 'unknown', grantRevision: '0', mask: 1 },
    { ...target, ...snapshot, kind: 'account', login: 'a\nb', grantRevision: '0', mask: 1 },
    { ...target, ...snapshot, kind: 'account', login: 'a', grantRevision: '2', mask: 1 },
  ])
    assert.equal(parseNodeGrantRequest(value), undefined);
});

test('node grant pages cannot change snapshot or return another action’s receipt', () => {
  const grants = Array.from({ length: 25 }, (_, i) => ({
    subjectId: id(i + 2),
    revision: '1',
    label: 'Group',
    mask: 31,
  }));
  const good = { status: 'ready', page: { ...snapshot, grants, after: id(26) } };
  assert.deepEqual(parseNodeGrantReply(good, target), good);
  assert.deepEqual(parseNodeGrantReply(good, { ...target, ...snapshot, after: id(1) }), good);
  for (const [value, request] of [
    [good, add],
    [good, { ...target, ...snapshot, after: id(2) }],
    [good, { ...target, ...snapshot, changeSeq: '8', after: id(1) }],
    [{ ...good, page: { ...good.page, grants: [...grants, grants[0]] } }, target],
    [{ ...good, page: { ...good.page, after: id(27) } }, target],
    [{ ...good, page: { ...good.page, grants: [{ ...grants[0], mask: 0 }] } }, target],
    [
      { ...good, page: { ...good.page, grants: [{ ...grants[0], signature: 'unexpected' }] } },
      target,
    ],
    [{ status: 'changed' }, target],
    [{ status: 'signed-grant' }, target],
    [{ status: 'stale', page: {} }, target],
  ] as [unknown, NodeGrantRequest][])
    assert.equal(parseNodeGrantReply(value, request), undefined);
  for (const status of [
    'changed',
    'unchanged',
    'stale',
    'busy',
    'unavailable',
    'signed-grant',
    'cannot-delegate',
    'subject-unavailable',
    'unsupported',
  ])
    assert.deepEqual(parseNodeGrantReply({ status }, revoke), { status });
});
test('boundary key review binds scopes, revisions, permissions and certified members', () => {
  const request = parseGroupBoundaryGrantRequest({
    nodeId: id(1),
    nodeRevision: '7',
    boundaryId: id(2),
    groupId: id(3),
    groupRevision: '4',
    mask: 3,
  });
  assert.ok(request);
  const review = 'a5'.repeat(32);
  const preview = {
    ...request,
    review,
    previousMask: 1,
    members: [{ id: id(4), login: 'operator' }],
  };
  const response = { status: 'review', preview };
  assert.deepEqual(parseGroupBoundaryGrantReply(response, request), response);
  assert.equal(parseGroupBoundaryGrantReply(response, { ...request, review }), undefined);
  for (const change of [
    { nodeId: id(5) },
    { boundaryId: id(5) },
    { groupRevision: '5' },
    { previousMask: 3 },
    { members: [{ id: id(4), login: 'wrong\nmember' }] },
    { members: [] },
    { ciphertext: 'synthetic' },
  ]) {
    assert.equal(
      parseGroupBoundaryGrantReply({ ...response, preview: { ...preview, ...change } }, request),
      undefined,
    );
  }
  assert.equal(parseGroupBoundaryGrantReply({ status: 'changed' }, request), undefined);
  assert.deepEqual(parseGroupBoundaryGrantReply({ status: 'changed' }, { ...request, review }), {
    status: 'changed',
  });
  for (const change of [
    { mask: 0 },
    { mask: 4 },
    { groupRevision: '04' },
    { review: null },
    { ciphertext: 'synthetic' },
  ]) {
    assert.equal(parseGroupBoundaryGrantRequest({ ...request, ...change }), undefined);
  }
});

test('rotation review requires a strict permission reduction and its own confirmation', () => {
  const request = parseGroupBoundaryGrantRequest(
    {
      nodeId: id(1),
      nodeRevision: '7',
      boundaryId: id(2),
      groupId: id(3),
      groupRevision: '4',
      mask: 0,
    },
    true,
  );
  assert.ok(request);
  assert.equal(parseGroupBoundaryGrantRequest(request), undefined);
  assert.equal(parseGroupBoundaryGrantRequest({ ...request, mask: 3 }, true), undefined);
  const review = 'ab'.repeat(32);
  const preview = { ...request, review, previousMask: 1 };
  assert.deepEqual(parseGroupBoundaryGrantReply({ status: 'review', preview }, request, true), {
    status: 'review',
    preview: { ...preview, members: [] },
  });
  assert.equal(parseGroupBoundaryGrantReply({ status: 'review', preview }, request), undefined);
  for (const invalid of [
    { ...preview, previousMask: 0 },
    { ...preview, members: [] },
  ]) {
    assert.equal(
      parseGroupBoundaryGrantReply({ status: 'review', preview: invalid }, request, true),
      undefined,
    );
  }
  assert.deepEqual(
    parseGroupBoundaryGrantReply({ status: 'changed' }, { ...request, review }, true),
    { status: 'changed' },
  );
});
