import assert from 'node:assert/strict';
import test from 'node:test';
import { parseGroupKeyReply, parseGroupKeyRequest } from '../electron/vault-shared-group-key.ts';
import {
  parseMemberRotationReply,
  parseMemberRotationRequest,
} from '../electron/vault-shared-group-member-rotation.ts';

const id = (n: number) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`;
const request = { groupId: id(1), revision: '3' };
const review = '5a'.repeat(32);
const preview = { ...request, review, members: [{ id: id(2), login: 'alice' }] };

test('group key review returns only the exact group and certified roster', () => {
  assert.deepEqual(parseGroupKeyRequest(request), request);
  assert.deepEqual(parseGroupKeyRequest({ ...request, review }), { ...request, review });
  for (const invalid of [
    null,
    { ...request, groupId: id(0) },
    { ...request, revision: '03' },
    { ...request, revision: '9223372036854775807' },
    { ...request, review: review.toUpperCase() },
    { ...request, review: '' },
    { ...request, privateKey: 'unexpected' },
  ])
    assert.equal(parseGroupKeyRequest(invalid), undefined);

  assert.deepEqual(parseGroupKeyReply({ status: 'review', preview }, request), {
    status: 'review',
    preview,
  });
  for (const bad of [
    { ...preview, groupId: id(6) },
    { ...preview, revision: '4' },
    { ...preview, review: '' },
    { ...preview, members: [] },
    {
      ...preview,
      members: Array.from({ length: 65 }, (_, i) => ({ id: id(i + 3), login: 'member' })),
    },
    { ...preview, members: [preview.members[0], preview.members[0]] },
    { ...preview, members: [{ ...preview.members[0], login: 'a\nb' }] },
    { ...preview, members: [{ ...preview.members[0], privateKey: 'unexpected' }] },
    { ...preview, signer: 'unexpected' },
  ])
    assert.equal(parseGroupKeyReply({ status: 'review', preview: bad }, request), undefined);
  assert.equal(
    parseGroupKeyReply({ status: 'review', preview }, { ...request, review }),
    undefined,
  );
  assert.equal(parseGroupKeyReply({ status: 'issued' }, request), undefined);
  assert.deepEqual(parseGroupKeyReply({ status: 'issued' }, { ...request, review }), {
    status: 'issued',
  });
  for (const status of [
    'busy',
    'stale',
    'unavailable',
    'unsupported',
    'no-members',
    'too-large',
    'incomplete',
    'provisioned',
  ])
    assert.deepEqual(parseGroupKeyReply({ status }, request), { status });
});

test('keyed member removal binds the preview and receipt to the requested scope', () => {
  const target = { ...request, memberId: id(2), jobId: id(3) };
  const remove = { action: 'remove', ...target } as const;
  const resume = { action: 'resume', groupId: request.groupId } as const;
  const removePreview = { ...target, boundaries: 2, remaining: [], review };
  assert.deepEqual(parseMemberRotationRequest(remove), remove);
  assert.deepEqual(parseMemberRotationRequest({ ...remove, review }), { ...remove, review });
  assert.deepEqual(parseMemberRotationRequest(resume), resume);
  assert.deepEqual(parseMemberRotationRequest({ ...resume, jobId: target.jobId }), {
    ...resume,
    jobId: target.jobId,
  });
  for (const invalid of [
    null,
    { ...remove, groupId: id(0) },
    { ...remove, jobId: id(0) },
    { ...remove, memberId: id(0) },
    { ...remove, revision: '9223372036854775807' },
    { ...remove, review: '' },
    { ...remove, expected: 0 },
    { ...resume, jobId: null },
    { ...resume, review },
  ])
    assert.equal(parseMemberRotationRequest(invalid), undefined);

  const approved = { status: 'review', preview: removePreview };
  assert.deepEqual(parseMemberRotationReply(approved, remove), approved);
  assert.equal(parseMemberRotationReply(approved, { ...remove, review }), undefined);
  const scoped = { ...remove, suspension: '9223372036854775807' };
  const scopedReply = { ...approved, preview: { ...removePreview, suspension: scoped.suspension } };
  assert.deepEqual(parseMemberRotationRequest(scoped), scoped);
  assert.deepEqual(parseMemberRotationRequest({ ...scoped, review }), { ...scoped, review });
  assert.deepEqual(parseMemberRotationReply(scopedReply, scoped), scopedReply);
  assert.equal(parseMemberRotationReply(scopedReply, remove), undefined);
  assert.equal(parseMemberRotationReply(approved, scoped), undefined);
  assert.equal(parseMemberRotationReply(scopedReply, { ...scoped, suspension: '1' }), undefined);
  for (const suspension of [null, 1, '0', '02', '9223372036854775808']) {
    assert.equal(parseMemberRotationRequest({ ...remove, suspension }), undefined);
  }
  for (const action of ['add', 'resume', 'reconcile']) {
    assert.equal(parseMemberRotationRequest({ ...scoped, action }), undefined);
  }
  for (const preview of [
    { ...removePreview, jobId: id(5) },
    { ...removePreview, memberId: id(5) },
    { ...removePreview, revision: '4' },
    { ...removePreview, groupId: id(5) },
    { ...removePreview, boundaries: 4097 },
    { ...removePreview, remaining: [{ id: target.memberId, login: 'removed-member' }] },
    { ...removePreview, remaining: [{ id: id(5), login: 'custodian', privateKey: 'extra' }] },
  ])
    assert.equal(parseMemberRotationReply({ status: 'review', preview }, remove), undefined);

  const receipt = { jobId: target.jobId, pending: 2 };
  const rotated = { status: 'rotated', receipt };
  assert.deepEqual(parseMemberRotationReply(rotated, { ...remove, review }), rotated);
  assert.equal(parseMemberRotationReply(rotated, resume), undefined);
  assert.deepEqual(parseMemberRotationReply({ status: 'pending', receipt }, resume), {
    status: 'pending',
    receipt,
  });
  assert.equal(
    parseMemberRotationReply({ status: 'pending', receipt }, { ...resume, jobId: id(8) }),
    undefined,
  );
  assert.equal(parseMemberRotationReply({ status: 'complete', receipt }, resume), undefined);
  assert.equal(
    parseMemberRotationReply({ status: 'pending', receipt: { ...receipt, pending: 0 } }, resume),
    undefined,
  );
  assert.deepEqual(parseMemberRotationReply({ status: 'complete' }, resume), {
    status: 'complete',
  });
  assert.equal(
    parseMemberRotationReply({ status: 'complete' }, { ...resume, jobId: target.jobId }),
    undefined,
  );
  assert.deepEqual(parseMemberRotationReply({ status: 'rotation-pending' }, remove), {
    status: 'rotation-pending',
  });
  assert.equal(parseMemberRotationReply({ status: 'busy', context: 'extra' }, remove), undefined);
});

test('keyed member addition accepts only the reviewed certified login and request', () => {
  const add = { action: 'add', ...request, jobId: id(3), login: 'alice' } as const;
  assert.deepEqual(parseMemberRotationRequest(add), add);
  assert.equal(parseMemberRotationRequest({ ...add, memberId: id(2) }), undefined);
  assert.equal(parseMemberRotationRequest({ ...add, login: 'a\nb' }), undefined);
  assert.equal(parseMemberRotationRequest({ ...add, login: 'é'.repeat(129) }), undefined);
  const addition = {
    ...request,
    jobId: add.jobId,
    review,
    boundaries: 2,
    member: { id: id(2), login: add.login },
  };
  const reply = { status: 'review-add', addition };
  assert.deepEqual(parseMemberRotationReply(reply, add), reply);
  assert.equal(parseMemberRotationReply(reply, { ...add, review }), undefined);
  for (const altered of [
    { ...addition, member: { ...addition.member, login: 'another-account' } },
    { ...addition, jobId: id(4) },
    { ...addition, boundaries: -1 },
    { ...addition, revision: '4' },
  ])
    assert.equal(
      parseMemberRotationReply({ status: 'review-add', addition: altered }, add),
      undefined,
    );
  const done = { status: 'added', receipt: { jobId: add.jobId, pending: 0 } };
  assert.deepEqual(parseMemberRotationReply(done, { ...add, review }), done);
  assert.equal(
    parseMemberRotationReply({ ...done, receipt: { ...done.receipt, pending: 1 } }, add),
    undefined,
  );
  assert.equal(
    parseMemberRotationReply(done, { action: 'resume', groupId: add.groupId }),
    undefined,
  );
  assert.deepEqual(parseMemberRotationReply({ status: 'account-unavailable' }, add), {
    status: 'account-unavailable',
  });
});

test('roster reconciliation binds the review and retry to the original pending rotation', () => {
  const request = { action: 'reconcile', groupId: id(1), jobId: id(2) } as const;
  assert.deepEqual(parseMemberRotationRequest({ ...request, review }), { ...request, review });
  assert.equal(parseMemberRotationRequest({ ...request, jobId: id(0) }), undefined);
  assert.equal(parseMemberRotationRequest({ ...request, targetGroupId: id(3) }), undefined);
  const { groupId, jobId } = request;
  const reconciliation = {
    groupId,
    jobId,
    targetGroupId: id(3),
    groupName: 'Related group',
    boundaries: 2,
    members: [],
    review,
  };
  const preview = { status: 'reconcile-review', reconciliation };
  assert.deepEqual(parseMemberRotationReply(preview, request), preview);
  assert.equal(parseMemberRotationReply(preview, { ...request, review }), undefined);
  for (const invalid of [
    { ...reconciliation, jobId: id(6) },
    { ...reconciliation, targetGroupId: id(0) },
    { ...reconciliation, boundaries: 0 },
    { ...reconciliation, groupName: ' another group ' },
    { ...reconciliation, members: [{ id: id(0), login: 'alice' }] },
  ])
    assert.equal(
      parseMemberRotationReply({ status: 'reconcile-review', reconciliation: invalid }, request),
      undefined,
    );
  const completed = { status: 'reconciled' };
  assert.deepEqual(parseMemberRotationReply(completed, { ...request, review }), completed);
  assert.equal(parseMemberRotationReply(completed, request), undefined);
  const receipt = { status: 'roster-changed', receipt: { jobId, pending: 1 } };
  assert.deepEqual(parseMemberRotationReply(receipt, { action: 'resume', groupId }), receipt);
  assert.equal(parseMemberRotationReply(receipt, request), undefined);
  assert.equal(
    parseMemberRotationReply(receipt, { action: 'resume', groupId, jobId: id(6) }),
    undefined,
  );
});
