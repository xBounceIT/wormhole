import assert from 'node:assert/strict';
import test from 'node:test';
import {
  confirmedSlotDefault,
  parseSlotDefaultReply,
  parseSlotDefaultRequest,
} from '../electron/vault-shared-slot-default.ts';

const slotId = '11111111-1111-4111-8111-111111111111';
const workspaceId = '22222222-2222-4222-8222-222222222222';
const credentialId = '33333333-3333-4333-8333-333333333333';
const request = { slotId, credentialName: 'Contabilità RDP' };
const choice = {
  ...request,
  slotName: 'Finance',
  protocol: 'rdp' as const,
  slotRevision: '7',
  credentialRevision: '2',
  credentialId,
  hasDefault: false,
};
const review = {
  status: 'review' as const,
  workspaceId,
  choice,
  authenticationRequired: true as const,
};

test('shared default confirmation binds the selected signed revisions and workspace', () => {
  for (const assign of [true, false]) {
    const candidate = assign
      ? review
      : {
          ...review,
          choice: {
            ...choice,
            credentialName: '',
            credentialId: '',
            credentialRevision: '',
            hasDefault: true,
          },
        };
    const preview = { slotId, credentialName: candidate.choice.credentialName };
    assert.deepEqual(parseSlotDefaultRequest(preview), preview);
    assert.deepEqual(parseSlotDefaultReply(candidate, preview), candidate);
    const commit = confirmedSlotDefault(candidate);
    assert.deepEqual(parseSlotDefaultRequest(commit), commit);
    assert.deepEqual(commit.confirmation, {
      workspaceId,
      slotRevision: '7',
      credentialId: assign ? credentialId : '',
      credentialRevision: assign ? '2' : '',
    });
    for (const status of ['saved', 'authentication-required']) {
      assert.equal(parseSlotDefaultReply({ status }, preview), undefined);
      assert.deepEqual(parseSlotDefaultReply({ status }, commit), { status });
    }
    assert.equal(parseSlotDefaultReply(candidate, commit), undefined);
  }
  for (const status of ['unchanged', 'unavailable', 'busy', 'stale', 'unsupported']) {
    assert.deepEqual(parseSlotDefaultReply({ status }, request), { status });
  }
  const imported = { ...review, choice: { ...choice, slotName: 'Finance\nRemote' } };
  assert.deepEqual(parseSlotDefaultReply(imported, request), imported);
  assert.deepEqual(parseSlotDefaultReply({ status: 'review', workspaceId, choice }, request), {
    status: 'review',
    workspaceId,
    choice,
  });
});

test('shared default parser rejects invalid scopes, private fields and excessive data', () => {
  const confirmed = confirmedSlotDefault(review);
  for (const invalid of [
    null,
    {},
    { ...request, slotId: 'slot' },
    { ...request, other: 1 },
    { ...request, credentialName: 'é'.repeat(513) },
    { ...request, credentialName: '\u0000' },
    { ...request, credentialName: '\ud800' },
    { ...confirmed, credentialName: '' },
    { ...confirmed, confirmation: null },
    ...[
      { workspaceId: '' },
      { slotRevision: '0' },
      { slotRevision: '9223372036854775807' },
      { credentialId: '' },
      { credentialRevision: '-1' },
      { secret: 'hidden' },
    ].map((fields) => ({ ...confirmed, confirmation: { ...confirmed.confirmation, ...fields } })),
  ]) {
    assert.equal(parseSlotDefaultRequest(invalid), undefined);
  }
  assert.ok(parseSlotDefaultRequest({ ...request, credentialName: 'é'.repeat(512) }));
  for (const invalid of [
    null,
    {},
    { status: 'unexpected' },
    { status: 'busy', data: '' },
    { ...review, workspaceId: 'bad' },
    { ...review, authenticationRequired: false },
    { ...review, other: true },
    { ...review, choice: null },
    ...[
      { slotId: workspaceId },
      { slotName: ' ' },
      { slotRevision: '9223372036854775807' },
      { credentialName: 'other' },
      { credentialId: '' },
      { credentialRevision: '' },
      { protocol: 'https' },
      { hasDefault: 1 },
      { password: 'hidden' },
    ].map((fields) => ({ ...review, choice: { ...choice, ...fields } })),
  ]) {
    assert.equal(parseSlotDefaultReply(invalid, request), undefined);
  }
});
