import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseAccountBoundaryRotationReply,
  parseAccountBoundaryRotationRequest,
  parseAccountSuspensionReply,
  parseAccountSuspensionRequest,
  consumePersonalRootRecoveryFactors,
  parsePersonalRootRecoveryRequest,
  parsePersonalRootRecoveryReply,
} from '../electron/vault-account-suspension.ts';

const accountId = '12345678-1234-4234-8234-123456789abc';
const boundaryId = '82345678-1234-4234-8234-123456789abc';
const id = '92345678-1234-4234-8234-123456789abc';

test('personal key recovery exchanges a scoped review and consumes only fresh factors', () => {
  const request = { accountId, suspension: '11' };
  const review = '6a'.repeat(32);
  const confirmation = { ...request, review };
  const reply = { status: 'review', review, enrollment: id };
  assert.deepEqual(parsePersonalRootRecoveryRequest(request), request);
  assert.deepEqual(parsePersonalRootRecoveryRequest(confirmation), confirmation);
  for (const bad of [
    null,
    { ...request, accountId: 'invalid' },
    { ...request, suspension: '01' },
    { ...confirmation, review: 'ab' },
    { ...request, holder: id },
    { ...request, password: 'unwanted' },
  ]) {
    assert.equal(parsePersonalRootRecoveryRequest(bad), undefined);
  }
  assert.deepEqual(parsePersonalRootRecoveryReply(reply, request), reply);
  assert.equal(
    parsePersonalRootRecoveryReply({ ...reply, enrollment: 'invalid' }, request),
    undefined,
  );
  assert.equal(
    parsePersonalRootRecoveryReply({ ...reply, password: 'unwanted' }, request),
    undefined,
  );
  assert.equal(parsePersonalRootRecoveryReply(reply, confirmation), undefined);
  for (const status of ['changed', 'invalid-authentication']) {
    assert.equal(parsePersonalRootRecoveryReply({ status }, request), undefined);
    assert.deepEqual(parsePersonalRootRecoveryReply({ status }, confirmation), { status });
  }
  for (const status of [
    'busy',
    'stale',
    'unsupported',
    'unavailable',
    'rotation-required',
    'enrollment-required',
    'unchanged',
  ]) {
    assert.deepEqual(parsePersonalRootRecoveryReply({ status }, request), { status });
    assert.equal(parsePersonalRootRecoveryReply({ status, enrollment: id }, request), undefined);
  }
  assert.equal(parsePersonalRootRecoveryReply(null, request), undefined);
  assert.equal(parsePersonalRootRecoveryReply({ status: 'unexpected' }, request), undefined);

  const password = new Uint8Array([1, 2, 3]);
  const ask = new Uint8Array(32).fill(5);
  const owned = consumePersonalRootRecoveryFactors({ password, ask });
  assert.deepEqual(owned.password, new Uint8Array([1, 2, 3]));
  assert.deepEqual(owned.ask, new Uint8Array(32).fill(5));
  assert.ok(password.every((x) => x === 0) && ask.every((x) => x === 0));
  assert.deepEqual(consumePersonalRootRecoveryFactors({ password: new Uint8Array([1]) }), {
    password: new Uint8Array([1]),
  });
  for (const invalid of [
    null,
    { password: new Uint8Array() },
    { password: 'plaintext' },
    { password: new Uint8Array(1025).fill(1) },
    { password: new Uint8Array([1]), ask: new Uint8Array(31).fill(1) },
    { password: new Uint8Array([1]), slotId: id },
  ]) {
    assert.throws(() => consumePersonalRootRecoveryFactors(invalid), /authentication/i);
    if (invalid?.password instanceof Uint8Array) assert.ok(invalid.password.every((x) => x === 0));
    if (invalid?.ask instanceof Uint8Array) assert.ok(invalid.ask.every((x) => x === 0));
  }
});

test('manual boundary rotation binds review to a precise captured key version', () => {
  const request = {
    accountId,
    boundaryId,
    rootId: id,
    purpose: 'secret',
    suspension: '1',
    rootVersion: '2',
  } as const;
  const review = '6a'.repeat(32);
  assert.deepEqual(parseAccountBoundaryRotationRequest(request), request);
  const confirm = { ...request, review };
  assert.deepEqual(parseAccountBoundaryRotationRequest(confirm), confirm);
  for (const invalid of [
    null,
    { ...request, purpose: 'write' },
    { ...request, suspension: '01' },
    { ...request, boundaryId: 'invalid' },
    { ...request, rootId: 'invalid' },
    { ...request, accountId: 'invalid' },
    { ...request, rootVersion: '0' },
    { ...request, rootVersion: 2 },
    { ...request, rootVersion: '2147483647' },
    { ...request, review: review.toUpperCase() },
    { ...request, review: null },
    { ...request, keyMaterial: 'unwanted' },
  ])
    assert.equal(parseAccountBoundaryRotationRequest(invalid), undefined);
  assert.deepEqual(parseAccountBoundaryRotationReply({ status: 'review', review }, request), {
    status: 'review',
    review,
  });
  assert.equal(parseAccountBoundaryRotationReply({ status: 'review', review }, confirm), undefined);
  assert.equal(
    parseAccountBoundaryRotationReply({ status: 'review', review: 'invalid' }, request),
    undefined,
  );
  assert.deepEqual(parseAccountBoundaryRotationReply({ status: 'changed' }, confirm), {
    status: 'changed',
  });
  assert.equal(parseAccountBoundaryRotationReply({ status: 'changed' }, request), undefined);
  for (const status of [
    'unchanged',
    'busy',
    'stale',
    'group-rotation-required',
    'unavailable',
    'unsupported',
  ]) {
    assert.deepEqual(parseAccountBoundaryRotationReply({ status }, request), { status });
    assert.equal(parseAccountBoundaryRotationReply({ status, review }, request), undefined);
  }
  assert.equal(parseAccountBoundaryRotationReply(null, request), undefined);
  assert.equal(parseAccountBoundaryRotationReply({ status: 'bogus' }, request), undefined);
});

test('suspension inventory pins its account, category, revision and contiguous cursor', () => {
  const request = { accountId, kind: 'roots' } as const;
  const next = { ...request, revision: '49', after: '25' };
  assert.deepEqual(parseAccountSuspensionRequest(request), request);
  assert.deepEqual(parseAccountSuspensionRequest(next), next);
  for (const input of [
    null,
    { ...request, accountId: 'not-an-account' },
    { ...request, kind: 'web' },
    { ...request, revision: '49' },
    { ...next, after: '025' },
    { ...next, after: '9223372036854775808' },
    { ...next, otherAccount: id },
  ])
    assert.equal(parseAccountSuspensionRequest(input), undefined);
  const root = {
    position: '1',
    boundaryId,
    kind: 'secret',
    id,
    revision: '3',
    direct: false,
    groupCount: '2',
    status: 'retired',
  };
  const entries = [root, ...Array.from({ length: 24 }, (_, i) => ({ position: String(i + 2) }))];
  const page = { ...request, revision: next.revision, after: '25', entries };
  const ready = { status: 'ready', page };
  assert.deepEqual(parseAccountSuspensionReply(ready, request), ready);
  const personal = {
    status: 'ready',
    page: { ...request, revision: '49', entries: [{ ...root, personal: true }] },
  };
  assert.deepEqual(parseAccountSuspensionReply(personal, request), personal);
  const second = {
    status: 'ready',
    page: { ...request, revision: '49', entries: [{ position: '26' }] },
  };
  assert.deepEqual(parseAccountSuspensionReply(second, next), second);
  assert.equal(parseAccountSuspensionReply(second, request), undefined);
  assert.equal(parseAccountSuspensionReply(ready, next), undefined);
  for (const override of [
    { after: '24' },
    { accountId: id },
    { revision: null },
    { kind: 'passwords' },
    { entries: entries.slice(0, 24) },
    { entries: [...entries, { position: '26' }] },
    { entries: {} },
    { csrf: 'unexpected' },
  ])
    assert.equal(
      parseAccountSuspensionReply({ ...ready, page: { ...page, ...override } }, request),
      undefined,
    );
  for (const entry of [
    undefined,
    { position: '1', name: 'restricted name' },
    { position: '1', personal: true },
    { ...root, boundaryId: 'bad' },
    { ...root, position: '01' },
    { ...root, kind: 'root' },
    { ...root, revision: '0' },
    { ...root, groupCount: '2147483648' },
    { ...root, groupCount: '0' },
    { ...root, direct: 'no' },
    { ...root, status: 'deleted' },
    { ...root, ciphertext: 'unexpected' },
    { ...root, personal: false },
    { ...root, personal: 'true' },
  ])
    assert.equal(
      parseAccountSuspensionReply(
        { status: 'ready', page: { ...request, revision: '49', entries: [entry] } },
        request,
      ),
      undefined,
    );
});

test('password inventory exposes only a metadata reference and reports unavailable scopes without data', () => {
  const request = { accountId, kind: 'passwords' } as const;
  const secret = { position: '1', boundaryId, kind: 'credential', id };
  const payload = (entry: unknown) => ({
    status: 'ready',
    page: { ...request, revision: '1', entries: [entry] },
  });
  assert.deepEqual(parseAccountSuspensionReply(payload(secret), request), payload(secret));
  const named = { ...secret, name: 'Database credentials' };
  assert.deepEqual(parseAccountSuspensionReply(payload(named), request), payload(named));
  for (const field of [
    { kind: 'root' },
    { name: '\x00' },
    { name: '🦉'.repeat(1025) },
    { name: 'a'.repeat(4097) },
    { name: false },
    { personal: true },
    { password: 'unexpected' },
  ])
    assert.equal(parseAccountSuspensionReply(payload({ ...secret, ...field }), request), undefined);
  for (const status of ['busy', 'stale', 'unavailable', 'not-recorded', 'unsupported']) {
    assert.deepEqual(parseAccountSuspensionReply({ status }, request), { status });
    assert.equal(parseAccountSuspensionReply({ status, page: {} }, request), undefined);
  }
  assert.equal(parseAccountSuspensionReply(null, request), undefined);
});

test('suspension groups disclose an exact job only for a queued rotation', () => {
  const request = { accountId, kind: 'groups' } as const;
  const group = { position: '1', id: boundaryId, kind: 'group', name: 'Operations', revision: '9' };
  const response = (entry: unknown) => ({
    status: 'ready',
    page: { ...request, revision: '20', entries: [entry, { position: '2' }] },
  });
  assert.deepEqual(parseAccountSuspensionRequest(request), request);
  for (const status of ['needs-removal', 'waiting', 'resolved']) {
    const ready = response({ ...group, status });
    assert.deepEqual(parseAccountSuspensionReply(ready, request), ready);
    assert.equal(
      parseAccountSuspensionReply(response({ ...group, status, jobId: id }), request),
      undefined,
    );
  }
  const queued = { ...group, status: 'queued', jobId: id };
  assert.deepEqual(parseAccountSuspensionReply(response(queued), request), response(queued));
  for (const entry of [
    { ...queued, jobId: null },
    { ...queued, jobId: 'bad' },
    { ...queued, name: '' },
    { ...queued, name: '🦉'.repeat(257) },
    { ...queued, name: 'Group\u0000' },
    { ...queued, revision: '01' },
    { ...queued, boundaryId },
    { position: '1', jobId: id },
  ]) {
    assert.equal(parseAccountSuspensionReply(response(entry), request), undefined);
  }
});

test('web exposure inventory accepts only scoped connection references and restricted positions', () => {
  const request = { accountId, kind: 'web-sessions' } as const;
  assert.deepEqual(parseAccountSuspensionRequest(request), request);
  const entry = { position: '1', boundaryId, kind: 'web-target', id, name: 'Company portal' };
  const response = (item: unknown) => ({
    status: 'ready',
    page: { ...request, revision: '41', entries: [item, { position: '2' }] },
  });
  assert.deepEqual(parseAccountSuspensionReply(response(entry), request), response(entry));
  for (const item of [
    { ...entry, kind: 'node' },
    { ...entry, name: '' },
    { ...entry, name: '\u0000' },
    { ...entry, name: '🦉'.repeat(1025) },
    { ...entry, host: 'unexpected' },
    { ...entry, deviceId: id },
    { ...entry, archive: 'unexpected' },
    { position: '1', name: 'Restricted target' },
  ])
    assert.equal(parseAccountSuspensionReply(response(item), request), undefined);
  assert.equal(
    parseAccountSuspensionReply(response(entry), { ...request, kind: 'passwords' }),
    undefined,
  );
});
