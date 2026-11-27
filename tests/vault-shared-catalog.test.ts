import {
  parseSharedConnectionContext,
  parseSharedConnectionContextRequest,
} from '../electron/vault-shared-connection.ts';
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseSharedCatalogPage,
  parseSharedCatalogRequest,
  parseSharedChanges,
  parseSharedChangesRequest,
} from '../electron/vault-shared-catalog.ts';

const id = '11111111-1111-4111-8111-111111111111';

test('shared change hints reject rollback, mixed resets and noncanonical identifiers', () => {
  const request = { epoch: '1', changeSeq: '7' };
  const change = {
    epoch: '1',
    changeSeq: '8',
    reset: false,
    nodes: ['11111111-1111-4111-8111-111111111111'],
  };
  assert.deepEqual(parseSharedChangesRequest(request), request);
  assert.deepEqual(parseSharedChanges(change, request), change);
  assert.ok(parseSharedChanges({ ...change, epoch: '2', reset: true, nodes: [] }, request));
  assert.ok(parseSharedChanges({ ...change, nodes: [] }, request));
  for (const bad of [
    null,
    {},
    { ...request, extra: 1 },
    { epoch: '0', changeSeq: '1' },
    { epoch: '01', changeSeq: '0' },
    { epoch: '1', changeSeq: -1 },
  ])
    assert.equal(parseSharedChangesRequest(bad), undefined);
  for (const bad of [
    null,
    {},
    { ...change, extra: 1 },
    { ...change, epoch: '0' },
    { ...change, epoch: '2' },
    { ...change, epoch: '1', changeSeq: '6' },
    { ...change, changeSeq: '7' },
    { ...change, reset: true },
    { ...change, reset: 1 },
    { ...change, nodes: null },
    { ...change, nodes: Array(33).fill(id) },
    { ...change, nodes: [id, id] },
    { ...change, nodes: ['bad'] },
  ])
    assert.equal(parseSharedChanges(bad, request), undefined);
  assert.equal(parseSharedChanges(change, { epoch: '0', changeSeq: '1' }), undefined);
  assert.equal(parseSharedChanges(change, { epoch: '2', changeSeq: '7' }), undefined);
});
const second = '22222222-2222-4222-8222-222222222222';
const request = { after: '', epoch: '0', changeSeq: '0', limit: 1 };
const node = {
  id,
  parentId: null,
  name: 'server',
  kind: 1,
  sortOrder: '-9223372036854775808',
  protocol: 0,
  host: '',
  port: 0,
  username: null,
  canUse: false,
};
const page = () => ({
  epoch: '9223372036854775807',
  changeSeq: '0',
  nodes: [{ ...node }],
  next: null,
});

test('shared catalog requests reject ambiguous and out of range cursors', () => {
  assert.deepEqual(parseSharedCatalogRequest(request), request);
  assert.ok(parseSharedCatalogRequest({ after: id, epoch: '1', changeSeq: '0', limit: 32 }));
  for (const value of [
    null,
    [],
    {},
    { ...request, extra: 1 },
    ...[
      { after: null },
      { after: 'bad' },
      { after: id },
      { epoch: '1' },
      { epoch: '-1' },
      { epoch: '00' },
      { changeSeq: '1' },
      { changeSeq: '9223372036854775808' },
      { changeSeq: 0 },
      { limit: 0 },
      { limit: 33 },
      { limit: 1.5 },
      { limit: '1' },
    ].map((delta) => ({ ...request, ...delta })),
  ])
    assert.equal(parseSharedCatalogRequest(value), undefined);
});

test('shared metadata projection preserves int64 precision and rejects private fields', () => {
  assert.deepEqual(parseSharedCatalogPage(page(), request), page());
  assert.equal(
    parseSharedCatalogPage({ ...page(), nodes: [{ ...node, editRevision: '7' }] }, request)
      ?.nodes[0].editRevision,
    '7',
  );
  assert.equal(
    parseSharedCatalogPage({ ...page(), nodes: [{ ...node, editRevision: '0' }] }, request),
    undefined,
  );
  assert.equal(
    parseSharedCatalogPage({ ...page(), nodes: [{ ...node, canUse: true }] }, request)?.nodes[0]
      .canUse,
    true,
  );
  const nullable = { ...node, protocol: null, host: null, port: null, username: '' };
  assert.ok(parseSharedCatalogPage({ ...page(), nodes: [nullable] }, request));
  const withNotes = { ...page(), nodes: [{ ...node, notesRevision: '9223372036854775807' }] };
  assert.deepEqual(parseSharedCatalogPage(withNotes, request), withNotes);
  for (const delta of [
    { credentialId: id },
    { password: 'secret' },
    { rowVersion: '1' },
    { notesRevision: '0' },
    { notesRevision: '01' },
    { notesRevision: null },
    { notesRevision: '9223372036854775808' },
    { notes: 'private note' },
    { id: 'bad' },
    { parentId: id },
    { parentId: 'bad' },
    { name: '' },
    { name: '\ud800' },
    { name: 'x'.repeat(257) },
    { name: 'a\nb' },
    { kind: 2 },
    { canUse: 1 },
    { canUse: null },
    { kind: 0, canUse: true },
    { sortOrder: '01' },
    { sortOrder: '9223372036854775808' },
    { protocol: 2 },
    { protocol: '0' },
    { host: 'a\nb' },
    { host: 'a'.repeat(16385) },
    { port: -1 },
    { port: 65536 },
    { port: 1.5 },
    { port: '0' },
    { username: 'a\rb' },
    { username: 'a'.repeat(2049) },
  ])
    assert.equal(
      parseSharedCatalogPage({ ...page(), nodes: [{ ...node, ...delta }] }, request),
      undefined,
    );
});

test('shared pages bind pagination to one snapshot and strictly increasing identities', () => {
  const p = page();
  const next = { after: id, epoch: p.epoch, changeSeq: p.changeSeq };
  assert.deepEqual(parseSharedCatalogPage({ ...p, next }, request)?.next, next);
  assert.ok(
    parseSharedCatalogPage({ ...p, nodes: [{ ...node, id: second }] }, { ...next, limit: 1 }),
  );
  assert.equal(parseSharedCatalogPage(p, { ...next, limit: 1 }), undefined);
  for (const value of [
    null,
    [],
    { ...p, extra: 1 },
    { ...p, epoch: '0' },
    { ...p, changeSeq: '-1' },
    { ...p, nodes: null },
    { ...p, nodes: [node, node] },
    { ...p, nodes: [], next },
    { ...p, next: {} },
    { ...p, next: { ...next, extra: 1 } },
    { ...p, next: { ...next, after: second } },
    { ...p, next: { ...next, epoch: '1' } },
    { ...p, next: { ...next, changeSeq: '1' } },
  ])
    assert.equal(parseSharedCatalogPage(value, request), undefined);
  assert.equal(parseSharedCatalogPage(p, { ...request, limit: 0 }), undefined);
  assert.equal(
    parseSharedCatalogPage({ ...p, epoch: '1', nodes: [] }, { ...next, limit: 1 }),
    undefined,
  );
  assert.equal(
    parseSharedCatalogPage({ ...p, nodes: [node, node] }, { ...request, limit: 2 }),
    undefined,
  );
  assert.deepEqual(parseSharedCatalogPage({ ...p, nodes: [] }, request)?.nodes, []);
});

test('shared connection context accepts only bound public native protocol metadata', () => {
  const request = { nodeId: id };
  assert.deepEqual(parseSharedConnectionContextRequest(request), request);
  for (const protocol of [0, 1, 3, 4, 5, 6, 7])
    assert.deepEqual(parseSharedConnectionContext({ ...request, protocol }, request), {
      ...request,
      protocol,
    });
  for (const value of [null, [], {}, { nodeId: 'bad' }, { ...request, host: 'secret' }])
    assert.equal(parseSharedConnectionContextRequest(value), undefined);
  for (const value of [
    null,
    [],
    {},
    { ...request, protocol: 2 },
    { ...request, protocol: '0' },
    { ...request, protocol: null },
    { ...request, protocol: NaN },
    { ...request, protocol: 0, nodeId: second },
    { ...request, protocol: 0, password: 'private' },
  ])
    assert.equal(parseSharedConnectionContext(value, request), undefined);
});
