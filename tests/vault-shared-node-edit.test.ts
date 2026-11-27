import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseSharedNodeEditRequest,
  parseSharedNodeEditReply,
  sharedEditFields,
} from '../electron/vault-shared-node-edit.ts';

const nodeId = '30d33ae2-1be0-43da-b3af-b40b85e36b13';
const workspaceId = 'eb51370c-f441-4efe-8498-e8b552d05fc4';
const read = { nodeId, revision: '8' };
const write = {
  ...read,
  workspaceId,
  epoch: '1',
  changeSeq: '0',
  changes: { host: null, port: 2200 },
};
const fields = Object.fromEntries(
  Object.keys(sharedEditFields).map((key) => [key, key === 'name' ? 'Office' : null]),
);

test('slot choices bind each page to a writable item, snapshot and exclusive cursor', () => {
  const snapshot = { ...read, workspaceId, epoch: '1', changeSeq: '0' };
  const browse = { ...snapshot, slotAfter: '' };
  const slot = { id: workspaceId, name: 'Office access', protocol: 'rdp', allowSelfService: true };
  const slotPage = { kind: 'slots', entries: [slot], next: { id: slot.id } };
  const reply = { status: 'slot-choices', ...snapshot, slotPage };
  for (const slotAfter of ['', nodeId]) {
    const request = { ...snapshot, slotAfter };
    assert.deepEqual(parseSharedNodeEditRequest(request), request);
    assert.deepEqual(parseSharedNodeEditReply(reply, request), reply);
  }
  const empty = { ...reply, slotPage: { kind: 'slots', entries: [] } };
  assert.deepEqual(parseSharedNodeEditReply(empty, { ...browse, slotAfter: slot.id }), empty);
  assert.equal(parseSharedNodeEditReply(reply, { ...browse, slotAfter: slot.id }), undefined);
  for (const value of [
    { ...write, slotAfter: '' },
    { ...read, slotAfter: '' },
    { ...browse, slotAfter: null },
    { ...browse, slotAfter: { id: nodeId } },
    { ...browse, slotAfter: 'bad' },
    { ...browse, authentication: {} },
  ])
    assert.equal(parseSharedNodeEditRequest(value), undefined);
  for (const value of [
    { ...reply, nodeId: workspaceId },
    { ...reply, revision: '7' },
    { ...reply, workspaceId: nodeId },
    { ...reply, epoch: '2' },
    { ...reply, changeSeq: '1' },
    { ...reply, fields },
    { status: 'authentication-required' },
    { ...reply, status: 'ready' },
    ...[
      { ...slotPage, kind: 'accounts' },
      { ...slotPage, next: { id: nodeId } },
      { ...slotPage, entries: [slot, slot] },
      { ...slotPage, entries: Array(26).fill(slot) },
      { ...slotPage, entries: [{ ...slot, credentialId: nodeId }] },
    ].map((slotPage) => ({ ...reply, slotPage })),
  ])
    assert.equal(parseSharedNodeEditReply(value, browse), undefined);
  for (const request of [read, write])
    assert.equal(parseSharedNodeEditReply(reply, request), undefined);
});

test('catalog edits carry only typed public changes and a complete snapshot', () => {
  assert.deepEqual(parseSharedNodeEditRequest(read), read);
  assert.deepEqual(parseSharedNodeEditRequest(write), write);
  const folder = { id: workspaceId, revision: '4' };
  for (const parent of [null, folder]) {
    const move = { ...write, changes: { parent } };
    assert.deepEqual(parseSharedNodeEditRequest(move), move);
  }
  const valid = {
    ...write,
    changes: {
      name: '🙂'.repeat(256),
      protocol: 0,
      host: '',
      port: 0,
      tunnelEnabled: false,
      credentialId: nodeId,
    },
  };
  assert.deepEqual(parseSharedNodeEditRequest(valid), valid);
  for (const value of [
    null,
    { ...read, epoch: '1' },
    { ...read, revision: '08' },
    { ...write, workspaceId: '' },
    { ...write, revision: '9223372036854775807' },
    { ...write, epoch: '0' },
    { ...write, changeSeq: '-1' },
  ])
    assert.equal(parseSharedNodeEditRequest(value), undefined);
  for (const changes of [
    null,
    {},
    { password: 'test' },
    { name: null },
    { name: '🙂'.repeat(257) },
    { name: 'a\tb' },
    { host: 'one\ntwo' },
    { credentialId: 'invalid' },
    { port: -1 },
    { port: 65536 },
    { protocol: 2 },
    { tunnelEnabled: 0 },
    { parent: null, name: 'Move and rename' },
    { parent: { ...folder, extra: true } },
    { parent: { ...folder, id: nodeId } },
    { parent: { ...folder, id: 'missing' } },
    { parent: { ...folder, revision: '0' } },
    { parent: {} },
  ])
    assert.equal(parseSharedNodeEditRequest({ ...write, changes }), undefined);
});

test('catalog edit replies bind the node, revision and response fields to the request', () => {
  const ready = { ...read, status: 'ready', workspaceId, epoch: '2', changeSeq: '5', fields };
  assert.deepEqual(parseSharedNodeEditReply(ready, read), ready);
  const canMove = { ...ready, canMove: true };
  assert.deepEqual(parseSharedNodeEditReply(canMove, read), canMove);
  const inline = { ...ready, usesInlinePassword: true };
  assert.deepEqual(parseSharedNodeEditReply(inline, read), inline);
  const saved = { ...read, status: 'saved', revision: '9' };
  assert.deepEqual(parseSharedNodeEditReply(saved, write), saved);
  const auth = { status: 'authentication-required' };
  assert.deepEqual(parseSharedNodeEditReply(auth, write), auth);
  assert.deepEqual(parseSharedNodeEditReply({ status: 'unavailable' }, read), {
    status: 'unavailable',
  });
  for (const value of [
    null,
    auth,
    saved,
    { ...ready, nodeId: workspaceId },
    { ...ready, epoch: '0' },
    { ...ready, canMove: false },
    { ...ready, usesInlinePassword: false },
    { ...ready, usesInlinePassword: 'true' },
    { ...ready, changeSeq: '-2' },
    { ...ready, revision: '7' },
    { ...ready, fields: { name: 'partial' } },
    { ...ready, fields: { ...fields, factor: 'test' } },
    { status: 'unavailable', details: 'internal' },
  ])
    assert.equal(parseSharedNodeEditReply(value, read), undefined);
  for (const value of [
    ready,
    { ...saved, revision: '10' },
    { ...saved, nodeId: workspaceId },
    { ...saved, unexpected: true },
    { status: 'authentication-required', factor: 'test' },
  ])
    assert.equal(parseSharedNodeEditReply(value, write), undefined);
});
