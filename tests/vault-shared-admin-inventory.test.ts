import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseAdminInventoryReply,
  parseAdminInventoryRequest,
} from '../electron/vault-shared-admin-inventory.ts';

const id = (n: number) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`;
const at = '2026-11-23T12:00:00.123456Z';

test('administration requests scope cursors to their section and preserve audit microseconds', () => {
  assert.deepEqual(parseAdminInventoryRequest({ kind: 'accounts' }), { kind: 'accounts' });
  assert.deepEqual(parseAdminInventoryRequest({ kind: 'devices', next: { id: id(3) } }), {
    kind: 'devices',
    next: { id: id(3) },
  });
  const request = { kind: 'sessions', next: { id: id(3), at } };
  assert.deepEqual(parseAdminInventoryRequest(request), request);
  for (const bad of [
    null,
    { kind: 'credentials' },
    { kind: 'devices', next: { id: id(3), at } },
    { kind: 'sessions', next: { id: id(3) } },
    { kind: 'audit', next: { id: id(0), at } },
    { kind: 'audit', next: { id: id(3), at: at.replace('11-23', '02-30') } },
    { kind: 'audit', next: { id: id(3), at: at.replace('.123456', '.123') } },
    { kind: 'audit', next: { id: id(3), at }, account: id(1) },
  ])
    assert.equal(parseAdminInventoryRequest(bad), undefined);
});

test('administration replies are bounded to one ordered page with exact fields', () => {
  const account = { id: id(1), login: 'admin', role: 'administrator', status: 'enabled' };
  const device = { id: id(1), login: 'admin', name: 'Desk', status: 'pending', at };
  const session = {
    id: id(1),
    login: 'admin',
    deviceId: id(2),
    appVersion: '2.4.3',
    transport: 'tls',
    at,
  };
  const event = {
    id: id(1),
    login: '',
    actorId: id(2),
    sessionId: id(3),
    action: 'login',
    status: 'success',
    source: 'ui',
    at,
  };
  for (const [kind, record, invalid] of [
    ['accounts', account, { ...account, status: 'deleted' }],
    ['devices', device, { ...device, name: '\rsecret' }],
    ['unencrypted-clients', device, { ...device, clientAddr: '192.0.2.1' }],
    ['sessions', session, { ...session, clientAddr: '192.0.2.1' }],
    ['audit', event, { ...event, sessionRole: 'private-role' }],
  ] as const) {
    const reply = { status: 'ready', page: { kind, entries: [record] } };
    assert.deepEqual(parseAdminInventoryReply(reply, { kind }), reply);
    assert.equal(
      parseAdminInventoryReply({ ...reply, page: { kind, entries: [invalid] } }, { kind }),
      undefined,
    );
    assert.equal(
      parseAdminInventoryReply({ ...reply, page: { kind, entries: [record, record] } }, { kind }),
      undefined,
    );
  }
  const kind = 'audit';
  const entries = Array.from({ length: 25 }, (_, index) => ({ ...event, id: id(30 - index) }));
  const next = { id: id(6), at };
  const reply = { status: 'ready', page: { kind, entries, next } };
  assert.deepEqual(parseAdminInventoryReply(reply, { kind }), reply);
  assert.equal(parseAdminInventoryReply(reply, { kind, next }), undefined);
  assert.equal(
    parseAdminInventoryReply(
      { ...reply, page: { kind, entries, next: { id: id(5), at } } },
      { kind },
    ),
    undefined,
  );
  assert.equal(
    parseAdminInventoryReply({ ...reply, page: { kind, entries: [...entries, event] } }, { kind }),
    undefined,
  );
  assert.deepEqual(parseAdminInventoryReply({ status: 'unavailable' }, { kind }), {
    status: 'unavailable',
  });
  assert.equal(
    parseAdminInventoryReply({ status: 'unavailable', page: reply.page }, { kind }),
    undefined,
  );
});
