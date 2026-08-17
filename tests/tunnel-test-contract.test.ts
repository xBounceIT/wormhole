import assert from 'node:assert/strict';
import test from 'node:test';

import {
  isTunnelIdentifier,
  isTunnelTestHost,
  parseTunnelDetailsResponse,
  parseTunnelSummaryList,
  parseTunnelTestRequest,
} from '../electron/tunnel-test-contract.ts';

const tunnelID = '11111111-2222-3333-4444-555555555555';

test('tunnel test IPC accepts an omitted probe or one complete bounded target', () => {
  assert.deepEqual(parseTunnelTestRequest({ id: tunnelID, attempt: 1 }), {
    id: tunnelID,
    attempt: 1,
  });
  assert.deepEqual(
    parseTunnelTestRequest({
      id: tunnelID,
      attempt: 2,
      targetHost: ' server.internal ',
      targetPort: 443,
    }),
    { id: tunnelID, attempt: 2, targetHost: 'server.internal', targetPort: 443 },
  );
});

test('tunnel test IPC rejects malformed identifiers and partial or mistyped probes', () => {
  assert.equal(isTunnelIdentifier(tunnelID), true);
  assert.equal(isTunnelIdentifier('not-an-id'), false);
  for (const request of [
    { id: 'not-an-id' },
    { id: tunnelID },
    { id: tunnelID, attempt: 0 },
    { id: tunnelID, attempt: 1.5 },
    { id: tunnelID, attempt: 1, targetHost: 42 },
    { id: tunnelID, attempt: 1, targetHost: 'server.internal' },
    { id: tunnelID, attempt: 1, targetPort: 443 },
    { id: tunnelID, attempt: 1, targetHost: 'server.internal', targetPort: 0 },
    { id: tunnelID, attempt: 1, targetHost: 'bad\nhost', targetPort: 443 },
    { id: tunnelID, attempt: 1, targetHost: 'bad\u0080host', targetPort: 443 },
    { id: tunnelID, attempt: 1, targetHost: 'bad host', targetPort: 443 },
    { id: tunnelID, attempt: 1, targetHost: 'server.internal:443', targetPort: 443 },
    { id: tunnelID, attempt: 1, targetHost: '[server.internal]', targetPort: 443 },
  ]) {
    assert.throws(() => parseTunnelTestRequest(request), /invalid/i);
  }
});

test('tunnel test IPC host validation preserves DNS and IPv4/IPv6 targets', () => {
  for (const host of ['server.internal', '127.0.0.1', '2001:db8::1', '[2001:db8::1]']) {
    assert.equal(isTunnelTestHost(host), true, host);
  }
  for (const host of [
    '',
    'bad host',
    'bad\u0080host',
    'server.internal:443',
    '[server.internal]',
    'bad/path',
  ]) {
    assert.equal(isTunnelTestHost(host), false, host);
  }
});

test('tunnel response contracts preserve bounded generic endpoint metadata', () => {
  const details = {
    id: tunnelID,
    name: 'Corporate VPN',
    kind: 2,
    endpoint: '[2001:db8::1]:443',
    settings: { Host: '2001:db8::1', Password: 'secret' },
  };
  assert.deepEqual(parseTunnelDetailsResponse(details), details);
  assert.deepEqual(
    parseTunnelSummaryList([
      { id: tunnelID, name: 'Corporate VPN', kind: 'Fortinet', endpoint: 'vpn.example.test:443' },
      { id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', name: 'Unavailable', kind: 'OpenVPN' },
    ]),
    [
      { id: tunnelID, name: 'Corporate VPN', kind: 'Fortinet', endpoint: 'vpn.example.test:443' },
      {
        id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        name: 'Unavailable',
        kind: 'OpenVPN',
        endpoint: undefined,
      },
    ],
  );
});

test('tunnel response contracts reject malformed or unbounded backend output', () => {
  const validDetails = {
    id: tunnelID,
    name: 'Corporate VPN',
    kind: 2,
    settings: {},
  };
  for (const details of [
    null,
    { ...validDetails, id: 'invalid' },
    { ...validDetails, name: '' },
    { ...validDetails, kind: 7 },
    { ...validDetails, settings: [] },
    { ...validDetails, endpoint: '' },
    { ...validDetails, endpoint: 'vpn.example.test:443\nsecret' },
    { ...validDetails, endpoint: `vpn.${'a'.repeat(513)}:443` },
  ]) {
    assert.throws(() => parseTunnelDetailsResponse(details), /invalid/i);
  }
  for (const summaries of [
    {},
    [{ id: tunnelID, name: 'VPN', kind: 2 }],
    [{ id: tunnelID, name: 'VPN', kind: 'x'.repeat(65) }],
    [{ id: tunnelID, name: 'VPN', kind: 'OpenVPN', endpoint: 'bad\u0080endpoint' }],
  ]) {
    assert.throws(() => parseTunnelSummaryList(summaries), /invalid/i);
  }
});
