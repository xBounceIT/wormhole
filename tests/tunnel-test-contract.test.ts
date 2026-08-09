import assert from 'node:assert/strict';
import test from 'node:test';

import {
  isTunnelIdentifier,
  isTunnelTestHost,
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
