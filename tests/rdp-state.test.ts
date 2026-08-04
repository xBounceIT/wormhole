import assert from 'node:assert/strict';
import test from 'node:test';
import { applyRdpBackendEvent } from '../src/rdp-state.ts';

test('a non-terminal logon notification does not make retry start a duplicate process', () => {
  const next = applyRdpBackendEvent(
    { rdpStatus: 'starting', rdpBackend: 'activex' },
    { type: 'logonError', backend: 'activex', code: -2 },
  );

  assert.equal(next.rdpStatus, 'starting');
  assert.equal(next.rdpBackend, 'activex');
});

test('native ready arriving after connected does not regress the surface to starting', () => {
  const next = applyRdpBackendEvent(
    { rdpStatus: 'connected', rdpBackend: 'activex' },
    { type: 'ready', backend: 'activex' },
  );

  assert.equal(next.rdpStatus, 'connected');
});

test('a terminal disconnect still fails after an earlier logon notification', () => {
  const afterLogon = applyRdpBackendEvent(
    { rdpStatus: 'starting', rdpBackend: 'activex' },
    { type: 'logonError', backend: 'activex', code: 3 },
  );
  const afterDisconnect = applyRdpBackendEvent(afterLogon, {
    type: 'disconnected',
    backend: 'activex',
    code: 3,
    message: 'Credentials were rejected.',
  });

  assert.equal(afterDisconnect.rdpStatus, 'failed');
  assert.equal(afterDisconnect.rdpError, 'Credentials were rejected.');
});
