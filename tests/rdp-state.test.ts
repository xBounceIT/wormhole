import assert from 'node:assert/strict';
import test from 'node:test';
import { applyRdpBackendEvent, applyRdpSystemClientOpenFailure } from '../src/rdp-state.ts';

test('a normalized remote signout closes the RDP session without a failure or stale logon message', () => {
  const connected = {
    rdpStatus: 'connected' as const,
    rdpBackend: 'activex' as const,
    rdpError: 'Previous logon notification.',
  };
  const disconnected = applyRdpBackendEvent(connected, { type: 'disconnected', code: 0 });
  const exited = applyRdpBackendEvent(disconnected, { type: 'exited', code: 0 });

  assert.equal(disconnected.rdpStatus, 'disconnected');
  assert.equal(disconnected.rdpError, undefined);
  assert.equal(exited.rdpStatus, 'disconnected');
  assert.equal(exited.rdpError, undefined);
});

test('a normal helper exit preserves an actual RDP disconnect failure', () => {
  const disconnected = applyRdpBackendEvent(
    { rdpStatus: 'connected' as const },
    { type: 'disconnected', code: 2308, message: 'Socket closed.' },
  );
  const exited = applyRdpBackendEvent(disconnected, { type: 'exited', code: 0 });

  assert.equal(exited.rdpStatus, 'failed');
  assert.equal(exited.rdpError, 'Socket closed.');
});

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

test('system Remote Desktop state is tracked only while its process is active', () => {
  const started = applyRdpBackendEvent(
    { rdpStatus: 'disconnected' as const, rdpExternal: false },
    { type: 'started', backend: 'activex', external: true },
  );
  const connected = applyRdpBackendEvent(started, {
    type: 'connected',
    backend: 'activex',
    external: true,
  });
  const exited = applyRdpBackendEvent(connected, {
    type: 'exited',
    backend: 'activex',
    external: true,
    code: 0,
  });

  assert.equal(started.rdpExternal, true);
  assert.equal(connected.rdpExternal, true);
  assert.equal(exited.rdpExternal, false);
  assert.equal(exited.rdpStatus, 'disconnected');
});

test('system-client preflight failure preserves an accepted embedded lifecycle', () => {
  const connected = {
    rdpStatus: 'connected' as const,
    rdpBackend: 'activex' as const,
    rdpExternal: false,
  };

  const preflightFailure = applyRdpSystemClientOpenFailure(
    connected,
    'System client is unavailable.',
    false,
  );
  const launchFailure = applyRdpSystemClientOpenFailure(
    connected,
    'System client did not start.',
    true,
  );

  assert.equal(preflightFailure.rdpStatus, 'connected');
  assert.equal(preflightFailure.rdpExternal, false);
  assert.equal(launchFailure.rdpStatus, 'failed');
  assert.equal(launchFailure.rdpExternal, false);
});
