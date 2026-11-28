import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import {
  parseSealedRdpOpen,
  parseSealedRdpBounds,
  parseSealedRdpControl,
  parseSealedRdpEvent,
} from '../electron/sealed-rdp-contract.ts';

const bounds = () => ({ x: -100, y: 20, width: 800, height: 600 });
const opening = () => ({
  sessionId: randomUUID(),
  nodeId: randomUUID(),
  ownerWindow: '123',
  bounds: bounds(),
});

test('sealed RDP opening accepts only node authority and public surface coordinates', () => {
  const q = opening();
  assert.deepEqual(parseSealedRdpOpen(q), q);
  assert.deepEqual(parseSealedRdpOpen({ ...q, requireContentProtection: true }), {
    ...q,
    requireContentProtection: true,
  });
  for (const requireContentProtection of [false, null, 1, 'true'])
    assert.equal(parseSealedRdpOpen({ ...q, requireContentProtection }), undefined);
  for (const visible of [true, false])
    assert.equal(parseSealedRdpOpen({ ...q, visible })?.visible, visible);
  for (const visible of [null, 0, 'false'])
    assert.equal(parseSealedRdpOpen({ ...q, visible }), undefined);
  assert.deepEqual(parseSealedRdpOpen({ ...q, credentialId: randomUUID() })?.bounds, q.bounds);
  assert.ok(parseSealedRdpOpen({ ...q, ownerWindow: '' })); // native Windows admission additionally requires HWND
  for (const patch of [
    { password: 'secret' },
    { profile: {} },
    { sessionId: '' },
    { nodeId: '' },
    { credentialId: '' },
    { ownerWindow: 123 },
    { ownerWindow: '0' },
    { ownerWindow: '01' },
    { ownerWindow: '-1' },
    { ownerWindow: '18446744073709551616' },
    { ownerWindow: '1'.repeat(21) },
    { bounds: null },
  ])
    assert.equal(parseSealedRdpOpen({ ...q, ...patch }), undefined, JSON.stringify(patch));
  for (const value of [null, [], {}, 1]) assert.equal(parseSealedRdpOpen(value), undefined);
  const clone = parseSealedRdpOpen(q)!;
  clone.bounds.width = 1;
  assert.equal(q.bounds.width, 800);
  for (const patch of [
    { x: 1.1 },
    { y: NaN },
    { width: 0 },
    { height: 16385 },
    { x: -1000001 },
    { y: 1000001 },
    { width: Infinity },
    { extra: true },
  ])
    assert.equal(parseSealedRdpBounds({ ...bounds(), ...patch }), undefined);
  assert.equal(parseSealedRdpBounds(null), undefined);
});

test('sealed RDP controls use exact payloads and never permit connection or credential changes', () => {
  const commands = [
    { op: 'resize', bounds: bounds() },
    { op: 'show', bounds: bounds() },
    { op: 'hide' },
    { op: 'focus' },
    { op: 'certificate', certificateAccepted: false },
    ...[
      { kind: 'release' },
      { kind: 'painted', code: 1 },
      { kind: 'key', code: 30, down: true },
      { kind: 'unicode', code: 128, down: false },
      { kind: 'pointer', x: 1, y: 3, flags: 0x0800 },
    ].map((input) => ({ op: 'input', input })),
  ];
  for (const q of commands) {
    assert.deepEqual(parseSealedRdpControl(q), q);
    assert.equal(parseSealedRdpControl({ ...q, password: 'secret' }), undefined);
    if ('input' in q)
      assert.equal(
        parseSealedRdpControl({ ...q, input: { ...q.input, password: 'secret' } }),
        undefined,
      );
  }
  for (const value of [
    null,
    {},
    { op: 'start' },
    { op: 'connect' },
    { op: 'show' },
    { op: 'resize', bounds: {} },
    { op: 'input', input: null },
    { op: 'input', input: { kind: 'key', code: 0, down: false } },
    { op: 'certificate', certificateAccepted: 1 },
  ])
    assert.equal(parseSealedRdpControl(value), undefined);
});

test('sealed RDP event parser rejects capabilities, cross-session output and malformed framebuffer events', () => {
  const id = randomUUID(),
    base = { sessionId: id, lifecycleId: id, external: false, backend: 'activex' };
  for (const type of [
    'started',
    'ready',
    'connected',
    'loginComplete',
    'disconnected',
    'fatalError',
    'logonError',
    'autoReconnecting',
    'autoReconnected',
    'exited',
    'ack',
    'error',
  ]) {
    assert.deepEqual(parseSealedRdpEvent({ ...base, type }, id), { ...base, type });
  }
  const status = {
    ...base,
    type: 'logonError',
    code: -1,
    attempt: 2,
    max: 10,
    credentialFailure: true,
    message: 'private provider diagnostic',
  };
  assert.equal(parseSealedRdpEvent(status, id)?.message, 'RDP authentication failed');
  for (const type of ['error', 'fatalError', 'ready'])
    assert.equal(
      parseSealedRdpEvent({ ...base, type, message: 'private' }, id)?.message,
      type === 'ready' ? '' : 'RDP connection failed',
    );
  const frame = {
    desktopWidth: 800,
    desktopHeight: 600,
    x: 0,
    y: 0,
    width: 1,
    height: 1,
    rgba: 'AAAAAA==',
  };
  const certificate = { host: 'host.example', fingerprint: 'SHA256:123' };
  const events = [
    { ...base, type: 'frame', frame },
    { ...base, type: 'frameEnd', paintId: 4 },
    { ...base, type: 'certificate', certificate },
  ];
  for (const value of events) assert.deepEqual(parseSealedRdpEvent(value, id), value);
  for (const value of events)
    assert.equal(parseSealedRdpEvent({ ...value, requestId: randomUUID() }, id), undefined);
  const copied = parseSealedRdpEvent(events[0], id)!;
  copied.frame!.x = 3;
  assert.equal(frame.x, 0);
  parseSealedRdpEvent(events[2], id)!.certificate!.host = 'changed';
  assert.equal(certificate.host, 'host.example');
  for (const patch of [
    { sessionId: randomUUID() },
    { lifecycleId: randomUUID() },
    { external: true },
    { requestId: '' },
    { backend: 'unknown' },
    { type: 'recipient' },
    { type: 'nativeControl' },
    { password: 'secret' },
    { code: 1.5 },
    { attempt: -1 },
    { max: 65536 },
    { message: '\ud800' },
    { credentialFailure: true },
  ])
    assert.equal(parseSealedRdpEvent({ ...base, type: 'connected', ...patch }, id), undefined);
  for (const bad of [
    { type: 'frame', frame: null },
    { type: 'frame', frame: { ...frame, extra: true } },
    { type: 'frame', frame: { ...frame, width: 0 } },
    { type: 'frameEnd', paintId: 0 },
    { type: 'certificate', certificate: {} },
    { type: 'certificate', certificate: { ...certificate, host: '' } },
    { type: 'certificate', certificate: { ...certificate, extra: true } },
  ])
    assert.equal(parseSealedRdpEvent({ ...base, ...bad }, id), undefined);
  for (const value of [null, {}, []]) assert.equal(parseSealedRdpEvent(value, id), undefined);
  assert.equal(parseSealedRdpEvent({ ...base, type: 'ready' }, ''), undefined);
});
