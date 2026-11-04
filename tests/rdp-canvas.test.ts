import assert from 'node:assert/strict';
import test from 'node:test';
import { assertRdpSurfaceOwner, isRdpFrame, isRdpInput } from '../electron/rdp-framebuffer.ts';
import {
  createRdpInputQueue,
  decodeRdpTile,
  rdpKeyInput,
  rdpPointerInput,
} from '../src/rdp-canvas.ts';
import type { RdpInput } from '../electron/rdp-framebuffer.ts';

const frame = {
  desktopWidth: 2,
  desktopHeight: 1,
  x: 1,
  y: 0,
  width: 1,
  height: 1,
  rgba: 'AP8A/w==',
};

test('surface ownership cannot be replaced by another window', () => {
  const owner = {};
  assert.doesNotThrow(() => assertRdpSurfaceOwner(owner, undefined));
  assert.doesNotThrow(() => assertRdpSurfaceOwner(owner, owner));
  assert.throws(() => assertRdpSurfaceOwner({}, owner), /another window/);
});

test('queued input keeps its original lifecycle and blur discards unsent keys', async () => {
  let lifecycle = 'old';
  const sent: { input: RdpInput; id: string }[] = [];
  let unblock!: () => void;
  const queue = createRdpInputQueue(
    async (input, id) => {
      sent.push({ input, id });
      if (sent.length === 1)
        await new Promise<void>((resolve) => {
          unblock = resolve;
        });
    },
    () => lifecycle,
  );
  queue.push({ kind: 'key', code: 1, down: true });
  queue.push({ kind: 'key', code: 1, down: false });
  lifecycle = 'new';
  unblock();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(
    sent.map((item) => item.id),
    ['old', 'old'],
  );
  let resume!: () => void;
  const released: RdpInput[] = [];
  const blurred = createRdpInputQueue(async (input) => {
    released.push(input);
    if (released.length === 1)
      await new Promise<void>((resolve) => {
        resume = resolve;
      });
  });
  blurred.push({ kind: 'key', code: 1, down: true });
  blurred.push({ kind: 'key', code: 2, down: true });
  blurred.push({ kind: 'release' });
  resume();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(released, [{ kind: 'key', code: 1, down: true }, { kind: 'release' }]);
});

test('a failed key-up triggers one bounded release for the same lifecycle', async () => {
  const sent: RdpInput[] = [];
  const queue = createRdpInputQueue(async (input) => {
    sent.push(input);
    throw new Error('transport failure');
  });
  queue.push({ kind: 'key', code: 1, down: false });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent, [{ kind: 'key', code: 1, down: false }, { kind: 'release' }]);
  for (const code of [0, -1, 0x100000000, 1.5, NaN])
    assert.equal(isRdpInput({ kind: 'painted', code }), false);
});
test('RDP tiles are bounded and decode into the advertised pixels', () => {
  assert.deepEqual([...decodeRdpTile(frame)!], [0, 255, 0, 255]);
  for (const invalid of [
    null,
    {},
    { ...frame, width: 129 },
    { ...frame, height: 0 },
    { ...frame, x: 2 },
    { ...frame, y: -1 },
    { ...frame, desktopWidth: Infinity },
    { ...frame, desktopHeight: 16384, desktopWidth: 16384 },
    { ...frame, rgba: '%%%%%%%%' },
    { ...frame, rgba: 'AP8A' },
    { ...frame, rgba: 'AP8AAAAA' },
  ]) {
    if (invalid && 'rgba' in invalid && invalid.rgba === 'AP8AAAAA') {
      assert.equal(decodeRdpTile(invalid as typeof frame), undefined);
    } else {
      assert.equal(isRdpFrame(invalid), false);
      assert.equal(decodeRdpTile(invalid as typeof frame), undefined);
    }
  }
});

test('RDP input validation rejects oversized and unsupported native input', () => {
  for (const valid of [
    { kind: 'release' },
    { kind: 'painted', code: 1 },
    { kind: 'key', code: 0x11d, down: false },
    { kind: 'unicode', code: 0x20ac, down: true },
    ...[0x0800, 0x1000, 0x2000, 0x4000, 0x9000, 0xa000, 0xc000, 0x0278, 0x0388].map((flags) => ({
      kind: 'pointer',
      x: 16383,
      y: 0,
      flags,
    })),
  ]) {
    assert.equal(isRdpInput(valid), true);
  }
  for (const invalid of [
    null,
    '',
    {},
    { kind: 'unknown' },
    { kind: 'pointer', x: -1, y: 0, flags: 0x0800 },
    { kind: 'pointer', x: 0, y: 16384, flags: 0x0800 },
    { kind: 'pointer', x: 0, y: 0, flags: '2048' },
    { kind: 'pointer', x: 0, y: 0, flags: 0xffff },
    { kind: 'key', code: 512, down: true },
    { kind: 'key', code: 1.5, down: true },
    { kind: 'unicode', code: 65536, down: true },
    { kind: 'key', code: 1, down: 1 },
  ]) {
    assert.equal(isRdpInput(invalid), false);
  }
});

test('canvas input maps CSS coordinates and physical key combinations', () => {
  assert.deepEqual(
    rdpPointerInput(
      { left: 10, top: 20, width: 200, height: 100 },
      { width: 1000, height: 500 },
      110,
      70,
      0x9000,
    ),
    { kind: 'pointer', x: 500, y: 250, flags: 0x9000 },
  );
  assert.deepEqual(
    rdpPointerInput(
      { left: 10, top: 20, width: 200, height: 100 },
      { width: 1000, height: 500 },
      -100,
      200,
      0x1000,
    ),
    { kind: 'pointer', x: 0, y: 499, flags: 0x1000 },
  );
  assert.equal(
    rdpPointerInput({ left: 0, top: 0, width: 0, height: 100 }, { width: 1, height: 1 }, 0, 0, 0),
    undefined,
  );
  assert.equal(
    rdpPointerInput({ left: 0, top: 0, width: 1, height: 1 }, { width: 0, height: 1 }, 0, 0, 0),
    undefined,
  );
  for (const [key, code] of [
    ['KeyA', 0x1e],
    ['KeyQ', 0x10],
    ['KeyZ', 0x2c],
    ['Digit0', 0x0b],
    ['ControlRight', 0x11d],
    ['F12', 0x58],
    ['Numpad0', 0x52],
  ] as const) {
    assert.deepEqual(rdpKeyInput(key, true), { kind: 'key', code, down: true });
  }
  assert.equal(rdpKeyInput('Unidentified', true), undefined);
});

test('pointer motion is coalesced without losing button and keyboard ordering', async () => {
  const sent: RdpInput[] = [];
  let unblock!: () => void;
  const queue = createRdpInputQueue(async (input) => {
    sent.push(input);
    if (sent.length === 1)
      await new Promise<void>((resolve) => {
        unblock = resolve;
      });
  });
  const move = (x: number): RdpInput => ({ kind: 'pointer', x, y: 0, flags: 0x0800 });
  queue.push(move(1));
  queue.push(move(2));
  queue.push(move(3));
  queue.push({ kind: 'key', code: 1, down: false });
  unblock();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent, [move(1), move(3), { kind: 'key', code: 1, down: false }]);
  queue.close();
  queue.push(move(4));
  assert.equal(sent.length, 3);
});

test('overload releases held input and transport failure clears the pending queue', async () => {
  const sent: RdpInput[] = [];
  let unblock!: () => void;
  const queue = createRdpInputQueue(async (input) => {
    sent.push(input);
    if (sent.length === 1)
      await new Promise<void>((resolve) => {
        unblock = resolve;
      });
  });
  for (let i = 0; i < 258; i++) queue.push({ kind: 'key', code: 1, down: true });
  unblock();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent, [{ kind: 'key', code: 1, down: true }, { kind: 'release' }]);
  let attempts = 0;
  const failing = createRdpInputQueue(async () => {
    attempts++;
    throw new Error('closed');
  });
  failing.push({ kind: 'release' });
  failing.push({ kind: 'release' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(attempts, 1);
});
