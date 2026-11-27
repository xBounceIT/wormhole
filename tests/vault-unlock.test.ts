import assert from 'node:assert/strict';
import test from 'node:test';
import { consumeVaultUnlockInput, encodeVaultUnlockFrame } from '../electron/vault-unlock.ts';
import { parseVaultUnlockResult } from '../electron/vault-contract.ts';

const vaultId = '11111111-1111-4111-8111-111111111111';
const slotId = '22222222-2222-4222-8222-222222222222';
const request = (factor: Uint8Array, kind: 'password' | 'recovery' = 'password') => ({
  vaultId,
  slotId,
  kind,
  factor,
});

test('unlock input consumes only the borrowed slice and isolates its owned factor', () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 5]);
  const input = consumeVaultUnlockInput(request(bytes.subarray(1, 4)));
  assert.deepEqual([...bytes], [1, 0, 0, 0, 5]);
  assert.deepEqual([...input.factor], [2, 3, 4]);
  input.factor.fill(0);
  assert.deepEqual([...bytes], [1, 0, 0, 0, 5]);
});

test('unlock rejects invalid identity, kind, shape and factor while consuming caller bytes', () => {
  for (const extra of [
    { vaultId: 'BAD' },
    { slotId: '00000000-0000-0000-0000-000000000000' },
    { vaultId: 1 },
    { slotId: 1 },
    { slotId: 'BAD' },
    { vaultId: '00000000-0000-0000-0000-000000000000' },
    { kind: 'hello' },
    { password: 'secret' },
  ]) {
    const value = { ...request(new Uint8Array([1, 2, 3])), ...extra };
    assert.throws(() => consumeVaultUnlockInput(value), {
      message: 'Invalid vault unlock request.',
    });
    assert.ok(value.factor.every((byte) => byte === 0));
  }
  for (const value of [
    null,
    [],
    {},
    1,
    request(new Uint8Array()),
    request(new Uint8Array(1025).fill(1)),
    request(new Uint8Array(31).fill(1), 'recovery'),
    request(new Uint8Array(33).fill(1), 'recovery'),
    request(new Uint8Array(new SharedArrayBuffer(32)).fill(1)),
    { ...request(new Uint8Array(1)), factor: 'secret' },
    { vaultId, slotId, factor: new Uint8Array([1]) },
  ])
    assert.throws(() => consumeVaultUnlockInput(value), {
      message: 'Invalid vault unlock request.',
    });
});

test('mutable unlock frame encodes every base64 tail and byte value without secret strings', () => {
  for (const size of [1, 2, 3, 4, 31, 32, 33, 256, 1024]) {
    const original = Uint8Array.from({ length: size }, (_, i) => (i * 67) % 256);
    const input = consumeVaultUnlockInput(request(original.slice()));
    const frame = encodeVaultUnlockFrame(Number.MAX_SAFE_INTEGER, input);
    const decoded = JSON.parse(frame.toString('utf8'));
    assert.deepEqual(decoded, {
      version: 1,
      id: Number.MAX_SAFE_INTEGER,
      operation: 'unlock',
      payload: { vaultId, slotId, password: Buffer.from(original).toString('base64') },
    });
    assert.equal(frame.at(-1), 10);
    input.factor.fill(0);
    frame.fill(0);
  }
  const recovery = consumeVaultUnlockInput(request(new Uint8Array(32).fill(7), 'recovery'));
  const frame = encodeVaultUnlockFrame(1, recovery);
  assert.deepEqual(Object.keys(JSON.parse(frame.toString()).payload), [
    'vaultId',
    'slotId',
    'recoveryKey',
  ]);
  frame.fill(0);
  for (const id of [0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1])
    assert.throws(() => encodeVaultUnlockFrame(id, recovery), /Invalid vault request ID/);
  recovery.factor.fill(0);
});

test('successful unlock reports the actual native memory-lock result', () => {
  for (const lockedMemory of [true, false]) {
    const result = { unlocked: true, lockedMemory };
    assert.deepEqual(parseVaultUnlockResult(result), result);
  }
  for (const value of [
    null,
    [],
    {},
    { unlocked: false, lockedMemory: true },
    { unlocked: true, lockedMemory: 'false' },
    { unlocked: true, lockedMemory: true, key: 'secret' },
  ])
    assert.equal(parseVaultUnlockResult(value), undefined);
});

test('formatted recovery is forwarded as bytes for native checksum verification', () => {
  const factor = new TextEncoder().encode('WHREC1-' + 'A'.repeat(69));
  const input = consumeVaultUnlockInput({ vaultId, slotId, kind: 'recovery-code', factor });
  assert.ok(factor.every((byte) => byte === 0));
  const frame = encodeVaultUnlockFrame(1, input);
  const payload = JSON.parse(frame.toString()).payload;
  assert.equal(Buffer.from(payload.recoveryCode, 'base64').length, 76);
  assert.equal(payload.recoveryKey, undefined);
  input.factor.fill(0);
  frame.fill(0);
  assert.throws(
    () =>
      consumeVaultUnlockInput({
        vaultId,
        slotId,
        kind: 'recovery-code',
        factor: new Uint8Array(75),
      }),
    /Invalid/,
  );
});
