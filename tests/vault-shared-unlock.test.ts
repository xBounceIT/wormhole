import assert from 'node:assert/strict';
import test from 'node:test';
import { join, resolve, sep } from 'node:path';
import { Session } from 'node:inspector/promises';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import {
  consumeSharedVaultUnlockInput,
  consumeSharedVaultContinuationInput,
  hasSharedVaultContinuation,
  encodeSharedVaultUnlockFrame,
  parseSharedVaultAdmission,
  parseSharedVaultRecovery,
  parseSharedTLSBundleExport,
  parseSharedRecoveryKitNativeRefresh,
  parseSharedRecoveryKitRefresh,
  validSharedTLSBundlePath,
  validSharedRecoveryKitPath,
} from '../electron/vault-shared-unlock.ts';

const profiler = new Session();
const externalCoverage =
  process.execArgv.includes('--experimental-test-coverage') || !!process.env.NODE_V8_COVERAGE;
if (!externalCoverage) {
  profiler.connect();
  await profiler.post('Profiler.enable');
  await profiler.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
}

const vaultId = '11111111-1111-4111-8111-111111111111';
const slotId = '22222222-2222-4222-8222-222222222222';

test('recovery kit paths and replies accept only the bounded native contract', () => {
  assert.ok(validSharedRecoveryKitPath(resolve('team.WHRECOVERY')));
  for (const input of [
    null,
    'team.whrecovery',
    resolve('team.whtls'),
    resolve('a\u0000.whrecovery'),
  ])
    assert.equal(validSharedRecoveryKitPath(input), false);
  for (const receipt of ['updated', 'unavailable', 'invalid-kit', 'save-failed'])
    assert.equal(parseSharedRecoveryKitRefresh(receipt), receipt);
  for (const status of ['authentication-required', 'invalid-authentication']) {
    assert.equal(parseSharedRecoveryKitNativeRefresh(status), status);
    assert.equal(parseSharedRecoveryKitRefresh(status), undefined);
  }
  for (const receipt of [null, 'recovered', { status: 'updated', code: 'forged' }])
    assert.equal(parseSharedRecoveryKitRefresh(receipt), undefined);
});

test('only main can attach a bounded TLS update path to ordinary admission', () => {
  const path = resolve('team-è.WHTLS');
  const input = consumeSharedVaultUnlockInput(value(), '2.4.3');
  assert.ok(validSharedTLSBundlePath(path));
  const frame = encodeSharedVaultUnlockFrame(3, 'shared-unlock', input, path);
  assert.equal(JSON.parse(frame.toString()).payload.tlsUpdatePath, path);
  frame.fill(0);
  for (const bad of [
    null,
    'relative.whtls',
    resolve('unexpected.json'),
    resolve('ab\u0000.whtls'),
    `${resolve('trusted')}${sep}..${sep}rotated.whtls`,
    join(resolve('trusted'), 'a'.repeat(4097) + '.whtls'),
  ])
    assert.equal(validSharedTLSBundlePath(bad), false);
  for (const operation of [
    'shared-recover-password',
    'shared-recover-enrollment',
    'shared-continue-enrollment',
  ] as const)
    assert.throws(() => encodeSharedVaultUnlockFrame(3, operation, input, path));
  const submitted = { ...value(), tlsUpdatePath: path };
  assert.throws(() => consumeSharedVaultUnlockInput(submitted, '2.4.3'));
  assert.ok(submitted.password.every((n) => n === 0));
  input.password.fill(0);
  input.ask?.fill(0);
  assert.equal(parseSharedTLSBundleExport({ exported: true }), true);
  assert.equal(parseSharedTLSBundleExport({ exported: false }), false);
  for (const message of [null, [], {}, { exported: 0 }, { exported: true, path }])
    assert.equal(parseSharedTLSBundleExport(message), undefined);
});
const value = () => ({
  vaultId,
  slotId,
  password: new Uint8Array([7, 8, 9]),
  ask: new Uint8Array(32).fill(11),
});

test('continuation owns overlapping factors and encodes only the fixed enrollment operation', () => {
  for (const withASK of [true, false]) {
    const raw = Uint8Array.from({ length: 64 }, (_, i) => i + 1),
      expected = raw.slice();
    const input = consumeSharedVaultContinuationInput(
      {
        vaultId,
        slotId,
        password: raw.subarray(8, 40),
        ...(withASK ? { ask: raw.subarray(0, 32) } : {}),
        code: raw.subarray(16, 32),
        acknowledgeTLSOff: withASK,
      },
      '1.2.3',
    );
    assert.ok(hasSharedVaultContinuation(input));
    assert.deepEqual(input.code, Buffer.from(expected.subarray(16, 32)));
    assert.deepEqual(input.password, Buffer.from(expected.subarray(8, 40)));
    if (withASK) assert.deepEqual(input.ask, Buffer.from(expected.subarray(0, 32)));
    const frame = encodeSharedVaultUnlockFrame(5, 'shared-continue-enrollment', input);
    const payload = JSON.parse(frame.toString()).payload;
    assert.equal(payload.code, Buffer.from(expected.subarray(16, 32)).toString('base64'));
    assert.equal(payload.acknowledgeTLSOff, withASK);
    assert.equal(
      payload.factors.password,
      Buffer.from(expected.subarray(8, 40)).toString('base64'),
    );
    assert.deepEqual(Object.keys(payload).sort(), [
      'acknowledgeTLSOff',
      'appVersion',
      'code',
      'factors',
    ]);
    input.code.fill(0);
    input.password.fill(0);
    input.ask?.fill(0);
    frame.fill(0);
    assert.ok(raw.subarray(withASK ? 0 : 8, 40).every((n) => n === 0));
  }
  for (const extra of [
    { code: new Uint8Array(15).fill(9) },
    { code: new Uint8Array(new SharedArrayBuffer(16)).fill(9) },
    { acknowledgeTLSOff: undefined },
    { acknowledgeTLSOff: 1 },
    { endpoint: 'untrusted' },
    { password: new Uint8Array() },
    { vaultId: 'wrong' },
  ]) {
    const request = {
      ...value(),
      code: new Uint8Array(16).fill(6),
      acknowledgeTLSOff: false,
      ...extra,
    };
    assert.throws(() => consumeSharedVaultContinuationInput(request, '1.0.0'));
    for (const key of ['password', 'ask', 'code'] as const)
      assert.ok(request[key].every((n) => n === 0));
  }
  for (const request of [null, [], {}, 42])
    assert.throws(() => consumeSharedVaultContinuationInput(request, '1.0.0'));
  const ordinary = consumeSharedVaultUnlockInput(value(), '1.0.0');
  assert.equal(hasSharedVaultContinuation(ordinary), false);
  assert.throws(() => encodeSharedVaultUnlockFrame(1, 'shared-continue-enrollment', ordinary));
  ordinary.password.fill(0);
  ordinary.ask?.fill(0);
});

test('shared factors own exact copies even when borrowed views overlap', () => {
  const bytes = Uint8Array.from({ length: 64 }, (_, i) => i + 1);
  const original = bytes.slice();
  const input = consumeSharedVaultUnlockInput(
    { vaultId, slotId, password: bytes.subarray(16, 48), ask: bytes.subarray(0, 32) },
    '1.2.3-beta.1',
  );
  assert.deepEqual(input.password, Buffer.from(original.subarray(16, 48)));
  assert.deepEqual(input.ask, Buffer.from(original.subarray(0, 32)));
  assert.ok(bytes.subarray(0, 48).every((n) => n === 0));
  assert.deepEqual(bytes.subarray(48), original.subarray(48));
  input.password.fill(0);
  input.ask!.fill(0);
});

test('invalid shared factors/version consume both input views', () => {
  for (const extra of [
    { unexpected: true },
    { vaultId: 'bad' },
    { slotId: 'bad' },
    { password: new Uint8Array() },
    { password: new Uint8Array(1025).fill(7) },
    { ask: undefined },
    { ask: new Uint8Array(31).fill(7) },
    { ask: new Uint8Array(new SharedArrayBuffer(32)).fill(7) },
    { password: new Uint8Array(new SharedArrayBuffer(3)).fill(7) },
    { password: 'secret' },
  ]) {
    const request = { ...value(), ...extra };
    assert.throws(() => consumeSharedVaultUnlockInput(request, '1.0.0'), /Invalid shared/);
    if (request.password instanceof Uint8Array) assert.ok(request.password.every((n) => n === 0));
    if (request.ask instanceof Uint8Array) assert.ok(request.ask.every((n) => n === 0));
  }
  for (const version of ['', '1.2', '1.2.3\n', '1.2.3-' + 'a'.repeat(64), null]) {
    const request = value();
    assert.throws(
      () => consumeSharedVaultUnlockInput(request, version as string),
      /Invalid shared/,
    );
    assert.ok(request.password.every((n) => n === 0));
    assert.ok(request.ask.every((n) => n === 0));
  }
  for (const request of [null, [], {}, 42])
    assert.throws(() => consumeSharedVaultUnlockInput(request, '1.0.0'), /Invalid shared/);
});

test('shared frames use the native nested factor contract without immutable secret encoding', () => {
  for (const operation of [
    'shared-unlock',
    'shared-recover-password',
    'shared-recover-enrollment',
  ] as const) {
    for (const size of [1, 2, 3, 4, 32, 256, 1024]) {
      const bytes = Uint8Array.from({ length: size }, (_, i) => (i * 67) % 256);
      for (const useASK of [false, true]) {
        const ask = new Uint8Array(32).fill(19);
        const input = consumeSharedVaultUnlockInput(
          { vaultId, slotId, password: bytes.slice(), ...(useASK ? { ask: ask.slice() } : {}) },
          '1.0.0',
        );
        const frame = encodeSharedVaultUnlockFrame(1, operation, input);
        assert.deepEqual(JSON.parse(frame.toString()), {
          version: 1,
          id: 1,
          operation,
          payload: {
            appVersion: '1.0.0',
            factors: {
              vaultId,
              slotId,
              password: Buffer.from(bytes).toString('base64'),
              ...(useASK ? { ask: Buffer.from(ask).toString('base64') } : {}),
            },
          },
        });
        assert.equal(frame.at(-1), 10);
        input.password.fill(0);
        input.ask?.fill(0);
        frame.fill(0);
      }
    }
  }
  const input = consumeSharedVaultUnlockInput(value(), '1.0.0');
  for (const id of [0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1])
    assert.throws(() => encodeSharedVaultUnlockFrame(id, 'shared-unlock', input), /Invalid shared/);
  assert.throws(
    () => encodeSharedVaultUnlockFrame(1, 'other' as 'shared-unlock', input),
    /Invalid shared/,
  );
  input.password.fill(0);
  input.ask?.fill(0);
});

test('shared acknowledgement cannot impersonate local workspace unlock or include secrets', () => {
  for (const lockedMemory of [false, true])
    for (const orgEscrow of [false, true])
      assert.deepEqual(parseSharedVaultAdmission({ admitted: true, lockedMemory, orgEscrow }), {
        admitted: true,
        lockedMemory,
        orgEscrow,
      });
  assert.deepEqual(parseSharedVaultRecovery({ recovered: true }), { recovered: true });
  for (const v of [
    null,
    [],
    {},
    { admitted: false, lockedMemory: true },
    { admitted: true, lockedMemory: 1 },
    { admitted: true, lockedMemory: true },
    { admitted: true, lockedMemory: true, orgEscrow: null },
    { admitted: true, lockedMemory: true, orgEscrow: 'false' },
    { admitted: true, lockedMemory: true, orgEscrow: 0 },
    { admitted: true, lockedMemory: true, orgEscrow: false, policy: 'unverified' },
    { admitted: true, lockedMemory: true, keys: [] },
    { unlocked: true, lockedMemory: true },
  ])
    assert.equal(parseSharedVaultAdmission(v), undefined);
  for (const v of [
    null,
    [],
    {},
    { recovered: false },
    { recovered: true, keys: [] },
    { admitted: true },
  ])
    assert.equal(parseSharedVaultRecovery(v), undefined);
});

test('authenticated admission parser meets measured coverage', async (t) => {
  if (externalCoverage) return;
  try {
    const report = await profiler.post('Profiler.takePreciseCoverage');
    const ranges = report.result
      .filter((script) => script.url.endsWith('/vault-shared-unlock.ts'))
      .flatMap((script) => script.functions)
      .filter((fn) => fn.functionName === 'parseSharedVaultAdmission')
      .flatMap((fn) => fn.ranges);
    assert.ok(ranges.length);
    const percent = (100 * ranges.filter((range) => range.count > 0).length) / ranges.length;
    t.diagnostic('Admission notice parser: ' + percent.toFixed(2) + '% V8 blocks');
    assert.ok(percent >= coverageThreshold);
    for (const method of [
      'consumeSharedVaultContinuationInput',
      'hasSharedVaultContinuation',
      'encodeSharedVaultUnlockFrame',
    ]) {
      const ranges = report.result
        .filter((script) => script.url.endsWith('/vault-shared-unlock.ts'))
        .flatMap((script) => script.functions)
        .filter((fn) => fn.functionName === method)
        .flatMap((fn) => fn.ranges);
      assert.ok(ranges.length);
      const percent = (100 * ranges.filter((r) => r.count > 0).length) / ranges.length;
      t.diagnostic(method + ': ' + percent.toFixed(2) + '% V8 blocks');
      assert.ok(percent >= coverageThreshold, method);
    }
  } finally {
    await profiler.post('Profiler.stopPreciseCoverage');
    profiler.disconnect();
  }
});
