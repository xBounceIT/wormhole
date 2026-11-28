import assert from 'node:assert/strict';
import test from 'node:test';
import {
  confirmNativeProcessExit,
  hasNativeProcessExitProof,
} from '../electron/vault-process-exit.ts';
import { hasChildExited } from '../electron/child-process-exit.ts';
const executable = process.execPath;
const state = () => ({ pid: 123, exitCode: null, signalCode: null });
test('native proof checks one owned PID with bounded secret-free execution and caches only its identity', () => {
  const child = state();
  let calls = 0;
  const run = (exe: string, args: string[], options: any) => {
    calls++;
    assert.equal(exe, executable);
    assert.deepEqual(args, ['--operation', 'process-exit-proof', '--process-id', '123']);
    assert.equal(options.windowsHide, true);
    assert.deepEqual(options.stdio, ['ignore', 'pipe', 'ignore']);
    assert.equal(options.timeout, 2000);
    assert.equal(options.maxBuffer, 512);
    return { status: 0, stdout: Buffer.from('{"version":1,"pid":123,"terminated":true}') };
  };
  assert.equal(confirmNativeProcessExit(executable, child, 'win32', run as any), true);
  assert.equal(hasChildExited(child), true);
  assert.equal(hasNativeProcessExitProof(child), true);
  assert.equal(confirmNativeProcessExit(executable, child, 'win32', run as any), true);
  assert.equal(calls, 1);
  assert.equal(hasChildExited(state()), false, 'same numeric PID is not another child proof');
  child.pid = 124;
  assert.equal(hasChildExited(child), false);
});
test('code zero without a signaled kernel wait, malformed replies and failed helpers never acknowledge', () => {
  for (const result of [
    { status: 0, stdout: '{"version":1,"pid":123,"terminated":false}' },
    { status: 0, stdout: '{"version":1,"pid":124,"terminated":true}' },
    { status: 0, stdout: '{"version":2,"pid":123,"terminated":true}' },
    { status: 0, stdout: '{"version":1,"pid":123,"terminated":true,"exitCode":0}' },
    { status: 0, stdout: '{"version":1,"pid":123,"terminated":"true"}' },
    { status: 0, stdout: 'null' },
    { status: 0, stdout: '[]' },
    { status: 0, stdout: 'invalid' },
    { status: 0, stdout: ' '.repeat(513) },
    { status: 0, stdout: null },
    { status: 1, stdout: '{"version":1,"pid":123,"terminated":true}' },
    { status: 0, stdout: '{}', error: Error('private helper diagnostic') },
  ]) {
    const child = state();
    assert.equal(
      confirmNativeProcessExit(executable, child, 'win32', (() => result) as any),
      false,
    );
    assert.equal(hasNativeProcessExitProof(child), false);
  }
  assert.equal(
    confirmNativeProcessExit(executable, state(), 'win32', () => {
      throw Error('private');
    }),
    false,
  );
  const changing = state();
  assert.equal(
    confirmNativeProcessExit(executable, changing, 'win32', () => {
      changing.pid = 124;
      return { status: 0, stdout: '{"version":1,"pid":123,"terminated":true}' };
    }),
    false,
  );
});
test('unsupported platforms, relative paths and invalid process IDs never invoke a helper', () => {
  const never = () => {
    throw Error('must not start');
  };
  for (const platform of ['linux', 'darwin'] as const)
    assert.equal(confirmNativeProcessExit(executable, state(), platform, never), false);
  for (const path of ['', 'relative.exe', 'x'.repeat(5000)])
    assert.equal(confirmNativeProcessExit(path, state(), 'win32', never), false);
  for (const pid of [undefined, 0, -1, NaN, Infinity, 1.5, 2 ** 32])
    assert.equal(confirmNativeProcessExit(executable, { ...state(), pid }, 'win32', never), false);
});
