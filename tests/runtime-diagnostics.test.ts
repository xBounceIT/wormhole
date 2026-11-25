import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  backendErrorText,
  createRuntimeDiagnostics,
  expectBackendExit,
  observeBackendProcess,
  withIpcDiagnostics,
} from '../electron/runtime-diagnostics.ts';

function setup(t: { after: (cleanup: () => void) => void }) {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole-runtime-log-'));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  const day = path.join(root, 'logs', 'wormhole-20261231.log');
  const fallback = path.join(root, 'electron', 'wormhole-diagnostics.log');
  let now = new Date(2026, 11, 31, 23, 59, 52);
  const record = createRuntimeDiagnostics({
    databasePath: () => path.join(root, 'wormhole.db'),
    fallbackPath: () => fallback,
    now: () => now,
  });
  return { root, day, fallback, record, setTime: (time: Date) => (now = time) };
}

test('Electron appends to the shared daily log and coalesces repeated errors', (t) => {
  const { root, day, record, setTime } = setup(t);
  mkdirSync(path.dirname(day));
  writeFileSync(day, 'existing Go record\n');

  record('ERR', 'workspace load failed', { exitCode: 1 });
  record('ERR', 'workspace load failed', { exitCode: 1 });
  setTime(new Date(2026, 11, 31, 23, 59, 59));
  record('ERR', 'workspace load failed', { exitCode: 1 });
  assert.match(readFileSync(day, 'utf8'), /^existing Go record\n/);
  assert.match(readFileSync(day, 'utf8'), /"exitCode":1,"repeated":1/);

  setTime(new Date(2027, 0, 1, 0, 0, 5));
  record('ERR', 'workspace load failed', { exitCode: 1 });
  assert.match(
    readFileSync(path.join(root, 'logs', 'wormhole-20270101.log'), 'utf8'),
    /\[ERR\] \[electron pid=\d+\] workspace load failed/,
  );
});

test('Electron persists an error when the primary log is inaccessible and resumes the daily log', (t) => {
  const { root, day, fallback, record } = setup(t);
  const logs = path.join(root, 'logs');
  writeFileSync(logs, 'blocked by file');
  mkdirSync(path.dirname(fallback));
  writeFileSync(fallback, 'x'.repeat(1024 * 1024));

  record('ERR', 'Backend executable missing');
  assert.match(
    readFileSync(fallback, 'utf8'),
    /Backend executable missing.*primary log unavailable/,
  );
  assert.equal(readFileSync(fallback + '.previous').length, 1024 * 1024);

  rmSync(logs);
  record('WRN', 'workspace recovered');
  assert.match(readFileSync(day, 'utf8'), /workspace recovered/);
});

test('diagnostics report an unwritable primary and fallback without replacing either', (t) => {
  const { day, fallback, record } = setup(t);
  mkdirSync(day, { recursive: true });
  mkdirSync(fallback, { recursive: true });
  const consoleError = t.mock.method(console, 'error', () => {});
  assert.equal(record('ERR', 'First failure'), false);
  assert.equal(record('ERR', 'Second failure'), false);
  assert.equal(consoleError.mock.callCount(), 1);
  rmdirSync(fallback);
  assert.equal(record('ERR', 'Second failure'), true);
  assert.match(readFileSync(fallback, 'utf8'), /Second failure/);
});

test('Electron writes to the fallback without following a linked log directory', (t) => {
  const { root, day, fallback, record } = setup(t);
  const otherDirectory = path.join(root, 'other-data');
  mkdirSync(otherDirectory);
  symlinkSync(otherDirectory, path.dirname(day), process.platform === 'win32' ? 'junction' : 'dir');
  const untouched = path.join(otherDirectory, path.basename(day));
  writeFileSync(untouched, 'another file\n');
  assert.equal(record('ERR', 'Cannot start workspace'), true);
  assert.match(readFileSync(fallback, 'utf8'), /Cannot start workspace/);
  assert.equal(readFileSync(untouched, 'utf8'), 'another file\n');
});

test('reports requiring persistence do not acknowledge identical unwritten entries', (t) => {
  const { day, fallback, record } = setup(t);
  assert.equal(record('WRN', 'Previous dump detected', {}, true), true);
  assert.equal(record('WRN', 'Previous dump detected', {}, true), true);
  assert.equal(readFileSync(day, 'utf8').match(/Previous dump detected/g)?.length, 2);
  rmSync(day);
  mkdirSync(day);
  mkdirSync(fallback, { recursive: true });
  t.mock.method(console, 'error', () => {});
  assert.equal(record('WRN', 'Previous dump detected', {}, true), false);
});

test('IPC failures retain rejection identity and never persist rejected values', async (t) => {
  const { day, record } = setup(t);
  const syncFailure = Object.assign(new Error('private credential'), { code: 'EACCES' });
  const asynchronousFailure = Object.assign(new Error('private remote response'), {
    code: 'PRIVATE_TOKEN',
  });
  const successful = withIpcDiagnostics((value: string) => value, 'example:ok', record);
  assert.equal(await successful('private value'), 'private value');
  const sync = withIpcDiagnostics(
    () => {
      throw syncFailure;
    },
    'example:sync',
    record,
  );
  const async = withIpcDiagnostics(
    () => Promise.reject(asynchronousFailure),
    'example:async',
    record,
  );
  await assert.rejects(sync, (error) => error === syncFailure);
  await assert.rejects(async, (error) => error === asynchronousFailure);

  const text = readFileSync(day, 'utf8');
  assert.match(text, /IPC failed \(example:sync\) {"code":"EACCES"}/);
  assert.match(text, /IPC failed \(example:async\)/);
  assert.doesNotMatch(text, /private|PRIVATE|example:ok/);
});

test('child process monitoring retains only the Go sink status and an unexpected exit', async (t) => {
  const { day, record } = setup(t);
  const child = spawn(
    process.execPath,
    [
      '-e',
      "process.stderr.write('private-token\\n' + 'x'.repeat(2048) + '\\nWormhole diagnostic');" +
        "setTimeout(() => { process.stderr.write(' log unavailable: permission\\n'); process.exitCode = 7; }, 15)",
    ],
    { windowsHide: true },
  );
  observeBackendProcess(child, 'serve', record);
  assert.deepEqual(await once(child, 'close'), [7, null]);
  const clean = spawn(process.execPath, ['-e', ''], { windowsHide: true });
  observeBackendProcess(clean, 'serial', record);
  expectBackendExit(clean);
  await once(clean, 'close');

  const missing = spawn(path.join(path.dirname(day), 'missing-backend-executable'));
  observeBackendProcess(missing, 'rdp', record);
  await new Promise((resolve) => missing.on('close', resolve));

  const text = readFileSync(day, 'utf8');
  assert.match(text, /backend log unavailable \(serve\).*"cause":"permission"/);
  assert.match(text, /backend process exited \(serve\).*"exitCode":7/);
  assert.match(text, /backend process error \(rdp\).*"code":"ENOENT"/);
  assert.doesNotMatch(text, /private-token|xxxx|serial/);
  assert.equal(
    backendErrorText('Wormhole diagnostic log unavailable: permission\r\nPublic error\r\n'),
    'Public error',
  );
});

test('backend exit diagnostics do not depend on pipes closing or an intended shutdown', (t) => {
  const { day, record } = setup(t);
  const child = new EventEmitter() as ChildProcess;
  observeBackendProcess(child, 'rdp', record);
  expectBackendExit(child);
  child.emit('exit', 2, null);
  // An inherited handle can keep the close event pending indefinitely.
  assert.match(readFileSync(day, 'utf8'), /backend process exited \(rdp\).*"exitCode":2/);
  const forcedStop = new EventEmitter() as ChildProcess;
  observeBackendProcess(forcedStop, 'serial', record);
  expectBackendExit(forcedStop);
  forcedStop.emit('exit', null, 'SIGTERM');
  assert.doesNotMatch(readFileSync(day, 'utf8'), /serial/);
});
