import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { spawn } from 'node:child_process';
import { hasChildExited } from '../electron/child-process-exit.ts';
import { stopChildProcess } from '../electron/rdp.ts';
test('exit proof accepts only native notifications or an independent kernel proof', () => {
  const live = { exitCode: null, signalCode: null, pid: 123 };
  assert.equal(hasChildExited({} as any), false);
  assert.equal(hasChildExited(live), false);
  assert.equal(hasChildExited({ ...live, exitCode: 0 }), true);
  assert.equal(hasChildExited({ ...live, signalCode: 'SIGTERM' }), true);
  for (const pid of [undefined, 0, -1, 1.5, NaN, Infinity, 2 ** 53, process.pid])
    assert.equal(
      hasChildExited({ ...live, pid }),
      false,
      'PID presence or a signal-zero probe is no wait proof',
    );
});
test(
  'a real absent PID without notifications or a kernel verifier cannot acknowledge shutdown',
  { skip: process.platform !== 'win32', timeout: 20000 },
  async () => {
    const child = spawn(process.execPath, ['-e', 'process.exit(0)'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    await new Promise<void>((resolve, reject) => {
      child.once('close', () => resolve());
      child.once('error', reject);
    });
    let kills = 0;
    const stale = Object.assign(new EventEmitter(), {
      pid: child.pid,
      exitCode: null,
      signalCode: null,
      stdin: { end: () => {} },
      kill: () => {
        kills++;
        return false;
      },
    });
    assert.equal(hasChildExited(stale), false);
    assert.equal(
      await stopChildProcess(stale as any, { gracefulTimeoutMs: 1, forceKillTimeoutMs: 1 }),
      false,
    );
    assert.equal(kills, 1);
  },
);
test('stop still waits or force-stops a live child and rejects an unconfirmed exit', async () => {
  let kills = 0;
  const child = Object.assign(new EventEmitter(), {
    exitCode: null as number | null,
    signalCode: null,
    stdin: { end: () => {} },
    kill: () => {
      kills++;
      return false;
    },
  });
  assert.equal(
    await stopChildProcess(child as any, { gracefulTimeoutMs: 1, forceKillTimeoutMs: 1 }),
    false,
  );
  assert.equal(kills, 1);
  child.kill = () => {
    kills++;
    child.exitCode = 0;
    child.emit('close');
    return true;
  };
  assert.equal(
    await stopChildProcess(child as any, { gracefulTimeoutMs: 1, forceKillTimeoutMs: 1 }),
    true,
  );
  const graceful = Object.assign(new EventEmitter(), {
    exitCode: null as number | null,
    signalCode: null,
    stdin: {
      end: () => {
        queueMicrotask(() => {
          graceful.exitCode = 0;
          graceful.emit('close');
        });
      },
    },
    kill: () => {
      throw Error('must not kill');
    },
  });
  assert.equal(await stopChildProcess(graceful as any), true);
});

test('a controller owning descendants can forbid forced termination and retain an unconfirmed stop', async () => {
  let kills = 0;
  const child = Object.assign(new EventEmitter(), {
    exitCode: null as number | null,
    signalCode: null,
    stdin: { end: () => {} },
    kill: () => {
      kills++;
      child.exitCode = 0;
      child.emit('close');
      return true;
    },
  });
  const options = { gracefulTimeoutMs: 1, forceKillTimeoutMs: 1, forceKill: false as const };
  assert.equal(await stopChildProcess(child as any, options), false);
  assert.equal(kills, 0);
  assert.equal(child.exitCode, null);
  assert.equal(child.listenerCount('close'), 0);
  child.exitCode = 0;
  child.emit('close');
  assert.equal(await stopChildProcess(child as any, options), true);
  assert.equal(kills, 0);
});
