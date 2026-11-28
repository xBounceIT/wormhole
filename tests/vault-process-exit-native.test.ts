import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { execFile, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { EventEmitter } from 'node:events';
import { confirmNativeProcessExit } from '../electron/vault-process-exit.ts';
import { hasChildExited } from '../electron/child-process-exit.ts';
import { stopChildProcess } from '../electron/rdp.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
let directory: string, executable: string;
before(
  async () => {
    if (process.platform !== 'win32') return;
    directory = await mkdtemp(join(tmpdir(), 'wormhole-process-proof-'));
    executable = join(directory, 'backend.exe');
    await promisify(execFile)('go', ['build', '-o', executable, '.'], {
      cwd: fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url)),
      windowsHide: true,
      timeout: 120000,
    });
  },
  { timeout: 150000 },
);
after(async () => {
  if (directory) {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
  }
});
test(
  'real Go kernel proof distinguishes live/absent PIDs and safely stops a wrapper missing native notifications',
  { skip: process.platform !== 'win32', timeout: 30000 },
  async () => {
    assert.equal(confirmNativeProcessExit(executable, { pid: process.pid }), false);
    const child = spawn(process.execPath, ['-e', 'process.exit(0)'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    await new Promise<void>((yes, no) => {
      child.once('close', () => yes());
      child.once('error', no);
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
      await stopChildProcess(stale as any, {
        gracefulTimeoutMs: 1,
        forceKillTimeoutMs: 1,
        nativeExecutable: executable,
      }),
      true,
    );
    assert.equal(kills, 0);
    assert.equal(hasChildExited(stale), true);
  },
);
test(
  'vault lock requires the real Go kernel proof when its process notification is missing',
  { skip: process.platform !== 'win32', timeout: 30000 },
  async () => {
    let actual: ChildProcessWithoutNullStreams | undefined, wrapper: any;
    const client = new VaultBackendClient(
      {
        executable,
        databasePath: join(directory, 'no-store.db'),
        stopGraceMs: 50,
        stopConfirmationMs: 2000,
      },
      (exe, args) => {
        actual = spawn(exe, args, { stdio: 'pipe', windowsHide: true });
        wrapper = Object.assign(new EventEmitter(), {
          pid: actual.pid,
          exitCode: null,
          signalCode: null,
          stdin: actual.stdin,
          stdout: actual.stdout,
          stderr: actual.stderr,
          kill: (signal?: NodeJS.Signals) => actual!.kill(signal),
        });
        actual.once('spawn', () => wrapper.emit('spawn'));
        actual.once('error', (error) => wrapper.emit('error', error));
        return wrapper;
      },
    );
    try {
      assert.equal((await client.status()).unlocked, false);
      await client.lock();
      assert.equal(hasChildExited(wrapper), true);
      assert.equal(wrapper.exitCode, null);
      assert.equal(wrapper.signalCode, null);
      assert.equal(confirmNativeProcessExit(executable, { pid: actual!.pid }), true);
    } finally {
      await client.lock();
      if (actual)
        await stopChildProcess(actual, {
          gracefulTimeoutMs: 1000,
          forceKillTimeoutMs: 1000,
          nativeExecutable: executable,
        });
    }
  },
);
