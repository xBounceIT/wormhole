import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { parseVaultSshManualContext } from '../electron/vault-ssh-manual.ts';
import { sealSshTemporaryCredentials } from '../src/vault-ssh-credentials-sender.ts';
import { stopChildProcess } from '../electron/rdp.ts';

let directory: string, fixture: string;
const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
before(
  async () => {
    directory = await mkdtemp(join(tmpdir(), 'wormhole-ssh-manual-interop-'));
    fixture = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
    await promisify(execFile)('go', ['test', '-c', '-o', fixture, '.'], {
      cwd,
      windowsHide: true,
      timeout: 120000,
    });
  },
  { timeout: 180000 },
);
after(async () => {
  if (directory) {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
  }
});
for (const mode of [
  'password',
  'route',
  'key',
  'certificate',
  'passphrase',
  'empty-passphrase',
  'tamper',
])
  test(
    `isolated SSH credential sender interoperates with native Go (${mode})`,
    { timeout: 60000 },
    async () => {
      const child = spawn(
        fixture,
        ['-test.run=^TestVaultSSHManualSenderInteropFixture$', '-test.timeout=30s'],
        {
          cwd,
          windowsHide: true,
          stdio: 'pipe',
          env: { ...process.env, WORMHOLE_TEST_SSH_MANUAL_INTEROP: mode },
        },
      );
      child.stderr.resume();
      const exited = new Promise<number | null>((resolve, reject) => {
        child.once('exit', resolve);
        child.once('error', reject);
      });
      void exited.catch(() => {});
      const reader = createInterface({ input: child.stdout });
      const next = () =>
        new Promise<string>((resolve, reject) => {
          const timer = setTimeout(() => reject(Error('SSH manual interop timed out')), 30000);
          reader.once('line', (line) => {
            clearTimeout(timer);
            resolve(line);
          });
        });
      try {
        const context = parseVaultSshManualContext(JSON.parse(await next()));
        assert.ok(context);
        if (mode === 'route') assert.equal(context.route!.rowVersion, '9223372036854775807');
        if (mode === 'tamper') context.plan.host.binding.host = 'redirect.example';
        const values = mode.includes('passphrase')
          ? { passphrase: mode === 'empty-passphrase' ? '' : 'explicit-override' }
          : {
              username: '例-user',
              ...(mode === 'key' || mode === 'certificate'
                ? {
                    privateKey: 'document-key',
                    passphrase: 'key-passphrase',
                    ...(mode === 'certificate' ? { certificate: 'document-certificate' } : {}),
                  }
                : { password: 'one-use-browser' }),
            };
        const input = Object.fromEntries(
          ['username', 'password', 'privateKey', 'passphrase', 'certificate'].map((k) => [
            k,
            new TextEncoder().encode(values[k as keyof typeof values] ?? ''),
          ]),
        ) as any;
        const sealed = await sealSshTemporaryCredentials(context, input);
        assert.ok((Object.values(input) as Uint8Array[]).every((v) => v.every((b) => b === 0)));
        const ack = next();
        child.stdin.end(JSON.stringify(sealed) + '\n');
        assert.deepEqual(JSON.parse(await ack), { ok: true });
        assert.equal(await exited, 0);
      } finally {
        reader.close();
        child.stdout.resume();
        assert.equal(
          await stopChildProcess(child, { gracefulTimeoutMs: 1000, forceKillTimeoutMs: 1000 }),
          true,
        );
      }
    },
  );
