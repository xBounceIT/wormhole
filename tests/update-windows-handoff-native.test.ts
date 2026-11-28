import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { completeWindowsUpdateHandoff } from '../electron/update-installer.ts';

test(
  'Electron confirms a real Windows update worker using a signed fixture release',
  { skip: process.platform !== 'win32', timeout: 180_000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-handoff-'));
    t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }));
    const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
    const options = { cwd, windowsHide: true, timeout: 120_000 };
    const cache = join(directory, 'cache', 'updates');
    await mkdir(cache, { recursive: true });
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const pin = Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url').toString('hex');
    const worker = join(directory, 'backend.exe');
    execFileSync(
      'go',
      ['build', '-ldflags', '-X main.updateManifestPublicKeyHex=' + pin, '-o', worker, '.'],
      options,
    );
    const name = 'Wormhole-9.8.7-win-' + process.arch + '-setup.exe';
    const image = join(cache, name);
    for (const suffix of [
      'mac-universal-setup.dmg',
      'arm64.AppImage',
      'x86_64.AppImage',
      process.arch === 'arm64' ? 'win-x64-setup.exe' : 'win-arm64-setup.exe',
    ]) {
      await writeFile(join(cache, 'Wormhole-9.8.7-' + suffix), 'fixture');
    }
    execFileSync('go', ['build', '-o', image, './testdata/update-installer'], options);
    const seed = Buffer.from(privateKey.export({ format: 'jwk' }).d!, 'base64url');
    try {
      execFileSync('go', ['run', './cmd/sign-update-manifest', 'v9.8.7', cache, pin], {
        ...options,
        input: seed.toString('hex'),
      });
    } finally {
      seed.fill(0);
    }
    const bytes = await readFile(image);
    const request = {
      installerFileName: name,
      installerUrl: 'https://github.com/xBounceIT/wormhole/releases/download/v9.8.7/' + name,
      installerSize: bytes.length,
      installerSha256: createHash('sha256').update(bytes).digest('hex'),
      currentVersion: '9.8.6',
      signedManifest: (await readFile(join(cache, 'Wormhole-UpdateManifest-v1.json'))).toString(
        'base64',
      ),
    };
    const start = () =>
      spawn(
        worker,
        ['--operation', 'update-install-windows', '--database', join(directory, 'workspace.db')],
        { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true },
      );
    await assert.rejects(
      completeWindowsUpdateHandoff(start(), request, async () => {
        throw Error('Vault locked');
      }),
      /Vault locked/,
    );
    const record = image + '.args';
    await assert.rejects(readFile(record), { code: 'ENOENT' });
    await completeWindowsUpdateHandoff(start(), request, async (publisher, commit) => {
      assert.equal(publisher, false);
      commit(false);
    });
    // The worker has exited; the verified installer owns its remaining handles.
    const deadline = Date.now() + 10_000;
    while (true) {
      try {
        const args = await readFile(record, 'utf8');
        if (args) {
          assert.equal(args, '/SILENT /NORESTART /NORESTARTAPPLICATIONS');
          break;
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      assert.ok(Date.now() < deadline, 'The installer did not record its arguments');
      await delay(20);
    }
    await rm(record);
  },
);
