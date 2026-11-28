import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { build } from 'vite';
const require = createRequire(import.meta.url);
test(
  'real Go root and disposable recipients persist complete Chromium state between two owned native sessions',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-native-vpn-session-'));
    try {
      const backend = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
      await promisify(execFile)('go', ['test', '-c', '-o', backend, '.'], {
        cwd: fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url)),
        windowsHide: true,
        timeout: 120000,
      });
      const output = await build({
        configFile: false,
        logLevel: 'silent',
        ssr: { noExternal: true },
        build: {
          ssr: true,
          write: false,
          minify: false,
          rolldownOptions: {
            input: fileURLToPath(new URL('./fixtures/vpn-session-main.ts', import.meta.url)),
            output: { format: 'cjs' },
            external: ['electron', /^node:/],
          },
        },
      });
      const chunks = (Array.isArray(output) ? output : [output])
        .flatMap((o) => o.output)
        .filter((o) => o.type === 'chunk');
      assert.equal(chunks.length, 1);
      const script = join(directory, 'main.cjs');
      await writeFile(script, chunks[0].code);
      const { ELECTRON_RUN_AS_NODE: _, ...env } = process.env,
        electron = require('electron') as string,
        headless = process.platform === 'linux' && !env.DISPLAY;
      for (const kind of [
        'ssl',
        'ipsec',
        'shared-ssl',
        'shared-ipsec',
        'fallback',
        'shared-fallback',
      ]) {
        const running = promisify(execFile)(
          headless ? 'xvfb-run' : electron,
          headless ? ['--auto-servernum', electron, script] : [script],
          {
            env: {
              ...env,
              WORMHOLE_STORAGE_DIRECTORY: directory,
              WORMHOLE_STORAGE_BACKEND: backend,
              WORMHOLE_STORAGE_KIND: kind,
            },
            windowsHide: true,
            timeout: 90000,
          },
        );
        running.child.stderr?.on('data', (chunk) => process.stderr.write(chunk));
        const { stdout } = await running;
        assert.equal(JSON.parse(stdout.trim()).ok, true);
      }
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  },
);
