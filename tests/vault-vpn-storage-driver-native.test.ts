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
import { coverageThreshold } from '../scripts/test-coverage.ts';
const require = createRequire(import.meta.url);

test(
  'native session driver restores scoped DOM/IDB/cookies offline, preserving third-party keys and fresh bearer isolation',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-vpn-driver-'));
    try {
      const output = await build({
        configFile: false,
        logLevel: 'silent',
        ssr: { noExternal: true },
        build: {
          ssr: true,
          write: false,
          minify: false,
          rolldownOptions: {
            input: fileURLToPath(new URL('./fixtures/vpn-storage-driver-main.ts', import.meta.url)),
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
      const { ELECTRON_RUN_AS_NODE: _, ...env } = process.env;
      const electron = require('electron') as string,
        headless = process.platform === 'linux' && !env.DISPLAY;
      const running = promisify(execFile)(
        headless ? 'xvfb-run' : electron,
        headless ? ['--auto-servernum', electron, script] : [script],
        {
          env: { ...env, WORMHOLE_STORAGE_DIRECTORY: directory },
          windowsHide: true,
          timeout: 150000,
        },
      );
      running.child.stderr?.on('data', (chunk) => process.stderr.write(chunk));
      const { stdout } = await running;
      const result = JSON.parse(stdout.trim());
      assert.equal(result.ok, true);
      console.log(
        'Native VPN storage driver V8 block coverage ' + result.coverage.toFixed(2) + '%',
      );
      assert.ok(result.coverage >= coverageThreshold);
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  },
);
