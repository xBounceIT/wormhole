import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import { tunnelBrowserContext } from './fixtures/vault-tunnel-browser.ts';

test(
  'installer runtime closure loads and seals native browser tokens without repository dependencies',
  { timeout: 60000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-vault-saml-package-'));
    try {
      await promisify(execFile)(
        process.execPath,
        [
          fileURLToPath(
            new URL('../scripts/stage-electron-runtime-dependencies.mjs', import.meta.url),
          ),
          fileURLToPath(
            new URL('../installer/electron-runtime-dependencies.json', import.meta.url),
          ),
          fileURLToPath(new URL('../node_modules', import.meta.url)),
          join(directory, 'node_modules'),
        ],
        { windowsHide: true, timeout: 30000 },
      );
      const result = await build({
        configFile: false,
        logLevel: 'silent',
        ssr: { noExternal: true },
        build: {
          ssr: true,
          write: false,
          minify: false,
          rolldownOptions: {
            input: fileURLToPath(new URL('../electron/vault-tunnel-browser.ts', import.meta.url)),
            output: { format: 'cjs' },
            external: ['@hpke/core'],
          },
        },
      });
      const chunks = (Array.isArray(result) ? result : [result])
        .flatMap((o) => o.output)
        .filter((o) => o.type === 'chunk');
      assert.equal(chunks.length, 1);
      assert.match(chunks[0].code, /require\(["']@hpke\/core["']\)/);
      await writeFile(join(directory, 'sender.cjs'), chunks[0].code);
      await writeFile(join(directory, 'context.json'), JSON.stringify(tunnelBrowserContext()));
      const { stdout } = await promisify(execFile)(
        process.execPath,
        [
          '-e',
          "const assert=require('node:assert/strict');const c=require('./context.json');const {sealTunnelBrowserToken,parseVaultTunnelBrowserEnvelope}=require('./sender.cjs');const token=Buffer.from('aB'.repeat(16));sealTunnelBrowserToken(c,token).then(result=>{assert.ok(parseVaultTunnelBrowserEnvelope(result));assert.ok(token.every(v=>v===0));console.log('sealed');}).catch(()=>process.exit(1));",
        ],
        {
          cwd: directory,
          windowsHide: true,
          timeout: 15000,
          env: { ...process.env, NODE_PATH: '' },
        },
      );
      assert.equal(stdout.trim(), 'sealed');
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
    }
  },
);
