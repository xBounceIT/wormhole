import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import { buildVaultBitwardenBridge } from '../scripts/Build-VaultBitwardenBridge.mjs';
const require = createRequire(import.meta.url);

test(
  'native extension endpoint enforces sandbox admission and exchanges sealed Go state on supported hosts',
  { timeout: 180000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-endpoint-native-'));
    try {
      await mkdir(join(directory, 'profile'));
      const path = join(directory, 'extension');
      await mkdir(path);
      await writeFile(
        join(path, 'manifest.json'),
        JSON.stringify({
          manifest_version: 2,
          name: 'Wormhole endpoint fixture',
          version: '1.0.0',
          permissions: ['storage'],
          background: { scripts: ['background.js'], persistent: true },
        }),
      );
      await writeFile(
        join(path, 'background.js'),
        `
globalThis.bitwardenMain={memoryStorageForStateProviders:{store:{},save:async function(k,v){this.store[k]=JSON.stringify(v)},remove:async function(k){delete this.store[k]}}};
globalThis.fixtureLogin=()=>new Promise(yes=>{bitwardenMain.memoryStorageForStateProviders.store.token=JSON.stringify('endpoint-native-private-session');chrome.storage.local.set({account:'endpoint-native-private-account'},yes)});
globalThis.fixtureMatches=wantSession=>new Promise(yes=>chrome.storage.local.get(null,v=>yes(v.account==='endpoint-native-private-account'&&(wantSession?bitwardenMain.memoryStorageForStateProviders.store.token===JSON.stringify('endpoint-native-private-session'):bitwardenMain.memoryStorageForStateProviders.store.token===undefined))));
globalThis.fixtureReady=true;
`,
      );
      const executable = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
      await promisify(execFile)('go', ['test', '-c', '-o', executable, '.'], {
        cwd: fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url)),
        timeout: 120000,
        windowsHide: true,
      });
      const asset = await buildVaultBitwardenBridge(directory);
      await build({
        configFile: false,
        logLevel: 'warn',
        ssr: { external: ['electron'], noExternal: true },
        build: {
          ssr: fileURLToPath(new URL('./fixtures/bitwarden-endpoint-main.ts', import.meta.url)),
          outDir: directory,
          emptyOutDir: false,
          rollupOptions: { output: { format: 'cjs', entryFileNames: 'main.cjs' } },
        },
      });
      const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
      const electron = require('electron') as string,
        headless = process.platform === 'linux' && !env.DISPLAY;
      const native = promisify(execFile)(
        headless ? 'xvfb-run' : electron,
        headless
          ? ['--auto-servernum', electron, '--no-sandbox', join(directory, 'main.cjs')]
          : [join(directory, 'main.cjs')],
        {
          env: {
            ...env,
            WORMHOLE_ENDPOINT_TEST_PACKAGE: fileURLToPath(
              new URL('../package.json', import.meta.url),
            ),
            WORMHOLE_ENDPOINT_TEST_DIRECTORY: directory,
            WORMHOLE_ENDPOINT_TEST_EXECUTABLE: executable,
            WORMHOLE_ENDPOINT_TEST_ASSET: asset,
          },
          timeout: 120000,
          windowsHide: true,
          maxBuffer: 2 * 1024 * 1024,
        },
      );
      native.child.stdout?.on('data', (raw: Buffer) => {
        for (const line of raw.toString().split(/\r?\n/))
          if (/^ENDPOINT_STAGE [a-z-]+$/.test(line)) console.log(line);
      });
      const result = await native;
      const line = result.stdout.split(/\r?\n/).find((line) => line.startsWith('{"complete"'));
      assert.ok(line, result.stderr);
      const metadata = JSON.parse(line);
      assert.equal(metadata.complete, true);
      assert.equal(metadata.persistentDiagnosticOnly, true);
      if (process.platform !== 'linux') {
        assert.equal(metadata.nativeSandboxProof, true);
        assert.equal(metadata.restored, true);
        assert.equal(metadata.coldRestart, true);
      } else assert.equal(metadata.nativeSandboxProof, false);
      assert.doesNotMatch(result.stdout, /endpoint-native-private/);
      t.diagnostic(line);
      if (result.stderr.trim()) t.diagnostic(result.stderr);
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
    }
  },
);
