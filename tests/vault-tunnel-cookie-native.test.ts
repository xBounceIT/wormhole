import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { build } from 'vite';
import {
  parseVaultTunnelCookieChallenge,
  parseVaultTunnelCookieEnvelope,
} from '../electron/vault-tunnel-cookie.ts';
import { stopChildProcess } from '../electron/rdp.ts';
const require = createRequire(import.meta.url),
  cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
let directory: string, fixture: string;
before(
  async () => {
    directory = await mkdtemp(join(tmpdir(), 'wormhole-vault-cookie-'));
    fixture = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
    await promisify(execFile)('go', ['test', '-c', '-o', fixture, '.'], {
      cwd,
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
          input: fileURLToPath(
            new URL('../electron/vault-tunnel-browser-dialog.ts', import.meta.url),
          ),
          output: { format: 'cjs' },
          external: ['electron', 'node:crypto'],
        },
      },
    });
    const chunks = (Array.isArray(output) ? output : [output])
      .flatMap((o) => o.output)
      .filter((o) => o.type === 'chunk');
    assert.equal(chunks.length, 1);
    await writeFile(join(directory, 'dialog.cjs'), chunks[0].code);
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
  'ready',
  'ready-redirect',
  'ready-late',
  'ready-large',
  'ready-callback',
  'ready-callback-navigation',
  'callback-untrusted-source',
  'cancel',
  'no-http-only',
  'expired',
])
  test(
    'isolated Chromium SSL authentication completes the native Go attempt (' + mode + ')',
    { timeout: 60000 },
    async () => {
      const child = spawn(
        fixture,
        ['-test.run=^TestVaultTunnelCookieInteropFixture$', '-test.timeout=30s'],
        {
          cwd,
          windowsHide: true,
          stdio: 'pipe',
          env: { ...process.env, WORMHOLE_TEST_COOKIE_INTEROP: mode },
        },
      );
      child.stderr.resume();
      const exited = new Promise<number | null>((r, j) => {
        child.once('exit', r);
        child.once('error', j);
      });
      void exited.catch(() => {});
      const reader = createInterface({ input: child.stdout }),
        lines = reader[Symbol.asyncIterator]();
      const next = async () => {
        const row = await lines.next();
        assert.equal(row.done, false);
        return JSON.parse(row.value);
      };
      try {
        const { binding } = await next(),
          context = parseVaultTunnelCookieChallenge(await next(), binding);
        assert.ok(context);
        assert.equal(context.binding.rowVersion, '9223372036854775807');
        const browser = join(directory, mode);
        await mkdir(browser);
        await writeFile(join(browser, 'context.json'), JSON.stringify(context));
        await writeFile(
          join(browser, 'main.cjs'),
          `const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');const {readFileSync}=require('node:fs');const {join}=require('node:path');const {VaultTunnelBrowserDialog}=require('../dialog.cjs');app.disableHardwareAcceleration();app.setPath('userData',__dirname);app.setPath('sessionData',__dirname);app.whenReady().then(async()=>{const parent=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false}});let window;const dialog=new VaultTunnelBrowserDialog({createWindow:options=>{assert.equal(options.webPreferences.preload,undefined);window=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});window.show=()=>{};return window;}});const context=JSON.parse(readFileSync(join(__dirname,'context.json'),'utf8'));const controller=new AbortController();if(!${JSON.stringify(mode)}.startsWith('ready'))setTimeout(()=>controller.abort(),${mode === 'callback-untrusted-source' ? 2500 : 100});try{const envelope=await dialog.open(parent,()=>true,context,controller.signal);assert.equal(window.isDestroyed(),true);console.log(JSON.stringify(envelope));}catch{assert.equal(!${JSON.stringify(mode)}.startsWith('ready'),true);assert.equal(window.isDestroyed(),true);console.log(JSON.stringify({cancelled:true}));}finally{await dialog.cancelChallenge(context);parent.destroy();}app.quit();}).catch(error=>{console.error(error);app.exit(1);});`,
        );
        const { ELECTRON_RUN_AS_NODE: _, ...env } = process.env,
          electron = require('electron') as string,
          headless = process.platform === 'linux' && !env.DISPLAY;
        const { stdout } = await promisify(execFile)(
          headless ? 'xvfb-run' : electron,
          headless
            ? ['--auto-servernum', electron, join(browser, 'main.cjs')]
            : [join(browser, 'main.cjs')],
          { env, windowsHide: true, timeout: 20000 },
        );
        const envelope = JSON.parse(stdout.trim());
        if (mode.startsWith('ready')) {
          assert.ok(parseVaultTunnelCookieEnvelope(envelope));
          child.stdin.end(JSON.stringify(envelope) + '\n');
        } else {
          assert.deepEqual(envelope, { cancelled: true });
          child.stdin.end();
        }
        assert.deepEqual(await next(), { ok: true });
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
