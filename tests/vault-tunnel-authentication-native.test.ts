import { build } from 'vite';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { sealTunnelAuthentication } from '../src/vault-tunnel-authentication-sender.ts';
import { parseVaultTunnelAuthenticationContext } from '../electron/vault-tunnel-authentication.ts';
import { stopChildProcess } from '../electron/rdp.ts';
const require = createRequire(import.meta.url);
let directory: string, fixture: string;
const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
before(
  async () => {
    directory = await mkdtemp(join(tmpdir(), 'wormhole-tunnel-authentication-interop-'));
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
for (const mode of ['username', 'fixed', 'tamper', 'browser', 'browser-fixed'])
  test(`VPN factor sender interoperates with native Go (${mode})`, { timeout: 60000 }, async () => {
    const child = spawn(
      fixture,
      ['-test.run=^TestVaultTunnelAuthenticationSenderInteropFixture$', '-test.timeout=30s'],
      {
        cwd,
        windowsHide: true,
        stdio: 'pipe',
        env: { ...process.env, WORMHOLE_TEST_TUNNEL_AUTH_INTEROP: mode },
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
        const timer = setTimeout(() => reject(Error('VPN interop fixture timed out')), 30000);
        reader.once('line', (line) => {
          clearTimeout(timer);
          resolve(line);
        });
      });
    try {
      const context = parseVaultTunnelAuthenticationContext(JSON.parse(await next()));
      assert.ok(context);
      assert.equal(context.binding.rowVersion, '9223372036854775807');
      assert.equal(context.binding.configurationVersion, '9223372036854775806');
      const input = new TextEncoder().encode('one-use-browser');
      const username = new TextEncoder().encode(context.usernameRequired ? 'utente-é' : '');
      if (mode === 'tamper') context.binding.host = 'redirect.example';
      const sealed = mode.startsWith('browser')
        ? await browserAuthentication(context)
        : await sealTunnelAuthentication(context, username, input);
      if (mode.startsWith('browser')) {
        input.fill(0);
        username.fill(0);
      }
      assert.ok(input.every((v) => v === 0) && username.every((v) => v === 0));
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
  });

async function browserAuthentication(context: unknown) {
  const browserDirectory = join(directory, 'browser');
  await mkdir(browserDirectory, { recursive: true });
  const renderer = await build({
    configFile: false,
    logLevel: 'silent',
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('../src/vault-tunnel-authentication.ts', import.meta.url)),
        formats: ['iife'],
        name: 'PasswordDocument',
      },
    },
  });
  const main = await build({
    configFile: false,
    logLevel: 'silent',
    build: {
      ssr: true,
      write: false,
      minify: false,
      rolldownOptions: {
        input: fileURLToPath(
          new URL('../electron/vault-tunnel-authentication-dialog.ts', import.meta.url),
        ),
        output: { format: 'cjs' },
        external: ['electron', 'node:crypto'],
      },
    },
  });
  const entry = (output: any) => {
    const chunks = (Array.isArray(output) ? output : [output])
      .flatMap((o) => o.output)
      .filter((o: any) => o.type === 'chunk');
    assert.equal(chunks.length, 1);
    return chunks[0].code;
  };
  await writeFile(join(browserDirectory, 'screen.js'), entry(renderer));
  await writeFile(join(browserDirectory, 'dialog.cjs'), entry(main));
  const preload = stripTypeScriptTypes(
    await readFile(
      new URL('../electron/vault-tunnel-authentication-preload.cts', import.meta.url),
      'utf8',
    ),
  ).replace(
    /import\s*{\s*contextBridge,\s*ipcRenderer\s*}\s*from 'electron';/,
    "const {contextBridge, ipcRenderer} = require('electron');",
  );
  await writeFile(join(browserDirectory, 'preload.cjs'), preload);
  await writeFile(join(browserDirectory, 'context.json'), JSON.stringify(context));
  await writeFile(
    join(browserDirectory, 'document.html'),
    `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'"><section class="startup-card"></section><script src="screen.js"></script><script src="test-input.js"></script>`,
  );
  await writeFile(
    join(browserDirectory, 'test-input.js'),
    `if(typeof require!=='undefined'||typeof process!=='undefined'||window.wormhole)throw Error('Node/app exposed');
const api=window.vaultTunnelAuthentication;if(JSON.stringify(Object.keys(api).sort())!==JSON.stringify(['cancel','contentProtectionAvailable','context','submit']))throw Error('unexpected password bridge');
(async()=>{const deadline=Date.now()+10000;let input;do{await new Promise(r=>setTimeout(r,5));input=document.querySelector('input[type=password]')}while(input.disabled&&Date.now()<deadline);if(input.disabled)throw Error('password context missing');const name=document.querySelector('input[type=text]');if(!name.disabled)name.value='utente-é';input.value='one-use-browser';document.querySelector('form').dispatchEvent(new Event('submit',{cancelable:true}));if(input.value!==''||name.value!=='')throw Error('DOM password retained');})().catch(()=>api.cancel());`,
  );
  await writeFile(
    join(browserDirectory, 'main.cjs'),
    `const {app,BrowserWindow,ipcMain}=require('electron');const assert=require('node:assert/strict');const {readFileSync}=require('node:fs');const {join}=require('node:path');const {pathToFileURL}=require('node:url');const {VaultTunnelAuthenticationDialog}=require('./dialog.cjs');app.disableHardwareAcceleration();app.setPath('userData',__dirname);app.setPath('sessionData',__dirname);
app.whenReady().then(async()=>{const parent=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false}});let child;
const dialog=new VaultTunnelAuthenticationDialog({ipc:{handle:(channel,fn)=>ipcMain.handle(channel,(event,...args)=>{assert.equal(JSON.stringify(args).includes('one-use-browser')||JSON.stringify(args).includes('utente-é'),false);return fn(event,...args);})},createWindow:options=>{child=new BrowserWindow({...options,webPreferences:{...options.webPreferences,offscreen:true,backgroundThrottling:false}});child.show=()=>{};return child;},url:pathToFileURL(join(__dirname,'document.html')).href,preload:join(__dirname,'preload.cjs')});
try{const envelope=await dialog.open(parent,()=>true,JSON.parse(readFileSync(join(__dirname,'context.json'),'utf8')),new AbortController().signal);assert.equal(child.isDestroyed(),true);console.log(JSON.stringify(envelope));}finally{dialog.cancel();parent.destroy();}app.quit();}).catch(error=>{console.error(error);app.exit(1)});`,
  );
  const { ELECTRON_RUN_AS_NODE: _, ...env } = process.env,
    electron = require('electron') as string;
  const headless = process.platform === 'linux' && !env.DISPLAY;
  const { stdout } = await promisify(execFile)(
    headless ? 'xvfb-run' : electron,
    headless
      ? ['--auto-servernum', electron, join(browserDirectory, 'main.cjs')]
      : [join(browserDirectory, 'main.cjs')],
    { env, windowsHide: true, timeout: 20000 },
  );
  return JSON.parse(stdout.trim());
}
