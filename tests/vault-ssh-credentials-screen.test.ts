import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { build } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';
const require = createRequire(import.meta.url);
test(
  'SSH credential document encrypts inside sandboxed Chromium and clears its DOM on every boundary',
  { timeout: 60000 },
  async (t) => {
    const output = await build({
      configFile: false,
      logLevel: 'silent',
      build: {
        write: false,
        minify: false,
        lib: {
          entry: fileURLToPath(new URL('./fixtures/ssh-credentials-screen.ts', import.meta.url)),
          formats: ['iife'],
          name: 'PasswordTests',
        },
      },
    });
    const code = (Array.isArray(output) ? output : [output])
      .flatMap((o) => o.output)
      .filter((o) => o.type === 'chunk')
      .map((o) => (o.type === 'chunk' ? o.code : ''))
      .join('\n');
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-ssh-credentials-screen-'));
    try {
      await writeFile(
        join(directory, 'startup.css'),
        await readFile(new URL('../src/startup.css', import.meta.url)),
      );
      await writeFile(
        join(directory, 'index.html'),
        '<!doctype html><html><link rel="stylesheet" href="startup.css"><body></body></html>',
      );
      await writeFile(
        join(directory, 'renderer.json'),
        JSON.stringify({
          code:
            code +
            '\nawait PasswordTests.runSshCredentialsScreenTests();\n//# sourceURL=wormhole-ssh-credentials-screen.js',
          coverageThreshold,
        }),
      );
      await writeFile(
        join(directory, 'main.cjs'),
        `const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');const {readFileSync}=require('node:fs');const {join}=require('node:path');app.disableHardwareAcceleration();app.setPath('userData',__dirname);app.setPath('sessionData',__dirname);const {code,coverageThreshold}=JSON.parse(readFileSync(join(__dirname,'renderer.json'),'utf8'));
app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,offscreen:true,backgroundThrottling:false}});try{await window.loadFile(join(__dirname,'index.html'));const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});await window.webContents.executeJavaScript('(async()=>{'+code+'\\n})()');const report=await debug.sendCommand('Profiler.takePreciseCoverage');const script=report.result.find(s=>s.url==='wormhole-ssh-credentials-screen.js');assert.ok(script);const fn=script.functions.find(f=>f.functionName==='mountVaultSshCredentialsScreen');assert.ok(fn);const extent=fn.ranges[0],ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);const percent=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log('SSH credentials screen '+percent.toFixed(2)+'% V8 blocks');assert.ok(percent>=coverageThreshold);}finally{window.destroy();}app.quit();}).catch(e=>{console.error(e);app.exit(1);});`,
      );
      const { ELECTRON_RUN_AS_NODE: _, ...env } = process.env,
        electron = require('electron') as string;
      const headless = process.platform === 'linux' && !env.DISPLAY;
      const { stdout, stderr } = await promisify(execFile)(
        headless ? 'xvfb-run' : electron,
        headless
          ? ['--auto-servernum', electron, join(directory, 'main.cjs')]
          : [join(directory, 'main.cjs')],
        { env, windowsHide: true, timeout: 45000 },
      );
      assert.match(stdout, /SSH credentials screen/);
      t.diagnostic(stdout.trim());
      if (stderr.trim()) t.diagnostic(stderr.trim());
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
    }
  },
);
