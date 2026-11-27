import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { build } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';
const require = createRequire(import.meta.url);
test('VNC surface sends vault identifiers, preserves legacy input and hides ordinary vault password fields in Chromium', async (context) => {
  const output = await build({
    configFile: false,
    logLevel: 'silent',
    define: { 'process.env.NODE_ENV': JSON.stringify('development') },
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('./fixtures/vnc-surface.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'VncSurfaceTests',
      },
    },
  });
  const code = (Array.isArray(output) ? output : [output])
    .flatMap((x) => x.output)
    .filter((x) => x.type === 'chunk')
    .map((x) => (x.type === 'chunk' ? x.code : ''))
    .join('\n');
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vnc-surface-'));
  try {
    writeFileSync(
      join(directory, 'renderer.json'),
      JSON.stringify({
        code: `globalThis.assert=require('node:assert/strict');${code}\nawait VncSurfaceTests.runVncSurfaceTests();\n//# sourceURL=wormhole-vnc-surface.js`,
        coverageThreshold,
      }),
    );
    writeFileSync(
      join(directory, 'harness.cjs'),
      `const assert=require('node:assert/strict');const {readFileSync}=require('node:fs');const {join}=require('node:path');const {app,BrowserWindow}=require('electron');app.disableHardwareAcceleration();app.setPath('userData',__dirname);app.setPath('sessionData',__dirname);const {code,coverageThreshold}=JSON.parse(readFileSync(join(__dirname,'renderer.json'),'utf8'));
app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,width:800,height:600,webPreferences:{nodeIntegration:true,contextIsolation:false,backgroundThrottling:false,offscreen:true}});window.webContents.on('console-message',e=>{if(e.level==='error')console.error(e.message)});try{await window.loadURL('data:text/html,<div id="root" style="width:600px;height:500px"></div>');window.webContents.debugger.attach('1.3');await window.webContents.debugger.sendCommand('Profiler.enable');await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});await window.webContents.executeJavaScript('(async()=>{'+code+'\\n})()');const coverage=await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');const script=coverage.result.find(s=>s.url==='wormhole-vnc-surface.js');assert.ok(script);const fn=script.functions.find(f=>f.functionName==='VncSurface');assert.ok(fn);const extent=fn.ranges[0],ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);const percent=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log('VNC surface V8 block coverage '+percent.toFixed(2)+'%');assert.ok(percent>=coverageThreshold)}finally{window.destroy()}app.quit()}).catch(error=>{console.error(error);app.exit(1)});`,
    );
    const { ELECTRON_RUN_AS_NODE: _, ...env } = process.env;
    const executable = require('electron') as string;
    const headless = process.platform === 'linux' && !env.DISPLAY;
    const args = headless
      ? ['--auto-servernum', executable, join(directory, 'harness.cjs')]
      : [join(directory, 'harness.cjs')];
    const { stdout, stderr } = await promisify(execFile)(headless ? 'xvfb-run' : executable, args, {
      env: { ...env, NODE_ENV: 'test' },
      windowsHide: true,
      timeout: 60000,
    });
    context.diagnostic(stdout.trim());
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
