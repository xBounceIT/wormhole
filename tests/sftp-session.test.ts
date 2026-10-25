import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { build } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

test('File transfer tabs browse trees, route shortcuts and manage editor saves in Chromium', async (context) => {
  const output = await build({
    configFile: false,
    logLevel: 'silent',
    define: { 'process.env.NODE_ENV': JSON.stringify('development') },
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('./fixtures/sftp-session.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'SftpSessionTests',
      },
    },
  });
  const bundle = (Array.isArray(output) ? output : [output])
    .flatMap((result) => result.output)
    .filter((item) => item.type === 'chunk')
    .map((item) => (item.type === 'chunk' ? item.code : ''))
    .join('\n');
  const renderer = `globalThis.assert = require('node:assert/strict'); globalThis.crypto.randomUUID = require('node:crypto').randomUUID;${bundle}\nSftpSessionTests.runSftpSessionTests().catch(error => { for (const item of error.errors ?? [error]) console.error(item.stack ?? item); throw error; });\n//# sourceURL=wormhole-sftp-session.js`;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-sftp-session-'));
  try {
    const harness = join(directory, 'session.cjs');
    writeFileSync(
      harness,
      `const assert=require('node:assert/strict');const {app,BrowserWindow}=require('electron');app.setPath('userData',${JSON.stringify(directory)});app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,width:1300,height:900,webPreferences:{nodeIntegration:true,contextIsolation:false,backgroundThrottling:false}});window.webContents.on('console-message',(event)=>{if(event.level==='error')console.error(event.message)});try{await window.loadURL('data:text/html,<div id="root"></div>');window.webContents.debugger.attach('1.3');await window.webContents.debugger.sendCommand('Profiler.enable');await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});const source=${JSON.stringify(renderer)};await window.webContents.executeJavaScript(source);const coverage=await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');const script=coverage.result.find(item=>item.url==='wormhole-sftp-session.js');assert.ok(script);const failures=[];for(const name of ['SftpBrowserSurface','SftpDirectoryTree','SftpEditorSettings','SftpEditedFiles','SftpRecoveryNotice']){const fn=script.functions.find(item=>item.functionName===name);assert.ok(fn,'Missing '+name);const ranges=script.functions.flatMap(item=>item.ranges).filter(range=>range.startOffset>=fn.ranges[0].startOffset&&range.endOffset<=fn.ranges[0].endOffset);const percent=100*ranges.filter(range=>range.count>0).length/ranges.length;console.log(name+': V8 block coverage '+percent.toFixed(2)+'%');if(percent<${coverageThreshold})failures.push(name);}assert.deepEqual(failures,[]);}finally{window.destroy()}app.quit()}).catch(error=>{console.error(error);app.exit(1)});`,
    );
    const require = createRequire(import.meta.url);
    const electron = require('electron') as string;
    const { ELECTRON_RUN_AS_NODE: _runAsNode, ...environment } = process.env;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const result = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...environment, NODE_ENV: 'test' }, windowsHide: true, timeout: 60000 },
    );
    context.diagnostic(result.stdout.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
