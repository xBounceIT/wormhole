import assert from 'node:assert/strict';
import test from 'node:test';
import { build } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { coverageThreshold } from '../scripts/test-coverage.ts';

test('shared catalog mounts real terminals and file tabs with owned reconnect and revocation in Chromium', async (t) => {
  const output = await build({
    configFile: false,
    logLevel: 'silent',
    define: { 'process.env.NODE_ENV': JSON.stringify('development') },
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    plugins: [tailwindcss()],
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('./fixtures/shared-workspace.ts', import.meta.url)),
        formats: ['iife'],
        name: 'SharedWorkspaceTests',
      },
    },
  });
  const assets = (Array.isArray(output) ? output : [output]).flatMap((r) => r.output);
  const bundle = assets
    .filter((a) => a.type === 'chunk')
    .map((a) => a.code)
    .join('\n');
  const css = assets
    .filter((a) => a.type === 'asset' && a.fileName.endsWith('.css'))
    .map((a) => String(a.source))
    .join('\n');
  assert.ok(css.length > 0);
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-shared-workspace-'));
  try {
    writeFileSync(
      join(directory, 'renderer.js'),
      bundle + '\n//# sourceURL=wormhole-shared-workspace.js',
    );
    writeFileSync(join(directory, 'layout.css'), css);
    writeFileSync(
      join(directory, 'index.html'),
      '<!doctype html><html><head><link rel="stylesheet" href="layout.css"></head><body></body></html>',
    );
    const screenshotDirectory = process.env.WORMHOLE_TEST_SCREENSHOTS;
    if (screenshotDirectory) mkdirSync(screenshotDirectory, { recursive: true });
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
 const assert=require('node:assert/strict'),{readFileSync,writeFileSync}=require('node:fs'),{app,BrowserWindow}=require('electron');
 app.setPath('userData',${JSON.stringify(directory)});
 app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,width:1360,height:850,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,backgroundThrottling:false}});try{
 await window.loadURL(${JSON.stringify(pathToFileURL(join(directory, 'index.html')).href)});
 if(process.env.WORMHOLE_TEST_SCREENSHOTS)await window.webContents.insertCSS('*, *::before, *::after { transition: none !important; }');
 const debug=window.webContents.debugger;debug.attach('1.3');await debug.sendCommand('Emulation.setFocusEmulationEnabled',{enabled:true});await debug.sendCommand('Profiler.enable');await debug.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});
 async function capture(filename) {
   const destination = process.env.WORMHOLE_TEST_SCREENSHOTS;
   if (!destination) return;
   const expected = await window.webContents.executeJavaScript('document.fonts.ready.then(() => ({ dark: document.documentElement.classList.contains("dark"), width: innerWidth, height: innerHeight }))');
   // A hidden window may return its previous painted surface after a resize or theme change.
   for (let attempt = 0; attempt < 20; attempt++) {
     const image = await window.webContents.capturePage(undefined, { stayHidden: true, stayAwake: true });
     const { width, height } = image.getSize();
     if (width === expected.width && height === expected.height) {
       const corner = image.toBitmap({ scaleFactor: 1 })[0];
       if (expected.dark ? corner < 100 : corner > 175) {
         writeFileSync(require('node:path').join(destination, filename), image.toPNG());
         return;
       }
     }
     await new Promise(resolve => setTimeout(resolve, 25));
   }
   throw Error('Workspace did not paint its requested size and theme: ' + filename);
 }
 const viewport=async(width,height)=>{
   window.setContentSize(width,height);
   await debug.sendCommand('Emulation.setDeviceMetricsOverride',{width,height,mobile:false,deviceScaleFactor:1});
   assert.deepEqual(await window.webContents.executeJavaScript('[innerWidth,innerHeight]'),[width,height]);
 };
 await viewport(1360,850);
 await window.webContents.executeJavaScript(readFileSync(${JSON.stringify(join(directory, 'renderer.js'))},'utf8'));
 const result=await window.webContents.executeJavaScript(${JSON.stringify(
   `SharedWorkspaceTests.runSharedWorkspaceTests('${screenshotDirectory ? 'verified' : 'off'}')`,
 )});assert.equal(result.sessions,2);assert.equal(result.opens,4);
 const shellBounds=await window.webContents.executeJavaScript('(()=>{const card=document.querySelector(".shared-workspace").getBoundingClientRect();const sidebar=document.querySelector(".shared-workspace-sidebar").getBoundingClientRect();const signOut=[...document.querySelectorAll("button")].find(b=>b.textContent==="Sign out").getBoundingClientRect();return [card.x,card.y,card.width===innerWidth,signOut.width<sidebar.width/2]})()');assert.deepEqual(shellBounds,[0,0,true,true]);
 await capture('shared-connect-workspace.png');
 await viewport(600,820);
 const narrow=await window.webContents.executeJavaScript('({width:innerWidth,scroll:document.documentElement.scrollWidth,top:document.querySelector(".startup-card").getBoundingClientRect().top,panel:document.querySelector(".shared-session-panel").getBoundingClientRect().height})');assert.ok(narrow.scroll<=narrow.width+1&&narrow.top>=0&&narrow.panel>=400,JSON.stringify(narrow));await capture('shared-connect-workspace-narrow.png');
 await window.webContents.executeJavaScript('SharedWorkspaceTests.checkCompactWorkspace()');
 await viewport(1360,850);await window.webContents.executeJavaScript('document.documentElement.classList.remove("dark")');await capture('shared-connect-workspace-light.png');
 await window.webContents.executeJavaScript('SharedWorkspaceTests.finishSharedWorkspaceTests()');
 await window.webContents.executeJavaScript('SharedWorkspaceTests.checkSharedWebSurface()');
 await window.webContents.executeJavaScript('SharedWorkspaceTests.checkSharedSerialSurface()');
 await window.webContents.executeJavaScript('SharedWorkspaceTests.checkSharedRenderFailure()');
 const report=await debug.sendCommand('Profiler.takePreciseCoverage'),script=report.result.find(s=>s.url==='wormhole-shared-workspace.js');assert.ok(script);
 for(const name of ['VaultSecurityProfile','SharedSecuritySettings','SharedUpdateControls','SharedSessionsView','SharedVncSurface','SharedRdpSurface','TerminalSurface','mountSharedWorkspace','copyTextToClipboard','writeClipboardText']){const fn=script.functions.find(f=>f.functionName===name);assert.ok(fn,name);const extent=fn.ranges[0],ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges),percent=100*ranges.filter(r=>r.count>0).length/ranges.length;console.log(name+': '+percent.toFixed(2)+'% V8 blocks');assert.ok(percent>=${coverageThreshold},name+' coverage');}
 }finally{window.destroy()}app.quit()}).catch(error=>{console.error(error);app.exit(1)});`,
    );
    const require = createRequire(import.meta.url),
      electron = require('electron') as string,
      { ELECTRON_RUN_AS_NODE: _, ...env } = process.env,
      needsDisplay = process.platform === 'linux' && !env.DISPLAY;
    const result = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...env, NODE_ENV: 'test' }, windowsHide: true, timeout: 60000 },
    );
    t.diagnostic(result.stdout.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
