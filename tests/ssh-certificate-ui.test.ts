import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import tailwindcss from '@tailwindcss/vite';
import { build } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);

test('SSH certificate editor renews independently and the connection shortcut selects the saved key', async (context) => {
  const result = await build({
    configFile: false,
    logLevel: 'silent',
    plugins: [tailwindcss()],
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    define: { 'process.env.NODE_ENV': JSON.stringify('development') },
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('./fixtures/ssh-certificate.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'SSHCertificateTests',
      },
    },
  });
  const outputs = (Array.isArray(result) ? result : [result]).flatMap((item) => item.output);
  const script = outputs.find((item) => item.type === 'chunk');
  const css = outputs.find((item) => item.type === 'asset' && item.fileName.endsWith('.css'));
  assert.ok(script?.type === 'chunk');
  assert.ok(css?.type === 'asset');
  const renderer = `globalThis.IS_REACT_ACT_ENVIRONMENT = true; globalThis.crypto.randomUUID = require('node:crypto').randomUUID; window.certificateAssert = require('node:assert/strict');\n${script.code}\nwindow.runCertificateTests();\n//# sourceURL=wormhole-ssh-certificate-ui.js`;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-ssh-certificate-'));
  const harness = join(directory, 'certificate.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harness,
      `const {app,BrowserWindow}=require('electron');
      app.setPath('userData',${JSON.stringify(directory)}); app.setPath('sessionData',${JSON.stringify(directory)});
      app.whenReady().then(async()=>{
        const window=new BrowserWindow({show:false,width:1200,height:900,webPreferences:{nodeIntegration:true,contextIsolation:false,backgroundThrottling:false}});
        window.webContents.on('console-message', details=>console.log(details.message));
        try {
          await window.loadURL('data:text/html,<html class="dark"><style>html,body,%23root{height:100%;margin:0}</style><div id="root"></div></html>');
          await window.webContents.insertCSS(${JSON.stringify(String(css.source))});
          window.webContents.debugger.attach('1.3');
          await window.webContents.debugger.sendCommand('Profiler.enable');
          await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage',{callCount:true,detailed:true});
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
          const coverage=await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
          const script=coverage.result.find(item=>item.url==='wormhole-ssh-certificate-ui.js');
          if(!script)throw new Error('Missing SSH certificate renderer coverage');
          for(const name of ['selectPrivateKey','selectCertificate','credentialDraftFor']){
            const functions=script.functions.filter(item=>item.functionName===name);
            const ranges=functions.flatMap(item=>item.ranges);
            const percent=100*ranges.filter(item=>item.count>0).length/ranges.length;
            console.log(name+': V8 block coverage '+percent.toFixed(2)+'%');
            if(!(percent>=${coverageThreshold}))throw new Error(name+' coverage below ${coverageThreshold}%');
          }
        }finally{window.destroy();}app.quit();
      }).catch(error=>{console.error(error);app.exit(1);});`,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 120000, windowsHide: true },
    );
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
