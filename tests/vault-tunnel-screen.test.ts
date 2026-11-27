import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);
test('protected tunnel screen handles revisions, failures and closing during asynchronous operations', async (context) => {
  const result = await build({
    configFile: false,
    logLevel: 'silent',
    define: { 'process.env.NODE_ENV': JSON.stringify('development') },
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('./fixtures/vault-tunnel-screen.ts', import.meta.url)),
        formats: ['iife'],
        name: 'VaultTunnelScreenTests',
      },
    },
  });
  const bundle = (Array.isArray(result) ? result : [result])
    .flatMap((item) => item.output)
    .filter((item) => item.type === 'chunk')
    .map((item) => (item.type === 'chunk' ? item.code : ''))
    .join('\n');
  mkdirSync(resolve('artifacts/vault'), { recursive: true });
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-tunnel-screen-'));
  const harness = join(directory, 'editor.cjs');
  const css =
    readFileSync(new URL('../src/startup.css', import.meta.url), 'utf8') +
    readFileSync(new URL('../src/vault-tunnel.css', import.meta.url), 'utf8');
  const renderer = `globalThis.assert = require('node:assert/strict');const style=document.createElement('style');style.textContent=${JSON.stringify(css)};document.head.append(style); ${bundle}\n globalThis.disposeFields = await VaultTunnelScreenTests.runVaultTunnelScreenTests();\n//# sourceURL=wormhole-vault-tunnel-screen.js\n`;
  try {
    writeFileSync(
      join(directory, 'index.html'),
      '<!doctype html><html><body class="vault-tunnel-document"></body></html>',
    );
    writeFileSync(
      join(directory, 'renderer.json'),
      JSON.stringify({ source: '(async () => {' + renderer + '})()', coverageThreshold }),
    );
    writeFileSync(
      harness,
      `const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { app, BrowserWindow } = require('electron');
app.disableHardwareAcceleration();
const { source, coverageThreshold } = JSON.parse(readFileSync(join(__dirname, 'renderer.json'), 'utf8'));
app.setPath('userData', __dirname);
app.setPath('sessionData', __dirname);
app.whenReady().then(async () => {
  const window = new BrowserWindow({ show: false, width:780,height:740, webPreferences: { nodeIntegration: true, contextIsolation: false, backgroundThrottling: false,offscreen:true } });
  try {
    await window.loadFile(join(__dirname, 'index.html'));
    window.webContents.debugger.attach('1.3');
    await window.webContents.debugger.sendCommand('Profiler.enable');
    await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
    await window.webContents.executeJavaScript(source);
    const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
    const script = coverage.result.find(item => item.url === 'wormhole-vault-tunnel-screen.js');
    assert.ok(script);
    for (const name of ['mountVaultTunnelScreen','parseReferences']) {
    const fn = script.functions.find(item => item.functionName === name);
    assert.ok(fn);
    const extent=fn.ranges[0];const ranges=script.functions.filter(f=>f.ranges[0].startOffset>=extent.startOffset&&f.ranges[0].endOffset<=extent.endOffset).flatMap(f=>f.ranges);
    const percent = ranges.filter(item => item.count > 0).length * 100 / ranges.length;
    console.log('Vault tunnel screen '+name+': V8 block coverage ' + percent.toFixed(2) + '%');
    assert.ok(percent >= coverageThreshold);
    }
    await window.webContents.executeJavaScript('window.scrollTo(0,0);');
    await new Promise(r=>setTimeout(r,200));
    require('node:fs').writeFileSync(${JSON.stringify(resolve('artifacts/vault/tunnel-screen.png'))},(await window.webContents.capturePage()).toPNG());
    await window.webContents.executeJavaScript('disposeFields();');
  } finally {
    window.destroy();
  }
  app.quit();
}).catch(error => { console.error(error); app.exit(1); });`,
    );
    const { ELECTRON_RUN_AS_NODE: _runAsNode, ...environment } = process.env;
    const electron = require('electron') as string;
    const headless = process.platform === 'linux' && !environment.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 30_000, windowsHide: true },
    );
    context.diagnostic(stdout.trim());
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
