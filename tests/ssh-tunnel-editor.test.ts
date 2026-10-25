import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { build } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);
test('SSH tunnel fields expose both modes, cycle-safe choices and explicit pin reset in Chromium', async (context) => {
  const result = await build({
    configFile: false,
    logLevel: 'silent',
    define: { 'process.env.NODE_ENV': JSON.stringify('development') },
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('./fixtures/ssh-tunnel-editor.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'SshTunnelTests',
      },
    },
  });
  const bundle = (Array.isArray(result) ? result : [result])
    .flatMap((item) => item.output)
    .filter((item) => item.type === 'chunk')
    .map((item) => (item.type === 'chunk' ? item.code : ''))
    .join('\n');
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-ssh-editor-'));
  const harness = join(directory, 'editor.cjs');
  const renderer = `globalThis.assert = require('node:assert/strict'); ${bundle}\n await SshTunnelTests.runSshTunnelEditorTests();\n//# sourceURL=wormhole-ssh-editor.js\n`;
  try {
    writeFileSync(
      harness,
      `const assert = require('node:assert/strict'); const { app, BrowserWindow } = require('electron'); app.setPath('userData', ${JSON.stringify(directory)}); app.setPath('sessionData', ${JSON.stringify(directory)}); app.whenReady().then(async () => { const window = new BrowserWindow({ show: false, webPreferences: { nodeIntegration: true, contextIsolation: false, backgroundThrottling: false } }); try { await window.loadURL('data:text/html,<div id="root"></div>'); window.webContents.debugger.attach('1.3'); await window.webContents.debugger.sendCommand('Profiler.enable'); await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true }); await window.webContents.executeJavaScript(${JSON.stringify('(async () => {' + renderer + '})()')}); const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage'); const script = coverage.result.find(item => item.url === 'wormhole-ssh-editor.js'); assert.ok(script); const fn = script.functions.find(item => item.functionName === 'SshTunnelFields'); assert.ok(fn); const percent = fn.ranges.filter(item => item.count > 0).length * 100 / fn.ranges.length; console.log('SSH tunnel editor: V8 block coverage ' + percent.toFixed(2) + '%'); assert.ok(percent >= ${coverageThreshold}); } finally { window.destroy(); } app.quit(); }).catch(error => { console.error(error); app.exit(1); });`,
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
