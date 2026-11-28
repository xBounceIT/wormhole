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

const require = createRequire(import.meta.url);

test('protected vault Settings enroll and remove Windows Hello with actionable feedback', async (context) => {
  const bundle = await build({
    configFile: false,
    logLevel: 'silent',
    esbuild: { jsx: 'automatic' },
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    define: { 'process.env.NODE_ENV': JSON.stringify('development') },
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('./fixtures/vault-hello-settings.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'HelloSettingsFixture',
      },
    },
  });
  const chunk = (Array.isArray(bundle) ? bundle : [bundle])
    .flatMap((result) => result.output)
    .find((output) => output.type === 'chunk');
  assert.ok(chunk?.type === 'chunk');
  const script = `${chunk.code}\nHelloSettingsFixture.exercise();\n//# sourceURL=vault-hello-settings-fixture.js`;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-hello-settings-'));
  try {
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
      const { app, BrowserWindow } = require('electron');
      app.disableHardwareAcceleration();
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true, backgroundThrottling: false } });
        try {
          await window.loadURL('data:text/html,<html><body></body></html>');
          const debug = window.webContents.debugger;
          debug.attach('1.3');
          await debug.sendCommand('Profiler.enable');
          await debug.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
          await window.webContents.executeJavaScript(${JSON.stringify(script)});
          const report = await debug.sendCommand('Profiler.takePreciseCoverage');
          const entry = report.result.find(script => script.url === 'vault-hello-settings-fixture.js');
          for (const name of ['VaultPresenceSettings', 'ProfileChoice']) {
          const range = entry?.functions.find(fn => fn.functionName === name)?.ranges[0];
          if (!range) throw Error('Missing coverage for ' + name);
          const blocks = entry.functions.filter(fn => fn.ranges[0].startOffset >= range.startOffset && fn.ranges[0].endOffset <= range.endOffset).flatMap(fn => fn.ranges);
          const coverage = 100 * blocks.filter(block => block.count > 0).length / blocks.length;
          console.log(name + ': ' + coverage.toFixed(2) + '% V8 blocks');
          if (coverage < ${coverageThreshold}) throw Error(name + ' coverage below ${coverageThreshold}%');
          }
        } finally { window.destroy(); }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const { stdout } = await promisify(execFile)(require('electron'), [harness], {
      cwd: resolve(import.meta.dirname, '..'),
      timeout: 45_000,
    });
    context.diagnostic(stdout.trim());
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});
