import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { build } from 'vite';
import tailwindcss from '@tailwindcss/vite';

test('RDP renders pixels and owns input, visibility and lifecycle inside its tab', async (t) => {
  const output = await build({
    configFile: false,
    logLevel: 'silent',
    plugins: [tailwindcss()],
    define: { 'process.env.NODE_ENV': JSON.stringify('development') },
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('./fixtures/rdp-canvas.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'CanvasTests',
      },
    },
  });
  const bundle = (Array.isArray(output) ? output : [output])
    .flatMap((item) => item.output)
    .filter((item) => item.type === 'chunk')
    .map((item) => item.code)
    .join('\n');
  const css = (Array.isArray(output) ? output : [output])
    .flatMap((item) => item.output)
    .filter((item) => item.type === 'asset' && item.fileName.endsWith('.css'))
    .map((item) => String(item.source))
    .join('\n');
  assert.ok(css.length > 0);
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-rdp-canvas-'));
  const harness = join(directory, 'test.cjs');
  const renderer = `const style = document.createElement('style'); style.textContent = ${JSON.stringify(css)}; document.head.append(style); globalThis.assert = require('node:assert/strict'); ${bundle}\nCanvasTests.runRdpCanvasTests();\n//# sourceURL=wormhole-rdp-canvas.js`;
  writeFileSync(
    harness,
    `
    const { app, BrowserWindow } = require('electron');
    const assert = require('node:assert/strict');
    app.whenReady().then(async () => {
      const window = new BrowserWindow({ show: false, webPreferences: { nodeIntegration: true, contextIsolation: false, backgroundThrottling: false } });
      try {
        await window.loadURL('data:text/html,<style>html,body,%23root{height:100%;margin:0}</style><div id="root"></div>');
        window.webContents.debugger.attach('1.3');
        await window.webContents.debugger.sendCommand('Profiler.enable');
        await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
        await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
        const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
        const script = coverage.result.find(item => item.url === 'wormhole-rdp-canvas.js');
        const component = script.functions.find(item => item.functionName === 'RdpCanvas');
        assert.ok(component);
        const [componentRange] = component.ranges;
        const componentFunctions = script.functions.filter(item => item.ranges[0].startOffset >= componentRange.startOffset && item.ranges[0].endOffset <= componentRange.endOffset);
        const ranges = componentFunctions.flatMap(item => item.ranges);
        const componentCoverage = ranges.filter(item => item.count > 0).length * 100 / ranges.length;
        console.log('RdpCanvas and callbacks V8 blocks: ' + componentCoverage.toFixed(1) + '%');
        assert.ok(componentCoverage >= 80, 'Canvas callback coverage below 80%');
        const surface = script.functions.find(item => item.functionName === 'RdpSurface');
        assert.ok(surface);
        const surfaceCoverage = surface.ranges.filter(item => item.count > 0).length * 100 / surface.ranges.length;
        console.log('RdpSurface V8 blocks: ' + surfaceCoverage.toFixed(1) + '%');
        assert.ok(surfaceCoverage >= 80);
        for (const name of ['RdpCanvas', 'pointer', 'key', 'wheel', 'composition']) {
          const fn = script.functions.find(item => item.functionName === name && item.ranges[0].startOffset >= componentRange.startOffset && item.ranges[0].endOffset <= componentRange.endOffset);
          assert.ok(fn, 'missing coverage for ' + name);
          const percent = fn.ranges.filter(item => item.count > 0).length * 100 / fn.ranges.length;
          console.log(name + ' V8 blocks: ' + percent.toFixed(1) + '%');
          assert.ok(percent >= 80, name + ' coverage below 80%');
        }
      } finally { window.destroy(); }
      app.quit();
    }).catch(error => { console.error(error); app.exit(1); });
  `,
  );
  const environment = { ...process.env, NODE_ENV: 'test' };
  delete environment.ELECTRON_RUN_AS_NODE;
  try {
    const electron = createRequire(import.meta.url)('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const result = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      {
        env: environment,
        timeout: 45000,
        windowsHide: true,
      },
    );
    for (const line of result.stdout.trim().split(/\r?\n/)) t.diagnostic(line);
    assert.ok(result.stdout.includes('RdpCanvas'));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
