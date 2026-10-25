import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { build } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);

// The repository's Node coverage excludes TSX and process entrypoints. Exercise the real
// component, preload command, validator and main-process handler against native WebContents.
test('HTTPS text buttons zoom only the native page and honor connection visibility', async (context) => {
  const output = await build({
    configFile: false,
    logLevel: 'silent',
    define: { 'process.env.NODE_ENV': JSON.stringify('development') },
    resolve: { alias: { '@': fileURLToPath(new URL('../src', import.meta.url)) } },
    build: {
      write: false,
      minify: false,
      lib: {
        entry: fileURLToPath(new URL('./fixtures/web-surface.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'WebSurfaceTests',
      },
    },
  });
  const bundle = (Array.isArray(output) ? output : [output])
    .flatMap((result) => result.output)
    .filter((item) => item.type === 'chunk')
    .map((item) => (item.type === 'chunk' ? item.code : ''))
    .join('\n');
  assert.ok(bundle.length > 0);
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const slice = (source: string, from: string, to: string) => {
    const start = source.indexOf(from);
    const end = source.indexOf(to, start);
    assert.ok(start >= 0 && end > start, `Missing source section: ${from}`);
    return source.slice(start, end);
  };
  const mainCode = stripTypeScriptTypes(`
    const sshMaxSessionIdLength = 128;
    const authSession = { isAccessAllowed: true };
    ${readFileSync(new URL('../electron/web-browser-tabs.ts', import.meta.url), 'utf8').replace(/^export /gm, '')}
    ${slice(main, 'function isRecord(', 'function parseBackupPasswordRequest(')}
    ${slice(main, 'function isSshSessionId(', 'function isUuid(')}
    ${slice(main, 'function isWebCommandRequest(', 'function isTreeTooltipRequest(')}
    ${readFileSync(new URL('../electron/web-zoom.ts', import.meta.url), 'utf8').replace('export ', '')}
    const manager = new (class {
      ${slice(main, '  async command(owner:', '  async openBitwardenPopup(')}
    })();
  `);
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const preloadCommand = stripTypeScriptTypes(
    `({${slice(preload, '  commandWebSession:', '  showTreeTooltip:')}}).commandWebSession`,
  );
  const renderer = `
    const ipcRenderer = require('electron').ipcRenderer;
    globalThis.assert = require('node:assert/strict');
    globalThis.runWebCommand = ${preloadCommand};
    globalThis.readWebZoom = () => ipcRenderer.invoke('test:read-zoom');
    ${bundle}
    WebSurfaceTests.runWebSurfaceTests();
    //# sourceURL=wormhole-web-surface.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-web-surface-'));
  const harnessPath = join(directory, 'web-surface.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const assert = require('node:assert/strict');
      const { app, BrowserWindow, WebContentsView, ipcMain } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      ${mainCode}
      app.whenReady().then(async () => {
        const owner = new BrowserWindow({ show: false, webPreferences: {
          nodeIntegration: true, contextIsolation: false, backgroundThrottling: false,
        } });
        const view = new WebContentsView({ webPreferences: { partition: 'web-zoom-test' } });
        owner.contentView.addChildView(view);
        await view.webContents.loadURL('data:text/html,<p>HTTPS page content</p>');
        let navigationCount = 0;
        view.webContents.on('did-start-navigation', () => navigationCount++);
        Object.assign(manager, {
          surfaces: new Map([['session', { owner, view, disposed: false, tabs: new WebBrowserTabs() }]]),
          bitwardenPopups: new Map(), sendEvent: () => {},
        });
        ipcMain.handle('web:command', async (event, request) => {
          assert.equal(event.sender, owner.webContents);
          if (!isWebCommandRequest(request)) throw new Error('Invalid browser command');
          await manager.command(owner, request);
        });
        ipcMain.handle('test:read-zoom', () => ({
          pageFactor: view.webContents.getZoomFactor(),
          workspaceFactor: owner.webContents.getZoomFactor(), navigationCount,
        }));
        try {
          await owner.loadURL('data:text/html,<div id="root"></div>');
          owner.webContents.debugger.attach('1.3');
          await owner.webContents.debugger.sendCommand('Profiler.enable');
          await owner.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', {
            callCount: true, detailed: true,
          });
          await owner.webContents.executeJavaScript(${JSON.stringify(renderer)});
          const coverage = await owner.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
          const script = coverage.result.find(item => item.url === 'wormhole-web-surface.js');
          assert.ok(script, 'Missing renderer coverage');
          for (const name of ['command', 'ToolbarButton']) {
            const fn = script.functions.find(item => item.functionName === name);
            assert.ok(fn, 'Missing coverage for ' + name);
            const covered = fn.ranges.filter(item => item.count > 0).length;
            const percent = covered * 100 / fn.ranges.length;
            console.log(name + ': V8 block coverage ' + percent.toFixed(2) + '%');
            assert.ok(percent >= ${coverageThreshold}, name + ' coverage is below threshold');
          }
        } finally {
          view.webContents.close();
          owner.destroy();
        }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 30_000, windowsHide: true },
    );
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
