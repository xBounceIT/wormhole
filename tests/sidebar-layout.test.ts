import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { runInNewContext } from 'node:vm';
import tailwindcss from '@tailwindcss/vite';
import { build } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);

test('sidebar pin IPC validates input and requires workspace authentication', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = main.indexOf("  ipcMain.handle('settings:set-sidebar-pinned'");
  const end = main.indexOf("  ipcMain.handle('settings:set-sidebar-width'", start);
  assert.ok(start >= 0 && end > start);
  let handler: (event: unknown, value: unknown) => Promise<unknown> = async () => assert.fail();
  let authenticated = true;
  const calls: unknown[] = [];
  runInNewContext(stripTypeScriptTypes(main.slice(start, end)), {
    ipcMain: {
      handle: (channel: string, callback: typeof handler) => {
        assert.equal(channel, 'settings:set-sidebar-pinned');
        handler = callback;
      },
    },
    serializeAuthOperation: (action: () => Promise<unknown>) => action(),
    requireWorkspaceAuth: async () => {
      if (!authenticated) throw new Error('Workspace is locked');
    },
    runBackend: async (operation: string, request: { pinned: boolean }) => {
      calls.push([operation, request.pinned]);
      return { updated: true };
    },
  });
  for (const value of [undefined, null, 'false', 0, {}, []]) {
    await assert.rejects(handler(null, value), /Sidebar pin setting is invalid/);
  }
  assert.deepEqual(calls, []);
  for (const pinned of [false, true]) {
    assert.deepEqual(await handler(null, pinned), { updated: true });
  }
  assert.deepEqual(calls, [
    ['settings-set-sidebar-pinned', false],
    ['settings-set-sidebar-pinned', true],
  ]);
  authenticated = false;
  await assert.rejects(handler(null, false), /Workspace is locked/);
  assert.equal(calls.length, 2);

  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  assert.match(
    preload,
    /setSidebarPinned: \(pinned: boolean\) => ipcRenderer.invoke\('settings:set-sidebar-pinned', pinned\)/,
  );
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const layout = app.slice(app.indexOf('<SidebarLayout'), app.indexOf('</SidebarLayout>'));
  assert.match(layout, /initialPinned=\{initialSettings.sidebarPinned !== false\}/);
  assert.match(layout, /await window.wormhole.setSidebarPinned\(pinned\)/);
  assert.match(layout, /<SidebarPinButton \/>/);
  assert.match(layout, /onOverlayOpenChange=\{setSidebarOverlayOpen\}/);
  assert.match(layout, /isWebSurfaceVisible=\{[\s\S]*!sidebarOverlayOpen/);
});

test('pinned and auto-hide sidebars preserve layout, focus, menus and saved preferences', async (context) => {
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
        entry: fileURLToPath(new URL('./fixtures/sidebar-layout.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'SidebarLayoutTests',
      },
    },
  });
  const outputs = (Array.isArray(result) ? result : [result]).flatMap((item) => item.output);
  const script = outputs.find((item) => item.type === 'chunk');
  const css = outputs.find((item) => item.type === 'asset' && item.fileName.endsWith('.css'));
  assert.ok(script?.type === 'chunk');
  assert.ok(css?.type === 'asset');
  const renderer = `
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    window.sidebarAssert = require('node:assert/strict');
    window.sidebarInput = event => require('electron').ipcRenderer.invoke('test:input', event);
    window.sidebarReducedMotion = reduce => require('electron').ipcRenderer.invoke('test:reduced-motion', reduce);
    window.sidebarObserve = stage => require('electron').ipcRenderer.invoke('test:observe', stage);
    ${script.code}
    //# sourceURL=wormhole-sidebar-layout.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-sidebar-layout-'));
  const harnessPath = join(directory, 'sidebar-layout.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow, ipcMain } = require('electron');
      const nativeScale = Number(process.argv[2]);
      app.commandLine.appendSwitch('force-device-scale-factor', String(nativeScale));
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false, width: 1200, height: 800, titleBarStyle: 'hidden',
          ...(process.platform !== 'darwin' ? { titleBarOverlay: { color: '#0a0a0a', symbolColor: '#ffffff', height: 48 } } : {}),
          webPreferences: {
          nodeIntegration: true, contextIsolation: false, backgroundThrottling: false,
        } });
        ipcMain.handle('test:input', (_event, input) => window.webContents.sendInputEvent(input));
        ipcMain.handle('test:observe', async (_event, stage) => {
          console.log('Sidebar App: ' + stage);
          const checkHandle = stage.startsWith('pinned-');
          if (checkHandle || (process.env.WORMHOLE_TEST_SCREENSHOTS && ['collapsed', 'hover', 'tree-highlight'].includes(stage))) {
            // Freeze motion for stills: capturing a hidden window can resume a stale paint frame.
            const stillStyles = await window.webContents.insertCSS('[data-sidebar-surface], [data-sidebar-content] { transition: none !important; }');
            try {
              const viewport = await window.webContents.executeJavaScript('({ width: innerWidth, height: innerHeight })');
              for (const scale of checkHandle ? [1, 1.25, 1.5, 2] : [null]) {
                if (scale !== null) {
                  await window.webContents.debugger.sendCommand('Emulation.setDeviceMetricsOverride', { ...viewport, mobile: false, deviceScaleFactor: scale });
                }
                await window.webContents.capturePage();
                await window.webContents.executeJavaScript('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))');
                const capture = await window.webContents.capturePage();
                if (process.env.WORMHOLE_TEST_SCREENSHOTS) {
                  const suffix = (nativeScale === 1 ? '' : '-native-' + nativeScale) + (scale === null || scale === 1 ? '' : '-' + scale);
                  require('node:fs').writeFileSync(require('node:path').join(process.env.WORMHOLE_TEST_SCREENSHOTS, 'sidebar-' + stage + suffix + '.png'), capture.toPNG());
                }
                if (checkHandle) {
                  const bounds = await window.webContents.executeJavaScript('(() => { const separator = document.querySelector("[data-slot=resizable-handle]").getBoundingClientRect(); const grip = document.querySelector("[data-slot=resizable-handle] > div").getBoundingClientRect(); return { left: separator.left, centerX: separator.left + separator.width / 2, centerY: grip.top + grip.height / 2 }; })()');
                  const size = capture.getSize(1);
                  const scaleX = size.width / viewport.width;
                  const scaleY = size.height / viewport.height;
                  const left = Math.floor((bounds.left - 6) * scaleX);
                  const top = Math.floor((bounds.centerY - 24) * scaleY);
                  const width = Math.ceil(13 * scaleX);
                  const middleY = Math.floor(bounds.centerY * scaleY) - top;
                  const pixels = capture.toBitmap({ scaleFactor: 1 });
                  const colorAt = (x, y) => pixels.readUInt32LE(((top + y) * size.width + left + x) * 4);
                  const borderColor = colorAt(Math.floor(bounds.centerX * scaleX) - left, 0);
                  const borderPixels = [];
                  const gripPixels = [];
                  for (let x = 0; x < width; x++) {
                    if (colorAt(x, 0) === borderColor) borderPixels.push(x);
                    if (colorAt(x, middleY) === borderColor) gripPixels.push(x);
                  }
                  const assert = require('node:assert/strict');
                  assert.ok(Math.abs(scaleX - nativeScale) < 0.01, 'The native capture must exercise the selected physical pixel scale');
                  assert.equal(pixels.length, size.width * size.height * 4);
                  assert.ok(borderPixels.length > 0 && gripPixels.length > borderPixels.length, 'The grip must visibly extend beyond the divider');
                  // Opposite pixel-width parity permits only the nearest half-pixel center.
                  const centerDelta = Math.abs(gripPixels[0] + gripPixels.at(-1) - borderPixels[0] - borderPixels.at(-1));
                  assert.ok(centerDelta <= (gripPixels.length + borderPixels.length) % 2, 'Painted grip pixels must be centered on the complete divider in ' + stage + ' at ' + scale + 'x');
                }
              }
            } finally {
              if (checkHandle) await window.webContents.debugger.sendCommand('Emulation.clearDeviceMetricsOverride');
              await window.webContents.removeInsertedCSS(stillStyles);
            }
          }
        });
        ipcMain.handle('test:reduced-motion', (_event, reduce) => window.webContents.debugger.sendCommand('Emulation.setEmulatedMedia', {
          features: [{ name: 'prefers-reduced-motion', value: reduce ? 'reduce' : 'no-preference' }],
        }));
        try {
          await window.loadURL('data:text/html,<style>html,body,%23root{height:100%;margin:0}</style><div id="root"></div>');
          await window.webContents.insertCSS(${JSON.stringify(String(css.source))});
          window.webContents.focus();
          window.webContents.debugger.attach('1.3');
          await window.webContents.debugger.sendCommand('Emulation.setEmulatedMedia', {
            features: [{ name: 'prefers-reduced-motion', value: 'no-preference' }],
          });
          await window.webContents.debugger.sendCommand('Profiler.enable');
          await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)} + ';window.runSidebarTests(' + (nativeScale !== 1) + ');');
          const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
          const script = coverage.result.find(item => item.url === 'wormhole-sidebar-layout.js');
          if (!script) throw new Error('Missing sidebar renderer coverage');
          for (const name of nativeScale === 1 ? ['SidebarLayout', 'SidebarPinButton', 'SidebarNavigation', 'ContextMenuOverlayProvider'] : []) {
            const parent = script.functions.find(item => item.functionName === name);
            if (!parent) throw new Error('Missing coverage for ' + name);
            const range = parent.ranges[0];
            const ranges = script.functions.filter(item => item.ranges[0].startOffset >= range.startOffset && item.ranges[0].endOffset <= range.endOffset).flatMap(item => item.ranges);
            const covered = ranges.filter(item => item.count > 0).length;
            const percent = 100 * covered / ranges.length;
            console.log(name + ': V8 block coverage ' + covered + '/' + ranges.length + ' (' + percent.toFixed(2) + '%)');
            if (percent < ${coverageThreshold}) throw new Error(name + ' coverage below ${coverageThreshold}%');
          }
        } finally { window.destroy(); }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    for (const scale of [1, 2]) {
      const args = [harnessPath, String(scale)];
      const { stdout, stderr } = await promisify(execFile)(
        needsDisplay ? 'xvfb-run' : electron,
        needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', ...args] : args,
        { env: { ...environment, NODE_ENV: 'test' }, timeout: 120_000, windowsHide: true },
      );
      context.diagnostic('Native pixel scale: ' + scale);
      for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
      if (stderr.trim()) process.stderr.write(stderr);
    }
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
