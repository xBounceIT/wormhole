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

const require = createRequire(import.meta.url);

test('settings opens as a centered two-pane overlay dialog with search, occlusion, and auth stacking', async () => {
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
        entry: fileURLToPath(new URL('./fixtures/settings-dialog.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'SettingsDialogTests',
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
    window.settingsAssert = require('node:assert/strict');
    window.settingsInput = event => require('electron').ipcRenderer.invoke('test:input', event);
    window.settingsReducedMotion = reduce => require('electron').ipcRenderer.invoke('test:reduced-motion', reduce);
    ${script.code}
    //# sourceURL=wormhole-settings-dialog.js
  `;

  const directory = mkdtempSync(join(tmpdir(), 'wormhole-settings-dialog-'));
  const harnessPath = join(directory, 'settings-dialog.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow, ipcMain } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.on('window-all-closed', () => {});
      app.whenReady().then(async () => {
        let activeWindow = null;
        ipcMain.handle('test:input', async (_event, input) => {
          if (input.type === 'mouseMove') {
            await activeWindow.webContents.capturePage().catch(() => undefined);
          }
          activeWindow.webContents.sendInputEvent(input);
        });
        ipcMain.handle('test:reduced-motion', (_event, reduce) =>
          activeWindow.webContents.debugger.sendCommand('Emulation.setEmulatedMedia', {
            features: [{ name: 'prefers-reduced-motion', value: reduce ? 'reduce' : 'no-preference' }],
          }),
        );
        for (const [mode, width, height] of [['desktop', 1200, 800], ['compact', 640, 480]]) {
          const window = new BrowserWindow({
            show: false,
            width,
            height,
            useContentSize: true,
            webPreferences: {
              nodeIntegration: true,
              contextIsolation: false,
              backgroundThrottling: false,
            },
          });
          activeWindow = window;
          try {
            await window.loadURL('data:text/html,<style>html,body,%23root{height:100%;margin:0}</style><div id="root"></div>');
            await window.webContents.insertCSS(${JSON.stringify(String(css.source))});
            window.webContents.focus();
            window.webContents.debugger.attach('1.3');
            await window.webContents.executeJavaScript(${JSON.stringify(renderer)} + ';window.runSettingsDialogTests(' + JSON.stringify(mode) + ');');
          } finally {
            window.destroy();
          }
        }
        app.quit();
      }).catch(error => {
        console.error(error);
        app.exit(1);
      });
    `,
    );

    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const { stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 120_000, windowsHide: true },
    );
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
