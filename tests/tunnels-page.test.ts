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

test('VPN tunnels lay out responsively and combine provider, search, and card actions in Chromium', async () => {
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
        entry: fileURLToPath(new URL('./fixtures/tunnels-page.tsx', import.meta.url)),
        formats: ['iife'],
        name: 'TunnelsPageTests',
      },
    },
  });
  const outputs = (Array.isArray(result) ? result : [result]).flatMap((item) => item.output);
  const script = outputs.find((item) => item.type === 'chunk');
  const css = outputs.find((item) => item.type === 'asset' && item.fileName.endsWith('.css'));
  assert.ok(script?.type === 'chunk');
  assert.ok(css?.type === 'asset');

  const directory = mkdtempSync(join(tmpdir(), 'wormhole-tunnels-page-'));
  try {
    const harness = join(directory, 'tunnels-page.cjs');
    writeFileSync(join(directory, 'renderer.js'), script.code);
    writeFileSync(join(directory, 'renderer.css'), css.source);
    writeFileSync(
      harness,
      `const { app, BrowserWindow } = require('electron');
const assert = require('node:assert/strict');
const { readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const source = readFileSync(join(__dirname, 'renderer.js'), 'utf8');
const css = readFileSync(join(__dirname, 'renderer.css'), 'utf8');
app.setPath('userData', __dirname);
app.setPath('sessionData', __dirname);
app.on('window-all-closed', () => {});
app.whenReady().then(async () => {
  for (const [width, height, columns, paneWidth] of [[980, 640, 1, 380], [980, 640, 2, 600], [1440, 900, 3], [800, 620, 2], [500, 560, 1]]) {
    const window = new BrowserWindow({
      width, height, useContentSize: true, show: false,
      webPreferences: { nodeIntegration: true, contextIsolation: false, backgroundThrottling: false },
    });
    try {
      await window.loadURL('data:text/html,<style>html,body,%23root{height:100%;margin:0}</style><div id="root"></div>');
      await window.webContents.insertCSS(css);
      window.webContents.debugger.attach('1.3');
      await window.webContents.debugger.sendCommand('Emulation.setEmulatedMedia', {
        features: [{ name: 'prefers-reduced-motion', value: 'reduce' }],
      });
      await window.webContents.executeJavaScript(\`
        globalThis.IS_REACT_ACT_ENVIRONMENT = true;
        globalThis.assert = require('node:assert/strict');
        \${source}
        TunnelsPageTests.run(\${columns}, \${paneWidth});
      \`);
      const debuggerApi = window.webContents.debugger;
      await debuggerApi.sendCommand('DOM.enable');
      await debuggerApi.sendCommand('CSS.enable');
      const cardSelector = '[data-tunnels-page] [data-slot=card]';
      await window.webContents.insertCSS(cardSelector + ' { transition: none !important; }');
      const cardBackground = () => window.webContents.executeJavaScript(
        'getComputedStyle(document.querySelector(' + JSON.stringify(cardSelector) + ')).backgroundColor',
      );
      const background = await cardBackground();
      const { root } = await debuggerApi.sendCommand('DOM.getDocument');
      const { nodeId } = await debuggerApi.sendCommand('DOM.querySelector', { nodeId: root.nodeId, selector: cardSelector });
      await debuggerApi.sendCommand('CSS.forcePseudoState', { nodeId, forcedPseudoClasses: ['hover'] });
      assert.equal(await cardBackground(), background, 'Tunnel card background must stay the same on hover');
      await debuggerApi.sendCommand('CSS.forcePseudoState', { nodeId, forcedPseudoClasses: [] });
      if (process.env.WORMHOLE_TEST_SCREENSHOTS) {
        const capture = await window.webContents.capturePage();
        writeFileSync(join(process.env.WORMHOLE_TEST_SCREENSHOTS, 'tunnels-' + (paneWidth ?? width) + '.png'), capture.toPNG());
      }
    } finally {
      window.destroy();
    }
  }
  app.quit();
}).catch(error => { console.error(error); app.exit(1); });`,
    );
    const { ELECTRON_RUN_AS_NODE: _runAsNode, ...environment } = process.env;
    const electron = require('electron') as string;
    const headless = process.platform === 'linux' && !environment.DISPLAY;
    const { stderr } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 60_000, windowsHide: true },
    );
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
