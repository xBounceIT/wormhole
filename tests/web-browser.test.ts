import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import { build, transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);

test('connection browser tabs, navigation, VPN status and recovery work in Chromium', async (context) => {
  const source = readFileSync(new URL('../src/components/WebSurface.tsx', import.meta.url), 'utf8')
    .replace(/^import[\s\S]*?from ['"][^'"]+['"];\r?\n/gm, '')
    .replace(/^export /gm, '');
  const transformed = await transformWithOxc(source, 'web-browser.tsx', {
    jsx: { runtime: 'classic' },
  });
  const fixture = await transformWithOxc(
    readFileSync(new URL('./fixtures/web-browser.tsx', import.meta.url), 'utf8'),
    'web-browser-fixture.tsx',
    { jsx: { runtime: 'classic' } },
  );
  const output = await build({
    configFile: false,
    logLevel: 'silent',
    plugins: [tailwindcss()],
    build: {
      write: false,
      rolldownOptions: { input: fileURLToPath(new URL('../src/index.css', import.meta.url)) },
    },
  });
  const css = (Array.isArray(output) ? output : [output])
    .flatMap((entry) => entry.output)
    .filter((entry) => entry.type === 'asset' && entry.fileName.endsWith('.css'))
    .map((entry) => String(entry.source))
    .join('\n');
  assert.ok(css.length > 0);
  const renderer = `
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { useEffect, useLayoutEffect, useRef, useState } = React;
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const assert = require('node:assert/strict');
    // data: fixtures lack the secure origin used by the app's file:/localhost renderer.
    crypto.randomUUID = require('node:crypto').randomUUID;
    const { AlertCircle, ChevronLeft, ChevronRight, Globe, LoaderCircle, LockKeyhole, Plus, RefreshCcw, ShieldCheck, X } = require(${JSON.stringify(require.resolve('lucide-react'))});
    const bitwardenIcon = ${JSON.stringify(`data:image/png;base64,${readFileSync(new URL('../Assets/Bitwarden/bitwarden-icon.png', import.meta.url)).toString('base64')}`)};
    const Button = ({ size, variant, ...props }) => React.createElement('button', props);
    const ConnectionStepper = () => React.createElement('span', null, 'Starting VPN');
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const style = document.createElement('style'); style.textContent = ${JSON.stringify(css)}; document.head.append(style);
    ${transformed.code}
    ${fixture.code}
    //# sourceURL=wormhole-web-browser.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-web-browser-'));
  try {
    const harnessPath = join(directory, 'browser.cjs');
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow } = require('electron');
      const { writeFileSync } = require('node:fs');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        // Offscreen rendering keeps real frame/decoder/layout behavior without hidden-window throttling.
        const window = new BrowserWindow({ show: false, width: 1100, height: 700, webPreferences: { offscreen: true, nodeIntegration: true, contextIsolation: false, backgroundThrottling: false } });
        try {
          await window.loadURL('data:text/html,<html class="dark"><div id="root"></div></html>');
          const debuggerApi = window.webContents.debugger;
          debuggerApi.attach('1.3');
          await debuggerApi.sendCommand('Profiler.enable');
          await debuggerApi.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
          const coverage = await debuggerApi.sendCommand('Profiler.takePreciseCoverage');
          const script = coverage.result.find(item => item.url === 'wormhole-web-browser.js');
          if (!script) throw new Error('Missing browser renderer coverage.');
          for (const name of ['WebSurface', 'WebTabFavicon', 'ToolbarButton', 'StatusOverlay']) {
            const parent = script.functions.find(item => item.functionName === name);
            if (!parent) throw new Error('Missing coverage for ' + name);
            const range = parent.ranges[0];
            const ranges = script.functions.filter(item => item.ranges[0].startOffset >= range.startOffset && item.ranges[0].endOffset <= range.endOffset).flatMap(item => item.ranges);
            const percent = 100 * ranges.filter(item => item.count > 0).length / ranges.length;
            console.log(name + ': V8 block coverage ' + percent.toFixed(2) + '%');
            if (percent < ${coverageThreshold}) throw new Error(name + ' coverage below ${coverageThreshold}%.');
          }
          if (process.env.WORMHOLE_BROWSER_SCREENSHOT) writeFileSync(process.env.WORMHOLE_BROWSER_SCREENSHOT, (await window.webContents.capturePage()).toPNG());
          await window.webContents.executeJavaScript('window.unmountWebBrowser()');
        } finally { window.destroy(); }
        app.quit();
      }).catch((error) => { console.error(error); app.exit(1); });
    `,
    );
    const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 90_000, windowsHide: true },
    );
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
