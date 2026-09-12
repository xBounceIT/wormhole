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

// Node coverage excludes TSX and process entrypoints. Measure these isolated login
// and close handlers in Chromium, including native modal hit testing and focus.
test('authentication and window-close prompts remain usable while the app is locked', async (context) => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('function AuthPrompt');
  const end = source.indexOf('type WormholeAppProps', start);
  assert.ok(start >= 0 && end > start);
  const slice = (from: string, to: string) => {
    const first = source.indexOf(from);
    const last = source.indexOf(to, first);
    assert.ok(first >= 0 && last > first, `Missing app section: ${from}`);
    return source.slice(first, last);
  };
  const closeOpen = source.indexOf('open={pendingWindowClose !== null}');
  const closeStart = source.lastIndexOf('<Dialog', closeOpen);
  const closeEnd = source.indexOf('</Dialog>', closeOpen) + '</Dialog>'.length;
  assert.ok(closeStart >= 0 && closeEnd > closeOpen);
  const authMountStart = source.indexOf('{visibleAuthPrompt && authState ? (');
  const authMountEnd = source.indexOf(') : null}', authMountStart) + ') : null}'.length;
  assert.ok(authMountStart >= 0 && authMountEnd > authMountStart);
  const workspaceStart = source.lastIndexOf(
    '<div',
    source.indexOf("aria-hidden={authGate !== 'unlocked'}"),
  );
  const workspaceEnd = source.indexOf('>', workspaceStart) + 1;
  const subscriptionStart = source.lastIndexOf(
    '  useEffect(() => {',
    source.indexOf('return window.wormhole?.onWindowCloseConfirmationRequested'),
  );
  const closeHarness = `
    function AppCloseHarness({ locked, onResult }) {
      const authGate = locked ? 'locked' : 'unlocked';
      const authState = { configured: true, mode: 'pin', windowsHello: { available: false, message: '' } };
      const authPrompt = null;
      const lockReason = 'Locked after inactivity.';
      const handleAuthPromptResult = onResult;
      const [authDialog, setAuthDialog] = useState(null);
      ${slice('  const [pendingWindowClose,', '  const sidebarWidth =')}
      ${source.slice(subscriptionStart, source.indexOf('  function reconnectSession', subscriptionStart))}
      ${slice('  const visibleAuthPrompt =', '  const credentialResult =')}
      return <>
        ${source.slice(authMountStart, authMountEnd)}
        ${source.slice(workspaceStart, workspaceEnd)}
          <button id="workspace-action">Workspace action</button>
          ${source.slice(closeStart, closeEnd)}
        </div>
      </>;
    }
  `;
  const dialog = readFileSync(new URL('../src/components/ui/dialog.tsx', import.meta.url), 'utf8');
  const dialogSource = dialog.slice(
    dialog.indexOf('const DialogOpenContext'),
    dialog.indexOf('export {'),
  );
  const dialogLifecycle = readFileSync(
    new URL('../src/dialog-lifecycle.ts', import.meta.url),
    'utf8',
  ).replace(/^export /gm, '');
  const startupSource = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');
  const cardStart = startupSource.indexOf('function renderCard');
  const cardEnd = startupSource.indexOf('function showError', cardStart);
  const unlockStart = startupSource.indexOf('function showUnlock');
  const unlockEnd = startupSource.indexOf('async function bootstrap', unlockStart);
  assert.ok(cardStart >= 0 && cardEnd > cardStart);
  assert.ok(unlockStart >= 0 && unlockEnd > unlockStart);
  const fixture = readFileSync(new URL('./fixtures/auth-prompt.tsx', import.meta.url), 'utf8');
  const transformed = await transformWithOxc(
    dialogLifecycle +
      dialogSource +
      source.slice(start, end) +
      closeHarness +
      startupSource.slice(cardStart, cardEnd) +
      startupSource.slice(unlockStart, unlockEnd) +
      fixture,
    'auth-prompt.tsx',
    {
      jsx: { runtime: 'classic' },
    },
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
    .flatMap((result) => result.output)
    .filter((asset) => asset.type === 'asset' && asset.fileName.endsWith('.css'))
    .map((asset) => (asset.type === 'asset' ? String(asset.source) : ''))
    .join('\n');
  assert.ok(css.length > 0);
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { useState, useRef, useCallback, useEffect, useLayoutEffect } = React;
    const { Dialog: DialogPrimitive } = require(${JSON.stringify(require.resolve('radix-ui'))});
    const { clsx } = require(${JSON.stringify(require.resolve('clsx'))});
    const { twMerge } = require(${JSON.stringify(require.resolve('tailwind-merge'))});
    const cn = (...inputs) => twMerge(clsx(inputs));
    const Card = 'div', CardHeader = 'div', CardTitle = 'h2', CardDescription = 'p';
    const CardContent = 'div', Button = 'button', Input = 'input', Label = 'label';
    const KeyRound = 'span', LoaderCircle = 'span', XIcon = 'span', TriangleAlert = 'span', Power = 'span', Badge = 'span';
    const root = document.getElementById('root');
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const style = document.createElement('style');
    style.textContent = ${JSON.stringify(css)};
    document.head.append(style);
    ${transformed.code}
    //# sourceURL=wormhole-auth-prompt.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-auth-prompt-'));
  const harnessPath = join(directory, 'auth-prompt.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow, ipcMain } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false, width: 1200, height: 800, webPreferences: {
          nodeIntegration: true, contextIsolation: false, backgroundThrottling: false,
        } });
        ipcMain.handle('test:escape', () => {
          window.webContents.sendInputEvent({ type: 'keyDown', keyCode: 'Escape' });
          window.webContents.sendInputEvent({ type: 'keyUp', keyCode: 'Escape' });
        });
        try {
          await window.loadURL('data:text/html,<div id="root"></div>');
          window.webContents.debugger.attach('1.3');
          await window.webContents.debugger.sendCommand('Profiler.enable');
          await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', {
            callCount: true, detailed: true,
          });
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
          const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
          const script = coverage.result.find(item => item.url === 'wormhole-auth-prompt.js');
          if (!script) throw new Error('Missing authentication renderer coverage.');
          for (const name of ['AuthPrompt', 'showUnlock', 'AppCloseHarness', 'DialogContent']) {
            const parent = script.functions.find(item => item.functionName === name);
            if (!parent) throw new Error('Missing coverage for ' + name);
            const range = parent.ranges[0];
            const ranges = script.functions
              .filter(item => item.ranges[0].startOffset >= range.startOffset &&
                item.ranges[0].endOffset <= range.endOffset)
              .flatMap(item => item.ranges);
            const covered = ranges.filter(item => item.count > 0).length;
            const percent = 100 * covered / ranges.length;
            console.log(name + ': V8 block coverage ' + covered + '/' + ranges.length +
              ' (' + percent.toFixed(2) + '%)');
            if (percent < ${coverageThreshold}) {
              throw new Error(name + ' coverage is below ${coverageThreshold}%.');
            }
          }
        } finally { window.destroy(); }
        app.quit();
      }).catch((error) => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 60_000, windowsHide: true },
    );
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
