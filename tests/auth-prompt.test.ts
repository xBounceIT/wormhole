import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);

// Node coverage excludes TSX and process entrypoints. Measure these isolated login
// handlers with Chromium's V8 block coverage while exercising real hooks and DOM.
test('authentication forms hide unavailable Hello and preserve fallback states', async (context) => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('function AuthPrompt');
  const end = source.indexOf('type WormholeAppProps', start);
  assert.ok(start >= 0 && end > start);
  const startupSource = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');
  const cardStart = startupSource.indexOf('function renderCard');
  const cardEnd = startupSource.indexOf('function showError', cardStart);
  const unlockStart = startupSource.indexOf('function showUnlock');
  const unlockEnd = startupSource.indexOf('async function bootstrap', unlockStart);
  assert.ok(cardStart >= 0 && cardEnd > cardStart);
  assert.ok(unlockStart >= 0 && unlockEnd > unlockStart);
  const fixture = readFileSync(new URL('./fixtures/auth-prompt.tsx', import.meta.url), 'utf8');
  const transformed = await transformWithOxc(
    source.slice(start, end) +
      startupSource.slice(cardStart, cardEnd) +
      startupSource.slice(unlockStart, unlockEnd) +
      fixture,
    'auth-prompt.tsx',
    {
      jsx: { runtime: 'classic' },
    },
  );
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { useState, useRef, useCallback, useEffect, useLayoutEffect } = React;
    const Card = 'div', CardHeader = 'div', CardTitle = 'h2', CardDescription = 'p';
    const CardContent = 'div', Button = 'button', Input = 'input', Label = 'label';
    const KeyRound = 'span', LoaderCircle = 'span';
    const root = document.getElementById('root');
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
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
      const { app, BrowserWindow } = require('electron');
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false, webPreferences: {
          nodeIntegration: true, contextIsolation: false,
        } });
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
          for (const name of ['AuthPrompt', 'showUnlock']) {
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
    const { stdout } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: environment, timeout: 30_000, windowsHide: true },
    );
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
