import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';

const require = createRequire(import.meta.url);

test('authentication prompt renders and announces independent Hello and fallback states', async () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('function AuthPrompt');
  const end = source.indexOf('type WormholeAppProps', start);
  assert.ok(start >= 0 && end > start);
  const fixture = readFileSync(new URL('./fixtures/auth-prompt.tsx', import.meta.url), 'utf8');
  const transformed = await transformWithOxc(
    source.slice(start, end) + fixture,
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
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    ${transformed.code}
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
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
        } finally { window.destroy(); }
        app.quit();
      }).catch((error) => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: environment, timeout: 30_000, windowsHide: true },
    );
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
