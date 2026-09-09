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

const require = createRequire(import.meta.url);

// scripts/test-coverage.ts excludes TSX from Node's loaded-module percentage.
// Exercise the modified pane handlers and border geometry in real React/Chromium instead.
test('SFTP panes keep drag feedback stable and draw unclipped borders in Chromium', async () => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('function isSftpPaneRoot');
  const end = source.indexOf('function SftpTransferQueue', start);
  assert.ok(start >= 0 && end > start);
  const helpers = ['sftp-state', 'sftp-format', 'sftp-dnd']
    .map((name) =>
      readFileSync(new URL(`../src/${name}.ts`, import.meta.url), 'utf8').replace(/^export /gm, ''),
    )
    .join('\n');
  const fixture = readFileSync(new URL('./fixtures/sftp-pane.tsx', import.meta.url), 'utf8');
  const transformed = await transformWithOxc(helpers + source.slice(start, end), 'sftp-pane.tsx', {
    jsx: { runtime: 'classic' },
  });
  const transformedFixture = await transformWithOxc(fixture, 'sftp-pane-fixture.tsx', {
    jsx: { runtime: 'classic' },
  });
  const output = await build({
    configFile: false,
    logLevel: 'silent',
    plugins: [tailwindcss()],
    build: {
      write: false,
      rolldownOptions: { input: fileURLToPath(new URL('../src/index.css', import.meta.url)) },
    },
  });
  const assets = (Array.isArray(output) ? output : [output]).flatMap((result) => result.output);
  const css = assets
    .filter((asset) => asset.type === 'asset' && asset.fileName.endsWith('.css'))
    .map((asset) => (asset.type === 'asset' ? String(asset.source) : ''))
    .join('\n');
  assert.ok(css.length > 0);
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { useState, useRef, useMemo, useCallback, useEffect, useLayoutEffect } = React;
    const Input = 'input', Button = 'button';
    const IconButton = ({ label, children, ...props }) => React.createElement('button', { ...props, 'aria-label': label }, children);
    const Wrapper = ({ children }) => children;
    const Hidden = () => null;
    const Tooltip = Wrapper, TooltipTrigger = Wrapper, TooltipContent = Hidden;
    const ContextMenu = Wrapper, ContextMenuTrigger = Wrapper, ContextMenuContent = Hidden;
    const ContextMenuItem = Hidden, ContextMenuSeparator = Hidden;
    const ArrowUp = 'i', ChevronDown = 'i', ChevronUp = 'i', RefreshCcw = 'i';
    const FolderPlus = 'i', FilePlus2 = 'i', Trash2 = 'i', LoaderCircle = 'i';
    const Search = 'i', FolderOpen = 'i', File = 'i', Pencil = 'i';
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const style = document.createElement('style');
    style.textContent = ${JSON.stringify(css)};
    document.head.append(style);
    ${transformed.code}
    ${transformedFixture.code}
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-sftp-pane-'));
  const harnessPath = join(directory, 'sftp-pane.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow } = require('electron');
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false, width: 1200, height: 800, webPreferences: {
          nodeIntegration: true, contextIsolation: false,
        } });
        try {
          await window.loadURL('data:text/html,<html class="dark"><div id="root"></div></html>');
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
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 30_000, windowsHide: true },
    );
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
