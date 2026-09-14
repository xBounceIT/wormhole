import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import tailwindcss from '@tailwindcss/vite';
import { build, transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);

// Use the production dialog, button and CSS in Chromium: Node's loaded-module
// coverage excludes TSX, and a DOM without layout cannot detect this overflow.
test('Bitwarden operation dialogs contain long messages and keep Close reachable', async (context) => {
  const section = (path: string, from: string, to: string) => {
    const source = readFileSync(new URL(path, import.meta.url), 'utf8');
    const start = source.indexOf(from);
    const end = source.indexOf(to, start);
    assert.ok(start >= 0 && end > start, `Missing source section: ${from}`);
    return source.slice(start, end);
  };
  const transformed = await transformWithOxc(
    readFileSync(new URL('../src/dialog-lifecycle.ts', import.meta.url), 'utf8').replace(
      /^export /gm,
      '',
    ) +
      section('../src/components/ui/button.tsx', 'const buttonVariants', 'export {') +
      section('../src/components/ui/dialog.tsx', 'const DialogOpenContext', 'export {') +
      section('../src/App.tsx', 'function BitwardenOperationDialog(', 'const mcpTokenPlaceholder'),
    'bitwarden-operation-dialog.tsx',
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
    .flatMap((result) => result.output)
    .filter((asset) => asset.type === 'asset' && asset.fileName.endsWith('.css'))
    .map((asset) => (asset.type === 'asset' ? String(asset.source) : ''))
    .join('\n');
  assert.ok(css.length > 0);
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { Dialog: DialogPrimitive, Slot } = require(${JSON.stringify(require.resolve('radix-ui'))});
    const { cva } = require(${JSON.stringify(require.resolve('class-variance-authority'))});
    const { clsx } = require(${JSON.stringify(require.resolve('clsx'))});
    const { twMerge } = require(${JSON.stringify(require.resolve('tailwind-merge'))});
    const { LoaderCircle, CheckCircle2, AlertCircle, XIcon } = require(${JSON.stringify(require.resolve('lucide-react'))});
    const cn = (...inputs) => twMerge(clsx(inputs));
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const style = document.createElement('style');
    style.textContent = ${JSON.stringify(css)};
    document.head.append(style);
    ${transformed.code}
    async function runDialogTests() {
      const root = createRoot(document.getElementById('root'));
      const description = 'Refresh the Bitwarden credentials available to Wormhole.';
      let title = 'Sync Bitwarden vault';
      let closeRequests = 0;
      const element = state => React.createElement(BitwardenOperationDialog, {
        description, title, state, onClose: () => closeRequests++,
      });
      const settle = () => new Promise(resolve => setTimeout(resolve, 100));
      const render = async state => {
        await React.act(async () => root.render(element(state)));
        await React.act(settle);
      };
      const dialog = () => document.querySelector('[role="dialog"]');
      const close = () => dialog().querySelector('[data-slot="dialog-footer"] button');
      const inside = (rect, bounds, label) => {
        assert.ok(rect.left >= bounds.left - 1 && rect.right <= bounds.right + 1 &&
          rect.top >= bounds.top - 1 && rect.bottom <= bounds.bottom + 1, label);
      };
      const error = 'Bitwarden could not be synchronized. Wormhole will continue using 238 cached credentials. ' +
        'Syncing failed: {"response":{"error":"invalid_grant"},"statusCode":400}node:internal/process/promises:392 ' +
        'new UnhandledPromiseRejection(reason); ^ UnhandledPromiseRejection: This error originated either by throwing inside of an async function.';
      const cases = [
        { title: 'Sync Bitwarden vault', status: 'warning', message: error },
        { title: 'Update Bitwarden CLI', status: 'error', message: 'Download failed: ' + 'x'.repeat(1000) },
        { title: 'Update Bitwarden extension', status: 'error', message: error.repeat(30), scroll: true },
        { title: 'Sync Bitwarden vault', status: 'success', message: 'Bitwarden vault synced successfully.' },
      ];
      for (const scenario of cases) {
        title = scenario.title;
        await render({ status: scenario.status, message: scenario.message });
        const popup = dialog();
        const message = [...popup.querySelectorAll('p')].find(item => item.textContent === scenario.message);
        assert.ok(message, 'the complete message must be preserved');
        const panel = message.parentElement;
        const bounds = popup.getBoundingClientRect();
        inside(bounds, { left: 0, top: 0, right: innerWidth, bottom: innerHeight }, 'dialog exceeds the viewport');
        inside(panel.getBoundingClientRect(), bounds, 'message panel exceeds the dialog');
        inside(popup.querySelector('[data-slot="dialog-footer"]').getBoundingClientRect(), bounds, 'footer exceeds the dialog');
        inside(close().getBoundingClientRect(), bounds, 'Close exceeds the dialog');
        for (const node of [popup, panel, message]) {
          assert.ok(node.scrollWidth <= node.clientWidth + 1, 'message must wrap without horizontal overflow');
        }
        const textRange = document.createRange();
        textRange.selectNodeContents(message);
        for (const rect of textRange.getClientRects()) {
          assert.ok(rect.left >= bounds.left && rect.right <= bounds.right, 'text exceeds the dialog');
        }
        if (scenario.scroll) {
          assert.ok(panel.scrollHeight > panel.clientHeight, 'long messages must scroll inside the dialog');
          panel.focus();
          assert.ok(document.activeElement === panel, 'long messages must accept keyboard focus');
          await React.act(async () => require('electron').ipcRenderer.invoke('test:scroll'));
          assert.ok(panel.scrollTop > 0, 'PageDown must scroll the long message');
          panel.scrollTop = panel.scrollHeight;
          assert.ok(panel.scrollTop > 0, 'the full message must remain reachable');
          assert.ok(message.getBoundingClientRect().bottom <= panel.getBoundingClientRect().bottom, 'the last line must be reachable');
        }
        const button = close().getBoundingClientRect();
        const target = document.elementFromPoint(button.x + button.width / 2, button.y + button.height / 2);
        assert.ok(close().contains(target), 'Close must remain clickable');
      }
      await render({ status: 'working', message: 'Syncing Bitwarden vault…' });
      assert.equal(close().disabled, true);
      assert.ok(!dialog().querySelector('[data-slot="dialog-close"]'));
      const escape = () => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
      const outside = () => {
        const overlay = document.querySelector('[data-slot="dialog-overlay"]');
        for (const type of ['pointerdown', 'pointerup']) overlay.dispatchEvent(
          new PointerEvent(type, { bubbles: true, cancelable: true, pointerType: 'mouse', button: 0 }));
        overlay.click();
      };
      await React.act(async () => { close().click(); escape(); outside(); });
      assert.equal(closeRequests, 0, 'working operations cannot be dismissed');
      for (const [status, dismiss] of [
        ['success', escape], ['warning', () => close().click()], ['error', outside],
      ]) {
        await render({ status, message: error });
        const before = closeRequests;
        await React.act(async () => dismiss());
        await React.act(settle);
        assert.equal(closeRequests, before + 1, status + ' must be dismissible');
      }
      await render(null);
      await React.act(async () => root.unmount());
    }
    runDialogTests();
    //# sourceURL=wormhole-bitwarden-operation-dialog.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-bitwarden-operation-dialog-'));
  const harnessPath = join(directory, 'dialog.cjs');
  const viewports = [
    [1024, 768],
    [576, 341],
    [320, 320],
  ];
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow, ipcMain } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.on('window-all-closed', () => {});
      ipcMain.handle('test:scroll', async event => {
        await event.sender.debugger.sendCommand('Emulation.setFocusEmulationEnabled', { enabled: true });
        for (const type of ['rawKeyDown', 'keyUp']) await event.sender.debugger.sendCommand('Input.dispatchKeyEvent', {
          type, key: 'PageDown', code: 'PageDown', windowsVirtualKeyCode: 34,
        });
      });
      app.whenReady().then(async () => {
        for (const [width, height] of ${JSON.stringify(viewports)}) {
          const window = new BrowserWindow({ show: false, width, height, useContentSize: true,
            webPreferences: { nodeIntegration: true, contextIsolation: false, backgroundThrottling: false } });
          try {
            await window.loadURL('data:text/html,<html class="dark"><div id="root"></div></html>');
            window.webContents.debugger.attach('1.3');
            await window.webContents.debugger.sendCommand('Profiler.enable');
            await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
            await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
            const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
            const script = coverage.result.find(item => item.url === 'wormhole-bitwarden-operation-dialog.js');
            const parent = script?.functions.find(item => item.functionName === 'BitwardenOperationDialog');
            if (!parent) throw new Error('Missing Bitwarden dialog coverage.');
            const range = parent.ranges[0];
            const ranges = script.functions.filter(item => item.ranges[0].startOffset >= range.startOffset &&
              item.ranges[0].endOffset <= range.endOffset).flatMap(item => item.ranges);
            const covered = ranges.filter(item => item.count > 0).length;
            const percent = 100 * covered / ranges.length;
            console.log(width + 'x' + height + ': BitwardenOperationDialog V8 block coverage ' +
              covered + '/' + ranges.length + ' (' + percent.toFixed(2) + '%)');
            if (percent < ${coverageThreshold}) throw new Error('Bitwarden dialog coverage is below ${coverageThreshold}%.');
          } finally { window.destroy(); }
        }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    // Hidden windows do not reliably advance Chromium's smooth keyboard scroll animation.
    const { stdout, stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay
        ? ['--auto-servernum', electron, '--no-sandbox', '--disable-smooth-scrolling', harnessPath]
        : ['--disable-smooth-scrolling', harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 60_000, windowsHide: true },
    );
    if (stderr.trim()) process.stderr.write(stderr);
    for (const [width, height] of viewports) {
      assert.ok(stdout.includes(width + 'x' + height + ': BitwardenOperationDialog'));
    }
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
