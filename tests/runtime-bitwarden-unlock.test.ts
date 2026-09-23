import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);

test('runtime Bitwarden unlock shows and hides the password, then resets it', async (context) => {
  const source = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const start = source.indexOf('function RuntimeBitwardenUnlockDialog(');
  const end = source.indexOf('function BitwardenCliDialog(', start);
  assert.ok(start >= 0 && end > start);
  const secretHelpers = source.slice(
    source.indexOf('function clearSecretInput('),
    source.indexOf('function credentialSelectionFor('),
  );
  const transformed = await transformWithOxc(
    secretHelpers + source.slice(start, end),
    'runtime-bitwarden-unlock.tsx',
    {
      jsx: { runtime: 'classic' },
    },
  );
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { useCallback, useLayoutEffect, useRef, useState } = React;
    const passthrough = ({ children }) => children;
    const Dialog = ({ children, onOpenChange, open }) => {
      globalThis.dialogOnOpenChange = onOpenChange;
      globalThis.dialogOpen = open;
      return children;
    };
    const DialogContent = passthrough;
    const DialogHeader = passthrough;
    const DialogFooter = passthrough;
    const DialogDescription = passthrough;
    const DialogTitle = passthrough;
    const Label = props => React.createElement('label', props);
    const Input = props => React.createElement('input', props);
    const Button = props => React.createElement('button', props);
    const IconButton = ({ label, children, ...props }) =>
      React.createElement('button', { ...props, 'aria-label': label }, children);
    const Eye = () => React.createElement('span', { 'data-icon': 'eye' });
    const EyeOff = () => React.createElement('span', { 'data-icon': 'eye-off' });
    const KeyRound = () => React.createElement('span');
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    ${transformed.code}
    async function run() {
      const root = createRoot(document.getElementById('root'));
      const unlocks = [];
      let closes = 0;
      const render = async (props = {}) => React.act(async () => root.render(
        React.createElement(RuntimeBitwardenUnlockDialog, {
          busy: false, error: '', open: true, onClose: () => closes++,
          onUnlock: password => unlocks.push(password), ...props,
        })
      ));
      const field = () => document.getElementById('runtime-bitwarden-password');
      const show = () => document.querySelector('[aria-label="Show password"]');
      const hide = () => document.querySelector('[aria-label="Hide password"]');
      const submit = () => document.querySelector('button[type="submit"]');
      const setPassword = async value => React.act(async () => {
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(field(), value);
        field().dispatchEvent(new Event('input', { bubbles: true }));
      });

      await render();
      assert.equal(dialogOpen, true);
      assert.equal(field().type, 'password');
      assert.equal(show().getAttribute('aria-controls'), field().id);
      assert.equal(show().getAttribute('aria-pressed'), 'false');
      assert.equal(submit().disabled, true);
      await setPassword('sample-secret');
      assert.equal(submit().disabled, false);
      await React.act(async () => show().click());
      assert.equal(field().type, 'text');
      assert.equal(field().value, 'sample-secret');
      assert.equal(hide().getAttribute('aria-pressed'), 'true');
      await React.act(async () => hide().click());
      assert.equal(field().type, 'password');
      await React.act(async () => show().click());
      await React.act(async () => {
        document.querySelector('form').requestSubmit();
        document.querySelector('form').requestSubmit();
      });
      assert.deepEqual(unlocks, ['sample-secret']);
      assert.equal(field().value, '');
      assert.equal(field().type, 'password');
      await React.act(async () => document.querySelector('form').requestSubmit());
      assert.deepEqual(unlocks, ['sample-secret']);

      await render({ busy: true });
      assert.equal(show().disabled, true);
      assert.equal(submit().disabled, true);
      const cancel = () => [...document.querySelectorAll('button')].find(button => button.textContent === 'Cancel');
      assert.equal(cancel().disabled, true);
      await React.act(async () => dialogOnOpenChange(false));
      assert.equal(closes, 0);
      await React.act(async () => document.querySelector('form').requestSubmit());
      assert.deepEqual(unlocks, ['sample-secret']);
      await render({ error: 'Unlock failed.' });
      assert.equal(document.querySelector('[role="alert"]').textContent, 'Unlock failed.');
      await setPassword('another-secret');
      await React.act(async () => cancel().click());
      assert.equal(closes, 1);
      assert.equal(field().value, '');
      await setPassword('another-secret');
      await React.act(async () => show().click());
      await render({ open: false });
      assert.equal(dialogOpen, false);
      assert.equal(field().value, '');
      assert.equal(field().type, 'password');
      await render();
      assert.equal(field().type, 'password');
      assert.equal(field().value, '');
      await React.act(async () => root.unmount());
    }
    run();
    //# sourceURL=wormhole-runtime-bitwarden-unlock.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-runtime-bitwarden-unlock-'));
  const harnessPath = join(directory, 'unlock.cjs');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(
      harnessPath,
      `
      const { app, BrowserWindow } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.on('window-all-closed', () => {});
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false,
          webPreferences: { nodeIntegration: true, contextIsolation: false } });
        try {
          await window.loadURL('data:text/html,<div id="root"></div>');
          window.webContents.debugger.attach('1.3');
          await window.webContents.debugger.sendCommand('Profiler.enable');
          await window.webContents.debugger.sendCommand('Profiler.startPreciseCoverage',
            { callCount: true, detailed: true });
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
          const coverage = await window.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
          const script = coverage.result.find(item => item.url === 'wormhole-runtime-bitwarden-unlock.js');
          const parent = script?.functions.find(item => item.functionName === 'RuntimeBitwardenUnlockDialog');
          if (!parent) throw new Error('Missing runtime Bitwarden unlock coverage.');
          const range = parent.ranges[0];
          const ranges = script.functions.filter(item => item.ranges[0].startOffset >= range.startOffset &&
            item.ranges[0].endOffset <= range.endOffset).flatMap(item => item.ranges);
          const covered = ranges.filter(item => item.count > 0).length;
          const percent = 100 * covered / ranges.length;
          console.log('RuntimeBitwardenUnlockDialog V8 block coverage ' + covered + '/' +
            ranges.length + ' (' + percent.toFixed(2) + '%)');
          if (percent < ${coverageThreshold}) throw new Error('Runtime unlock coverage is below ${coverageThreshold}%.');
        } finally { window.destroy(); }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harnessPath] : [harnessPath],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 60_000, windowsHide: true },
    );
    if (stderr.trim()) process.stderr.write(stderr);
    assert.match(stdout, /RuntimeBitwardenUnlockDialog V8 block coverage/);
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
