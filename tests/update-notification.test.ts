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
const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');

// Execute production JSX and App handlers in Chromium, where TSX and layout can be
// measured. Node's loaded-module coverage separately measures update-state.ts.
test('update notifications support startup, dismissal, installation and the changelog page', async (context) => {
  const app = read('../src/App.tsx');
  const section = (source: string, from: string, to: string) => {
    const start = source.indexOf(from);
    const end = source.indexOf(to, start);
    assert.ok(start >= 0 && end > start, `Missing production section: ${from}`);
    return source.slice(start, end);
  };
  const effectStart = app.lastIndexOf(
    '  useEffect(() => {',
    app.indexOf('    let receivedResult = false;'),
  );
  const effectEnd = app.indexOf('  function handleAutoCopyOnSelectChange(', effectStart);
  assert.ok(effectStart >= 0 && effectEnd > effectStart);
  const mountStart = app.indexOf('{updateNotificationVisible && updateResult ? (');
  const mountEnd = app.indexOf(') : null}', mountStart) + ') : null}'.length;
  assert.ok(mountStart >= 0 && mountEnd > mountStart);
  const panelStart = app.indexOf('<SettingsTabPanel value="updates">');
  const panelEnd = app.indexOf('</SettingsTabPanel>', panelStart) + '</SettingsTabPanel>'.length;
  assert.ok(panelStart >= 0 && panelEnd > panelStart);
  const header = section(app, '        <header ', '        </header>');
  assert.ok(!header.includes('UpdateNotification') && !header.includes('handleInstallUpdate'));
  assert.ok(!header.includes('shouldOfferUpdate') && !header.includes('updateBannerVisible'));
  assert.match(app, /onInstallUpdate=\{\(\) => void handleInstallUpdate\(\)\}/);

  const fixture = await transformWithOxc(read('fixtures/update-notification.tsx'), 'fixture.tsx', {
    jsx: { runtime: 'classic' },
  });
  const production = `
    ${read('../src/update-state.ts').replace(/^export /gm, '')}
    ${read('../src/native-surface-overlay-state.ts').replace(/^export /gm, '')}
    ${section(read('../src/components/ui/context-menu.tsx'), 'type ContextMenuOverlayContextValue', 'function ContextMenu({')}
    ${section(read('../src/components/ui/button.tsx'), 'const buttonVariants', 'export {')}
    ${section(read('../src/components/ui/card.tsx'), 'function Card(', 'export {')}
    ${read('../src/components/UpdateNotification.tsx')
      .replace(/^import .*;\r?\n/gm, '')
      .replace(/^export /gm, '')}
    ${section(app, 'function SettingsSection(', 'function SettingsTabPanel(')}
    ${section(app, 'function formatLastUpdateCheck(', '// Settings hosts independent')}
    const Switch = ({ onCheckedChange, ...props }) => <input type="checkbox" {...props} onChange={event => onCheckedChange(event.target.checked)} />;
    const SettingsTabPanel = ({ children }) => <div>{children}</div>;
    function UpdateSettingsHarness({ update, settingsUpdatesRequest, onCheckForUpdates, onInstallUpdate, onDismissUpdate }) {
      ${section(app, '  const [activeTabSelection,', '  const [promptBeforeTunnelConnect,')}
      ${section(app, '  const updateAvailable =', '  const backupExportPasswordValid =')}
      const onSetAutoCheckForUpdates = () => {};
      return <div id="updates-page" data-active-tab={activeTab}>
        <button id="general-tab" onClick={() => setActiveTabSelection({ request: settingsUpdatesRequest, value: 'general' })}>General</button>
        {activeTab === 'updates' ? ${app.slice(panelStart, panelEnd)} : null}
      </div>;
    }
    let updateTestControls;
    function UpdateHarness({ initialSettings }) {
      const [authGate, setAuthGate] = useState('unlocked');
      const [activePage, setActivePage] = useState('sessions');
      const contextMenuOverlayOpen = useContextMenuOverlayOpen();
      ${section(app, '  const [updateCurrentVersion,', '  const [autoCopyOnSelect,')}
      ${section(app, '  const [updateBusy,', '  const treeMovePending =')}
      ${app.slice(effectStart, effectEnd)}
      ${section(app, '  async function handleInstallUpdate()', '  function handleSetAutoCheckForUpdates(')}
      updateTestControls = { dismiss: handleDismissUpdate, check: handleCheckForUpdates, install: handleInstallUpdate,
        viewChanges: handleViewUpdateChanges, setResult: setUpdateResult, setAuthGate };
      const update = { autoCheckForUpdates, busy: updateBusy, currentVersion: updateCurrentVersion,
        downloadProgress: updateDownloadProgress, lastUpdateCheck, result: updateResult,
        dismissedUpdateVersion, status: updateStatus };
      return <>
        <output id="native-surface-state">{contextMenuOverlayOpen ? 'hidden' : 'visible'}</output>
        ${app.slice(mountStart, mountEnd)}
        {activePage === 'settings' ? <UpdateSettingsHarness update={update} settingsUpdatesRequest={settingsUpdatesRequest}
          onCheckForUpdates={() => void handleCheckForUpdates()} onInstallUpdate={() => void handleInstallUpdate()}
          onDismissUpdate={handleDismissUpdate} /> : null}
      </>;
    }
    ${fixture.code}
  `;
  const transformed = await transformWithOxc(production, 'update-notification.tsx', {
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
  const css = (Array.isArray(output) ? output : [output])
    .flatMap((result) => result.output)
    .filter((asset) => asset.type === 'asset' && asset.fileName.endsWith('.css'))
    .map((asset) => (asset.type === 'asset' ? String(asset.source) : ''))
    .join('\n');
  assert.ok(css.length > 0);
  const renderer = `
    const assert = require('node:assert/strict');
    const React = require(${JSON.stringify(require.resolve('react'))});
    const { useState, useEffect, useMemo } = React;
    const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
    const { Slot } = require(${JSON.stringify(require.resolve('radix-ui'))});
    const { Download, X } = require(${JSON.stringify(require.resolve('lucide-react'))});
    const { cva } = require(${JSON.stringify(require.resolve('class-variance-authority'))});
    const { clsx } = require(${JSON.stringify(require.resolve('clsx'))});
    const { twMerge } = require(${JSON.stringify(require.resolve('tailwind-merge'))});
    const cn = (...inputs) => twMerge(clsx(inputs));
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    const style = document.createElement('style');
    style.textContent = ${JSON.stringify(css)};
    document.head.append(style);
    ${transformed.code}
    //# sourceURL=wormhole-update-notification.js
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-update-notification-'));
  const harnessPath = join(directory, 'updates.cjs');
  const viewports = [
    [1200, 800],
    [576, 341],
    [320, 320],
  ];
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
            const script = coverage.result.find(item => item.url === 'wormhole-update-notification.js');
            if (!script) throw new Error('Missing update renderer coverage.');
            for (const name of ['UpdateNotification', 'UpdateSettingsHarness', 'handleDismissUpdate', 'handleViewUpdateChanges', 'handleCheckForUpdates', 'handleInstallUpdate']) {
              const parent = script.functions.find(item => item.functionName === name);
              if (!parent) throw new Error('Missing coverage for ' + name);
              const range = parent.ranges[0];
              const ranges = script.functions.filter(item => item.ranges[0].startOffset >= range.startOffset &&
                item.ranges[0].endOffset <= range.endOffset).flatMap(item => item.ranges);
              const covered = ranges.filter(item => item.count > 0).length;
              const percent = 100 * covered / ranges.length;
              console.log(width + 'x' + height + ': ' + name + ' V8 block coverage ' + percent.toFixed(2) + '%');
              if (percent < ${coverageThreshold}) throw new Error(name + ' coverage is below ${coverageThreshold}%.');
            }
            const start = ${JSON.stringify(renderer.indexOf('useEffect(() => {', renderer.indexOf('function UpdateHarness(')))};
            const end = ${JSON.stringify(renderer.indexOf('const updateNotificationVisible =', renderer.indexOf('function UpdateHarness(')))};
            const ranges = script.functions.flatMap(item => item.ranges).filter(item => item.startOffset >= start && item.endOffset <= end);
            if (!(start > 0 && end > start && ranges.length > 0)) throw new Error('Missing update subscription coverage.');
            const percent = 100 * ranges.filter(item => item.count > 0).length / ranges.length;
            console.log(width + 'x' + height + ': update subscription V8 block coverage ' + percent.toFixed(2) + '%');
            if (percent < ${coverageThreshold}) throw new Error('Update subscription coverage is below ${coverageThreshold}%.');
          } finally { window.destroy(); }
        }
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
    for (const line of stdout.trim().split(/\r?\n/)) context.diagnostic(line);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
