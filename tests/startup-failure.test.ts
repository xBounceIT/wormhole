import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { transformWithOxc } from 'vite';
import { loadShellPage } from '../electron/shell-page-load.ts';
import { coverageThreshold } from '../scripts/test-coverage.ts';
import { runWindowTeardown } from '../electron/window-lifecycle.ts';

test('workspace failure IPC releases native resources once and ignores unrelated windows', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = main.indexOf("  ipcMain.on('workspace:failed'");
  const end = main.indexOf("  ipcMain.handle('startup:load'", start);
  assert.ok(start >= 0 && end > start);
  for (const scenario of [
    'healthy',
    'missing',
    'destroyed',
    'untrusted',
    'flush-failed',
    'shutdown-failed',
    'close-failed',
  ]) {
    const actions: string[] = [];
    const owner = {
      isDestroyed: () => scenario === 'destroyed',
      setOpacity: (opacity: number) => actions.push(`opacity:${opacity}`),
    };
    const failedWorkspaceWindows = new WeakSet();
    const startupReadyWindows = new WeakSet([owner]);
    const windowCloseCoordinators = new WeakMap();
    if (scenario !== 'untrusted')
      windowCloseCoordinators.set(owner, {
        updateActiveCount: (count: number) => actions.push(`active:${count}`),
      });
    let handler: (event: unknown) => void = () => assert.fail('Missing handler');
    let pending: Promise<unknown> = Promise.resolve();
    runInNewContext(stripTypeScriptTypes(main.slice(start, end)), {
      ipcMain: {
        on: (_channel: string, callback: typeof handler) => {
          handler = callback;
        },
      },
      BrowserWindow: { fromWebContents: () => (scenario === 'missing' ? undefined : owner) },
      failedWorkspaceWindows,
      startupReadyWindows,
      windowCloseCoordinators,
      serializeAuthOperation: (action: () => Promise<void>) =>
        (pending = Promise.resolve().then(action)),
      authSession: { lock: () => actions.push('lock') },
      runWindowTeardown,
      withBitwardenBrowserTimeout: (promise: Promise<void>) => promise,
      webSurfaces: {
        closeForWindow: () => {
          actions.push('close');
          if (scenario === 'close-failed') throw new Error('private');
        },
        flushAndCloseForWindow: async () => {
          actions.push('flush');
          if (scenario === 'flush-failed') throw new Error('private');
        },
      },
      shutdownNativeResources: async () => {
        actions.push('shutdown');
        if (scenario === 'shutdown-failed') throw new Error('private');
      },
      console: {
        warn: (...args: unknown[]) => {
          assert.equal(args.length, 1);
          assert.ok(!String(args[0]).includes('private'));
          actions.push('warning');
        },
      },
    });
    handler({ sender: {} });
    handler({ sender: {} });
    await pending.catch(() => undefined);
    await Promise.resolve();
    if (['missing', 'destroyed', 'untrusted'].includes(scenario)) {
      assert.deepEqual(actions, []);
      assert.equal(startupReadyWindows.has(owner), true);
    } else {
      assert.deepEqual(actions, [
        'active:0',
        'opacity:1',
        'lock',
        'flush',
        'close',
        'shutdown',
        ...(scenario.endsWith('-failed') ? ['warning'] : []),
      ]);
      assert.equal(startupReadyWindows.has(owner), false);
      assert.equal(failedWorkspaceWindows.has(owner), true);
    }
  }
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  assert.match(preload, /markWorkspaceFailed: \(\) => ipcRenderer.send\('workspace:failed'\)/);
  assert.match(main, /did-start-loading'[\s\S]*?failedWorkspaceWindows.delete\(window\)/);
  assert.match(main, /reason: failedWorkspaceWindows.has\(window\) \? 'renderer-failure'/);
});

test('failed shell loads report once and close, without leaking load error details', async () => {
  for (const scenario of ['success', 'rejected', 'throws', 'destroyed', 'dialog-destroys']) {
    let destroyed = scenario === 'destroyed';
    const actions: string[] = [];
    await loadShellPage({
      load: () => {
        if (scenario === 'throws') throw new Error('sensitive URL');
        return scenario === 'success' ? Promise.resolve() : Promise.reject('sensitive URL');
      },
      isDestroyed: () => destroyed,
      reportFailure: (...args: unknown[]) => {
        assert.deepEqual(args, []);
        actions.push('report');
        if (scenario === 'dialog-destroys') destroyed = true;
      },
      close: () => {
        actions.push('close');
      },
    });
    assert.deepEqual(
      actions,
      scenario === 'success' || scenario === 'destroyed'
        ? []
        : scenario === 'dialog-destroys'
          ? ['report']
          : ['report', 'close'],
    );
  }
});

test('the shell disposes the failed window even if the native error dialog fails', async () => {
  let closed = false;
  await loadShellPage({
    load: async () => {
      throw new Error('load failed');
    },
    isDestroyed: () => false,
    reportFailure: () => {
      throw new Error('dialog failed');
    },
    close: () => {
      closed = true;
    },
  });
  assert.equal(closed, true);
});

test('startup adapters wire native load recovery and wrap the complete React workspace', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const root = readFileSync(new URL('../src/WorkspaceRoot.tsx', import.meta.url), 'utf8');
  assert.match(
    main,
    /loadShellPage\(\{[\s\S]*?window\.loadURL\(rendererUrl\)[\s\S]*?window\.loadFile\(productionRendererPath\)/,
  );
  assert.match(
    root,
    /<WorkspaceErrorBoundary[\s\S]*?markWorkspaceFailed\(\)[\s\S]*?window\.location\.reload\(\)[\s\S]*?<ContextMenuOverlayProvider>[\s\S]*?<WorkspaceApp/,
  );
});

test('superseded navigation never closes the replacement page', async () => {
  for (const error of [
    Object.assign(new Error('superseded'), { code: 'ERR_ABORTED' }),
    { code: 'ERR_ABORTED' },
  ]) {
    await loadShellPage({
      load: async () => {
        throw error;
      },
      isDestroyed: () => false,
      reportFailure: () => assert.fail('Unexpected dialog'),
      close: () => assert.fail('Closed replacement'),
    });
  }
});

test('React render and effect failures show a recoverable screen instead of a blank root', async (context) => {
  const require = createRequire(import.meta.url);
  const source = readFileSync(
    new URL('../src/WorkspaceErrorBoundary.tsx', import.meta.url),
    'utf8',
  );
  const production = await transformWithOxc(
    source.replace(/^import .*;\r?\n/gm, '').replace('export class', 'class'),
    'boundary.tsx',
    { jsx: { runtime: 'classic' } },
  );
  const renderer = `
    var React = require(${JSON.stringify(require.resolve('react'))});
    var Component = React.Component;
    ${production.code}
    window.TestBoundary = WorkspaceErrorBoundary;
    void 0;
    //# sourceURL=wormhole-startup-boundary.js
  `;
  const fixture = `
    (async () => {
      const assert = require('node:assert/strict');
      const { createRoot } = require(${JSON.stringify(require.resolve('react-dom/client'))});
      globalThis.IS_REACT_ACT_ENVIRONMENT = true;
      const h = React.createElement;
      let notified = 0, retried = 0;
      function Broken({ mode }) {
        React.useEffect(() => { if (mode === 'effect') throw new Error('private failure'); }, []);
        if (mode === 'render') throw new Error('private failure');
        return h('p', null, 'Workspace ready');
      }
      // Reproduce the original failure: createRoot.render returns before React fails,
      // so the caller's try/catch cannot prevent the root from becoming empty.
      let uncaught = 0;
      let resolveFailure;
      const failed = new Promise(resolve => { resolveFailure = resolve; });
      globalThis.IS_REACT_ACT_ENVIRONMENT = false;
      const unprotected = createRoot(document.getElementById('root'), {
        onUncaughtError: () => { uncaught++; resolveFailure(); },
      });
      unprotected.render(h(Broken, { mode: 'render' }));
      await failed;
      assert.equal(uncaught, 1);
      assert.equal(document.getElementById('root').textContent, '');
      globalThis.IS_REACT_ACT_ENVIRONMENT = true;
      await React.act(async () => unprotected.unmount());
      for (const mode of ['healthy', 'render', 'effect']) {
        const root = createRoot(document.getElementById('root'));
        await React.act(async () => root.render(h(window.TestBoundary, {
          onFailure: () => notified++, onRetry: () => retried++,
        }, h(Broken, { mode }))));
        if (mode === 'healthy') {
          assert.equal(document.querySelector('[role=alert]'), null);
          assert.match(document.body.textContent, /Workspace ready/);
          assert.equal(notified, 0);
        } else {
          const alert = document.querySelector('[role=alert]');
          assert.ok(alert);
          assert.match(alert.textContent, /Wormhole couldn't open/);
          assert.ok(!alert.textContent.includes('private failure'));
          assert.equal(notified, mode === 'render' ? 1 : 2);
          await React.act(async () => alert.querySelector('button').click());
          assert.equal(retried, notified);
        }
        await React.act(async () => root.unmount());
      }
    })()
  `;
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-startup-test-'));
  const harness = join(directory, 'startup.cjs');
  try {
    writeFileSync(
      harness,
      `
      const { app, BrowserWindow } = require('electron');
      app.setPath('userData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false,
          webPreferences: { nodeIntegration: true, contextIsolation: false } });
        await window.loadURL('data:text/html,<div id="root"></div>');
        const debuggerApi = window.webContents.debugger;
        debuggerApi.attach('1.3');
        await debuggerApi.sendCommand('Profiler.enable');
        await debuggerApi.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
        await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
        await window.webContents.executeJavaScript(${JSON.stringify(fixture)});
        const coverage = await debuggerApi.sendCommand('Profiler.takePreciseCoverage');
        const script = coverage.result.find(item => item.url === 'wormhole-startup-boundary.js');
        if (!script) throw new Error('Missing production boundary coverage');
        const ranges = script.functions.flatMap(item => item.ranges);
        const percent = 100 * ranges.filter(item => item.count > 0).length / ranges.length;
        console.log('Startup boundary V8 block coverage: ' + percent.toFixed(2) + '%');
        if (percent < ${coverageThreshold}) throw new Error('Insufficient boundary coverage');
        window.destroy();
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const { ELECTRON_RUN_AS_NODE: _, ...environment } = process.env;
    const electron = require('electron') as string;
    const needsDisplay = process.platform === 'linux' && !environment.DISPLAY;
    const result = await promisify(execFile)(
      needsDisplay ? 'xvfb-run' : electron,
      needsDisplay ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 60_000, windowsHide: true },
    );
    context.diagnostic(result.stdout.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
