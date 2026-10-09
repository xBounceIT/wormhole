import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { runInNewContext } from 'node:vm';
import type { BrowserWindow, BrowserWindowConstructorOptions } from 'electron';
import { TreeTooltipManager, type TreeTooltipRequest } from '../electron/tree-tooltip.ts';

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

class FakeWindow extends EventEmitter {
  id = 1;
  destroyed = false;
  visible = true;
  minimized = false;
  content = { x: -1200, y: 85, width: 1000, height: 700 };
  bounds: Record<string, number> | undefined;
  shown = 0;
  raised = 0;
  raiseError = false;
  hidden = 0;
  ignored: unknown[] = [];
  menu: unknown = 'default';
  url = '';
  scripts: string[] = [];
  load = Promise.resolve();
  execute = () => Promise.resolve();
  webContents = {
    executeJavaScript: (script: string) => {
      this.scripts.push(script);
      return this.execute();
    },
  };
  isDestroyed() {
    return this.destroyed;
  }
  isVisible() {
    return this.visible;
  }
  isMinimized() {
    return this.minimized;
  }
  getContentBounds() {
    return this.content;
  }
  setBounds(bounds: Record<string, number>) {
    this.bounds = bounds;
  }
  showInactive() {
    this.shown += 1;
    this.visible = true;
  }
  moveTop() {
    if (this.raiseError) throw new Error('native window gone');
    this.raised += 1;
  }
  hide() {
    this.hidden += 1;
    this.visible = false;
  }
  destroy() {
    this.destroyed = true;
    this.emit('closed');
  }
  setIgnoreMouseEvents(...args: unknown[]) {
    this.ignored = args;
  }
  setMenu(menu: unknown) {
    this.menu = menu;
  }
  loadURL(url: string) {
    this.url = url;
    return this.load;
  }
  asBrowserWindow() {
    return this as unknown as BrowserWindow;
  }
}

function harness(popup = new FakeWindow()) {
  const owner = new FakeWindow();
  const options: BrowserWindowConstructorOptions[] = [];
  const manager = new TreeTooltipManager((value) => {
    options.push(value);
    return popup.asBrowserWindow();
  });
  const request: TreeTooltipRequest = {
    text: '192.0.2.10',
    anchor: { x: 220, y: 100, width: 180, height: 26 },
    width: 120,
  };
  const show = (value = request) => manager.show(owner.asBrowserWindow(), value);
  const hide = () => manager.hide(owner.asBrowserWindow());
  const close = () => manager.closeForWindow(owner.asBrowserWindow());
  return { owner, popup, manager, options, request, show, hide, close };
}

const settle = () => new Promise<void>((resolve) => setImmediate(resolve));

test('main process uses the native tooltip manager and closes auxiliary windows before quit', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  assert.match(main, /new TreeTooltipManager\(\(options\) => new BrowserWindow\(options\)\)/);
  const quit = main.slice(main.indexOf("app.on('before-quit'"));
  const closeTooltips = quit.indexOf('treeTooltips.closeForWindow(window)');
  assert.ok(closeTooltips >= 0 && closeTooltips < quit.indexOf('requestRendererCloseConfirmation'));
});

for (const channel of [
  'backend:event',
  'ssh:event',
  'serial:event',
  'rdp:event',
  'update:result',
]) {
  test(`${channel} broadcasts reach main windows without serializing to auxiliary tooltips`, () => {
    const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
    const send = main.indexOf(`window.webContents.send('${channel}'`);
    assert.ok(send >= 0);
    const start = main.lastIndexOf('for (const window of BrowserWindow.getAllWindows())', send);
    assert.ok(start >= 0);
    let end = main.indexOf('{', start);
    let depth = 1;
    while (depth > 0 && ++end < main.length) {
      if (main[end] === '{') depth += 1;
      if (main[end] === '}') depth -= 1;
    }
    assert.equal(depth, 0);
    const broadcast = stripTypeScriptTypes(main.slice(start, end + 1));
    const received: string[] = [];
    const window = (name: string, destroyed = false) => ({
      isDestroyed: () => destroyed,
      webContents: {
        send: (sentChannel: string, payload: unknown) => {
          assert.equal(sentChannel, channel);
          assert.equal(payload, event);
          received.push(name);
        },
      },
    });
    const primary = window('primary');
    const secondary = window('secondary');
    const closed = window('closed', true);
    const tooltip = window('tooltip');
    const otherAuxiliary = window('other-auxiliary');
    const event = { type: 'vnc.frame', data: 'frame-payload' };
    for (const visible of [true, false]) {
      Object.assign(tooltip, { isVisible: () => visible });
      received.length = 0;
      runInNewContext(broadcast, {
        BrowserWindow: {
          getAllWindows: () => [tooltip, primary, closed, otherAuxiliary, secondary],
        },
        windowCloseCoordinators: new Set([primary, secondary, closed]),
        event,
        message: event,
        result: event,
      });
      assert.deepEqual(received, ['primary', 'secondary']);
    }
  });
}

test('IP tooltip uses an owned native window above RDP without taking focus or mouse input', async () => {
  const { owner, popup, options, show } = harness();
  show();
  await settle();
  assert.equal(options[0].parent, owner);
  assert.equal(options[0].focusable, false);
  assert.equal(options[0].frame, false);
  assert.equal(options[0].show, false);
  assert.equal(options[0].transparent, true);
  assert.equal(options[0].skipTaskbar, true);
  assert.equal(options[0].alwaysOnTop, undefined);
  assert.deepEqual(options[0].webPreferences, {
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
    devTools: false,
  });
  assert.deepEqual(popup.ignored, [true, { forward: true }]);
  assert.equal(popup.menu, null);
  assert.deepEqual(popup.bounds, { x: -800, y: 178, width: 120, height: 40 });
  assert.equal(popup.shown, 1);
  assert.equal(popup.raised, 1);
  assert.match(decodeURIComponent(popup.url), /default-src 'none'/);
  assert.match(popup.scripts[0], /textContent = "192\.0\.2\.10"/);
});

test('bounds are clamped to the owner content area and remain in screen coordinates', async () => {
  const { popup, request, show } = harness();
  show({ ...request, anchor: { x: 999, y: 699, width: 50, height: 25 }, width: 120.4 });
  await settle();
  assert.deepEqual(popup.bounds, { x: -320, y: 745, width: 120, height: 40 });
  show({ ...request, anchor: { x: -500, y: -100, width: 1, height: 1 } });
  await settle();
  assert.deepEqual(popup.bounds, { x: -1200, y: 85, width: 120, height: 40 });
});

test('one tooltip window is reused and host text is assigned safely as text', async () => {
  const { popup, options, request, show, hide } = harness();
  hide();
  show();
  await settle();
  hide();
  show({ ...request, text: '<img src=x onerror=alert(1)>"\\\n' });
  await settle();
  assert.equal(options.length, 1);
  assert.equal(popup.shown, 2);
  assert.equal(popup.hidden, 1);
  assert.equal(
    popup.scripts[1],
    `document.getElementById('tooltip-text').textContent = ${JSON.stringify('<img src=x onerror=alert(1)>"\\\n')}`,
  );
});

test('a hide cancels a show waiting for the page to load', async () => {
  const popup = new FakeWindow();
  const load = deferred();
  popup.load = load.promise;
  const { show, hide } = harness(popup);
  show();
  hide();
  load.resolve();
  await settle();
  assert.equal(popup.shown, 0);
  assert.deepEqual(popup.scripts, []);
});

test('only the latest request can show after asynchronous text updates', async () => {
  const { popup, request, show } = harness();
  const first = deferred();
  popup.execute = () => first.promise;
  show();
  await settle();
  popup.execute = () => Promise.resolve();
  show({ ...request, text: '192.0.2.20' });
  await settle();
  first.resolve();
  await settle();
  assert.equal(popup.shown, 1);
  assert.match(popup.scripts.at(-1)!, /192\.0\.2\.20/);
});

test('hide and owner-window changes cancel a pending tooltip without disconnecting RDP', async () => {
  for (const event of ['blur', 'hide', 'minimize', 'move', 'resize']) {
    const { owner, popup, show } = harness();
    const update = deferred();
    popup.execute = () => update.promise;
    show();
    await settle();
    owner.emit(event);
    update.resolve();
    await settle();
    assert.equal(popup.shown, 0, event);
    assert.equal(popup.hidden, 1, event);
    assert.equal(owner.destroyed, false);
  }
});

test('destroyed, hidden, or minimized owners never present a tooltip', async () => {
  const destroyed = harness();
  destroyed.owner.destroyed = true;
  destroyed.show();
  assert.equal(destroyed.options.length, 0);
  for (const state of ['destroyed', 'visible', 'minimized'] as const) {
    const { owner, popup, show } = harness();
    const update = deferred();
    popup.execute = () => update.promise;
    show();
    await settle();
    owner[state] = state !== 'visible';
    update.resolve();
    await settle();
    assert.equal(popup.shown, 0, state);
  }
});

test('closing the owner or tooltip releases listeners and cancels in-flight work', async () => {
  for (const target of ['owner', 'popup', 'manager'] as const) {
    const { owner, popup, show, close, hide } = harness();
    const load = deferred();
    popup.load = load.promise;
    show();
    if (target === 'manager') close();
    else if (target === 'owner') owner.destroy();
    else popup.destroy();
    close();
    hide();
    load.resolve();
    await settle();
    assert.equal(popup.destroyed, true);
    assert.equal(popup.shown, 0);
    assert.deepEqual(owner.eventNames(), []);
    assert.deepEqual(popup.eventNames(), []);
  }
});

test('failed load or text update tears down the tooltip and allows a fresh retry', async () => {
  for (const failure of ['load', 'execute'] as const) {
    const { popup, show, options } = harness();
    if (failure === 'load') popup.load = Promise.reject(new Error('load failed'));
    else popup.execute = () => Promise.reject(new Error('renderer gone'));
    show();
    await settle();
    assert.equal(popup.destroyed, true);
    popup.destroyed = false;
    popup.load = Promise.resolve();
    popup.execute = () => Promise.resolve();
    show();
    await settle();
    assert.equal(options.length, 2);
    assert.equal(popup.shown, 1);
  }
});

test('a stale failed update cannot destroy a newer tooltip', async () => {
  const { popup, request, show } = harness();
  const first = deferred();
  popup.execute = () => first.promise;
  show();
  await settle();
  popup.execute = () => Promise.resolve();
  show({ ...request, text: '192.0.2.30' });
  await settle();
  first.reject(new Error('stale update'));
  await settle();
  assert.equal(popup.destroyed, false);
  assert.equal(popup.shown, 1);
});

test('a failed page load after hiding is discarded before the next hover', async () => {
  const owner = new FakeWindow();
  const first = new FakeWindow();
  const second = new FakeWindow();
  const load = deferred();
  first.load = load.promise;
  const windows = [first, second];
  const manager = new TreeTooltipManager(() => windows.shift()!.asBrowserWindow());
  const request = harness().request;
  manager.show(owner.asBrowserWindow(), request);
  manager.hide(owner.asBrowserWindow());
  load.reject(new Error('load failed after hide'));
  await settle();
  assert.equal(first.destroyed, true);
  manager.show(owner.asBrowserWindow(), request);
  await settle();
  assert.equal(second.shown, 1);
});

test('quit confirmation blocks new tooltip windows and cancellation restores normal hover', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const handler = main.slice(
    main.indexOf("  ipcMain.handle('tree-tooltip:show'"),
    main.indexOf("  ipcMain.handle('tree-tooltip:hide'"),
  );
  let show!: (event: unknown, request: unknown) => void;
  let shows = 0;
  const state = {
    quitCleanupStarted: true,
    isQuitting: false,
    ipcMain: {
      handle: (_name: string, callback: typeof show) => {
        show = callback;
      },
    },
    isTreeTooltipRequest: () => true,
    BrowserWindow: { fromWebContents: () => ({ isDestroyed: () => false }) },
    treeTooltips: {
      show: () => {
        shows += 1;
      },
    },
  };
  runInNewContext(stripTypeScriptTypes(handler), state);
  show({ sender: {} }, harness().request);
  assert.equal(shows, 0);
  state.quitCleanupStarted = false;
  show({ sender: {} }, harness().request);
  assert.equal(shows, 1);
  state.isQuitting = true;
  show({ sender: {} }, harness().request);
  assert.equal(shows, 1);
});

test('native RDP acknowledgements restore only the current session owner tooltip', () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const start = main.indexOf('  rdpClient.onEvent((event: RdpBackendEvent) => {');
  const callbackSource = main.slice(start, main.indexOf('  return rdpClient;', start));
  let callback!: (event: Record<string, unknown>) => void;
  const owner = {};
  const raised: unknown[] = [];
  runInNewContext(stripTypeScriptTypes(callbackSource), {
    rdpClient: {
      onEvent: (value: typeof callback) => {
        callback = value;
      },
    },
    rdpSurfacePlacements: new Map([['session-a', { owner }]]),
    rdpSessionAttempts: { isCurrent: (_id: string, generation: number) => generation === 7 },
    treeTooltips: { raiseForWindow: (value: unknown) => raised.push(value) },
    isRdpLifecycleEvent: () => false,
  });
  callback({ type: 'ack', sessionId: 'session-a', requestId: 'resize' });
  callback({ type: 'connected', sessionId: 'session-a', lifecycleGeneration: 7 });
  assert.deepEqual(raised, [owner, owner]);
  callback({ type: 'ack', sessionId: 'session-a', lifecycleGeneration: 6 });
  callback({ type: 'ack', sessionId: 'unknown' });
  callback({ type: 'ack' });
  assert.equal(raised.length, 2);
});

test('native event raises never show a closed tooltip or interrupt RDP on window failure', async () => {
  const { manager, owner, popup, show, hide, close } = harness();
  manager.raiseForWindow(owner.asBrowserWindow());
  assert.equal(popup.raised, 0);
  show();
  await settle();
  manager.raiseForWindow(owner.asBrowserWindow());
  assert.equal(popup.raised, 2);
  hide();
  manager.raiseForWindow(owner.asBrowserWindow());
  assert.equal(popup.raised, 2);
  show();
  await settle();
  for (const target of ['owner-destroyed', 'owner-hidden', 'owner-minimized', 'popup-destroyed']) {
    owner.destroyed = target === 'owner-destroyed';
    owner.visible = target !== 'owner-hidden';
    owner.minimized = target === 'owner-minimized';
    popup.destroyed = target === 'popup-destroyed';
    manager.raiseForWindow(owner.asBrowserWindow());
    assert.equal(popup.raised, 3, target);
  }
  owner.destroyed = false;
  owner.visible = true;
  owner.minimized = false;
  popup.destroyed = false;
  popup.raiseError = true;
  assert.doesNotThrow(() => manager.raiseForWindow(owner.asBrowserWindow()));
  assert.equal(popup.destroyed, true);
  close();
});

test('an old window load failure cannot tear down its replacement', async () => {
  const owner = new FakeWindow();
  const first = new FakeWindow();
  const second = new FakeWindow();
  const load = deferred();
  first.load = load.promise;
  const windows = [first, second];
  const manager = new TreeTooltipManager(() => windows.shift()!.asBrowserWindow());
  const request = harness().request;
  manager.show(owner.asBrowserWindow(), request);
  first.destroy();
  manager.show(owner.asBrowserWindow(), request);
  await settle();
  load.reject(new Error('old load failed'));
  await settle();
  assert.equal(second.destroyed, false);
  assert.equal(second.shown, 1);
});

test('real Electron tooltip stays owned, unfocused, and reusable over session views', async (context) => {
  const require = createRequire(import.meta.url);
  const { transformWithOxc } = await import('vite');
  const source = readFileSync(new URL('../electron/tree-tooltip.ts', import.meta.url), 'utf8');
  const transformed = await transformWithOxc(source, 'tree-tooltip.ts');
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-tree-tooltip-'));
  const modulePath = join(directory, 'tree-tooltip.mjs');
  const harnessPath = join(directory, 'tooltip.cjs');
  const stackingPath = join(directory, 'stacking.ps1');
  const { ELECTRON_RUN_AS_NODE: _electronRunAsNode, ...environment } = process.env;
  try {
    writeFileSync(modulePath, transformed.code);
    writeFileSync(
      stackingPath,
      `param([long]$Above, [long]$Below)
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NativeStacking {
  [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr hwnd, uint command);
  public static bool IsAbove(long above, long below) {
    var current = new IntPtr(below);
    for (var index = 0; index < 10000; index++) {
      current = GetWindow(current, 3);
      if (current == IntPtr.Zero) return false;
      if (current == new IntPtr(above)) return true;
    }
    throw new InvalidOperationException("Native window order did not terminate");
  }
}
'@
[NativeStacking]::IsAbove($Above, $Below)
`,
    );
    writeFileSync(
      harnessPath,
      `
      const assert = require('node:assert/strict');
      const { app, BrowserWindow, WebContentsView } = require('electron');
      const { execFileSync } = require('node:child_process');
      const isAbove = (above, below) => {
        const handle = window => window.getNativeWindowHandle().readBigUInt64LE().toString();
        return execFileSync('powershell.exe', ['-NoProfile', '-File', ${JSON.stringify(stackingPath)}, handle(above), handle(below)], { windowsHide: true, encoding: 'utf8', timeout: 10000 }).trim() === 'True';
      };
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      const waitUntil = async predicate => {
        const deadline = Date.now() + 5000;
        while (!predicate()) {
          if (Date.now() > deadline) throw new Error('Tooltip window did not reach expected state');
          await new Promise(resolve => setTimeout(resolve, 20));
        }
      };
      app.whenReady().then(async () => {
        const { TreeTooltipManager } = await import(${JSON.stringify(pathToFileURL(modulePath).href)});
        const owner = new BrowserWindow({ show: false, x: -10000, y: -10000, width: 600, height: 400 });
        const windows = [];
        const manager = new TreeTooltipManager(options => {
          const popup = new BrowserWindow(options);
          windows.push(popup);
          return popup;
        });
        let view, nativeRdp;
        try {
          await owner.loadURL('data:text/html,<div>Connection tree</div>');
          owner.showInactive();
          await new Promise(resolve => setTimeout(resolve, 100));
          const focusBefore = BrowserWindow.getFocusedWindow();
          const request = { text: '192.0.2.10', anchor: { x: 100, y: 40, width: 150, height: 30 }, width: 120 };
          manager.show(owner, request);
          await waitUntil(() => windows[0]?.isVisible());
          const popup = windows[0];
          assert.equal(popup.getParentWindow(), owner);
          assert.equal(popup.isFocusable(), false);
          assert.equal(popup.isFocused(), false);
          assert.equal(BrowserWindow.getFocusedWindow(), focusBefore);
          assert.equal(await popup.webContents.executeJavaScript("document.getElementById('tooltip-text').textContent"), request.text);
          const content = owner.getContentBounds();
          assert.deepEqual(popup.getBounds(), { x: content.x + 250, y: content.y + 35, width: 120, height: 40 });
          assert.deepEqual(popup.getContentSize(), [120, 40]);
          assert.equal(await popup.webContents.executeJavaScript("document.querySelector('.tooltip').getBoundingClientRect().height"), 28);
          view = new WebContentsView();
          owner.contentView.addChildView(view);
          view.setBounds({ x: 200, y: 0, width: 400, height: 300 });
          await view.webContents.loadURL('data:text/html,<body style="background:red">Session</body>');
          assert.equal(popup.isVisible(), true);
          if (${process.platform === 'win32'}) {
            nativeRdp = new BrowserWindow({ parent: owner, show: false, frame: false, x: content.x + 200, y: content.y, width: 300, height: 300 });
            await nativeRdp.loadURL('data:text/html,<body style="background:red">Native RDP sibling</body>');
            nativeRdp.showInactive();
            nativeRdp.moveTop();
            assert.equal(isAbove(popup, nativeRdp), false, 'Reproduce native RDP reclaiming the z-order');
            manager.raiseForWindow(owner);
            assert.equal(isAbove(popup, nativeRdp), true, 'An open tooltip must be raised above the native RDP sibling');
          }
          manager.hide(owner);
          assert.equal(popup.isVisible(), false);
          manager.show(owner, { ...request, text: '192.0.2.20' });
          await waitUntil(() => popup.isVisible());
          assert.equal(windows.length, 1);
          assert.equal(await popup.webContents.executeJavaScript("document.getElementById('tooltip-text').textContent"), '192.0.2.20');
          owner.emit('blur');
          assert.equal(popup.isVisible(), false);
          owner.destroy();
          assert.equal(popup.isDestroyed(), true);
          console.log('Native tooltip ownership, focus, bounds, reuse and teardown passed');
        } finally {
          manager.closeForWindow(owner);
          if (nativeRdp && !nativeRdp.isDestroyed()) nativeRdp.destroy();
          if (view && !view.webContents.isDestroyed()) view.webContents.close();
          if (!owner.isDestroyed()) owner.destroy();
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
      { env: { ...environment, NODE_ENV: 'test' }, timeout: 30_000, windowsHide: true },
    );
    if (stdout.trim()) context.diagnostic(stdout.trim());
    if (stderr.trim()) process.stderr.write(stderr);
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { force: true, recursive: true });
  }
});
