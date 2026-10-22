import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

import { parseThemeStartupRequest } from '../electron/theme-settings.ts';
import {
  nativeTitlebarOverlay,
  syncNativeTitlebarTheme,
} from '../electron/native-titlebar-theme.ts';
import {
  applyTheme,
  clearLegacyTheme,
  getInitialTheme,
  getSystemTheme,
  readLegacyTheme,
  themeStorageKey,
} from '../src/theme.ts';

test('native controls use contrasting symbols without changing the titlebar layout', () => {
  assert.deepEqual(nativeTitlebarOverlay('light'), {
    color: '#0a0a0a00',
    symbolColor: '#0a0a0a',
    height: 48,
  });
  assert.deepEqual(nativeTitlebarOverlay('dark'), {
    color: '#0a0a0a00',
    symbolColor: '#ffffff',
    height: 48,
  });
});

test('native controls follow theme transitions on Windows and Linux', () => {
  for (const platform of ['win32', 'linux'] as const) {
    const updates: unknown[] = [];
    const window = {
      isDestroyed: () => false,
      setTitleBarOverlay: (options: unknown) => updates.push(options),
    };
    for (const theme of ['light', 'dark', 'light']) {
      syncNativeTitlebarTheme(window, theme, platform);
    }
    assert.deepEqual(updates, [
      nativeTitlebarOverlay('light'),
      nativeTitlebarOverlay('dark'),
      nativeTitlebarOverlay('light'),
    ]);
  }
});

test('native theme updates ignore invalid input, closed windows and macOS traffic lights', () => {
  const window = {
    isDestroyed: () => false,
    setTitleBarOverlay: () => assert.fail('Unexpected native overlay update'),
  };
  for (const value of [undefined, null, 'system', 'LIGHT', '', {}, [], 1]) {
    syncNativeTitlebarTheme(window, value, 'win32');
  }
  syncNativeTitlebarTheme(window, 'light', 'darwin');
  syncNativeTitlebarTheme(null, 'light', 'win32');
  syncNativeTitlebarTheme({ ...window, isDestroyed: () => true }, 'light', 'win32');
});

test('applying a theme sends the actual rendered color scheme to native controls', (t) => {
  const updates: string[] = [];
  let systemDark = false;
  let darkClass = false;
  const root = {
    classList: {
      toggle: (name: string, enabled: boolean) => {
        assert.equal(name, 'dark');
        darkClass = enabled;
      },
    },
    style: { colorScheme: '' },
  };
  const previousWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const previousDocument = Object.getOwnPropertyDescriptor(globalThis, 'document');
  t.after(() => {
    for (const [key, descriptor] of [
      ['window', previousWindow],
      ['document', previousDocument],
    ] as const) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  });
  Object.defineProperty(globalThis, 'document', {
    configurable: true,
    value: { documentElement: root },
  });
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: {
      matchMedia: (query: string) => {
        assert.equal(query, '(prefers-color-scheme: dark)');
        return { matches: systemDark };
      },
      wormhole: {
        setTitlebarTheme: (theme: string) => {
          assert.equal(root.style.colorScheme, theme);
          assert.equal(darkClass, theme === 'dark');
          updates.push(theme);
        },
      },
    },
  });
  applyTheme('light');
  applyTheme('dark');
  applyTheme('system');
  systemDark = true;
  applyTheme('system');
  applyTheme('light');
  assert.deepEqual(updates, ['light', 'dark', 'light', 'dark', 'light']);
  Object.defineProperty(globalThis, 'window', { value: {} });
  assert.doesNotThrow(() => applyTheme('light'));
});

test('theme startup tolerates absent and disabled renderer storage', () => {
  assert.equal(readLegacyTheme(), null);
  assert.doesNotThrow(() => clearLegacyTheme());
  assert.equal(getSystemTheme(), 'light');
  const disabledStorage = {
    getItem: () => {
      throw new Error('Storage disabled');
    },
    removeItem: () => {
      throw new Error('Storage disabled');
    },
  };
  assert.equal(readLegacyTheme(disabledStorage), null);
  assert.doesNotThrow(() => clearLegacyTheme(disabledStorage));
  assert.equal(getInitialTheme('light'), 'light');
});

test('the real preload and IPC handler update only live application windows', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const preloadSource = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const start = mainSource.indexOf("  ipcMain.on('window:set-titlebar-theme'");
  const end = mainSource.indexOf("  ipcMain.on('startup:ready'", start);
  assert.ok(start >= 0 && end > start);
  const updates: unknown[] = [];
  let destroyed = false;
  const owner = {
    isDestroyed: () => destroyed,
    setTitleBarOverlay: (options: unknown) => updates.push(options),
  };
  const foreignWindow = {
    isDestroyed: () => false,
    setTitleBarOverlay: () => assert.fail('An unrelated window was updated'),
  };
  const sender = {};
  const foreignSender = {};
  const handlers = new Map<string, (event: { sender: object }, value: unknown) => void>();
  runInNewContext(stripTypeScriptTypes(mainSource.slice(start, end)), {
    ipcMain: {
      on: (channel: string, handler: (event: { sender: object }, value: unknown) => void) =>
        handlers.set(channel, handler),
    },
    BrowserWindow: {
      fromWebContents: (contents: object) =>
        contents === sender ? owner : contents === foreignSender ? foreignWindow : null,
    },
    windowCloseCoordinators: new WeakMap([[owner, {}]]),
    syncNativeTitlebarTheme,
    process: { platform: 'win32' },
  });
  let bridge: { setTitlebarTheme(theme: unknown): void } | undefined;
  const context = {
    contextBridge: {
      exposeInMainWorld: (name: string, api: typeof bridge) => {
        assert.equal(name, 'wormhole');
        bridge = api;
      },
    },
    ipcRenderer: {
      send: (channel: string, value: unknown) => {
        const handler = handlers.get(channel);
        assert.ok(handler, `Missing IPC handler for ${channel}`);
        handler({ sender }, value);
      },
    },
    process: { isMainFrame: true },
  };
  const preload = stripTypeScriptTypes(preloadSource).replace(/^import .* from 'electron';/m, '');
  runInNewContext(preload, context);
  assert.ok(bridge);
  bridge.setTitlebarTheme('light');
  bridge.setTitlebarTheme('dark');
  bridge.setTitlebarTheme('light');
  for (const value of [null, {}, 'system', 'LIGHT', 'dark\u0000', 'x'.repeat(4096)]) {
    bridge.setTitlebarTheme(value);
  }
  const handler = handlers.get('window:set-titlebar-theme')!;
  handler({ sender: foreignSender }, 'dark');
  handler({ sender: {} }, 'dark');
  destroyed = true;
  bridge.setTitlebarTheme('dark');
  assert.deepEqual(updates, [
    nativeTitlebarOverlay('light'),
    nativeTitlebarOverlay('dark'),
    nativeTitlebarOverlay('light'),
  ]);
  bridge = undefined;
  runInNewContext(preload, { ...context, process: { isMainFrame: false } });
  assert.equal(bridge, undefined, 'child frames must not receive the window controls bridge');
});

function memoryStorage(initial?: string) {
  const values = new Map<string, string>();
  if (initial !== undefined) values.set(themeStorageKey, initial);
  return {
    getItem(key: string) {
      return values.get(key) ?? null;
    },
    removeItem(key: string) {
      values.delete(key);
    },
  };
}

test('legacy renderer theme accepts only supported values and otherwise uses System', () => {
  assert.equal(readLegacyTheme(memoryStorage('dark')), 'dark');
  assert.equal(readLegacyTheme(memoryStorage('Light')), null);
  assert.equal(readLegacyTheme(memoryStorage('sepia')), null);
  assert.equal(getInitialTheme(readLegacyTheme(memoryStorage())), 'system');
});

test('legacy renderer theme is cleared only through the explicit migration cleanup', () => {
  const storage = memoryStorage('light');
  clearLegacyTheme(storage);
  assert.equal(readLegacyTheme(storage), null);
});

test('startup theme migration accepts only its narrow IPC request shape', () => {
  assert.deepEqual(parseThemeStartupRequest(undefined), {});
  assert.deepEqual(parseThemeStartupRequest({}), {});
  assert.deepEqual(parseThemeStartupRequest({ legacyTheme: 'dark' }), { legacyTheme: 'dark' });

  for (const value of [null, [], new Date(), { unexpected: true }, { legacyTheme: 'sepia' }]) {
    assert.throws(() => parseThemeStartupRequest(value), /settings request|theme is invalid/i);
  }
});

test('theme persistence crosses the validated Electron-to-Go settings bridge', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const preloadSource = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const appSource = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const startupSource = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');

  assert.match(preloadSource, /ipcRenderer\.invoke\('settings:set-theme', theme\)/);
  assert.match(mainSource, /if \(!isAppTheme\(value\)\)/);
  assert.match(
    mainSource,
    /ipcMain\.handle\('settings:set-theme',[\s\S]*?await requireWorkspaceAuth\(\)[\s\S]*?'settings-set-theme'/,
  );
  assert.match(appSource, /window\.wormhole\?\.setTheme\(nextTheme\)/);
  assert.match(appSource, /useState<Theme>\(initialSettings\.theme\)/);
  assert.doesNotMatch(appSource, /localStorage\.setItem/);
  assert.match(startupSource, /loadStartup\(legacyTheme \?\? undefined\)/);
  assert.match(startupSource, /applyTheme\(startup\.settings\.theme\)/);
  assert.match(startupSource, /startup\.themeMigration\.handled/);
});
