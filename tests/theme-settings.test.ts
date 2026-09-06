import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { parseThemeStartupRequest } from '../electron/theme-settings.ts';
import {
  clearLegacyTheme,
  getInitialTheme,
  readLegacyTheme,
  themeStorageKey,
} from '../src/theme.ts';

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
  assert.match(startupSource, /loadStartup\(legacyTheme \?\? undefined\)/);
  assert.match(startupSource, /applyTheme\(startup\.settings\.theme\)/);
  assert.match(startupSource, /startup\.themeMigration\.handled/);
});
