import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import {
  defaultSshTerminalTheme,
  isSshTerminalTheme,
  sshTerminalThemeIds,
} from '../electron/terminal-theme-settings.ts';
import { sshTerminalColors, sshTerminalThemes } from '../src/terminal-themes.ts';

test('SSH themes have complete independent ANSI palettes and safe fallbacks', () => {
  assert.equal(defaultSshTerminalTheme, 'tango');
  assert.deepEqual(
    sshTerminalThemes.map(({ id }) => id),
    sshTerminalThemeIds,
  );
  for (const id of sshTerminalThemeIds) {
    assert.ok(isSshTerminalTheme(id));
    const colors = sshTerminalColors(id);
    assert.equal(Object.keys(colors).length, 21);
    for (const color of Object.values(colors))
      assert.match(color!, /^#[0-9a-f]{6}([0-9a-f]{2})?$/i);
    colors.background = '#000000';
    assert.notEqual(sshTerminalColors(id).background, '#000000');
  }
  for (const value of [null, undefined, '', 'unknown', 'DRACULA', ' light', {}, 1, ['tango']]) {
    assert.equal(isSshTerminalTheme(value), false);
    assert.deepEqual(sshTerminalColors(value), sshTerminalColors(defaultSshTerminalTheme));
  }
});

test('Wormhole Dark ANSI blue directory names contrast with world-writable green backgrounds', () => {
  const colors = sshTerminalColors('wormhole-dark');
  function luminance(hex: string) {
    const channels = hex
      .slice(1)
      .match(/../g)!
      .map((channel) => {
        const value = parseInt(channel, 16) / 255;
        return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
  }
  for (const foreground of [colors.blue!, colors.brightBlue!]) {
    assert.ok((luminance(foreground) + 0.05) / (luminance(colors.green!) + 0.05) >= 4.5);
  }
});

test('the real SSH theme IPC bridge validates input and requires authentication before persistence', async () => {
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const preloadSource = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  const start = main.indexOf("  ipcMain.handle('settings:set-ssh-terminal-theme'");
  const end = main.indexOf("  ipcMain.handle('settings:set-theme'", start);
  assert.ok(start >= 0 && end > start);
  let authorized = true;
  let authChecks = 0;
  const writes: unknown[] = [];
  const handlers = new Map<string, (event: object, theme: unknown) => Promise<unknown>>();
  runInNewContext(stripTypeScriptTypes(main.slice(start, end)), {
    ipcMain: {
      handle: (channel: string, callback: (event: object, theme: unknown) => Promise<unknown>) =>
        handlers.set(channel, callback),
    },
    isSshTerminalTheme,
    serializeAuthOperation: (callback: () => Promise<unknown>) => callback(),
    requireWorkspaceAuth: async () => {
      authChecks++;
      if (!authorized) throw new Error('locked');
    },
    runBackend: async (operation: string, payload: { theme: string }) => {
      writes.push([operation, payload.theme]);
      return { updated: true };
    },
  });
  let bridge: { setSshTerminalTheme(value: unknown): Promise<unknown> };
  runInNewContext(stripTypeScriptTypes(preloadSource).replace(/^import .* from 'electron';/m, ''), {
    contextBridge: {
      exposeInMainWorld: (_name: string, api: typeof bridge) => {
        bridge = api;
      },
    },
    process: { isMainFrame: true },
    ipcRenderer: { invoke: (channel: string, value: unknown) => handlers.get(channel)!({}, value) },
  });
  for (const id of sshTerminalThemeIds) await bridge!.setSshTerminalTheme(id);
  assert.equal(authChecks, 4);
  assert.deepEqual(
    writes,
    sshTerminalThemeIds.map((id) => ['settings-set-ssh-terminal-theme', id]),
  );
  for (const invalid of [
    undefined,
    null,
    [],
    {},
    true,
    1,
    'unknown',
    'light\0',
    'x'.repeat(8192),
  ]) {
    await assert.rejects(bridge!.setSshTerminalTheme(invalid), /invalid/);
  }
  assert.equal(authChecks, 4, 'invalid input reached authentication/backend');
  authorized = false;
  await assert.rejects(bridge!.setSshTerminalTheme('light'), /locked/);
  assert.equal(writes.length, 4);
});
