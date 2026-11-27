import assert from 'node:assert/strict';
import test from 'node:test';
import { preferences } from './fixtures/vault-preferences.ts';
import { parseVaultPreferences } from '../electron/vault-preferences.ts';

test('preferences copy only the bounded native public projection', () => {
  assert.deepEqual(parseVaultPreferences(preferences()), preferences());
  const value = {
    ...preferences(),
    theme: 'dark',
    sidebarWidth: 600,
    connectionTreeExpansion: { defaultExpanded: false, folderIds: ['folder-a', '日本語'] },
    lastUpdateCheck: '2026-10-31T12:00:00Z',
    skippedUpdateVersion: 'v1.2.3',
  };
  const copy = parseVaultPreferences(value)!;
  assert.deepEqual(copy, value);
  value.connectionTreeExpansion.folderIds.push('later');
  assert.equal(copy.connectionTreeExpansion!.folderIds.length, 2);
  assert.ok(parseVaultPreferences({ ...preferences(), sidebarWidth: 256, theme: 'light' }));
  for (const sshTerminalTheme of ['wormhole-dark', 'dracula', 'tango', 'light']) {
    const themed = { ...preferences(), sshTerminalTheme };
    assert.deepEqual(parseVaultPreferences(themed), themed);
  }
  for (const bad of [
    null,
    [],
    {},
    { ...preferences(), password: 'private' },
    ...[null, undefined, false, '', 'unknown', 'tango\n', 'x'.repeat(2049)].map(
      (sshTerminalTheme) => ({ ...preferences(), sshTerminalTheme }),
    ),
    ...['theme', 'sidebarWidth', 'confirmOnWindowClose', 'lastUpdateCheck'].map((key) => ({
      ...preferences(),
      [key]: undefined,
    })),
    ...[255, 601, 320.5, NaN].map((sidebarWidth) => ({ ...preferences(), sidebarWidth })),
    ...[false, 'x'.repeat(2049), '\n'].map((lastUpdateCheck) => ({
      ...preferences(),
      lastUpdateCheck,
    })),
    ...[
      [],
      {},
      { defaultExpanded: 1, folderIds: [] },
      { defaultExpanded: true, folderIds: null },
      { defaultExpanded: true, folderIds: ['x'], secret: true },
      ...[[''], ['a', 'a'], [' x'], ['x\u007f'], ['x'.repeat(129)], Array(25001).fill('x')].map(
        (folderIds) => ({ defaultExpanded: true, folderIds }),
      ),
    ].map((connectionTreeExpansion) => ({ ...preferences(), connectionTreeExpansion })),
  ]) {
    assert.equal(parseVaultPreferences(bad), undefined);
  }
});
