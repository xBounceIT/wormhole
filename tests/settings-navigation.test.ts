import assert from 'node:assert/strict';
import test from 'node:test';
import {
  filterSettingsCategories,
  isSettingsTabId,
  resolveVisibleSettingsTab,
  settingsCategories,
  settingsCategoryById,
  type SettingsTabId,
} from '../src/settings-navigation.ts';

test('settings categories cover every tab in grouped order', () => {
  assert.deepEqual(
    settingsCategories.map((category) => category.id),
    ['general', 'file-transfer', 'security', 'extensions', 'mcp', 'backup', 'logs', 'updates'],
  );
  for (const category of settingsCategories) {
    assert.ok(category.label.length > 0);
    assert.ok(category.description.length > 0);
    assert.ok(category.keywords.length > 0);
    assert.equal(settingsCategoryById[category.id], category);
  }
});

test('isSettingsTabId validates known category ids only', () => {
  const validIds: SettingsTabId[] = [
    'general',
    'file-transfer',
    'security',
    'extensions',
    'mcp',
    'backup',
    'logs',
    'updates',
  ];
  for (const id of validIds) {
    assert.equal(isSettingsTabId(id), true);
  }
  for (const invalid of ['', 'settings', 'General', 'unknown', 'toString', '__proto__']) {
    assert.equal(isSettingsTabId(invalid), false);
  }
});

test('filterSettingsCategories filters by label, group, description, and keywords', () => {
  const all = filterSettingsCategories('');
  assert.deepEqual(
    all.map((group) => [group.label, group.items.map((item) => item.id)]),
    [
      ['App', ['general', 'file-transfer', 'security']],
      ['Integrations', ['extensions', 'mcp']],
      ['System', ['backup', 'logs', 'updates']],
    ],
  );

  assert.deepEqual(
    filterSettingsCategories('   ').map((group) => group.label),
    ['App', 'Integrations', 'System'],
  );

  const bitwarden = filterSettingsCategories('BITWARDEN');
  assert.deepEqual(
    bitwarden.map((group) => [group.label, group.items.map((item) => item.id)]),
    [['Integrations', ['extensions']]],
  );

  const multiToken = filterSettingsCategories('windows lock');
  assert.deepEqual(
    multiToken.map((group) => [group.label, group.items.map((item) => item.id)]),
    [['App', ['security']]],
  );

  const byGroup = filterSettingsCategories('integrations');
  assert.deepEqual(
    byGroup.map((group) => [group.label, group.items.map((item) => item.id)]),
    [['Integrations', ['extensions', 'mcp']]],
  );

  assert.deepEqual(filterSettingsCategories('no-such-setting-xyz'), []);
});

test('resolveVisibleSettingsTab keeps active match, switches on filter, and handles empty results', () => {
  assert.equal(resolveVisibleSettingsTab('security', ''), 'security');
  assert.equal(resolveVisibleSettingsTab('security', '   '), 'security');
  assert.equal(resolveVisibleSettingsTab('security', 'lock'), 'security');
  assert.equal(resolveVisibleSettingsTab('general', 'mcp'), 'mcp');
  assert.equal(resolveVisibleSettingsTab('general', 'release notes'), 'updates');
  assert.equal(resolveVisibleSettingsTab('general', 'nonexistent-query'), null);
  assert.equal(resolveVisibleSettingsTab('logs', ''), 'logs');
});
