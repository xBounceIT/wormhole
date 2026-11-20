export type SettingsTabId =
  | 'general'
  | 'file-transfer'
  | 'security'
  | 'extensions'
  | 'mcp'
  | 'backup'
  | 'logs'
  | 'updates';

export type SettingsGroupLabel = 'App' | 'Integrations' | 'System';

export type SettingsCategoryMeta = {
  id: SettingsTabId;
  group: SettingsGroupLabel;
  label: string;
  description: string;
  keywords: readonly string[];
};

export type SettingsCategoryGroup = {
  label: SettingsGroupLabel;
  items: readonly SettingsCategoryMeta[];
};

const settingsGroupOrder: readonly SettingsGroupLabel[] = ['App', 'Integrations', 'System'];

export const settingsCategories: readonly SettingsCategoryMeta[] = [
  {
    id: 'general',
    group: 'App',
    label: 'General',
    description: 'Appearance, tabs, terminal, and tunnel defaults.',
    keywords: [
      'appearance',
      'theme',
      'dark',
      'light',
      'system',
      'tabs',
      'close',
      'confirm',
      'window',
      'application',
      'terminal',
      'ssh',
      'color',
      'tango',
      'copy',
      'clipboard',
      'selection',
      'vpn',
      'tunnel',
      'prompt',
    ],
  },
  {
    id: 'file-transfer',
    group: 'App',
    label: 'File transfer',
    description: 'Remote file editors, size limits, and working copy recovery.',
    keywords: [
      'sftp',
      'file',
      'transfer',
      'editor',
      'default',
      'size',
      'mib',
      'swap',
      'panels',
      'remote',
      'patterns',
      'recover',
      'working copy',
    ],
  },
  {
    id: 'security',
    group: 'App',
    label: 'Security',
    description: 'App lock, Windows Hello, and idle auto-lock.',
    keywords: [
      'security',
      'lock',
      'app lock',
      'pin',
      'password',
      'windows hello',
      'biometric',
      'fallback',
      'backup method',
      'idle',
      'timeout',
      'auto-lock',
      'unlock',
    ],
  },
  {
    id: 'extensions',
    group: 'Integrations',
    label: 'Extensions',
    description: 'Use Bitwarden for credential passwords and Browser connections.',
    keywords: [
      'extensions',
      'bitwarden',
      'vault',
      'credential',
      'password manager',
      'cli',
      'bw',
      'server',
      'region',
      'sync',
      'browser extension',
      'zip',
      'folder',
      'https',
    ],
  },
  {
    id: 'mcp',
    group: 'Integrations',
    label: 'AI Agent (MCP)',
    description: 'Let a local AI agent open saved connections and control live SSH sessions.',
    keywords: [
      'ai',
      'agent',
      'mcp',
      'server',
      'localhost',
      'approval',
      'full access',
      'always ask',
      'first access',
      'port',
      'endpoint',
      'bearer',
      'token',
      'claude',
      'codex',
      'config',
    ],
  },
  {
    id: 'backup',
    group: 'System',
    label: 'Backup & Restore',
    description: 'Export and merge connections, credentials, SSH keys, and VPN tunnels.',
    keywords: [
      'backup',
      'restore',
      'export',
      'import',
      'json',
      'encrypt',
      'password',
      'plaintext',
      'merge',
      'workspace',
    ],
  },
  {
    id: 'logs',
    group: 'System',
    label: 'Logs',
    description: 'Diagnostic log files, verbosity, and daily rotation.',
    keywords: [
      'logs',
      'diagnostic',
      'file',
      'folder',
      'level',
      'info',
      'debug',
      'verbose',
      'rotation',
      'retention',
      'days',
    ],
  },
  {
    id: 'updates',
    group: 'System',
    label: 'Updates',
    description: 'Application version, automatic checks, and release notes.',
    keywords: [
      'updates',
      'version',
      'check',
      'startup',
      'install',
      'download',
      'appimage',
      'release notes',
      'changelog',
    ],
  },
];

export const settingsCategoryById = Object.fromEntries(
  settingsCategories.map((category) => [category.id, category]),
) as Record<SettingsTabId, SettingsCategoryMeta>;

const settingsCategorySearchIndex = new Map<SettingsTabId, string>(
  settingsCategories.map((category) => [
    category.id,
    `${category.label} ${category.description} ${category.group} ${category.keywords.join(' ')}`.toLowerCase(),
  ]),
);

export function isSettingsTabId(value: string): value is SettingsTabId {
  return Object.prototype.hasOwnProperty.call(settingsCategoryById, value);
}

export function filterSettingsCategories(query: string): SettingsCategoryGroup[] {
  const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const matching =
    tokens.length === 0
      ? settingsCategories
      : settingsCategories.filter((category) => {
          const haystack = settingsCategorySearchIndex.get(category.id) ?? '';
          return tokens.every((token) => haystack.includes(token));
        });

  return settingsGroupOrder
    .map((group) => ({
      label: group,
      items: matching.filter((category) => category.group === group),
    }))
    .filter((group) => group.items.length > 0);
}

export function resolveVisibleSettingsTab(
  activeTab: SettingsTabId,
  query: string,
): SettingsTabId | null {
  if (query.trim() === '') return activeTab;
  const filteredItems = filterSettingsCategories(query).flatMap((group) => group.items);
  if (filteredItems.some((item) => item.id === activeTab)) return activeTab;
  return filteredItems[0]?.id ?? null;
}
