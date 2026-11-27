import { vaultRecord, vaultFields, vaultMetadataText } from './vault-contract.ts';
import { isSshTerminalTheme, type SshTerminalTheme } from './terminal-theme-settings.ts';

export type VaultPreferences = {
  sshTerminalTheme?: SshTerminalTheme;
  theme: 'system' | 'light' | 'dark';
  promptBeforeTunnelConnect: boolean;
  autoCopyOnSelect: boolean;
  confirmOnTabClose: boolean;
  confirmOnWindowClose: boolean;
  sidebarWidth: number;
  sidebarPinned: boolean;
  connectionTreeExpansion: { defaultExpanded: boolean; folderIds: string[] } | null;
  autoCheckForUpdates: boolean;
  lastUpdateCheck: string | null;
  skippedUpdateVersion: string | null;
};

export type VaultUpdatePreferences = Partial<
  Pick<VaultPreferences, 'autoCheckForUpdates' | 'skippedUpdateVersion'>
> & { lastUpdateCheck?: string };

export function parseVaultPreferences(value: unknown): VaultPreferences | undefined {
  const booleans = [
    'promptBeforeTunnelConnect',
    'autoCopyOnSelect',
    'confirmOnTabClose',
    'confirmOnWindowClose',
    'sidebarPinned',
    'autoCheckForUpdates',
  ];
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      ...booleans,
      'theme',
      'sidebarWidth',
      'connectionTreeExpansion',
      'lastUpdateCheck',
      'skippedUpdateVersion',
      ...(Object.hasOwn(value, 'sshTerminalTheme') ? ['sshTerminalTheme'] : []),
    ]) ||
    (Object.hasOwn(value, 'sshTerminalTheme') && !isSshTerminalTheme(value.sshTerminalTheme)) ||
    !['system', 'light', 'dark'].includes(value.theme as string) ||
    booleans.some((key) => typeof value[key] !== 'boolean') ||
    !Number.isInteger(value.sidebarWidth) ||
    (value.sidebarWidth as number) < 256 ||
    (value.sidebarWidth as number) > 600 ||
    [value.lastUpdateCheck, value.skippedUpdateVersion].some(
      (v) => v !== null && (typeof v !== 'string' || v.length > 2048 || /\p{Cc}/u.test(v)),
    )
  )
    return undefined;
  const expansion = value.connectionTreeExpansion;
  if (
    expansion !== null &&
    (!vaultRecord(expansion) ||
      !vaultFields(expansion, ['defaultExpanded', 'folderIds']) ||
      typeof expansion.defaultExpanded !== 'boolean' ||
      !Array.isArray(expansion.folderIds) ||
      expansion.folderIds.length > 25000 ||
      !expansion.folderIds.every(
        (id) =>
          vaultMetadataText(id, 128, true) &&
          id.trim() === id &&
          !Array.from(id).some(
            (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
          ),
      ) ||
      new Set(expansion.folderIds).size !== expansion.folderIds.length)
  )
    return undefined;
  return {
    ...value,
    connectionTreeExpansion:
      expansion === null
        ? null
        : {
            defaultExpanded: expansion.defaultExpanded as boolean,
            folderIds: [...(expansion.folderIds as string[])],
          },
  } as VaultPreferences;
}
