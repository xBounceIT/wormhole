import type { VaultPreferences } from '../../electron/vault-preferences.ts';

export function preferences(): VaultPreferences {
  return {
    theme: 'system',
    promptBeforeTunnelConnect: true,
    autoCopyOnSelect: true,
    confirmOnTabClose: true,
    confirmOnWindowClose: true,
    sidebarWidth: 320,
    sidebarPinned: true,
    connectionTreeExpansion: null,
    autoCheckForUpdates: true,
    lastUpdateCheck: null,
    skippedUpdateVersion: null,
  };
}
