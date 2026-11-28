import { contextBridge, ipcRenderer } from 'electron';
// Only this main-owned isolated dialog receives the old-factor bridge.
contextBridge.exposeInMainWorld('vaultOSMigration', {
  contentProtectionAvailable: process.platform !== 'linux',
  context: () => ipcRenderer.invoke('vault-os-migration-setup:context'),
  prepare: (input: import('./vault-os-migration-contract.js').VaultOSMigrationPrepare) => {
    try {
      return ipcRenderer.invoke('vault-os-migration-setup:begin', input);
    } finally {
      if (input?.legacyFactor instanceof Uint8Array) input.legacyFactor.fill(0);
    }
  },
  cancel: () => ipcRenderer.invoke('vault-os-migration-setup:cancel'),
});
