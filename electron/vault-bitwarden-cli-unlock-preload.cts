import { contextBridge, ipcRenderer } from 'electron';
import type { VaultBitwardenCLIEnvelope } from './vault-bitwarden-cli-unlock.js';

contextBridge.exposeInMainWorld('vaultBitwardenCLIUnlock', {
  contentProtectionAvailable: process.platform !== 'linux',
  context: () => ipcRenderer.invoke('vault-bitwarden-cli-unlock:context'),
  submit: (envelope: VaultBitwardenCLIEnvelope) =>
    ipcRenderer.invoke('vault-bitwarden-cli-unlock:submit', envelope),
  cancel: () => ipcRenderer.invoke('vault-bitwarden-cli-unlock:cancel'),
});
