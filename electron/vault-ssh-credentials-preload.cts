import { contextBridge, ipcRenderer } from 'electron';
contextBridge.exposeInMainWorld('vaultSshCredentials', {
  contentProtectionAvailable: process.platform !== 'linux',
  context: () => ipcRenderer.invoke('vault-ssh-credentials:context'),
  submit: (envelope: import('./vault-ssh-manual.js').VaultSshManualEnvelope) =>
    ipcRenderer.invoke('vault-ssh-credentials:submit', envelope),
  cancel: () => ipcRenderer.invoke('vault-ssh-credentials:cancel'),
});
