import { contextBridge, ipcRenderer } from 'electron';
contextBridge.exposeInMainWorld('vaultRdpCredentials', {
  contentProtectionAvailable: process.platform !== 'linux',
  context: () => ipcRenderer.invoke('vault-rdp-credentials:context'),
  submit: (envelope: import('./vault-rdp-credentials.js').VaultRdpCredentialsEnvelope) =>
    ipcRenderer.invoke('vault-rdp-credentials:submit', envelope),
  cancel: () => ipcRenderer.invoke('vault-rdp-credentials:cancel'),
});
