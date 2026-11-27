import { contextBridge, ipcRenderer } from 'electron';
contextBridge.exposeInMainWorld('vaultVncPassword', {
  contentProtectionAvailable: process.platform !== 'linux',
  context: () => ipcRenderer.invoke('vault-vnc-password:context'),
  submit: (envelope: import('./vault-vnc-password.js').VaultVncPasswordEnvelope) =>
    ipcRenderer.invoke('vault-vnc-password:submit', envelope),
  cancel: () => ipcRenderer.invoke('vault-vnc-password:cancel'),
});
