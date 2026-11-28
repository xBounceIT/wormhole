import { contextBridge, ipcRenderer } from 'electron';
// Ciphertext-only bridge, present exclusively in the isolated notes window.
contextBridge.exposeInMainWorld('vaultNotes', {
  contentProtectionAvailable: process.platform !== 'linux',
  context: () => ipcRenderer.invoke('vault-notes:context'),
  read: (publicKey: string) => ipcRenderer.invoke('vault-notes:read', publicKey),
  close: () => ipcRenderer.invoke('vault-notes:close'),
});
