import { contextBridge, ipcRenderer } from 'electron';
// Ciphertext-only bridge, present exclusively in the isolated credentials window.
contextBridge.exposeInMainWorld('vaultCredentials', {
  copyAvailable: ['win32', 'darwin', 'linux'].includes(process.platform),
  copy: (field: 'username' | 'domain' | 'secret') =>
    ipcRenderer.invoke('vault-credentials:copy', field),
  contentProtectionAvailable: process.platform !== 'linux',
  context: () => ipcRenderer.invoke('vault-credentials:context'),
  read: (publicKey: string) => ipcRenderer.invoke('vault-credentials:read', publicKey),
  close: () => ipcRenderer.invoke('vault-credentials:close'),
});
