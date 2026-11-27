import { contextBridge, ipcRenderer } from 'electron';
contextBridge.exposeInMainWorld('vaultTunnelAuthentication', {
  contentProtectionAvailable: process.platform !== 'linux',
  context: () => ipcRenderer.invoke('vault-tunnel-authentication:context'),
  submit: (
    envelope: import('./vault-tunnel-authentication.js').VaultTunnelAuthenticationEnvelope,
  ) => ipcRenderer.invoke('vault-tunnel-authentication:submit', envelope),
  cancel: () => ipcRenderer.invoke('vault-tunnel-authentication:cancel'),
});
