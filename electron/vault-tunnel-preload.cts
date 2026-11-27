import { contextBridge, ipcRenderer } from 'electron';
// Present only in the main-owned tunnel document. Never expose the general app API.
contextBridge.exposeInMainWorld('vaultTunnel', {
  contentProtectionAvailable: process.platform !== 'linux',
  context: () => ipcRenderer.invoke('vault-tunnel:context'),
  capabilities: () => ipcRenderer.invoke('vault-tunnel:capabilities'),
  references: () => ipcRenderer.invoke('vault-tunnel:references'),
  importProfile: (choice: import('./vault-tunnel-import.js').VaultTunnelImportChoice) =>
    ipcRenderer.invoke('vault-tunnel:import', choice),
  discardImport: () => ipcRenderer.invoke('vault-tunnel:discard-import'),
  read: (publicKey: string) => ipcRenderer.invoke('vault-tunnel:read', publicKey),
  save: (input: import('./vault-tunnel.js').VaultTunnelInput) => {
    try {
      return ipcRenderer.invoke('vault-tunnel:save', input);
    } finally {
      if (input?.patch instanceof Uint8Array) input.patch.fill(0);
    }
  },
  close: () => ipcRenderer.invoke('vault-tunnel:close'),
});
