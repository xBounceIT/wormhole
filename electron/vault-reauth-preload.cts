import { contextBridge, ipcRenderer } from 'electron';
contextBridge.exposeInMainWorld('vaultReauthentication', {
  context: () => ipcRenderer.invoke('vault-reauth:context'),
  submit: async (input: { factor: Uint8Array }) => {
    try {
      return await ipcRenderer.invoke('vault-reauth:submit', input);
    } finally {
      input.factor?.fill(0);
    }
  },
  cancel: () => ipcRenderer.invoke('vault-reauth:cancel'),
});
