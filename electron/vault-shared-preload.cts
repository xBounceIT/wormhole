import { contextBridge, ipcRenderer } from 'electron';
contextBridge.exposeInMainWorld('vaultSharedAuthentication', {
  context: () => ipcRenderer.invoke('vault-shared:context'),
  inspectInvitation: (invitation: string) =>
    ipcRenderer.invoke('vault-shared:invitation', invitation),
  openInvitation: () => ipcRenderer.invoke('vault-shared:open-invitation'),
  openResetOffer: () => ipcRenderer.invoke('vault-shared:open-reset-offer'),
  selectTLSUpdate: (action: 'choose' | 'clear') =>
    ipcRenderer.invoke('vault-shared:tls-update', action),
  submit: async (input: { password: Uint8Array; ask?: Uint8Array; code?: Uint8Array }) => {
    try {
      return await ipcRenderer.invoke('vault-shared:submit', input);
    } finally {
      input.password?.fill(0);
      input.ask?.fill(0);
      input.code?.fill(0);
    }
  },
  cancel: () => ipcRenderer.invoke('vault-shared:cancel'),
});
