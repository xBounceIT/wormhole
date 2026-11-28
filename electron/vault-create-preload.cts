import { contextBridge, ipcRenderer } from 'electron';
// No application bridge, filesystem or recipient private key is exposed here.
contextBridge.exposeInMainWorld('vaultCreate', {
  contentProtectionAvailable: process.platform !== 'linux',
  begin: (input: import('./vault-enrollment-contract.js').VaultEnrollmentBegin) => {
    try {
      return ipcRenderer.invoke('vault-enrollment:begin', input);
    } finally {
      if (input?.password instanceof Uint8Array) input.password.fill(0);
      if (input?.publicKey instanceof Uint8Array) input.publicKey.fill(0);
    }
  },
  confirm: (input: import('./vault-enrollment-contract.js').VaultEnrollmentConfirm) => {
    try {
      return ipcRenderer.invoke('vault-enrollment:confirm', input);
    } finally {
      if (input?.groups instanceof Uint8Array) input.groups.fill(0);
    }
  },
  cancel: () => ipcRenderer.invoke('vault-enrollment:cancel'),
});
