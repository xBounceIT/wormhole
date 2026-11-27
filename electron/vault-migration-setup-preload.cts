import { contextBridge, ipcRenderer } from 'electron';
// No application bridge, filesystem or recipient private key is exposed here.
contextBridge.exposeInMainWorld('vaultCreate', {
  contentProtectionAvailable: process.platform !== 'linux',
  migrationContext: () => ipcRenderer.invoke('vault-migration-setup:context'),
  begin: (
    input: import('./vault-enrollment-contract.js').VaultEnrollmentBegin,
    legacy: { legacyMethod: string; legacyFactor: Uint8Array },
  ) => {
    try {
      return ipcRenderer.invoke('vault-migration-setup:begin', { ...input, ...legacy });
    } finally {
      if (legacy?.legacyFactor instanceof Uint8Array) legacy.legacyFactor.fill(0);
      if (input?.password instanceof Uint8Array) input.password.fill(0);
      if (input?.publicKey instanceof Uint8Array) input.publicKey.fill(0);
    }
  },
  confirm: (input: import('./vault-enrollment-contract.js').VaultEnrollmentConfirm) => {
    try {
      return ipcRenderer.invoke('vault-migration-setup:confirm', input);
    } finally {
      if (input?.groups instanceof Uint8Array) input.groups.fill(0);
    }
  },
  cancel: () => ipcRenderer.invoke('vault-migration-setup:cancel'),
});
