import { contextBridge, ipcRenderer } from 'electron';
import type { VaultEnrollmentBegin, VaultEnrollmentConfirm } from './vault-enrollment-contract.js';

contextBridge.exposeInMainWorld('vaultCreate', {
  contentProtectionAvailable: process.platform !== 'linux',
  upgradeContext: () => ipcRenderer.invoke('vault-upgrade-setup:context'),
  begin: (input: VaultEnrollmentBegin) => {
    try {
      return ipcRenderer.invoke('vault-upgrade-setup:begin', input);
    } finally {
      if (input?.password instanceof Uint8Array) input.password.fill(0);
      if (input?.publicKey instanceof Uint8Array) input.publicKey.fill(0);
    }
  },
  confirm: (input: VaultEnrollmentConfirm) => {
    try {
      return ipcRenderer.invoke('vault-upgrade-setup:confirm', input);
    } finally {
      if (input?.groups instanceof Uint8Array) input.groups.fill(0);
    }
  },
  cancel: () => ipcRenderer.invoke('vault-upgrade-setup:cancel'),
});
