import { contextBridge, ipcRenderer } from 'electron';
import type { VaultEnrollmentBegin, VaultEnrollmentConfirm } from './vault-enrollment-contract.js';
import type { VaultUnlockInput } from './vault-unlock.js';

contextBridge.exposeInMainWorld('vaultCreate', {
  contentProtectionAvailable: process.platform !== 'linux',
  rotationContext: () => ipcRenderer.invoke('vault-rotation-setup:context'),
  begin: (input: VaultEnrollmentBegin, _legacy: unknown, authentication: VaultUnlockInput) => {
    try {
      return ipcRenderer.invoke('vault-rotation-setup:begin', { ...input, authentication });
    } finally {
      if (input?.password instanceof Uint8Array) input.password.fill(0);
      if (input?.publicKey instanceof Uint8Array) input.publicKey.fill(0);
      if (authentication?.factor instanceof Uint8Array) authentication.factor.fill(0);
    }
  },
  confirm: (input: VaultEnrollmentConfirm) => {
    try {
      return ipcRenderer.invoke('vault-rotation-setup:confirm', input);
    } finally {
      if (input?.groups instanceof Uint8Array) input.groups.fill(0);
    }
  },
  cancel: () => ipcRenderer.invoke('vault-rotation-setup:cancel'),
});
