import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('vaultSharedSetup', {
  contentProtectionAvailable: process.platform !== 'linux',
  mode: () => ipcRenderer.invoke('vault-shared-setup:mode'),
  adminInventory: (value: import('./vault-shared-admin-inventory.js').AdminInventoryRequest) =>
    ipcRenderer.invoke('vault-shared-setup:admin-inventory', value),
  createSlot: (value: import('./vault-shared-admin-inventory.js').CredentialSlot) =>
    ipcRenderer.invoke('vault-shared-setup:create-slot', value),
  slotDefault: (
    value: import('./vault-shared-slot-default.js').SlotDefaultRequest,
    factors?: import('./vault-account-suspension.js').PersonalRootRecoveryFactors,
  ) => {
    try {
      return factors
        ? ipcRenderer.invoke('vault-shared-setup:slot-default', value, factors)
        : ipcRenderer.invoke('vault-shared-setup:slot-default', value);
    } finally {
      factors?.password.fill(0);
      factors?.ask?.fill(0);
    }
  },
  workspaceAccess: (value: import('./vault-shared-access.js').WorkspaceAccessRequest) =>
    ipcRenderer.invoke('vault-shared-setup:workspace-access', value),
  accountSuspension: (value: import('./vault-account-suspension.js').AccountSuspensionRequest) =>
    ipcRenderer.invoke('vault-shared-setup:account-suspension', value),
  accountBoundaryRotation: (
    value: import('./vault-account-suspension.js').AccountBoundaryRotationRequest,
  ) => ipcRenderer.invoke('vault-shared-setup:account-boundary-rotation', value),
  personalRootRecovery: (
    request: import('./vault-account-suspension.js').PersonalRootRecoveryRequest,
    factors?: import('./vault-account-suspension.js').PersonalRootRecoveryFactors,
  ) => {
    try {
      return factors
        ? ipcRenderer.invoke('vault-shared-setup:personal-root-recovery', request, factors)
        : ipcRenderer.invoke('vault-shared-setup:personal-root-recovery', request);
    } finally {
      if (factors?.password instanceof Uint8Array) factors.password.fill(0);
      if (factors?.ask instanceof Uint8Array) factors.ask.fill(0);
    }
  },
  adminGroups: (value: import('./vault-shared-admin-groups.js').GroupRequest) =>
    ipcRenderer.invoke('vault-shared-setup:admin-groups', value),
  grantTargets: (value: import('./vault-shared-catalog.js').SharedCatalogRequest) =>
    ipcRenderer.invoke('vault-shared-setup:grant-targets', value),
  nodeGrant: (value: import('./vault-shared-node-grants.js').NodeGrantRequest) =>
    ipcRenderer.invoke('vault-shared-setup:node-grant', value),
  groupKey: (value: import('./vault-shared-group-key.js').GroupKeyRequest) =>
    ipcRenderer.invoke('vault-shared-setup:group-key', value),
  groupBoundaryGrant: (
    value: import('./vault-shared-group-boundary-grant.js').GroupBoundaryGrantRequest,
  ) => ipcRenderer.invoke('vault-shared-setup:group-boundary-grant', value),
  groupBoundaryRotation: (
    value: import('./vault-shared-group-boundary-grant.js').GroupBoundaryGrantRequest,
  ) => ipcRenderer.invoke('vault-shared-setup:group-boundary-rotation', value),
  memberRotation: (
    value: import('./vault-shared-group-member-rotation.js').MemberRotationRequest,
  ) => ipcRenderer.invoke('vault-shared-setup:group-member-rotation', value),
  inspectBackup: (value: { password: Uint8Array; saveScript: boolean }) => {
    try {
      return ipcRenderer.invoke('vault-shared-setup:inspect-backup', value);
    } finally {
      if (value?.password instanceof Uint8Array) value.password.fill(0);
    }
  },
  applyBackup: (value: Record<string, unknown>) => {
    try {
      return ipcRenderer.invoke('vault-shared-setup:apply-backup', value);
    } finally {
      for (const field of ['password', 'deployerPassword']) {
        const factor = value?.[field];
        if (factor instanceof Uint8Array) factor.fill(0);
      }
    }
  },
  backupContext: () => ipcRenderer.invoke('vault-shared-setup:backup-context'),
  resetContext: () => ipcRenderer.invoke('vault-shared-setup:reset-context'),
  resetTargets: (after: string | null) =>
    ipcRenderer.invoke('vault-shared-setup:reset-targets', after),
  markResetHandover: (value: { userId: string; offerId: string }) =>
    ipcRenderer.invoke('vault-shared-setup:mark-reset-handover', value),
  leaveResetPending: (offerId: string) =>
    ipcRenderer.invoke('vault-shared-setup:leave-reset-pending', offerId),
  issueReset: (value: Record<string, unknown>) => {
    try {
      return ipcRenderer.invoke('vault-shared-setup:issue-reset', value);
    } finally {
      for (const field of ['recipient', 'password', 'ask']) {
        const factor = value?.[field];
        if (factor instanceof Uint8Array) factor.fill(0);
      }
    }
  },
  exportBackup: (value: Record<string, unknown>) => {
    try {
      return ipcRenderer.invoke('vault-shared-setup:export-backup', value);
    } finally {
      for (const field of ['recipient', 'password', 'ask']) {
        const factor = value?.[field];
        if (factor instanceof Uint8Array) factor.fill(0);
      }
    }
  },
  recover: (value: Record<string, unknown>) => {
    try {
      return ipcRenderer.invoke('vault-shared-setup:recover-admin', value);
    } finally {
      for (const field of ['recoveryCode', 'deployerPassword', 'accountPassword', 'ask']) {
        const bytes = value?.[field];
        if (bytes instanceof Uint8Array) bytes.fill(0);
      }
    }
  },
  request: (value: Record<string, unknown>) => {
    try {
      // IPC copies the bytes synchronously. Clear preload's copy before waiting.
      return ipcRenderer.invoke('vault-shared-setup:request', value);
    } finally {
      for (const field of ['password', 'accountPassword', 'ask', 'groups', 'recipient']) {
        const bytes = value?.[field];
        if (bytes instanceof Uint8Array) bytes.fill(0);
      }
    }
  },
  close: () => ipcRenderer.invoke('vault-shared-setup:close'),
});
