import {
  parseVaultUnlockResult,
  vaultFields,
  vaultID,
  vaultRecord,
  type VaultUnlockResult,
} from './vault-contract.ts';

export type VaultPresenceAvailability = 'ready' | 'unavailable' | 'remote-desktop';
export type VaultPresenceStatus = { availability: VaultPresenceAvailability; enrolled: boolean };
export type VaultPresenceSelection = { vaultId: string; slotId: string };
export type VaultPresenceKind = 'hello' | 'touch-id';
export type VaultPresenceAction = 'enroll' | 'remove';
export type VaultPresenceOperation = `${VaultPresenceKind}-${VaultPresenceAction}`;
export type VaultPresenceFailure = {
  status: 'unavailable' | 'remote-desktop' | 'canceled' | 'not-repeatable';
};
export type VaultPresenceUnlockResult = VaultUnlockResult | VaultPresenceFailure;
export type VaultPresenceEnrollment = { enrolled: true } | VaultPresenceFailure;
export type VaultPresenceRemoval = { removed: true; keyDeleted: boolean };
export type VaultPresenceChange = VaultPresenceEnrollment | VaultPresenceRemoval;

export function parseVaultPresenceSelection(value: unknown): VaultPresenceSelection | undefined {
  if (!vaultRecord(value) || !vaultFields(value, ['vaultId', 'slotId'])) return;
  const { vaultId, slotId } = value;
  if (vaultID(vaultId) && vaultID(slotId)) return { vaultId, slotId };
}

export function vaultHelloWindow(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[1-9][0-9]{0,19}$/.test(value) &&
    (value.length < 20 || value <= '18446744073709551615')
  );
}

export function parseVaultPresenceAvailability(
  value: unknown,
): VaultPresenceAvailability | undefined {
  if (!vaultRecord(value) || !vaultFields(value, ['status'])) return;
  const { status } = value;
  if (status === 'ready' || status === 'unavailable' || status === 'remote-desktop') return status;
}

function parseVaultPresenceFailure(value: unknown): VaultPresenceFailure | undefined {
  if (!vaultRecord(value) || !vaultFields(value, ['status'])) return;
  const { status } = value;
  if (
    status === 'unavailable' ||
    status === 'remote-desktop' ||
    status === 'canceled' ||
    status === 'not-repeatable'
  )
    return { status };
}

export function parseVaultPresenceUnlock(value: unknown): VaultPresenceUnlockResult | undefined {
  return parseVaultUnlockResult(value) ?? parseVaultPresenceFailure(value);
}

export function parseVaultPresenceEnrollment(value: unknown): VaultPresenceEnrollment | undefined {
  if (vaultRecord(value) && vaultFields(value, ['enrolled']) && value.enrolled === true)
    return { enrolled: true };
  return parseVaultPresenceFailure(value);
}

export function parseVaultPresenceRemoval(value: unknown): VaultPresenceRemoval | undefined {
  if (
    vaultRecord(value) &&
    vaultFields(value, ['removed', 'keyDeleted']) &&
    value.removed === true &&
    typeof value.keyDeleted === 'boolean'
  ) {
    return { removed: true, keyDeleted: value.keyDeleted };
  }
}
