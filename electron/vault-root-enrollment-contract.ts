import {
  parseVaultDescription,
  vaultFields,
  vaultRecord,
  type VaultDescriptor,
} from './vault-contract.ts';
import type { VaultEnrollmentBegin } from './vault-enrollment-contract.ts';
import type { VaultUnlockInput } from './vault-unlock.ts';

export type VaultRootEnrollmentContext = { slots: VaultDescriptor; encryptDatabase?: true };
export type VaultRootEnrollmentBegin = VaultEnrollmentBegin & { authentication: VaultUnlockInput };

export function parseVaultRootEnrollmentContext(
  value: unknown,
): VaultRootEnrollmentContext | undefined {
  if (!vaultRecord(value)) return undefined;
  const encryptDatabase = value.encryptDatabase === true;
  if (!vaultFields(value, encryptDatabase ? ['slots', 'encryptDatabase'] : ['slots']))
    return undefined;
  const slots = parseVaultDescription({ slots: value.slots });
  if (!slots || (encryptDatabase && slots.encrypted)) return undefined;
  return encryptDatabase ? { slots, encryptDatabase: true } : { slots };
}
