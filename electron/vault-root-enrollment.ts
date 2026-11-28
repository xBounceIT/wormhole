import { vaultFields, vaultRecord } from './vault-contract.ts';
import {
  consumeVaultEnrollmentBegin,
  type VaultEnrollmentBegin,
} from './vault-enrollment-contract.ts';
import { consumeVaultUnlockInput, type VaultUnlockInput } from './vault-unlock.ts';

import type { VaultRootEnrollmentBegin } from './vault-root-enrollment-contract.ts';
export {
  parseVaultRootEnrollmentContext,
  type VaultRootEnrollmentContext,
  type VaultRootEnrollmentBegin,
} from './vault-root-enrollment-contract.ts';

// Snapshot all potentially aliased inputs before either consumer erases them.
// No root, source path or recipient private key is accepted from this window.
export function consumeVaultRootEnrollmentBegin(value: unknown): VaultRootEnrollmentBegin {
  const o = vaultRecord(value) ? value : {};
  const authentication = vaultRecord(o.authentication) ? o.authentication : {};
  let factor: Uint8Array | undefined,
    input: VaultEnrollmentBegin | undefined,
    owned: VaultUnlockInput | undefined;
  try {
    if (
      !vaultFields(o, ['password', 'publicKey', 'authentication']) ||
      !(authentication.factor instanceof Uint8Array) ||
      !(authentication.factor.buffer instanceof ArrayBuffer) ||
      authentication.factor.length < 1 ||
      authentication.factor.length > 1024
    )
      throw Error('Invalid vault protection request.');
    factor = new Uint8Array(authentication.factor);
    input = consumeVaultEnrollmentBegin({ password: o.password, publicKey: o.publicKey });
    owned = consumeVaultUnlockInput({ ...authentication, factor });
    return { ...input, authentication: owned };
  } catch (error) {
    input?.password.fill(0);
    input?.publicKey.fill(0);
    owned?.factor.fill(0);
    throw error;
  } finally {
    factor?.fill(0);
    for (const bytes of [o.password, o.publicKey, authentication.factor])
      if (bytes instanceof Uint8Array) bytes.fill(0);
  }
}
