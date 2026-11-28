import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import {
  consumeVaultEnrollmentBegin,
  type VaultEnrollmentBegin,
} from './vault-enrollment-contract.ts';

export type VaultMigrationBegin = VaultEnrollmentBegin & {
  legacyMethod: 'none' | 'pin' | 'password';
  legacyFactor: Uint8Array;
};
export type VaultMigrationPrepared = { prepared: true; restartRequired: true; vaultId: string };
export type VaultLegacyMethod = 'none' | 'pin' | 'password';
export type VaultMigrationContext = { methods: VaultLegacyMethod[] };

export function parseVaultMigrationContext(value: unknown): VaultMigrationContext | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['methods']) ||
    !Array.isArray(value.methods) ||
    value.methods.length > 2 ||
    value.methods.some((method) => !['none', 'pin', 'password'].includes(method)) ||
    !['none', 'pin', 'password', 'password,pin'].includes(value.methods.join(','))
  )
    return undefined;
  return { methods: [...value.methods] as VaultLegacyMethod[] };
}

// Main/protected-window only. Never retain factors in application state or
// accept a source path, plan, key or restart authority from a renderer.
export function consumeVaultMigrationBegin(value: unknown): VaultMigrationBegin {
  const o = vaultRecord(value) ? value : {};
  let legacyFactor: Uint8Array | undefined;
  try {
    if (
      !vaultFields(o, ['password', 'publicKey', 'legacyMethod', 'legacyFactor']) ||
      !['none', 'pin', 'password'].includes(o.legacyMethod as string) ||
      !(o.legacyFactor instanceof Uint8Array) ||
      !(o.legacyFactor.buffer instanceof ArrayBuffer) ||
      o.legacyFactor.length > 1024 ||
      (o.legacyMethod === 'none' ? o.legacyFactor.length !== 0 : o.legacyFactor.length === 0)
    )
      throw Error('Invalid migration preparation.');
    // Snapshot before the enrollment consumer wipes its inputs: structured
    // clone can preserve aliases between the caller's factor buffers.
    legacyFactor = new Uint8Array(o.legacyFactor);
    const input = consumeVaultEnrollmentBegin({ password: o.password, publicKey: o.publicKey });
    return {
      ...input,
      legacyMethod: o.legacyMethod as VaultMigrationBegin['legacyMethod'],
      legacyFactor,
    };
  } catch (error) {
    legacyFactor?.fill(0);
    throw error;
  } finally {
    for (const name of ['password', 'publicKey', 'legacyFactor'])
      if (o[name] instanceof Uint8Array) o[name].fill(0);
  }
}

export function parseVaultMigrationPrepared(value: unknown): VaultMigrationPrepared | undefined {
  return vaultRecord(value) &&
    vaultFields(value, ['prepared', 'restartRequired', 'vaultId']) &&
    value.prepared === true &&
    value.restartRequired === true &&
    vaultID(value.vaultId)
    ? { prepared: true, restartRequired: true, vaultId: value.vaultId }
    : undefined;
}
