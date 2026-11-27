import { vaultRecord, vaultFields } from './vault-contract.ts';

export type VaultOSMigrationPrepare = {
  legacyMethod: 'none' | 'pin' | 'password';
  legacyFactor: Uint8Array;
};

export function consumeOSMigrationPrepare(value: unknown): VaultOSMigrationPrepare {
  const input = vaultRecord(value) ? value : {};
  try {
    if (
      !vaultFields(input, ['legacyMethod', 'legacyFactor']) ||
      !['none', 'pin', 'password'].includes(input.legacyMethod as string) ||
      !(input.legacyFactor instanceof Uint8Array) ||
      !(input.legacyFactor.buffer instanceof ArrayBuffer) ||
      input.legacyFactor.length > 1024 ||
      (input.legacyMethod === 'none'
        ? input.legacyFactor.length !== 0
        : input.legacyFactor.length === 0)
    )
      throw Error('Invalid migration preparation.');
    return {
      legacyMethod: input.legacyMethod as VaultOSMigrationPrepare['legacyMethod'],
      legacyFactor: new Uint8Array(input.legacyFactor),
    };
  } finally {
    if (input.legacyFactor instanceof Uint8Array) input.legacyFactor.fill(0);
  }
}
