import { vaultFields, vaultRecord } from './vault-contract.ts';
import { parseRecoveryDisplay, type RecoveryDisplayReceipt } from './vault-enrollment-contract.ts';

export type SharedRecoveryBackupInput = {
  recipient: Uint8Array;
  password?: Uint8Array;
  ask?: Uint8Array;
};

export type SharedRecoveryBackupResult =
  | { status: 'exported'; receipt: RecoveryDisplayReceipt }
  | {
      status:
        | 'unavailable'
        | 'authentication-required'
        | 'invalid-authentication'
        | 'too-large'
        | 'save-failed';
    };

export type SharedRecoveryBackupOperation = {
  authenticationRequired: boolean;
  submit(
    path: string,
    input: SharedRecoveryBackupInput,
    accepted: () => boolean,
  ): Promise<SharedRecoveryBackupResult>;
};

export function parseSharedRecoveryBackup(value: unknown): SharedRecoveryBackupResult | undefined {
  if (!vaultRecord(value)) return undefined;
  if (value.status === 'exported') {
    if (!vaultFields(value, ['status', 'vaultId', 'exportId', 'bundle'])) return undefined;
    const receipt = parseRecoveryDisplay({
      enrollmentId: value.exportId,
      vaultId: value.vaultId,
      bundle: value.bundle,
    });
    return receipt && { status: 'exported', receipt };
  }
  if (
    vaultFields(value, ['status']) &&
    (value.status === 'unavailable' ||
      value.status === 'authentication-required' ||
      value.status === 'invalid-authentication' ||
      value.status === 'too-large' ||
      value.status === 'save-failed')
  )
    return { status: value.status };
}

function bytes(value: unknown, minimum: number, maximum = minimum): value is Uint8Array {
  return (
    value instanceof Uint8Array &&
    value.buffer instanceof ArrayBuffer &&
    value.length >= minimum &&
    value.length <= maximum
  );
}

export function wipeSharedRecoveryBackup(value: unknown): void {
  if (!vaultRecord(value)) return;
  for (const field of ['recipient', 'password', 'ask']) {
    const bytes = value[field];
    if (bytes instanceof Uint8Array) bytes.fill(0);
  }
}

export function consumeSharedRecoveryBackup(
  value: unknown,
  authenticationRequired: boolean,
): SharedRecoveryBackupInput {
  try {
    if (
      !vaultRecord(value) ||
      !vaultFields(value, [
        'recipient',
        ...(authenticationRequired ? ['password'] : []),
        ...(authenticationRequired && Object.hasOwn(value, 'ask') ? ['ask'] : []),
      ]) ||
      !bytes(value.recipient, 32) ||
      (authenticationRequired && !bytes(value.password, 1, 1024)) ||
      (Object.hasOwn(value, 'ask') && !bytes(value.ask, 32))
    )
      throw Error('Invalid workspace backup request.');
    return {
      recipient: new Uint8Array(value.recipient),
      ...(value.password instanceof Uint8Array ? { password: new Uint8Array(value.password) } : {}),
      ...(value.ask instanceof Uint8Array ? { ask: new Uint8Array(value.ask) } : {}),
    };
  } finally {
    wipeSharedRecoveryBackup(value);
  }
}
