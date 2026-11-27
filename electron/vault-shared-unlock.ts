import { Buffer } from 'node:buffer';
import { extname, isAbsolute, normalize } from 'node:path';
import { consumeVaultUnlockInput, encodeVaultBytesObject } from './vault-unlock.ts';
import type { SharedVaultTransport } from './vault-shared-transport.ts';

export type SharedVaultUnlockInput = {
  vaultId: string;
  slotId: string;
  password: Uint8Array;
  ask?: Uint8Array;
  appVersion: string;
};
export type SharedVaultAdmission = {
  admitted: true;
  lockedMemory: boolean;
  orgEscrow: boolean;
};
export type SharedVaultRecovery = { recovered: true };
export class SharedReenrollmentPending extends Error {}
// Main adds controls only after validating the native runtime and current owner.
// This public renderer projection is distinct from the native three-flag receipt.
export type SharedVaultSessionAdmission = SharedVaultAdmission & {
  tls: SharedVaultTransport;
  recoveryBackup?: true;
  administrator?: true;
};
export type SharedVaultContinuationInput = SharedVaultUnlockInput & {
  code: Uint8Array;
  acknowledgeTLSOff: boolean;
};

export function hasSharedVaultContinuation(
  input: SharedVaultUnlockInput,
): input is SharedVaultContinuationInput {
  return (
    'code' in input &&
    input.code instanceof Uint8Array &&
    'acknowledgeTLSOff' in input &&
    typeof input.acknowledgeTLSOff === 'boolean'
  );
}

export function consumeSharedVaultContinuationInput(
  value: unknown,
  appVersion: string,
): SharedVaultContinuationInput {
  const object =
    typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
  const code = object?.code;
  let owned: Buffer | undefined;
  try {
    if (
      !object ||
      Array.isArray(object) ||
      Object.keys(object).length !== (Object.hasOwn(object, 'ask') ? 6 : 5) ||
      !['vaultId', 'slotId', 'password', 'code', 'acknowledgeTLSOff'].every((key) =>
        Object.hasOwn(object, key),
      ) ||
      !(code instanceof Uint8Array) ||
      !(code.buffer instanceof ArrayBuffer) ||
      code.length !== 16 ||
      typeof object.acknowledgeTLSOff !== 'boolean'
    )
      throw Error('Invalid continuation.');
    // Copy before consuming factors: all borrowed views may overlap.
    owned = Buffer.from(code);
    const input = consumeSharedVaultUnlockInput(
      {
        vaultId: object.vaultId,
        slotId: object.slotId,
        password: object.password,
        ...(Object.hasOwn(object, 'ask') ? { ask: object.ask } : {}),
      },
      appVersion,
    );
    return { ...input, code: owned, acknowledgeTLSOff: object.acknowledgeTLSOff };
  } catch {
    owned?.fill(0);
    throw Error('Invalid shared vault continuation request.');
  } finally {
    for (const key of ['password', 'ask', 'code'])
      if (object?.[key] instanceof Uint8Array) (object[key] as Uint8Array).fill(0);
  }
}

export function validSharedVaultAppVersion(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 64 &&
    /^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$/.test(value)
  );
}

export function validSharedTLSBundlePath(value: unknown): value is string {
  return validSharedArtifactPath(value, '.whtls');
}

export function validSharedRecoveryKitPath(value: unknown): value is string {
  return validSharedArtifactPath(value, '.whrecovery');
}

export function validSharedRecoveryBackupPath(value: unknown): value is string {
  return validSharedArtifactPath(value, '.json');
}

export function validSharedArtifactPath(value: unknown, extension: string): value is string {
  return (
    typeof value === 'string' &&
    Buffer.byteLength(value, 'utf8') <= 4096 &&
    isAbsolute(value) &&
    normalize(value) === value &&
    extname(value).toLowerCase() === extension &&
    !/\p{Cc}/u.test(value)
  );
}

export type SharedRecoveryKitRefresh = 'updated' | 'unavailable' | 'invalid-kit' | 'save-failed';
export type SharedRecoveryKitNativeRefresh =
  | SharedRecoveryKitRefresh
  | 'authentication-required'
  | 'invalid-authentication';

export function parseSharedRecoveryKitNativeRefresh(
  value: unknown,
): SharedRecoveryKitNativeRefresh | undefined {
  if (value === 'authentication-required' || value === 'invalid-authentication') return value;
  return parseSharedRecoveryKitRefresh(value);
}

export function parseSharedRecoveryKitRefresh(
  value: unknown,
): SharedRecoveryKitRefresh | undefined {
  if (
    value === 'updated' ||
    value === 'unavailable' ||
    value === 'invalid-kit' ||
    value === 'save-failed'
  )
    return value;
}

export function parseSharedTLSBundleExport(value: unknown): boolean | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  if (
    Object.keys(value).length === 1 &&
    Object.hasOwn(value, 'exported') &&
    'exported' in value &&
    typeof value.exported === 'boolean'
  )
    return value.exported;
}

// Native main supplies appVersion. No path, endpoint, policy or identity binding
// can be supplied by the factor input. Consume both caller buffers on every exit.
export function consumeSharedVaultUnlockInput(
  value: unknown,
  appVersion: string,
): SharedVaultUnlockInput {
  const object =
    typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
  const password = object?.password,
    ask = object?.ask;
  let owned: Uint8Array | undefined;
  let ownedASK: Uint8Array | undefined;
  try {
    if (
      !object ||
      Array.isArray(object) ||
      Object.keys(object).length !== (Object.hasOwn(object, 'ask') ? 4 : 3) ||
      !['vaultId', 'slotId', 'password'].every((key) => Object.hasOwn(object, key)) ||
      !validSharedVaultAppVersion(appVersion) ||
      (Object.hasOwn(object, 'ask') &&
        (!(ask instanceof Uint8Array) || !(ask.buffer instanceof ArrayBuffer) || ask.length !== 32))
    )
      throw Error('Invalid shared vault authentication request.');
    // Snapshot ASK before consuming password: the borrowed views may overlap.
    if (ask instanceof Uint8Array) ownedASK = Buffer.from(ask);
    const input = consumeVaultUnlockInput({
      vaultId: object.vaultId,
      slotId: object.slotId,
      kind: 'password',
      factor: password,
    });
    owned = input.factor;
    return {
      vaultId: input.vaultId,
      slotId: input.slotId,
      password: owned,
      ...(ownedASK ? { ask: ownedASK } : {}),
      appVersion,
    };
  } catch {
    owned?.fill(0);
    ownedASK?.fill(0);
    throw Error('Invalid shared vault authentication request.');
  } finally {
    if (password instanceof Uint8Array) password.fill(0);
    if (ask instanceof Uint8Array) ask.fill(0);
  }
}

export function encodeSharedVaultUnlockFrame(
  id: number,
  operation:
    | 'shared-unlock'
    | 'shared-recover-password'
    | 'shared-recover-enrollment'
    | 'shared-continue-enrollment',
  input: SharedVaultUnlockInput | SharedVaultContinuationInput,
  tlsUpdatePath?: string,
): Buffer {
  if (
    !Number.isSafeInteger(id) ||
    id < 1 ||
    (operation !== 'shared-unlock' &&
      operation !== 'shared-recover-password' &&
      operation !== 'shared-recover-enrollment' &&
      operation !== 'shared-continue-enrollment') ||
    (tlsUpdatePath !== undefined &&
      (operation !== 'shared-unlock' || !validSharedTLSBundlePath(tlsUpdatePath))) ||
    (operation === 'shared-continue-enrollment' &&
      (!('code' in input) ||
        input.code.length !== 16 ||
        typeof input.acknowledgeTLSOff !== 'boolean'))
  )
    throw Error('Invalid shared vault request.');
  const fields: [string, Uint8Array][] = [['password', input.password]];
  if (input.ask) fields.push(['ask', input.ask]);
  const factors = encodeVaultBytesObject({ vaultId: input.vaultId, slotId: input.slotId }, fields);
  const continuation =
    operation === 'shared-continue-enrollment' && 'code' in input
      ? encodeVaultBytesObject({ acknowledgeTLSOff: input.acknowledgeTLSOff }, [
          ['code', input.code],
        ])
      : undefined;
  try {
    return Buffer.concat([
      Buffer.from(
        `{"version":1,"id":${id},"operation":"${operation}","payload":{"appVersion":${JSON.stringify(input.appVersion)},"factors":`,
      ),
      factors,
      ...(tlsUpdatePath === undefined
        ? []
        : [Buffer.from(`,"tlsUpdatePath":${JSON.stringify(tlsUpdatePath)}`)]),
      ...(continuation
        ? [Buffer.from(','), continuation.subarray(1, continuation.length - 1)]
        : []),
      Buffer.from('}}\n'),
    ]);
  } finally {
    factors.fill(0);
    continuation?.fill(0);
  }
}

export function parseSharedVaultAdmission(value: unknown): SharedVaultAdmission | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const v = value as Record<string, unknown>;
  if (
    Object.keys(v).length !== 3 ||
    !Object.hasOwn(v, 'admitted') ||
    !Object.hasOwn(v, 'lockedMemory') ||
    !Object.hasOwn(v, 'orgEscrow') ||
    v.admitted !== true ||
    typeof v.lockedMemory !== 'boolean' ||
    typeof v.orgEscrow !== 'boolean'
  )
    return undefined;
  return { admitted: true, lockedMemory: v.lockedMemory, orgEscrow: v.orgEscrow };
}

export function parseSharedEnrollmentResult(
  value: unknown,
): SharedVaultAdmission | 'awaiting-activation' | undefined {
  if (
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    Object.hasOwn(value, 'awaitingActivation') &&
    (value as Record<string, unknown>).awaitingActivation === true
  )
    return 'awaiting-activation';
  return parseSharedVaultAdmission(value);
}

export function requireSharedEnrollmentAdmission(
  result: SharedVaultAdmission | 'awaiting-activation',
): SharedVaultAdmission {
  if (result === 'awaiting-activation') throw new SharedReenrollmentPending();
  return result;
}

export function parseSharedVaultRecovery(value: unknown): SharedVaultRecovery | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const v = value as Record<string, unknown>;
  if (Object.keys(v).length !== 1 || !Object.hasOwn(v, 'recovered') || v.recovered !== true)
    return undefined;
  return { recovered: true };
}
