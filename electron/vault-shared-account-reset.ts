import { Buffer } from 'node:buffer';
import { validSharedVaultAppVersion } from './vault-shared-unlock.ts';

export type SharedAccountResetInput = {
  kind: 'account-reset';
  code: Uint8Array;
  password: Uint8Array;
  ask: Uint8Array;
  deviceName: string;
};

// The protected renderer supplies factors only. Main supplies the chosen file
// and app version, and Go authenticates the offer.
export function consumeSharedAccountResetInput(
  value: unknown,
  appVersion: string,
): SharedAccountResetInput {
  const object =
    typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
  const code = object?.code;
  const password = object?.password;
  const ask = object?.ask;
  const owned: Uint8Array[] = [];
  try {
    const fields = ['kind', 'code', 'password', 'ask', 'deviceName'];
    if (
      !object ||
      Array.isArray(object) ||
      !validSharedVaultAppVersion(appVersion) ||
      Object.keys(object).length !== fields.length ||
      !fields.every((field) => Object.hasOwn(object, field)) ||
      object.kind !== 'account-reset' ||
      typeof object.deviceName !== 'string' ||
      !object.deviceName ||
      Buffer.byteLength(object.deviceName) > 4096 ||
      /\p{Cc}/u.test(object.deviceName) ||
      !validFactor(code, 16, 16) ||
      !validFactor(ask, 32, 32) ||
      !validFactor(password, 1, 1024)
    )
      throw Error('Invalid account reset request.');
    const own = (bytes: Uint8Array) => {
      const copy = Buffer.from(bytes);
      owned.push(copy);
      return copy;
    };
    return {
      kind: object.kind,
      code: own(code),
      password: own(password),
      ask: own(ask),
      deviceName: object.deviceName,
    };
  } catch {
    owned.forEach((bytes) => bytes.fill(0));
    throw Error('Invalid account reset request.');
  } finally {
    for (const bytes of [code, password, ask]) if (bytes instanceof Uint8Array) bytes.fill(0);
  }
}

function validFactor(value: unknown, min: number, max: number): value is Uint8Array {
  return (
    value instanceof Uint8Array &&
    value.buffer instanceof ArrayBuffer &&
    value.length >= min &&
    value.length <= max
  );
}
