import { Buffer } from 'node:buffer';
import { validSharedVaultAppVersion } from './vault-shared-unlock.ts';
import { validSharedInvitationText } from './vault-shared-invitation.ts';

export type SharedInitialJoinInput = {
  invitation: string;
  code: Uint8Array;
  password: Uint8Array;
  ask?: Uint8Array;
  deviceName: string;
  acknowledgeTLSOff: boolean;
};

// Main owns appVersion. Only a protected document may supply these factors;
// endpoints, roles, paths and device IDs are selected by Go from the invitation.
export function consumeSharedInitialJoinInput(
  value: unknown,
  appVersion: string,
): SharedInitialJoinInput {
  const object =
    typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
  const code = object?.code,
    password = object?.password,
    ask = object?.ask;
  const owned: Uint8Array[] = [];
  try {
    const fields = ['invitation', 'code', 'password', 'deviceName', 'acknowledgeTLSOff'];
    if (
      !object ||
      Array.isArray(object) ||
      !validSharedVaultAppVersion(appVersion) ||
      Object.keys(object).length !== fields.length + Number(Object.hasOwn(object, 'ask')) ||
      !fields.every((field) => Object.hasOwn(object, field)) ||
      !validSharedInvitationText(object.invitation) ||
      typeof object.deviceName !== 'string' ||
      object.deviceName.length === 0 ||
      Buffer.byteLength(object.deviceName, 'utf8') > 4096 ||
      /\p{Cc}/u.test(object.deviceName) ||
      typeof object.acknowledgeTLSOff !== 'boolean' ||
      !(code instanceof Uint8Array) ||
      !(code.buffer instanceof ArrayBuffer) ||
      code.length !== 16 ||
      !(password instanceof Uint8Array) ||
      !(password.buffer instanceof ArrayBuffer) ||
      password.length === 0 ||
      password.length > 1024 ||
      (Object.hasOwn(object, 'ask') &&
        (!(ask instanceof Uint8Array) || !(ask.buffer instanceof ArrayBuffer) || ask.length !== 32))
    )
      throw Error('Invalid shared workspace invitation request.');
    // Copy every view before wiping any borrowed view: factors may overlap.
    const own = (bytes: Uint8Array) => {
      const copy = Buffer.from(bytes);
      owned.push(copy);
      return copy;
    };
    return {
      invitation: object.invitation,
      code: own(code),
      password: own(password),
      ...(ask instanceof Uint8Array ? { ask: own(ask) } : {}),
      deviceName: object.deviceName,
      acknowledgeTLSOff: object.acknowledgeTLSOff,
    };
  } catch {
    owned.forEach((bytes) => bytes.fill(0));
    throw Error('Invalid shared workspace invitation request.');
  } finally {
    for (const bytes of [code, password, ask]) if (bytes instanceof Uint8Array) bytes.fill(0);
  }
}
