import { validSharedRecoveryKitPath, validSharedTLSBundlePath } from './vault-shared-unlock.ts';

export type AdminRecoveryInput = {
  workspaceId: string;
  host: string;
  port: number;
  database: string;
  role: string;
  loginName: string;
  deviceName: string;
  confirmed: true;
  recoveryCode: Uint8Array;
  deployerPassword: Uint8Array;
  accountPassword: Uint8Array;
  ask?: Uint8Array;
};
export type AdminRecoveryNativeInput = AdminRecoveryInput & { kitPath: string; trustPath: string };

const factors = ['recoveryCode', 'deployerPassword', 'accountPassword', 'ask'] as const;
const fields = [
  'workspaceId',
  'host',
  'port',
  'database',
  'role',
  'loginName',
  'deviceName',
  'confirmed',
];

export function wipeAdminRecoveryInput(value: unknown) {
  if (!value || typeof value !== 'object') return;
  for (const field of factors) {
    const factor = (value as Record<string, unknown>)[field];
    if (factor instanceof Uint8Array) factor.fill(0);
  }
}

export function consumeAdminRecoveryInput(value: unknown): AdminRecoveryInput {
  const input = value as AdminRecoveryInput;
  try {
    if (
      !input ||
      typeof input !== 'object' ||
      Array.isArray(input) ||
      !Object.keys(input).every((key) => [...fields, ...factors].includes(key)) ||
      !fields.every((field) => Object.hasOwn(input, field)) ||
      input.confirmed !== true ||
      typeof input.port !== 'number' ||
      !Number.isInteger(input.port) ||
      input.port < 1 ||
      input.port > 65535 ||
      typeof input.workspaceId !== 'string' ||
      !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(input.workspaceId) ||
      typeof input.role !== 'string' ||
      !/^wh_[a-z2-7]{8,16}_deployer$/.test(input.role) ||
      typeof input.database !== 'string' ||
      !/^[a-zA-Z0-9_-]{1,63}$/.test(input.database) ||
      !textField(input.host, 253) ||
      !textField(input.loginName, 256) ||
      !textField(input.deviceName, 4096) ||
      !validFactor(input.recoveryCode, 76, 76) ||
      !validFactor(input.deployerPassword, 1, 1024) ||
      !validFactor(input.accountPassword, 1, 1024) ||
      (Object.hasOwn(input, 'ask') && !validFactor(input.ask, 32, 32))
    )
      throw Error('Invalid workspace recovery request.');
    return {
      ...input,
      recoveryCode: Buffer.from(input.recoveryCode),
      deployerPassword: Buffer.from(input.deployerPassword),
      accountPassword: Buffer.from(input.accountPassword),
      ...(input.ask ? { ask: Buffer.from(input.ask) } : {}),
    };
  } finally {
    wipeAdminRecoveryInput(value);
  }
}

function validFactor(value: unknown, minimum: number, maximum: number): value is Uint8Array {
  return (
    value instanceof Uint8Array &&
    value.buffer instanceof ArrayBuffer &&
    value.length >= minimum &&
    value.length <= maximum
  );
}

function textField(value: unknown, maximum: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maximum &&
    !/\p{Cc}/u.test(value)
  );
}

export function validAdminRecoveryPaths(kit: string, trust: string) {
  return validSharedRecoveryKitPath(kit) && validSharedTLSBundlePath(trust);
}
