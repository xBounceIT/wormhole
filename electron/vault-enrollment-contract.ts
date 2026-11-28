// Shared public/ciphertext-only contract. Safe to import in the isolated dialog.
export type RecoveryDisplayReceipt = {
  enrollmentId: string;
  vaultId: string;
  bundle: { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
};
export type VaultEnrollment = RecoveryDisplayReceipt & { groups: [number, number] };
export type VaultEnrollmentBegin = { password: Uint8Array; publicKey: Uint8Array };
export type VaultEnrollmentConfirm = { enrollmentId: string; groups: Uint8Array };

export function enrollmentID(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) &&
    value !== '00000000-0000-0000-0000-000000000000'
  );
}
function fields(value: unknown, names: string[]): value is Record<string, unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === names.length &&
    names.every((name) => Object.hasOwn(value, name))
  );
}
export function enrollmentBytes(value: unknown, size: number): Uint8Array | undefined {
  if (
    typeof value !== 'string' ||
    value.length !== Math.ceil(size / 3) * 4 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  )
    return undefined;
  try {
    const decoded = atob(value);
    if (decoded.length !== size || btoa(decoded) !== value) return undefined;
    return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  } catch {
    return undefined;
  }
}
export function parseRecoveryDisplay(value: unknown): RecoveryDisplayReceipt | undefined {
  if (
    !fields(value, ['enrollmentId', 'vaultId', 'bundle']) ||
    !enrollmentID(value.enrollmentId) ||
    !enrollmentID(value.vaultId) ||
    !fields(value.bundle, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.bundle.formatVersion !== 1 ||
    value.bundle.suiteId !== 2 ||
    !enrollmentBytes(value.bundle.enc, 32) ||
    !enrollmentBytes(value.bundle.ciphertext, 92)
  )
    return undefined;
  return {
    enrollmentId: value.enrollmentId,
    vaultId: value.vaultId,
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: value.bundle.enc as string,
      ciphertext: value.bundle.ciphertext as string,
    },
  };
}

export function parseVaultEnrollment(value: unknown): VaultEnrollment | undefined {
  if (
    !fields(value, ['enrollmentId', 'vaultId', 'groups', 'bundle']) ||
    !Array.isArray(value.groups) ||
    value.groups.length !== 2 ||
    value.groups.some((group) => !Number.isInteger(group) || group < 1 || group > 11) ||
    value.groups[0] === value.groups[1]
  )
    return undefined;
  const { groups, ...display } = value;
  const receipt = parseRecoveryDisplay(display);
  return receipt && { ...receipt, groups: [groups[0], groups[1]] };
}
export function parseVaultEnrollmentCancel(value: unknown): true | undefined {
  return fields(value, ['cancelled']) && value.cancelled === true ? true : undefined;
}

// Copy before asynchronous work and consume the caller-owned input on all paths.
export function consumeVaultEnrollmentBegin(value: unknown): VaultEnrollmentBegin {
  const o = typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
  try {
    if (
      !fields(value, ['password', 'publicKey']) ||
      !(o.password instanceof Uint8Array) ||
      !(o.password.buffer instanceof ArrayBuffer) ||
      o.password.length < 1 ||
      o.password.length > 1024 ||
      !(o.publicKey instanceof Uint8Array) ||
      !(o.publicKey.buffer instanceof ArrayBuffer) ||
      o.publicKey.length !== 32
    )
      throw Error('Invalid vault enrollment request.');
    return { password: new Uint8Array(o.password), publicKey: new Uint8Array(o.publicKey) };
  } finally {
    if (o.password instanceof Uint8Array) o.password.fill(0);
    if (o.publicKey instanceof Uint8Array) o.publicKey.fill(0);
  }
}
export function consumeVaultEnrollmentConfirm(value: unknown): VaultEnrollmentConfirm {
  const o = typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
  try {
    if (
      !fields(value, ['enrollmentId', 'groups']) ||
      !enrollmentID(o.enrollmentId) ||
      !(o.groups instanceof Uint8Array) ||
      !(o.groups.buffer instanceof ArrayBuffer) ||
      o.groups.length !== 10
    )
      throw Error('Invalid vault enrollment confirmation.');
    return { enrollmentId: o.enrollmentId, groups: new Uint8Array(o.groups) };
  } finally {
    if (o.groups instanceof Uint8Array) o.groups.fill(0);
  }
}
