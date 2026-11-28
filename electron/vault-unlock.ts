import { Buffer } from 'node:buffer';
import type { SharedAdminSetupOperation } from './vault-shared-setup-contract.ts';

// Typed input only. Never persist a factor or expose it in an application model.
export type VaultUnlockInput = {
  vaultId: string;
  slotId: string;
  kind: 'password' | 'recovery' | 'recovery-code';
  factor: Uint8Array;
};

const identifier = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const nilID = '00000000-0000-0000-0000-000000000000';
const alphabet = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');

// Consume the IPC/caller-owned bytes even on malformed input. The bounded copy
// belongs to the client until forwarding, lock, queue rejection or startup error.
export function consumeVaultUnlockInput(value: unknown): VaultUnlockInput {
  const object =
    typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : undefined;
  const factor = object?.factor;
  try {
    if (
      !object ||
      Array.isArray(object) ||
      Object.keys(object).length !== 4 ||
      !['vaultId', 'slotId', 'kind', 'factor'].every((key) => Object.hasOwn(object, key)) ||
      typeof object.vaultId !== 'string' ||
      !identifier.test(object.vaultId) ||
      object.vaultId === nilID ||
      typeof object.slotId !== 'string' ||
      !identifier.test(object.slotId) ||
      object.slotId === nilID ||
      (object.kind !== 'password' &&
        object.kind !== 'recovery' &&
        object.kind !== 'recovery-code') ||
      !(factor instanceof Uint8Array) ||
      !(factor.buffer instanceof ArrayBuffer) ||
      (object.kind === 'password'
        ? factor.length < 1 || factor.length > 1024
        : factor.length !== (object.kind === 'recovery' ? 32 : 76))
    )
      throw new Error('Invalid vault unlock request.');
    return {
      vaultId: object.vaultId,
      slotId: object.slotId,
      kind: object.kind,
      factor: Buffer.from(factor),
    };
  } finally {
    if (factor instanceof Uint8Array) factor.fill(0);
  }
}

// Encode directly into a mutable frame. Buffer.toString('base64') / JSON.stringify
// of a factor would leave an immutable copy in the JS heap after clearing bytes.
export function encodeVaultUnlockFrame(
  id: number,
  input: VaultUnlockInput,
  operation: 'unlock' | 'migration-resume' | 'rotation-resume' = 'unlock',
): Buffer {
  const field =
    input.kind === 'password'
      ? 'password'
      : input.kind === 'recovery'
        ? 'recoveryKey'
        : 'recoveryCode';
  return encodeVaultBytesFrame(id, operation, { vaultId: input.vaultId, slotId: input.slotId }, [
    [field, input.factor],
  ]);
}

// Native typed callers supply public metadata and fixed byte-field names only.
export function encodeVaultBytesFrame(
  id: number,
  operation:
    | 'unlock'
    | 'migration-resume'
    | 'rotation-resume'
    | 'migration-setup-begin'
    | 'migration-setup-confirm'
    | 'rotation-setup-begin'
    | 'rotation-encryption-begin'
    | 'rotation-upgrade-begin'
    | 'migration-os-prepare'
    | 'rotation-setup-confirm'
    | 'local-backup-install'
    | 'enrollment-begin'
    | 'enrollment-confirm'
    | 'shared-join-initial'
    | 'shared-account-reset-redeem'
    | 'shared-admin-recover'
    | 'shared-recovery-inspect'
    | 'shared-recovery-restore'
    | 'shared-recovery-kit-refresh'
    | 'shared-tighten-profile'
    | 'shared-ssh-host-trust'
    | 'shared-node-edit'
    | 'shared-slot-default'
    | 'shared-personal-slot'
    | 'shared-node-credential'
    | 'shared-recovery-export'
    | 'shared-account-reset-issue'
    | 'shared-personal-root-recovery'
    | 'shared-setup-check'
    | 'shared-setup-preflight'
    | 'shared-setup-run'
    | 'shared-setup-prepare-tls'
    | 'shared-setup-prepare-generated-tls'
    | SharedAdminSetupOperation
    | 'credential-edit'
    | 'tunnel-edit'
    | 'connection-save'
    | 'web-session-save'
    | 'fresh-action',
  metadata: Record<string, unknown>,
  values: [string, Uint8Array][],
): Buffer {
  if (!Number.isSafeInteger(id) || id < 1) throw new Error('Invalid vault request ID.');
  const body = encodeVaultBytesObject(metadata, values);
  try {
    return Buffer.concat([
      Buffer.from(`{"version":1,"id":${id},"operation":"${operation}","payload":`),
      body,
      Buffer.from('}\n'),
    ]);
  } finally {
    body.fill(0);
  }
}

export function encodeVaultBytesObject(
  metadata: Record<string, unknown>,
  values: [string, Uint8Array][],
): Buffer {
  const publicFields = JSON.stringify(metadata).slice(1, -1);
  const prefix = Buffer.from(`{${publicFields}`);
  const names = values.map(([name], index) =>
    Buffer.from(`${publicFields || index > 0 ? ',' : ''}${JSON.stringify(name)}:"`),
  );
  const size =
    prefix.length +
    1 +
    values.reduce(
      (total, [, bytes], index) =>
        total + names[index].length + Math.ceil(bytes.length / 3) * 4 + 1,
      0,
    );
  const frame = Buffer.alloc(size);
  let out = prefix.copy(frame);
  for (let n = 0; n < values.length; n++) {
    out += names[n].copy(frame, out);
    const bytes = values[n][1];
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i],
        b = bytes[i + 1] ?? 0,
        c = bytes[i + 2] ?? 0;
      frame[out++] = alphabet[a >> 2];
      frame[out++] = alphabet[((a & 3) << 4) | (b >> 4)];
      frame[out++] = i + 1 < bytes.length ? alphabet[((b & 15) << 2) | (c >> 6)] : 61;
      frame[out++] = i + 2 < bytes.length ? alphabet[c & 63] : 61;
    }
    frame[out++] = 34;
  }
  frame.write('}', out);
  return frame;
}
