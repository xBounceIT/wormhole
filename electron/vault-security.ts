import { vaultRecord, vaultFields } from './vault-contract.ts';

export type VaultProfile = 'default' | 'standard' | 'hardened' | 'paranoid';
export type VaultSecurity = {
  sequence: string;
  workspace: VaultProfile;
  user: VaultProfile;
  os: VaultProfile;
  effective: VaultProfile;
  source: 'os' | 'workspace' | 'user';
  retainedUntilLock?: true;
  canTightenToStandard?: true;
};
export type VaultProfileStatus = Pick<
  VaultSecurity,
  'effective' | 'source' | 'canTightenToStandard'
> & {
  retainedUntilLock: boolean;
};

const profiles: VaultProfile[] = ['default', 'standard', 'hardened', 'paranoid'];

export function stricterVaultProfile(a: VaultProfile, b: VaultProfile): VaultProfile {
  return profiles.indexOf(a) >= profiles.indexOf(b) ? a : b;
}

export function parseVaultSecurity(value: unknown): VaultSecurity | undefined {
  if (!vaultRecord(value)) return undefined;
  const retained = value.retainedUntilLock === true;
  const canTighten = value.canTightenToStandard === true;
  if (
    !vaultFields(value, [
      'sequence',
      'workspace',
      'user',
      'os',
      'effective',
      'source',
      ...(retained ? ['retainedUntilLock'] : []),
      ...(canTighten ? ['canTightenToStandard'] : []),
    ]) ||
    typeof value.sequence !== 'string' ||
    !/^[1-9][0-9]{0,18}$/.test(value.sequence) ||
    BigInt(value.sequence) > 9223372036854775807n
  )
    return undefined;
  const ranks = [value.workspace, value.user, value.os].map((p) =>
    profiles.indexOf(p as VaultProfile),
  );
  if (ranks.some((rank) => rank < 0)) return undefined;
  const configured = profiles[Math.max(...ranks)]!;
  const effective = value.effective as VaultProfile;
  const source = value.source;
  if (canTighten && effective !== 'default') return undefined;
  const configuredSource =
    value.os !== 'default' && configured === value.os
      ? 'os'
      : configured !== value.workspace
        ? 'user'
        : 'workspace';
  if (source !== 'os' && source !== 'workspace' && source !== 'user') return undefined;
  if (
    retained
      ? profiles.indexOf(effective) <= Math.max(...ranks)
      : effective !== configured || source !== configuredSource
  )
    return undefined;
  return {
    sequence: value.sequence,
    workspace: value.workspace as VaultProfile,
    user: value.user as VaultProfile,
    os: value.os as VaultProfile,
    effective,
    source,
    ...(retained ? { retainedUntilLock: true as const } : {}),
    ...(canTighten ? { canTightenToStandard: true as const } : {}),
  };
}
