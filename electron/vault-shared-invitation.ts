import type { VaultStartupMetadata } from './vault-contract.ts';
export const maxSharedInvitationBytes = 2 * (1024 * 1024 + 384 * 1024);
export type SharedInvitation = {
  invitation: string;
  workspaceId: string;
  loginName: string;
  tls: 'off' | 'encrypted' | 'verified';
};

export function validSharedInvitationText(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxSharedInvitationBytes &&
    new TextEncoder().encode(value).length <= maxSharedInvitationBytes
  );
}

export function isSharedInitialStartup(value: VaultStartupMetadata): boolean {
  return (
    value.newWorkspace &&
    value.slots === null &&
    !value.shared &&
    !value.sharedJoin &&
    !value.legacy &&
    !value.osMigration &&
    !value.migration &&
    !value.rotation &&
    !value.upgrade &&
    !value.unprotected
  );
}

// Shape only: Go owns token/checksum/expiry and transport interpretation. These
// hints grant no policy or organisation authority, even after native decoding.
export function parseSharedInvitation(value: unknown): SharedInvitation | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const v = value as Record<string, unknown>;
  const keys = ['invitation', 'workspaceId', 'loginName', 'tls'];
  if (
    Object.keys(v).length !== 4 ||
    !keys.every((key) => Object.hasOwn(v, key)) ||
    !validSharedInvitationText(v.invitation) ||
    !/^WHINV[23]-/.test(v.invitation) ||
    typeof v.workspaceId !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v.workspaceId) ||
    v.workspaceId === '00000000-0000-0000-0000-000000000000' ||
    typeof v.loginName !== 'string' ||
    !v.loginName.length ||
    new TextEncoder().encode(v.loginName).length > 256 ||
    /\p{Cc}/u.test(v.loginName) ||
    (v.tls !== 'off' && v.tls !== 'encrypted' && v.tls !== 'verified')
  )
    return undefined;
  return {
    invitation: v.invitation,
    workspaceId: v.workspaceId,
    loginName: v.loginName,
    tls: v.tls,
  };
}
