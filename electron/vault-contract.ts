export type VaultStatus = {
  formatVersion: 1;
  stage: 'foundation';
  protectionAvailable: false;
  sharedWorkspaceAvailable: false;
  unlocked: boolean;
  lockedMemory: boolean;
};

export function parseVaultProtection(value: unknown): { protected: boolean } | undefined {
  return record(value) && fields(value, ['protected']) && typeof value.protected === 'boolean'
    ? { protected: value.protected }
    : undefined;
}

export type VaultUnprotectedOpened = VaultUnlockResult & { vaultId: string };
export function parseVaultUnprotectedOpened(value: unknown): VaultUnprotectedOpened | undefined {
  return record(value) &&
    fields(value, ['unlocked', 'lockedMemory', 'vaultId']) &&
    value.unlocked === true &&
    typeof value.lockedMemory === 'boolean' &&
    id(value.vaultId)
    ? { unlocked: true, lockedMemory: value.lockedMemory, vaultId: value.vaultId }
    : undefined;
}

export type VaultSlotDescriptor =
  | { id: string; kind: 'password'; preset: 'kdf-low' | 'kdf-v1' | 'kdf-v2' | 'kdf-v3' }
  | { id: string; kind: 'recovery' }
  | { id: string; kind: 'hello' }
  | { id: string; kind: 'touch-id' };

export type VaultDescriptor = {
  formatVersion: 1 | 2 | 3 | 5 | 6 | 7;
  vaultId: string;
  encrypted: boolean;
  slots: VaultSlotDescriptor[];
};

export type VaultStartupMetadata = {
  slots: VaultDescriptor | null;
  cosmetics: { theme: 'system' | 'light' | 'dark' };
  newWorkspace: boolean;
  legacy?: { unprotectedAllowed: boolean };
  shared?: { lastLoginName: string; serverDisplayName: string };
  sharedJoin?: {
    lastLoginName: string;
    serverDisplayName: string;
    canContinue?: true;
    adminRecovery?: true;
    accountReset?: true;
  };
  migration?: { pending: true };
  rotation?: { pending: true };
  upgrade?: { vaultId: string };
  unprotected?: { vaultId: string };
  unprotectedAllowed?: true;
  osMigration?: { vaultId: string };
};

export function parseVaultStartup(value: unknown): VaultStartupMetadata | undefined {
  if (
    !record(value) ||
    !fields(value, [
      'slots',
      'cosmetics',
      'newWorkspace',
      ...(Object.hasOwn(value, 'shared') ? ['shared'] : []),
      ...(Object.hasOwn(value, 'sharedJoin') ? ['sharedJoin'] : []),
      ...(Object.hasOwn(value, 'migration') ? ['migration'] : []),
      ...(Object.hasOwn(value, 'rotation') ? ['rotation'] : []),
      ...(Object.hasOwn(value, 'upgrade') ? ['upgrade'] : []),
      ...(Object.hasOwn(value, 'unprotected') ? ['unprotected'] : []),
      ...(Object.hasOwn(value, 'unprotectedAllowed') ? ['unprotectedAllowed'] : []),
      ...(Object.hasOwn(value, 'osMigration') ? ['osMigration'] : []),
      ...(Object.hasOwn(value, 'legacy') ? ['legacy'] : []),
    ]) ||
    typeof value.newWorkspace !== 'boolean' ||
    !record(value.cosmetics) ||
    !fields(value.cosmetics, ['theme']) ||
    !['system', 'light', 'dark'].includes(value.cosmetics.theme as string)
  )
    return undefined;
  const slots = parseVaultDescription({ slots: value.slots });
  if (
    Object.hasOwn(value, 'unprotectedAllowed') &&
    (!value.newWorkspace || value.unprotectedAllowed !== true)
  )
    return undefined;
  if (slots === undefined || (slots !== null && value.newWorkspace)) return undefined;
  const migration = Object.hasOwn(value, 'migration');
  const rotation = Object.hasOwn(value, 'rotation');
  const upgrade = Object.hasOwn(value, 'upgrade');
  const unprotected = Object.hasOwn(value, 'unprotected');
  const osMigration = Object.hasOwn(value, 'osMigration');
  const legacy = Object.hasOwn(value, 'legacy');
  if (
    legacy &&
    (slots !== null ||
      value.newWorkspace ||
      migration ||
      rotation ||
      upgrade ||
      unprotected ||
      osMigration ||
      Object.hasOwn(value, 'shared') ||
      !record(value.legacy) ||
      !fields(value.legacy, ['unprotectedAllowed']) ||
      typeof value.legacy.unprotectedAllowed !== 'boolean')
  )
    return undefined;
  if (
    osMigration &&
    (slots !== null ||
      value.newWorkspace ||
      migration ||
      rotation ||
      upgrade ||
      unprotected ||
      Object.hasOwn(value, 'shared') ||
      !record(value.osMigration) ||
      !fields(value.osMigration, ['vaultId']) ||
      !id(value.osMigration.vaultId))
  )
    return undefined;
  if (
    unprotected &&
    (upgrade ||
      slots !== null ||
      value.newWorkspace ||
      migration ||
      rotation ||
      Object.hasOwn(value, 'shared') ||
      !record(value.unprotected) ||
      !fields(value.unprotected, ['vaultId']) ||
      !id(value.unprotected.vaultId))
  )
    return undefined;
  if (
    upgrade &&
    (slots !== null ||
      value.newWorkspace ||
      migration ||
      rotation ||
      Object.hasOwn(value, 'shared') ||
      !record(value.upgrade) ||
      !fields(value.upgrade, ['vaultId']) ||
      !id(value.upgrade.vaultId))
  )
    return undefined;
  if (
    rotation &&
    (!slots ||
      slots.formatVersion !== 3 ||
      value.newWorkspace ||
      migration ||
      Object.hasOwn(value, 'shared') ||
      !record(value.rotation) ||
      !fields(value.rotation, ['pending']) ||
      value.rotation.pending !== true)
  )
    return undefined;
  if (
    migration &&
    (!slots ||
      slots.encrypted ||
      value.newWorkspace ||
      Object.hasOwn(value, 'shared') ||
      !record(value.migration) ||
      !fields(value.migration, ['pending']) ||
      value.migration.pending !== true)
  )
    return undefined;
  let shared: VaultStartupMetadata['shared'];
  let sharedJoin: VaultStartupMetadata['sharedJoin'];
  const joining = Object.hasOwn(value, 'sharedJoin');
  if (
    joining &&
    (Object.hasOwn(value, 'shared') ||
      migration ||
      rotation ||
      legacy ||
      upgrade ||
      unprotected ||
      osMigration)
  )
    return undefined;
  if (Object.hasOwn(value, 'shared') || joining) {
    const hint = joining ? value.sharedJoin : value.shared;
    if (
      !slots ||
      !slots.encrypted ||
      value.newWorkspace ||
      !record(hint) ||
      !fields(hint, [
        'lastLoginName',
        'serverDisplayName',
        ...(joining && Object.hasOwn(hint, 'canContinue') ? ['canContinue'] : []),
        ...(joining && Object.hasOwn(hint, 'adminRecovery') ? ['adminRecovery'] : []),
        ...(joining && Object.hasOwn(hint, 'accountReset') ? ['accountReset'] : []),
      ]) ||
      (Object.hasOwn(hint, 'canContinue') && (!joining || hint.canContinue !== true)) ||
      (Object.hasOwn(hint, 'adminRecovery') && (!joining || hint.adminRecovery !== true)) ||
      (Object.hasOwn(hint, 'accountReset') &&
        (!joining ||
          hint.accountReset !== true ||
          hint.canContinue !== true ||
          hint.adminRecovery === true)) ||
      !metadataText(hint.lastLoginName, 256) ||
      hint.lastLoginName.length === 0 ||
      !metadataText(hint.serverDisplayName, 256) ||
      hint.serverDisplayName.length === 0 ||
      /\p{Cc}/u.test(hint.lastLoginName) ||
      /\p{Cc}/u.test(hint.serverDisplayName)
    )
      return undefined;
    const hints = {
      lastLoginName: hint.lastLoginName,
      serverDisplayName: hint.serverDisplayName,
    };
    if (joining)
      sharedJoin = {
        ...hints,
        ...(hint.canContinue === true ? { canContinue: true as const } : {}),
        ...(hint.adminRecovery === true ? { adminRecovery: true as const } : {}),
        ...(hint.accountReset === true ? { accountReset: true as const } : {}),
      };
    else shared = hints;
  }
  return {
    slots,
    cosmetics: { theme: value.cosmetics.theme as VaultStartupMetadata['cosmetics']['theme'] },
    newWorkspace: value.newWorkspace,
    ...(legacy
      ? {
          legacy: {
            unprotectedAllowed: (value.legacy as { unprotectedAllowed: boolean })
              .unprotectedAllowed,
          },
        }
      : {}),
    ...(value.unprotectedAllowed === true ? { unprotectedAllowed: true as const } : {}),
    ...(osMigration
      ? { osMigration: { vaultId: (value.osMigration as { vaultId: string }).vaultId } }
      : {}),
    ...(shared ? { shared } : {}),
    ...(sharedJoin ? { sharedJoin } : {}),
    ...(migration ? { migration: { pending: true as const } } : {}),
    ...(rotation ? { rotation: { pending: true as const } } : {}),
    ...(upgrade ? { upgrade: { vaultId: (value.upgrade as { vaultId: string }).vaultId } } : {}),
    ...(unprotected
      ? { unprotected: { vaultId: (value.unprotected as { vaultId: string }).vaultId } }
      : {}),
  };
}

export type VaultCatalogNode = {
  id: string;
  parentId: string | null;
  name: string;
  kind: 0 | 1;
  sortOrder: string;
  protocol: number | null;
  host: string | null;
  port: number | null;
  username: string | null;
  rowVersion: string;
  hasNotes: boolean;
  hasInlinePassword: boolean;
};
export type VaultCatalogCredential = {
  id: string;
  name: string;
  protocol: 'ssh' | 'rdp' | 'vnc';
  kind: 'password' | 'sshKey';
  username: string;
  domain: string;
  provider: 'local' | 'bitwarden';
  rowVersion: string;
};
export type VaultCatalogTunnel = { id: string; name: string; kind: number; rowVersion: string };
export type VaultCatalog = {
  nodes: VaultCatalogNode[];
  credentials: VaultCatalogCredential[];
  tunnels: VaultCatalogTunnel[];
};

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function fields(value: Record<string, unknown>, names: string[]): boolean {
  return (
    Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name))
  );
}

function id(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) &&
    value !== '00000000-0000-0000-0000-000000000000'
  );
}

function metadataText(value: unknown, maximum: number, required = false): value is string {
  if (
    typeof value !== 'string' ||
    value.length > maximum ||
    value.includes('\0') ||
    (required && !/[^\p{White_Space}]/u.test(value)) ||
    new TextEncoder().encode(value).length > maximum
  )
    return false;
  for (const character of value) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff) return false;
  }
  return true;
}

export {
  record as vaultRecord,
  fields as vaultFields,
  id as vaultID,
  metadataText as vaultMetadataText,
  decimal as vaultRevision,
};

function decimal(value: unknown, signed = false): value is string {
  if (
    typeof value !== 'string' ||
    value.length > 20 ||
    !(signed ? /^(?:0|-?[1-9][0-9]*)$/ : /^[1-9][0-9]*$/).test(value)
  )
    return false;
  const number = BigInt(value);
  return number <= 9223372036854775807n && number >= (signed ? -9223372036854775808n : 1n);
}

// Reject extra properties instead of passing through untrusted records. This is
// stored display metadata only, never a resolution or authorization capability.
export function parseVaultCatalog(value: unknown): VaultCatalog | undefined {
  if (
    !record(value) ||
    !fields(value, ['nodes', 'credentials', 'tunnels']) ||
    !Array.isArray(value.nodes) ||
    !Array.isArray(value.credentials) ||
    !Array.isArray(value.tunnels) ||
    value.nodes.length + value.credentials.length + value.tunnels.length > 50_000
  )
    return undefined;
  const nodes: VaultCatalogNode[] = [];
  const credentials: VaultCatalogCredential[] = [];
  const tunnels: VaultCatalogTunnel[] = [];
  let previous = '';
  for (const n of value.nodes) {
    if (
      !record(n) ||
      !fields(n, [
        'id',
        'parentId',
        'name',
        'kind',
        'sortOrder',
        'protocol',
        'host',
        'port',
        'username',
        'rowVersion',
        'hasNotes',
        'hasInlinePassword',
      ]) ||
      !id(n.id) ||
      n.id <= previous ||
      (n.parentId !== null && (!id(n.parentId) || n.parentId === n.id)) ||
      !metadataText(n.name, 1024, true) ||
      [...n.name].length > 256 ||
      /\p{Cc}/u.test(n.name) ||
      (n.kind !== 0 && n.kind !== 1) ||
      !decimal(n.sortOrder, true) ||
      !decimal(n.rowVersion) ||
      (n.protocol !== null && ![0, 1, 3, 4, 5, 6, 7].includes(n.protocol as number)) ||
      (n.host !== null && (!metadataText(n.host, 16384) || /[\r\n]/.test(n.host))) ||
      (n.port !== null &&
        (typeof n.port !== 'number' ||
          !Number.isInteger(n.port) ||
          n.port < 0 ||
          n.port > 65535)) ||
      (n.username !== null && (!metadataText(n.username, 2048) || /[\r\n]/.test(n.username))) ||
      typeof n.hasNotes !== 'boolean' ||
      typeof n.hasInlinePassword !== 'boolean'
    )
      return undefined;
    nodes.push({
      id: n.id,
      parentId: n.parentId,
      name: n.name,
      kind: n.kind,
      sortOrder: n.sortOrder,
      protocol: n.protocol as number | null,
      host: n.host,
      port: n.port,
      username: n.username,
      rowVersion: n.rowVersion,
      hasNotes: n.hasNotes,
      hasInlinePassword: n.hasInlinePassword,
    });
    previous = n.id;
  }
  previous = '';
  for (const c of value.credentials) {
    if (
      !record(c) ||
      !fields(c, [
        'id',
        'name',
        'protocol',
        'kind',
        'username',
        'domain',
        'provider',
        'rowVersion',
      ]) ||
      !id(c.id) ||
      c.id <= previous ||
      !metadataText(c.name, 1024, true) ||
      !metadataText(c.username, 2048) ||
      !metadataText(c.domain, 2048) ||
      !decimal(c.rowVersion) ||
      (c.protocol !== 'ssh' && c.protocol !== 'rdp' && c.protocol !== 'vnc') ||
      (c.kind !== 'password' && c.kind !== 'sshKey') ||
      (c.provider !== 'local' && c.provider !== 'bitwarden') ||
      (c.kind === 'sshKey' && (c.protocol !== 'ssh' || c.provider !== 'local'))
    )
      return undefined;
    credentials.push({
      id: c.id,
      name: c.name,
      protocol: c.protocol,
      kind: c.kind,
      username: c.username,
      domain: c.domain,
      provider: c.provider,
      rowVersion: c.rowVersion,
    });
    previous = c.id;
  }
  previous = '';
  for (const t of value.tunnels) {
    if (
      !record(t) ||
      !fields(t, ['id', 'name', 'kind', 'rowVersion']) ||
      !id(t.id) ||
      t.id <= previous ||
      !metadataText(t.name, 512, true) ||
      [...t.name].length > 128 ||
      !decimal(t.rowVersion) ||
      typeof t.kind !== 'number' ||
      !Number.isInteger(t.kind) ||
      t.kind < 0 ||
      t.kind > 9
    )
      return undefined;
    tunnels.push({ id: t.id, name: t.name, kind: t.kind, rowVersion: t.rowVersion });
    previous = t.id;
  }
  const byID = new Map(nodes.map((node) => [node.id, node]));
  for (const node of nodes) {
    let current = node;
    for (let depth = 1; current.parentId !== null; depth++) {
      const parent = byID.get(current.parentId);
      if (!parent || parent.kind !== 0 || depth >= 128) return undefined;
      current = parent;
    }
  }
  return { nodes, credentials, tunnels };
}

export function parseVaultStatus(value: unknown): VaultStatus | undefined {
  if (
    !record(value) ||
    !fields(value, [
      'formatVersion',
      'stage',
      'protectionAvailable',
      'sharedWorkspaceAvailable',
      'unlocked',
      'lockedMemory',
    ]) ||
    value.formatVersion !== 1 ||
    value.stage !== 'foundation' ||
    value.protectionAvailable !== false ||
    value.sharedWorkspaceAvailable !== false ||
    typeof value.unlocked !== 'boolean' ||
    typeof value.lockedMemory !== 'boolean' ||
    (!value.unlocked && value.lockedMemory)
  )
    return undefined;
  return {
    formatVersion: 1,
    stage: 'foundation',
    protectionAvailable: false,
    sharedWorkspaceAvailable: false,
    unlocked: value.unlocked,
    lockedMemory: value.lockedMemory,
  };
}

// This projection is intentionally narrower than SlotFile: no salt, key-check,
// root reference, high-water mark, pending state, factor or wrapped key crosses IPC.
export function parseVaultDescriptor(value: unknown): VaultDescriptor | null | undefined {
  if (value === null) return null;
  if (
    !record(value) ||
    !fields(value, ['formatVersion', 'vaultId', 'encrypted', 'slots']) ||
    (value.formatVersion !== 1 &&
      value.formatVersion !== 2 &&
      value.formatVersion !== 3 &&
      value.formatVersion !== 5 &&
      value.formatVersion !== 6 &&
      value.formatVersion !== 7) ||
    !id(value.vaultId) ||
    typeof value.encrypted !== 'boolean' ||
    !Array.isArray(value.slots) ||
    value.slots.length < 1 ||
    value.slots.length > 16
  )
    return undefined;
  const slots: VaultSlotDescriptor[] = [];
  const seen = new Set<string>();
  let hello = false,
    touchID = false;
  for (const slot of value.slots) {
    if (!record(slot) || !id(slot.id) || seen.has(slot.id)) return undefined;
    seen.add(slot.id);
    if (slot.kind === 'recovery' && fields(slot, ['id', 'kind'])) {
      slots.push({ id: slot.id, kind: 'recovery' });
    } else if (
      slot.kind === 'hello' &&
      value.formatVersion >= 5 &&
      !hello &&
      fields(slot, ['id', 'kind'])
    ) {
      hello = true;
      slots.push({ id: slot.id, kind: 'hello' });
    } else if (
      slot.kind === 'touch-id' &&
      value.formatVersion >= 6 &&
      !touchID &&
      fields(slot, ['id', 'kind'])
    ) {
      touchID = true;
      slots.push({ id: slot.id, kind: 'touch-id' });
    } else if (
      slot.kind === 'password' &&
      fields(slot, ['id', 'kind', 'preset']) &&
      (slot.preset === 'kdf-low' ||
        slot.preset === 'kdf-v1' ||
        slot.preset === 'kdf-v2' ||
        slot.preset === 'kdf-v3')
    ) {
      slots.push({ id: slot.id, kind: 'password', preset: slot.preset });
    } else return undefined;
  }
  if ((hello || touchID) && !slots.some(({ kind }) => kind === 'password' || kind === 'recovery'))
    return undefined;
  return {
    formatVersion: value.formatVersion,
    vaultId: value.vaultId,
    encrypted: value.encrypted,
    slots,
  };
}

export function parseVaultDescription(value: unknown): VaultDescriptor | null | undefined {
  return record(value) && fields(value, ['slots']) ? parseVaultDescriptor(value.slots) : undefined;
}

export function parseVaultHeartbeat(value: unknown): true | undefined {
  return record(value) && fields(value, ['alive']) && value.alive === true ? true : undefined;
}

export type VaultUnlockResult = { unlocked: true; lockedMemory: boolean };
export function parseVaultUnlockResult(value: unknown): VaultUnlockResult | undefined {
  return record(value) &&
    fields(value, ['unlocked', 'lockedMemory']) &&
    value.unlocked === true &&
    typeof value.lockedMemory === 'boolean'
    ? { unlocked: true, lockedMemory: value.lockedMemory }
    : undefined;
}

export type VaultResponse = { id: number; result?: unknown; error?: string };

export function parseVaultCatalogEvent(text: string): true | undefined {
  if (text.length > 128) return undefined;
  const value = parseVaultNativeObject(text);
  return value &&
    fields(value, ['version', 'id', 'event']) &&
    value.version === 1 &&
    value.id === 0 &&
    value.event === 'shared-catalog-changed'
    ? true
    : undefined;
}

// Accept Go's HTML-safe string escaping as well as JSON.stringify. Canonical
// comparison rejects duplicate/escaped keys and rounded numeric IDs before schema
// projection. Sealed protocol bundles use their own relay contract.
export function parseVaultNativeObject(text: string): Record<string, unknown> | undefined {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (
    !record(value) ||
    (JSON.stringify(value) !== text &&
      JSON.stringify(value).replace(
        /[<>&\u2028\u2029]/g,
        (character) => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'),
      ) !== text)
  )
    return undefined;
  return value;
}

export function parseVaultResponse(text: string): VaultResponse | undefined {
  const value = parseVaultNativeObject(text);
  if (
    !value ||
    value.version !== 1 ||
    typeof value.id !== 'number' ||
    !Number.isSafeInteger(value.id) ||
    value.id < 1
  )
    return undefined;
  if (fields(value, ['version', 'id', 'result'])) return { id: value.id, result: value.result };
  if (
    fields(value, ['version', 'id', 'error']) &&
    typeof value.error === 'string' &&
    [
      'vault_busy',
      'vault_cancelled',
      'vault_operation_failed',
      'vault_invalid_response',
      'vault_workspace_connection_limit',
    ].includes(value.error)
  )
    return { id: value.id, error: value.error };
  return undefined;
}
