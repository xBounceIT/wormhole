import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';

type SuspensionKind = 'roots' | 'passwords' | 'groups' | 'web-sessions';
export type AccountSuspensionRequest = {
  accountId: string;
  kind: SuspensionKind;
  revision?: string;
  after?: string;
};
type RootStatus = 'active' | 'retired' | 'rotating' | 'pending';
export type SuspensionGroupEntry = {
  position: string;
  kind: 'group';
  boundaryId?: undefined;
  id: string;
  name: string;
  revision: string;
} & (
  | { status: 'queued'; jobId: string }
  | { status: 'needs-removal' | 'waiting' | 'resolved'; jobId?: undefined }
);
type Entry =
  | { position: string; boundaryId?: undefined; kind?: undefined }
  | SuspensionGroupEntry
  | {
      position: string;
      boundaryId: string;
      id: string;
      kind: 'view' | 'secret';
      revision: string;
      direct: boolean;
      groupCount: string;
      status: RootStatus;
      personal?: true;
    }
  | {
      position: string;
      boundaryId: string;
      id: string;
      kind: 'credential' | 'node' | 'tunnel' | 'slot-value';
      name?: string;
    }
  | {
      position: string;
      boundaryId: string;
      id: string;
      kind: 'web-target';
      name: string;
    };
type Page = {
  accountId: string;
  kind: SuspensionKind;
  revision: string;
  entries: Entry[];
  after?: string;
};
export type AccountSuspensionReply =
  | { status: 'ready'; page: Page }
  | { status: 'busy' | 'stale' | 'unavailable' | 'not-recorded' | 'unsupported' };
export type AccountSuspensionPort = (
  request: AccountSuspensionRequest,
) => Promise<AccountSuspensionReply>;

export type AccountBoundaryRotationRequest = {
  accountId: string;
  suspension: string;
  boundaryId: string;
  purpose: 'view' | 'secret';
  rootId: string;
  rootVersion: string;
  review?: string;
};
export type AccountBoundaryRotationReply =
  | { status: 'review'; review: string }
  | {
      status:
        | 'changed'
        | 'unchanged'
        | 'busy'
        | 'stale'
        | 'group-rotation-required'
        | 'unavailable'
        | 'unsupported';
    };
export type AccountBoundaryRotationPort = (
  request: AccountBoundaryRotationRequest,
) => Promise<AccountBoundaryRotationReply>;

export type PersonalRootRecoveryRequest = {
  accountId: string;
  suspension: string;
  review?: string;
};

export type PersonalRootRecoveryFactors = { password: Uint8Array; ask?: Uint8Array };

export type PersonalRootRecoveryReply =
  | { status: 'review'; review: string; enrollment: string }
  | { status: 'enrollment-required'; canReenroll?: true }
  | {
      status:
        | 'changed'
        | 'unchanged'
        | 'busy'
        | 'stale'
        | 'rotation-required'
        | 'invalid-authentication'
        | 'unavailable'
        | 'unsupported';
    };

export type PersonalRootRecoveryPort = (
  request: PersonalRootRecoveryRequest,
  factors?: PersonalRootRecoveryFactors,
) => Promise<PersonalRootRecoveryReply>;

const ordinal = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^[1-9][0-9]{0,18}$/.test(value) &&
  (value.length < 19 || value <= '9223372036854775807');

const keyNumber = (value: unknown): value is string =>
  typeof value === 'string' && /^(0|[1-9][0-9]{0,9})$/.test(value) && +value <= 2147483647;

const reviewDigest = (value: unknown): value is string =>
  typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

export function parsePersonalRootRecoveryRequest(
  value: unknown,
): PersonalRootRecoveryRequest | undefined {
  if (!vaultRecord(value)) return;
  const { accountId, suspension, review } = value;
  if (!vaultID(accountId) || !ordinal(suspension)) return;
  if (vaultFields(value, ['accountId', 'suspension'])) return { accountId, suspension };
  if (vaultFields(value, ['accountId', 'suspension', 'review']) && reviewDigest(review))
    return { accountId, suspension, review };
}

export function parsePersonalRootRecoveryReply(
  value: unknown,
  request: PersonalRootRecoveryRequest,
): PersonalRootRecoveryReply | undefined {
  if (!vaultRecord(value)) return;
  const { status, review, enrollment } = value;
  switch (status) {
    case 'review':
      if (
        !request.review &&
        vaultFields(value, ['status', 'review', 'enrollment']) &&
        reviewDigest(review) &&
        vaultID(enrollment)
      )
        return { status, review, enrollment };
      return;
    case 'changed':
    case 'invalid-authentication':
      if (!request.review) return;
      return vaultFields(value, ['status']) ? { status } : undefined;
    case 'enrollment-required':
      if (
        !request.review &&
        value.canReenroll === true &&
        vaultFields(value, ['status', 'canReenroll'])
      )
        return { status, canReenroll: true };
      return vaultFields(value, ['status']) ? { status } : undefined;
    case 'unchanged':
    case 'busy':
    case 'stale':
    case 'rotation-required':
    case 'unavailable':
    case 'unsupported':
      return vaultFields(value, ['status']) ? { status } : undefined;
  }
}

export function wipePersonalRootRecoveryFactors(value: unknown): void {
  if (!vaultRecord(value)) return;
  for (const factor of [value.password, value.ask])
    if (factor instanceof Uint8Array) factor.fill(0);
}

export function consumePersonalRootRecoveryFactors(value: unknown): PersonalRootRecoveryFactors {
  try {
    if (
      !vaultRecord(value) ||
      !vaultFields(value, Object.hasOwn(value, 'ask') ? ['password', 'ask'] : ['password'])
    )
      throw Error('Invalid personal key recovery authentication.');
    const { password, ask } = value;
    if (
      !(password instanceof Uint8Array) ||
      !(password.buffer instanceof ArrayBuffer) ||
      password.length < 1 ||
      password.length > 1024 ||
      (Object.hasOwn(value, 'ask') &&
        (!(ask instanceof Uint8Array) || !(ask.buffer instanceof ArrayBuffer) || ask.length !== 32))
    )
      throw Error('Invalid personal key recovery authentication.');
    return {
      password: new Uint8Array(password),
      ...(ask instanceof Uint8Array ? { ask: new Uint8Array(ask) } : {}),
    };
  } finally {
    wipePersonalRootRecoveryFactors(value);
  }
}

export function parseAccountBoundaryRotationRequest(
  value: unknown,
): AccountBoundaryRotationRequest | undefined {
  if (!vaultRecord(value)) return;
  const { accountId, suspension, boundaryId, purpose, rootId, rootVersion, review } = value;
  const fields = ['accountId', 'suspension', 'boundaryId', 'purpose', 'rootId', 'rootVersion'];
  if (
    !vaultID(accountId) ||
    !ordinal(suspension) ||
    !vaultID(boundaryId) ||
    (purpose !== 'view' && purpose !== 'secret') ||
    !vaultID(rootId) ||
    !keyNumber(rootVersion) ||
    rootVersion === '0' ||
    rootVersion === '2147483647'
  )
    return;
  if (vaultFields(value, fields))
    return { accountId, suspension, boundaryId, purpose, rootId, rootVersion };
  if (vaultFields(value, [...fields, 'review']) && reviewDigest(review))
    return { accountId, suspension, boundaryId, purpose, rootId, rootVersion, review };
}

export function parseAccountBoundaryRotationReply(
  value: unknown,
  request: AccountBoundaryRotationRequest,
): AccountBoundaryRotationReply | undefined {
  if (!vaultRecord(value)) return;
  const { status, review } = value;
  switch (status) {
    case 'review':
      if (!request.review && vaultFields(value, ['status', 'review']) && reviewDigest(review))
        return { status, review };
      return;
    case 'changed':
      if (!request.review) return;
      return vaultFields(value, ['status']) ? { status } : undefined;
    case 'unchanged':
    case 'busy':
    case 'stale':
    case 'group-rotation-required':
    case 'unavailable':
    case 'unsupported':
      return vaultFields(value, ['status']) ? { status } : undefined;
  }
}

export function parseAccountSuspensionRequest(
  value: unknown,
): AccountSuspensionRequest | undefined {
  if (!vaultRecord(value)) return;
  const { accountId, kind, revision, after } = value;
  if (
    !vaultID(accountId) ||
    (kind !== 'roots' && kind !== 'passwords' && kind !== 'groups' && kind !== 'web-sessions')
  )
    return;
  if (vaultFields(value, ['accountId', 'kind'])) return { accountId, kind };
  if (
    vaultFields(value, ['accountId', 'kind', 'revision', 'after']) &&
    ordinal(revision) &&
    ordinal(after)
  )
    return { accountId, kind, revision, after };
}

function validEntry(value: unknown, kind: SuspensionKind): value is Entry {
  if (!vaultRecord(value) || !ordinal(value.position)) return false;
  if (vaultFields(value, ['position'])) return true;
  if (kind === 'groups') {
    const { status, name } = value;
    const fields = ['position', 'kind', 'id', 'name', 'revision', 'status'];
    return (
      value.kind === 'group' &&
      vaultID(value.id) &&
      ordinal(value.revision) &&
      typeof name === 'string' &&
      name.length > 0 &&
      name.length <= 1024 &&
      new TextEncoder().encode(name).length <= 1024 &&
      !/\p{Cc}/u.test(name) &&
      (status === 'queued'
        ? vaultFields(value, [...fields, 'jobId']) && vaultID(value.jobId)
        : (status === 'needs-removal' || status === 'waiting' || status === 'resolved') &&
          vaultFields(value, fields))
    );
  }
  if (!vaultID(value.boundaryId) || !vaultID(value.id)) return false;
  if (kind === 'web-sessions') {
    const { name } = value;
    return (
      value.kind === 'web-target' &&
      vaultFields(value, ['position', 'boundaryId', 'kind', 'id', 'name']) &&
      typeof name === 'string' &&
      name.length > 0 &&
      new TextEncoder().encode(name).length <= 4096 &&
      !/\p{Cc}/u.test(name)
    );
  }
  if (kind === 'roots')
    return (
      vaultFields(value, [
        'position',
        'boundaryId',
        'kind',
        'id',
        'revision',
        'direct',
        'groupCount',
        'status',
        ...(Object.hasOwn(value, 'personal') ? ['personal'] : []),
      ]) &&
      (!Object.hasOwn(value, 'personal') || value.personal === true) &&
      (value.kind === 'view' || value.kind === 'secret') &&
      keyNumber(value.revision) &&
      value.revision !== '0' &&
      keyNumber(value.groupCount) &&
      typeof value.direct === 'boolean' &&
      (value.direct || value.groupCount !== '0') &&
      (value.status === 'active' ||
        value.status === 'retired' ||
        value.status === 'rotating' ||
        value.status === 'pending')
    );
  return (
    vaultFields(value, [
      'position',
      'boundaryId',
      'kind',
      'id',
      ...(Object.hasOwn(value, 'name') ? ['name'] : []),
    ]) &&
    (value.kind === 'credential' ||
      value.kind === 'node' ||
      value.kind === 'tunnel' ||
      value.kind === 'slot-value') &&
    (!Object.hasOwn(value, 'name') ||
      (typeof value.name === 'string' &&
        value.name.length <= 4096 &&
        new TextEncoder().encode(value.name).length <= 4096 &&
        !/\p{Cc}/u.test(value.name)))
  );
}

export function parseAccountSuspensionReply(
  value: unknown,
  request: AccountSuspensionRequest,
): AccountSuspensionReply | undefined {
  if (!vaultRecord(value)) return;
  const { status, page } = value;
  if (
    status === 'busy' ||
    status === 'stale' ||
    status === 'unavailable' ||
    status === 'not-recorded' ||
    status === 'unsupported'
  )
    return vaultFields(value, ['status']) ? { status } : undefined;
  if (
    status !== 'ready' ||
    !vaultFields(value, ['status', 'page']) ||
    !vaultRecord(page) ||
    !vaultFields(page, [
      'accountId',
      'kind',
      'revision',
      'entries',
      ...(Object.hasOwn(page, 'after') ? ['after'] : []),
    ]) ||
    page.accountId !== request.accountId ||
    page.kind !== request.kind ||
    !ordinal(page.revision) ||
    (request.revision !== undefined && page.revision !== request.revision) ||
    !Array.isArray(page.entries) ||
    page.entries.length > 25
  )
    return;
  let before = BigInt(request.after ?? '0');
  const entries: Entry[] = [];
  for (const entry of page.entries) {
    if (!validEntry(entry, request.kind) || BigInt(entry.position) !== before + 1n) return;
    entries.push(entry);
    before += 1n;
  }
  const after = page.after;
  if (
    Object.hasOwn(page, 'after') &&
    (!ordinal(after) || entries.length !== 25 || after !== entries.at(-1)?.position)
  )
    return;
  return {
    status,
    page: {
      accountId: request.accountId,
      kind: request.kind,
      revision: page.revision,
      entries,
      ...(typeof after === 'string' ? { after } : {}),
    },
  };
}
