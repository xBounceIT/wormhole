import {
  vaultFields,
  vaultID,
  vaultMetadataText,
  vaultRecord,
  vaultRevision,
} from './vault-contract.ts';

export type SharedCatalogCursor = { after: string; epoch: string; changeSeq: string };
export type SharedCatalogRequest = SharedCatalogCursor & { limit: number };
export type SharedChangesRequest = { epoch: string; changeSeq: string };
export type SharedChanges = SharedChangesRequest & { reset: boolean; nodes: string[] };

export function parseSharedChangesRequest(value: unknown): SharedChangesRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['epoch', 'changeSeq']) ||
    !sequence(value.epoch) ||
    !sequence(value.changeSeq) ||
    (value.epoch === '0' && value.changeSeq !== '0')
  )
    return undefined;
  return { epoch: value.epoch, changeSeq: value.changeSeq };
}

export function parseSharedChanges(
  value: unknown,
  request: SharedChangesRequest,
): SharedChanges | undefined {
  if (
    !parseSharedChangesRequest(request) ||
    !vaultRecord(value) ||
    !vaultFields(value, ['epoch', 'changeSeq', 'reset', 'nodes']) ||
    !vaultRevision(value.epoch) ||
    !sequence(value.changeSeq) ||
    typeof value.reset !== 'boolean' ||
    !Array.isArray(value.nodes) ||
    value.nodes.length > 32 ||
    BigInt(value.epoch) < BigInt(request.epoch) ||
    (value.epoch === request.epoch && BigInt(value.changeSeq) < BigInt(request.changeSeq)) ||
    (value.epoch !== request.epoch && !value.reset) ||
    (value.nodes.length !== 0 &&
      (value.reset || (value.epoch === request.epoch && value.changeSeq === request.changeSeq)))
  )
    return undefined;
  let previous = '';
  for (const id of value.nodes) {
    if (!vaultID(id) || id <= previous) return undefined;
    previous = id;
  }
  return {
    epoch: value.epoch,
    changeSeq: value.changeSeq,
    reset: value.reset,
    nodes: [...value.nodes],
  };
}
export type SharedCatalogNode = {
  id: string;
  parentId: string | null;
  name: string;
  kind: number;
  sortOrder: string;
  protocol: number | null;
  host: string | null;
  port: number | null;
  username: string | null;
  canUse: boolean;
  notesRevision?: string;
  editRevision?: string;
  grantRevision?: string;
  grantBoundary?: string;
};
export type SharedCatalogPage = {
  epoch: string;
  changeSeq: string;
  nodes: SharedCatalogNode[];
  next: SharedCatalogCursor | null;
};

function sequence(value: unknown): value is string {
  return vaultRevision(value, true) && !value.startsWith('-');
}
export function parseSharedCatalogRequest(value: unknown): SharedCatalogRequest | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['after', 'epoch', 'changeSeq', 'limit']) ||
    typeof value.limit !== 'number' ||
    !Number.isInteger(value.limit) ||
    value.limit < 1 ||
    value.limit > 32 ||
    !sequence(value.epoch) ||
    !sequence(value.changeSeq) ||
    (value.after === ''
      ? value.epoch !== '0' || value.changeSeq !== '0'
      : !vaultID(value.after) || value.epoch === '0')
  )
    return undefined;
  return {
    after: value.after as string,
    epoch: value.epoch,
    changeSeq: value.changeSeq,
    limit: value.limit,
  };
}
export function parseSharedCatalogPage(
  value: unknown,
  request: SharedCatalogRequest,
): SharedCatalogPage | undefined {
  if (
    !parseSharedCatalogRequest(request) ||
    !vaultRecord(value) ||
    !vaultFields(value, ['epoch', 'changeSeq', 'nodes', 'next']) ||
    !vaultRevision(value.epoch) ||
    !sequence(value.changeSeq) ||
    !Array.isArray(value.nodes) ||
    value.nodes.length > request.limit ||
    (request.after !== '' &&
      (value.epoch !== request.epoch || value.changeSeq !== request.changeSeq))
  )
    return undefined;
  const nodes: SharedCatalogNode[] = [];
  let previous = request.after;
  for (const n of value.nodes) {
    if (
      !vaultRecord(n) ||
      !vaultFields(n, [
        'id',
        'parentId',
        'name',
        'kind',
        'sortOrder',
        'protocol',
        'host',
        'port',
        'username',
        'canUse',
        ...('notesRevision' in n ? ['notesRevision'] : []),
        ...('editRevision' in n ? ['editRevision'] : []),
        ...('grantRevision' in n ? ['grantRevision'] : []),
        ...('grantBoundary' in n ? ['grantBoundary'] : []),
      ]) ||
      !vaultID(n.id) ||
      ('editRevision' in n && !vaultRevision(n.editRevision)) ||
      typeof n.canUse !== 'boolean' ||
      ('notesRevision' in n && !vaultRevision(n.notesRevision)) ||
      ('grantRevision' in n && !vaultRevision(n.grantRevision)) ||
      ('grantBoundary' in n && (!vaultID(n.grantBoundary) || !vaultRevision(n.grantRevision))) ||
      (n.kind === 0 && n.canUse) ||
      n.id <= previous ||
      (n.parentId !== null && (!vaultID(n.parentId) || n.parentId === n.id)) ||
      !vaultMetadataText(n.name, 1024, true) ||
      [...n.name].length > 256 ||
      /\p{Cc}/u.test(n.name) ||
      (n.kind !== 0 && n.kind !== 1) ||
      !vaultRevision(n.sortOrder, true) ||
      (n.protocol !== null && ![0, 1, 3, 4, 5, 6, 7].includes(n.protocol as number)) ||
      (n.host !== null && (!vaultMetadataText(n.host, 16384) || /[\r\n]/.test(n.host))) ||
      (n.port !== null &&
        (typeof n.port !== 'number' ||
          !Number.isInteger(n.port) ||
          n.port < 0 ||
          n.port > 65535)) ||
      (n.username !== null && (!vaultMetadataText(n.username, 2048) || /[\r\n]/.test(n.username)))
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
      canUse: n.canUse,
      ...(typeof n.grantRevision === 'string' ? { grantRevision: n.grantRevision } : {}),
      ...(typeof n.grantBoundary === 'string' ? { grantBoundary: n.grantBoundary } : {}),
      ...(typeof n.notesRevision === 'string' ? { notesRevision: n.notesRevision } : {}),
      ...(typeof n.editRevision === 'string' ? { editRevision: n.editRevision } : {}),
    });
    previous = n.id;
  }
  let next: SharedCatalogCursor | null = null;
  if (value.next !== null) {
    if (
      !vaultRecord(value.next) ||
      !vaultFields(value.next, ['after', 'epoch', 'changeSeq']) ||
      nodes.length !== request.limit ||
      value.next.after !== previous ||
      value.next.epoch !== value.epoch ||
      value.next.changeSeq !== value.changeSeq
    )
      return undefined;
    next = { after: previous, epoch: value.epoch, changeSeq: value.changeSeq };
  }
  return { epoch: value.epoch, changeSeq: value.changeSeq, nodes, next };
}
