import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';

export type WorkspaceImportItemID = {
  kind: 'node' | 'credential' | 'tunnel';
  id: string;
};
export type WorkspaceImportItem = WorkspaceImportItemID & {
  name: string;
  destination: 'personal' | 'shared';
};
export type WorkspaceImportDecision = {
  nodeId: string;
  protocolPath: string;
  choice: 'keep' | 'new';
};
export type WorkspaceImportChange = WorkspaceImportDecision & {
  credentialChanged: boolean;
  usernameChanged: boolean;
  domainChanged: boolean;
  sourceChanged: boolean;
};
export type WorkspaceImportPreview = {
  reviewId: string;
  confirmation?: string;
  items: WorkspaceImportItem[];
  conflicts: { item: WorkspaceImportItemID; dependency: WorkspaceImportItemID }[];
  resolverChanges: WorkspaceImportChange[];
};
export type WorkspaceImportReviewRequest = {
  action: 'import-review';
  workspaceId: string;
  reviewId: string;
  shared: WorkspaceImportItemID[];
  decisions: WorkspaceImportDecision[];
};

const itemFields = ['kind', 'id'];
const decisionFields = ['nodeId', 'protocolPath', 'choice'];
const differenceFields = [
  'credentialChanged',
  'usernameChanged',
  'domainChanged',
  'sourceChanged',
] as const;
const accountPaths = new Set(['ssh', 'sftp', 'rdp', 'rdp-gateway', 'vnc', 'reveal']);
export const importItemKey = (item: WorkspaceImportItemID) => `${item.kind}/${item.id}`;
export const importDecisionKey = (decision: WorkspaceImportDecision) =>
  `${decision.nodeId}/${decision.protocolPath}`;

function parseItem(value: Record<string, unknown>): WorkspaceImportItemID | undefined {
  const { kind, id } = value;
  if ((kind === 'node' || kind === 'credential' || kind === 'tunnel') && vaultID(id))
    return { kind, id };
}
function parseDecision(value: Record<string, unknown>): WorkspaceImportDecision | undefined {
  const { nodeId, protocolPath, choice } = value;
  if (
    vaultID(nodeId) &&
    typeof protocolPath === 'string' &&
    accountPaths.has(protocolPath) &&
    (choice === 'keep' || choice === 'new')
  )
    return { nodeId, protocolPath, choice };
}

export function parseImportReviewRequest(
  value: Record<string, unknown>,
): WorkspaceImportReviewRequest | undefined {
  const { workspaceId, reviewId, shared, decisions } = value;
  if (
    !vaultFields(value, ['action', 'workspaceId', 'reviewId', 'shared', 'decisions']) ||
    value.action !== 'import-review' ||
    !vaultID(workspaceId) ||
    !vaultID(reviewId) ||
    !Array.isArray(shared) ||
    shared.length > 50_000 ||
    !Array.isArray(decisions) ||
    decisions.length > 100_000
  )
    return undefined;
  const selected: WorkspaceImportItemID[] = [];
  const choices: WorkspaceImportDecision[] = [];
  const seen = new Set<string>();
  for (const entry of shared) {
    const item =
      vaultRecord(entry) && vaultFields(entry, itemFields) ? parseItem(entry) : undefined;
    if (!item || seen.has(importItemKey(item))) return undefined;
    seen.add(importItemKey(item));
    selected.push(item);
  }
  seen.clear();
  for (const entry of decisions) {
    const decision =
      vaultRecord(entry) && vaultFields(entry, decisionFields) ? parseDecision(entry) : undefined;
    if (!decision || seen.has(importDecisionKey(decision))) return undefined;
    seen.add(importDecisionKey(decision));
    choices.push(decision);
  }
  return { action: 'import-review', workspaceId, reviewId, shared: selected, decisions: choices };
}

export function parseWorkspaceImportPreview(value: unknown): WorkspaceImportPreview | undefined {
  if (!vaultRecord(value)) return undefined;
  const { reviewId, confirmation, resolverFingerprint, items, conflicts, resolverChanges } = value;
  if (
    !vaultFields(value, [
      'reviewId',
      'resolverFingerprint',
      'items',
      'conflicts',
      'resolverChanges',
      ...(Object.hasOwn(value, 'confirmation') ? ['confirmation'] : []),
    ]) ||
    !vaultID(reviewId) ||
    typeof resolverFingerprint !== 'string' ||
    !/^[a-f0-9]{64}$/.test(resolverFingerprint) ||
    !Array.isArray(items) ||
    items.length > 50_000 ||
    !Array.isArray(conflicts) ||
    conflicts.length > 100_000 ||
    !Array.isArray(resolverChanges) ||
    resolverChanges.length > 100_000 ||
    (Object.hasOwn(value, 'confirmation') &&
      (!vaultID(confirmation) || items.length === 0 || conflicts.length !== 0))
  )
    return undefined;
  const result: WorkspaceImportPreview = {
    reviewId,
    ...(typeof confirmation === 'string' ? { confirmation } : {}),
    items: [],
    conflicts: [],
    resolverChanges: [],
  };
  const known = new Map<string, WorkspaceImportItem>();
  for (const entry of items) {
    if (!vaultRecord(entry) || !vaultFields(entry, [...itemFields, 'name', 'destination']))
      return undefined;
    const id = parseItem(entry);
    const { name, destination } = entry;
    if (
      !id ||
      known.has(importItemKey(id)) ||
      !vaultMetadataText(name, 4096, true) ||
      (destination !== 'personal' && destination !== 'shared')
    )
      return undefined;
    const item: WorkspaceImportItem = { ...id, name, destination };
    known.set(importItemKey(id), item);
    result.items.push(item);
  }
  for (const entry of conflicts) {
    if (!vaultRecord(entry) || !vaultFields(entry, ['item', 'dependency'])) return undefined;
    const ids = [entry.item, entry.dependency].map((raw) =>
      vaultRecord(raw) && vaultFields(raw, itemFields) ? parseItem(raw) : undefined,
    );
    const [item, dependency] = ids;
    if (
      !item ||
      !dependency ||
      known.get(importItemKey(item))?.destination !== 'shared' ||
      known.get(importItemKey(dependency))?.destination !== 'personal'
    )
      return undefined;
    result.conflicts.push({ item, dependency });
  }
  const seen = new Set<string>();
  for (const entry of resolverChanges) {
    if (
      !vaultRecord(entry) ||
      !vaultFields(entry, [
        ...decisionFields,
        ...differenceFields,
        'oldCredentialId',
        'newCredentialId',
      ]) ||
      ![entry.oldCredentialId, entry.newCredentialId].every((id) => id === '' || vaultID(id)) ||
      !differenceFields.every((flag) => typeof entry[flag] === 'boolean') ||
      !differenceFields.some((flag) => entry[flag] === true)
    )
      return undefined;
    const decision = parseDecision(entry);
    if (!decision || !known.has(`node/${decision.nodeId}`) || seen.has(importDecisionKey(decision)))
      return undefined;
    seen.add(importDecisionKey(decision));
    result.resolverChanges.push({
      ...decision,
      credentialChanged: entry.credentialChanged === true,
      usernameChanged: entry.usernameChanged === true,
      domainChanged: entry.domainChanged === true,
      sourceChanged: entry.sourceChanged === true,
    });
  }
  return result;
}
