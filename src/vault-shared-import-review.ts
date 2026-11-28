import {
  importDecisionKey,
  importItemKey,
  type WorkspaceImportDecision,
  type WorkspaceImportPreview,
  type WorkspaceImportReviewRequest,
} from '../electron/vault-shared-import.ts';

export function prepareImportReview(preview: WorkspaceImportPreview) {
  return {
    preview,
    dirty: false,
    shared: new Set(
      preview.items.filter((item) => item.destination === 'shared').map(importItemKey),
    ),
    decisions: new Map(
      preview.resolverChanges.map((change) => [importDecisionKey(change), change.choice]),
    ),
  };
}

export type ImportReview = ReturnType<typeof prepareImportReview>;

export function importReviewRequest(
  workspaceId: string,
  review: ImportReview,
): WorkspaceImportReviewRequest {
  return {
    action: 'import-review',
    workspaceId,
    reviewId: review.preview.reviewId,
    shared: review.preview.items
      .filter((item) => review.shared.has(importItemKey(item)))
      .map(({ id, kind }) => ({ id, kind })),
    decisions: review.preview.resolverChanges.map((change) => ({
      nodeId: change.nodeId,
      protocolPath: change.protocolPath,
      choice: review.decisions.get(importDecisionKey(change)) ?? change.choice,
    })),
  };
}

const pageSize = 24;
const kindLabel = { node: 'Catalog item', credential: 'Credential', tunnel: 'Tunnel' };
const pathLabel: Record<string, string> = {
  ssh: 'SSH',
  sftp: 'SFTP',
  rdp: 'RDP',
  'rdp-gateway': 'RDP gateway',
  vnc: 'VNC',
  reveal: 'Reveal',
};

function pageButton(label: string): HTMLButtonElement {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'startup-button startup-button-secondary';
  button.textContent = label;
  return button;
}

export function renderImportReview(
  container: HTMLElement,
  review: ImportReview,
  changed: () => void,
) {
  const { items, conflicts, resolverChanges } = review.preview;
  const section = document.createElement('section');
  const title = document.createElement('h3');
  title.textContent = 'Import the local workspace';
  const help = document.createElement('p');
  help.textContent =
    items.length > 0
      ? 'Items start in your personal destination with organisation recovery. Select Shared to make an item available to your workspace.'
      : 'The local workspace has no items to import.';
  section.append(title, help);
  container.append(section);
  const names = new Map(items.map((item) => [importItemKey(item), item.name]));
  if (conflicts.length) {
    const status = document.createElement('p');
    status.setAttribute('role', 'status');
    status.textContent = `${conflicts.length} shared dependencies need a destination change before import.`;
    section.append(status);
  }
  const total = items.length + resolverChanges.length + conflicts.length;
  if (!total) return;
  const list = document.createElement('div');
  const previous = pageButton('Previous page');
  const next = pageButton('Next page');
  const pageLabel = document.createElement('span');
  pageLabel.setAttribute('aria-live', 'polite');
  const pager = document.createElement('div');
  pager.className = 'shared-setup-actions';
  pager.append(previous, pageLabel, next);
  section.append(list, pager);
  let page = 0;
  const pages = Math.ceil(total / pageSize);
  function render() {
    list.replaceChildren();
    for (let i = page * pageSize; i < Math.min(total, (page + 1) * pageSize); i++) {
      if (i < items.length) {
        const item = items[i],
          key = importItemKey(item);
        const select = document.createElement('select');
        select.add(new Option('Personal', 'personal'));
        select.add(new Option('Shared', 'shared'));
        select.value = review.shared.has(key) ? 'shared' : 'personal';
        select.onchange = () => {
          if (select.value === 'shared') review.shared.add(key);
          else review.shared.delete(key);
          review.dirty = true;
          changed();
        };
        const label = document.createElement('label');
        label.append(`${kindLabel[item.kind]} · ${item.name}`, select);
        list.append(label);
      } else if (i < items.length + resolverChanges.length) {
        const delta = resolverChanges[i - items.length],
          key = importDecisionKey(delta);
        const select = document.createElement('select');
        select.add(new Option('Keep the current account', 'keep'));
        select.add(new Option('Use the new resolution', 'new'));
        select.value = review.decisions.get(key) ?? delta.choice;
        select.onchange = () => {
          const value: WorkspaceImportDecision['choice'] = select.value === 'new' ? 'new' : 'keep';
          review.decisions.set(key, value);
          review.dirty = true;
          changed();
        };
        const flags = [
          delta.credentialChanged && 'credential',
          delta.usernameChanged && 'username',
          delta.domainChanged && 'domain',
          delta.sourceChanged && 'source',
        ].filter(Boolean);
        const label = document.createElement('label');
        label.append(
          `${names.get(`node/${delta.nodeId}`)} · ${pathLabel[delta.protocolPath]} · Changed ${flags.join(', ')}`,
          select,
        );
        list.append(label);
      } else {
        const conflict = conflicts[i - items.length - resolverChanges.length];
        const row = document.createElement('p');
        row.textContent = `${names.get(importItemKey(conflict.item))} requires ${names.get(importItemKey(conflict.dependency))}, which is personal.`;
        list.append(row);
      }
    }
    previous.disabled = page === 0;
    next.disabled = page + 1 === pages;
    pageLabel.textContent = `Page ${page + 1} of ${pages}`;
  }
  previous.onclick = () => {
    if (page > 0) {
      page--;
      render();
    }
  };
  next.onclick = () => {
    if (page + 1 < pages) {
      page++;
      render();
    }
  };
  render();
}
