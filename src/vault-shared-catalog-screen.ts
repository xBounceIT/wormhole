import type {
  SharedCatalogNode,
  SharedCatalogCursor,
  SharedCatalogRequest,
  SharedChangesRequest,
} from '../electron/vault-shared-catalog.ts';
import { sharedConnectionMode, type SharedConnectionMode } from './shared-connection-mode.ts';
import { openSharedNodeEditor } from './vault-shared-node-editor.ts';
import { sharedEditFields } from '../electron/vault-shared-node-edit.ts';

export type SharedWorkspacePort = {
  connect(node: SharedCatalogNode, mode?: SharedConnectionMode): void;
  observeNodes(nodes: readonly SharedCatalogNode[]): void;
  dispose(): void;
};

// All authorization, signature checks and persistence stay in the native owner.
// Keep only the current page in the DOM; page cursors carry no secret capability.
export function mountSharedCatalogScreen(
  container: HTMLElement,
  api: Pick<
    NonNullable<Window['wormhole']>,
    'loadSharedCatalogPage' | 'loadSharedChanges' | 'onSharedCatalogChanged'
  > &
    Partial<Pick<NonNullable<Window['wormhole']>, 'showVaultNotes' | 'editSharedNode'>>,
  failed: () => void,
  sessions?: SharedWorkspacePort,
  openCredential?: (nodeId: string) => Promise<void>,
) {
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  const list = document.createElement('ul');
  list.className = 'shared-catalog-list';
  list.setAttribute('aria-label', 'Shared connections and folders');
  const refresh = document.createElement('button');
  refresh.type = 'button';
  refresh.className = 'startup-button startup-button-secondary';
  refresh.textContent = 'Refresh catalog';
  const header = document.createElement('header');
  header.className = 'shared-catalog-heading';
  const title = document.createElement('h2');
  title.textContent = 'Connections';
  header.append(title, refresh);
  const next = document.createElement('button');
  next.type = 'button';
  next.className = 'startup-button startup-button-secondary';
  next.textContent = 'Next page';
  next.hidden = true;
  let disposed = false,
    busy = false,
    cursor: SharedCatalogCursor | null = null;
  let snapshot: SharedChangesRequest | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let unsubscribe: (() => void) | undefined;
  let hintPending = false;
  let closeEditor: (() => void) | undefined;
  const schedule = () => {
    clearTimeout(timer);
    if (!disposed)
      timer = setTimeout(
        () => {
          void poll();
        },
        hintPending ? 0 : 30_000,
      );
  };
  const load = async (after: SharedCatalogCursor | null) => {
    if (disposed || busy) return;
    clearTimeout(timer);
    busy = true;
    refresh.disabled = next.disabled = true;
    list.replaceChildren();
    status.textContent = 'Loading shared catalog…';
    const request: SharedCatalogRequest = {
      ...(after ?? { after: '', epoch: '0', changeSeq: '0' }),
      limit: 32,
    };
    try {
      const page = await api.loadSharedCatalogPage(request);
      if (disposed) return;
      sessions?.observeNodes(page.nodes);
      for (const node of page.nodes) {
        const item = document.createElement('li');
        const name = document.createElement('strong');
        name.textContent = node.name;
        const detail = document.createElement('span');
        // Do not render markup or turn server-controlled addresses into links.
        detail.textContent =
          node.kind === 0
            ? 'Folder'
            : [node.host, node.port === null ? null : String(node.port), node.username]
                .filter((value) => value !== null && value !== '')
                .join(' · ');
        const row = document.createElement('div');
        row.className = 'shared-catalog-label';
        row.append(name);
        const protocolNames: Readonly<Record<number, string | undefined>> =
          sharedEditFields.protocol.options;
        const protocol =
          node.protocol === null || node.kind !== 1 ? undefined : protocolNames[node.protocol];
        if (protocol) {
          const type = document.createElement('small');
          type.textContent = protocol;
          row.append(type);
        }
        item.append(row, detail);
        const actions = document.createElement('div');
        actions.className = 'shared-catalog-actions';
        if (sessions && node.kind === 1) {
          const mode = sharedConnectionMode(node);
          const options: SharedConnectionMode[] =
            node.canUse && (node.protocol === null || mode === 'terminal')
              ? ['terminal', 'sftp']
              : mode
                ? [mode]
                : [];
          if (options.length) {
            for (const mode of options) {
              const connect = document.createElement('button');
              connect.type = 'button';
              connect.className = 'startup-button startup-button-secondary';
              connect.textContent =
                mode === 'web' ? 'Open browser' : mode === 'sftp' ? 'Files' : 'Connect';
              connect.setAttribute('aria-label', `${connect.textContent} · ${node.name}`);
              connect.onclick = () => {
                if (!disposed && item.isConnected)
                  sessions.connect(
                    node,
                    node.protocol === null && mode === 'terminal' ? undefined : mode,
                  );
              };
              actions.append(connect);
            }
          } else {
            const access = document.createElement('span');
            access.className = 'shared-catalog-access';
            access.textContent = node.canUse ? 'This protocol is not available yet.' : 'View only';
            actions.append(access);
          }
        }
        if (
          openCredential &&
          node.kind === 1 &&
          node.canUse &&
          (node.protocol === null || [0, 1, 6, 7].includes(node.protocol))
        ) {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'startup-button startup-button-secondary';
          button.textContent = 'My credential…';
          button.setAttribute('aria-label', 'My credential for ' + node.name);
          button.onclick = async () => {
            if (disposed || button.disabled || !item.isConnected) return;
            button.disabled = true;
            try {
              await openCredential(node.id);
            } catch {
              if (!disposed)
                status.textContent = 'Could not open the credential settings for this connection.';
            } finally {
              if (!disposed) button.disabled = false;
            }
          };
          actions.append(button);
        }
        const edit = api.editSharedNode;
        if (edit && node.editRevision) {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'startup-button startup-button-secondary';
          button.textContent = 'Edit';
          button.setAttribute('aria-label', 'Edit ' + node.name);
          button.onclick = () => {
            if (disposed || closeEditor || !item.isConnected) return;
            closeEditor = openSharedNodeEditor(
              container,
              node,
              edit,
              (saved) => {
                closeEditor = undefined;
                if (saved && !disposed) {
                  hintPending = true;
                  if (!busy) void load(null);
                }
              },
              api.loadSharedCatalogPage,
            );
          };
          actions.append(button);
        }
        const showNotes = api.showVaultNotes;
        if (showNotes && node.notesRevision) {
          const selection = { nodeId: node.id, rowVersion: node.notesRevision };
          const notes = document.createElement('button');
          notes.type = 'button';
          notes.className = 'startup-button startup-button-secondary';
          notes.textContent = 'Notes';
          notes.setAttribute('aria-label', `View stored notes · ${node.name}`);
          notes.onclick = () => {
            if (disposed || !item.isConnected || notes.disabled) return;
            notes.disabled = true;
            void showNotes(selection)
              .catch(() => {
                if (!disposed && item.isConnected)
                  status.textContent = 'Stored notes are unavailable.';
              })
              .finally(() => {
                notes.disabled = false;
              });
          };
          actions.append(notes);
        }
        if (actions.childElementCount > 0) item.append(actions);
        list.append(item);
      }
      cursor = page.next;
      snapshot = { epoch: page.epoch, changeSeq: page.changeSeq };
      next.hidden = cursor === null;
      status.textContent = page.nodes.length
        ? `${page.nodes.length} items on this page.`
        : 'No visible items.';
    } catch {
      if (!disposed) {
        dispose();
        failed();
      }
    } finally {
      busy = false;
      refresh.disabled = next.disabled = disposed;
      schedule();
    }
  };
  const poll = async () => {
    if (disposed || busy) return;
    hintPending = false;
    busy = true;
    refresh.disabled = next.disabled = true;
    try {
      const changes = await api.loadSharedChanges(snapshot ?? { epoch: '0', changeSeq: '0' });
      if (disposed) return;
      if (
        !snapshot ||
        changes.reset ||
        changes.nodes.length !== 0 ||
        changes.epoch !== snapshot.epoch ||
        changes.changeSeq !== snapshot.changeSeq
      ) {
        busy = false;
        await load(null);
      }
    } catch {
      if (!disposed) {
        dispose();
        failed();
      }
    } finally {
      busy = false;
      refresh.disabled = next.disabled = disposed;
      schedule();
    }
  };
  refresh.onclick = () => {
    void load(null);
  };
  next.onclick = () => {
    if (cursor) void load(cursor);
  };
  container.replaceChildren(header, status, list, next);
  function dispose() {
    disposed = true;
    closeEditor?.();
    cursor = null;
    snapshot = null;
    clearTimeout(timer);
    unsubscribe?.();
    unsubscribe = undefined;
    hintPending = false;
    list.replaceChildren();
    status.textContent = '';
    refresh.disabled = next.disabled = true;
    container.replaceChildren();
  }
  unsubscribe = api.onSharedCatalogChanged(() => {
    if (disposed) return;
    hintPending = true;
    if (!busy) schedule();
  });
  void poll();
  return dispose;
}
