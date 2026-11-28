import {
  isSftpTransferTerminal,
  shouldApplySftpReady,
  shouldApplySftpError,
  removeSftpTransferRow,
  settleSftpTransferRows,
  nextSftpOperationRefreshRequests,
  nextSftpTransferRefreshRequests,
  type SftpBrowserState,
} from './sftp-state.ts';

type Pane = 'local' | 'remote';
export type SharedFileAPI = Pick<
  NonNullable<Window['wormhole']>,
  | 'openSftpBrowser'
  | 'listSftpDirectory'
  | 'listLocalSftpDirectory'
  | 'operateSftp'
  | 'startSftpTransfer'
  | 'decideSftpConflict'
  | 'cancelSftpTransfer'
>;
type Transfer = {
  pane: Pane;
  path: string;
  direction: 'local-to-remote' | 'remote-to-local' | 'local-to-local';
};

// Presentation and request correlation only. Go owns paths, I/O, transfers and
// authorization. No credentials or connection plans are retained here.
export class SharedSftpSession {
  state: SftpBrowserState = { status: 'opening', path: '', entries: [], truncated: false };
  private operations = new Map<string, { pane: Pane; path: string }>();
  private transfers = new Map<string, Transfer>();
  private disposed = false;
  private id: string;
  private api: SharedFileAPI;
  private changed: () => void;
  constructor(id: string, api: SharedFileAPI, changed: () => void) {
    this.id = id;
    this.api = api;
    this.changed = changed;
  }

  private call<T>(run: () => Promise<T>): Promise<T> {
    return Promise.resolve().then(() => {
      if (this.disposed) throw Error('Session disposed.');
      return run();
    });
  }

  start(): void {
    if (this.disposed) return;
    const requestId = crypto.randomUUID();
    this.state = { ...this.state, status: 'opening', requestId, error: undefined };
    this.changed();
    void this.call(() => this.api.openSftpBrowser(this.id, requestId)).catch(() => {
      if (!this.disposed && this.state.requestId === requestId) {
        this.state = { ...this.state, status: 'failed', error: 'Could not open file transfer.' };
        this.changed();
      }
    });
    this.navigate('local', '');
  }

  navigate(pane: Pane, path: string): void {
    if (this.disposed) return;
    const requestId = crypto.randomUUID();
    if (pane === 'remote')
      this.state = {
        ...this.state,
        status: 'opening',
        previousPath: this.state.path,
        requestId,
        error: undefined,
      };
    else
      this.state = {
        ...this.state,
        local: {
          ...(this.state.local ?? { path: '', entries: [], truncated: false }),
          status: 'opening',
          previousPath: this.state.local?.path,
          requestId,
          error: undefined,
        },
      };
    this.changed();
    const request = this.call(() =>
      pane === 'remote'
        ? this.api.listSftpDirectory(this.id, path, requestId)
        : this.api.listLocalSftpDirectory(this.id, path, requestId),
    );
    void request.catch(() =>
      this.receive(
        pane === 'remote'
          ? {
              type: 'sftp.error',
              sessionId: this.id,
              requestId,
              error: 'Could not read this folder.',
            }
          : {
              type: 'sftp.local.error',
              sessionId: this.id,
              requestId,
              pane: 'local',
              error: 'Could not read this folder.',
            },
      ),
    );
  }

  operate(
    pane: Pane,
    operation: 'mkdir' | 'file' | 'delete' | 'rename' | 'open',
    path: string,
    destinationPath?: string,
  ): void {
    if (this.disposed || this.operations.size >= 64) return;
    const requestId = crypto.randomUUID();
    this.operations.set(requestId, { pane, path: this.path(pane) });
    void this.call(() =>
      this.api.operateSftp(this.id, {
        requestId,
        pane,
        operation,
        path,
        ...(destinationPath !== undefined ? { destinationPath } : {}),
      }),
    ).catch(() => {
      this.receive({
        type: 'sftp.operation',
        sessionId: this.id,
        requestId,
        pane,
        operation,
        path,
        error: 'File operation failed.',
      });
    });
  }

  transfer(
    direction: Transfer['direction'],
    destinationPath: string,
    items: Parameters<SharedFileAPI['startSftpTransfer']>[1]['items'],
  ): void {
    if (this.disposed || this.transfers.size >= 32 || items.length === 0) return;
    const transferId = crypto.randomUUID(),
      pane = direction === 'local-to-remote' ? 'remote' : 'local';
    this.transfers.set(transferId, { pane, path: destinationPath, direction });
    this.state = { ...this.state, transferError: undefined };
    this.changed();
    const snapshot = items.map(({ sourcePath, name, isDirectory, size }) => ({
      sourcePath,
      name,
      isDirectory,
      size,
    }));
    void this.call(() =>
      this.api.startSftpTransfer(this.id, {
        transferId,
        direction,
        destinationPath,
        items: snapshot,
      }),
    ).catch(() => {
      this.receive({
        type: 'sftp.transfer',
        sessionId: this.id,
        transferId,
        transferState: 'batch-failed',
        error: 'File transfer failed.',
      });
    });
  }

  decide(
    transferId: string,
    itemId: string,
    decision: 'overwrite' | 'skip',
    applyToAll: boolean,
  ): void {
    const conflict = this.state.conflict;
    if (
      this.disposed ||
      !conflict ||
      conflict.transferId !== transferId ||
      conflict.itemId !== itemId ||
      !this.transfers.has(transferId)
    )
      return;
    void this.call(() =>
      this.api.decideSftpConflict(this.id, transferId, itemId, decision, applyToAll),
    )
      .then(() => {
        if (!this.disposed && this.state.conflict === conflict) {
          this.state = { ...this.state, conflict: undefined };
          this.changed();
        }
      })
      .catch(() => {
        if (!this.disposed) {
          this.state = { ...this.state, transferError: 'Could not apply the conflict choice.' };
          this.changed();
        }
      });
  }

  cancel(transferId: string, itemId?: string): void {
    if (this.disposed || !this.transfers.has(transferId)) return;
    void this.call(() => this.api.cancelSftpTransfer(this.id, transferId, itemId)).catch(() => {
      if (!this.disposed) {
        this.state = { ...this.state, transferError: 'Could not cancel the transfer.' };
        this.changed();
      }
    });
  }
  clearError(): void {
    if (!this.disposed) {
      this.state = { ...this.state, transferError: undefined };
      this.changed();
    }
  }
  removeTransfer(transferId: string, itemId: string): void {
    if (this.disposed) return;
    this.state = {
      ...this.state,
      transfers: removeSftpTransferRow(this.state.transfers ?? [], transferId, itemId),
    };
    this.changed();
  }
  path(pane: Pane): string {
    return pane === 'remote' ? this.state.path : (this.state.local?.path ?? '');
  }

  receive(event: WormholeSshEvent): void {
    if (this.disposed || event.sessionId !== this.id) return;
    const old = this.state;
    switch (event.type) {
      case 'sftp.opening':
        if (old.requestId === event.requestId) this.state = { ...old, status: 'opening' };
        break;
      case 'sftp.ready':
        if (shouldApplySftpReady(old, event.path, event.requestId))
          this.state = {
            ...old,
            status: 'ready',
            previousPath: undefined,
            path: event.path,
            entries: event.entries,
            truncated: event.truncated,
            error: undefined,
          };
        break;
      case 'sftp.error':
        if (shouldApplySftpError(old, event.path, event.requestId))
          this.state = {
            ...old,
            status: 'failed',
            path: old.previousPath ?? old.path,
            previousPath: undefined,
            error: 'Could not read this folder.',
          };
        break;
      case 'sftp.local.ready':
        if (old.local?.requestId === event.requestId)
          this.state = {
            ...old,
            local: {
              status: 'ready',
              requestId: event.requestId,
              path: event.path,
              entries: event.entries,
              truncated: event.truncated,
              quickPaths: event.quickPaths ?? old.local.quickPaths,
            },
          };
        break;
      case 'sftp.local.error':
        if (old.local?.requestId === event.requestId)
          this.state = {
            ...old,
            local: {
              ...old.local,
              status: 'failed',
              path: old.local.previousPath ?? old.local.path,
              previousPath: undefined,
              error: 'Could not read this folder.',
            },
          };
        break;
      case 'sftp.operation': {
        const operation = this.operations.get(event.requestId);
        if (!operation || operation.pane !== event.pane) return;
        this.operations.delete(event.requestId);
        if (event.error) this.state = { ...old, transferError: 'File operation failed.' };
        else {
          this.state = {
            ...old,
            refreshRequests: nextSftpOperationRefreshRequests(old.refreshRequests, {
              ...operation,
              id: event.requestId,
            }),
          };
          if (this.path(event.pane) === operation.path) this.navigate(event.pane, operation.path);
        }
        break;
      }
      case 'sftp.conflict':
        if (this.transfers.has(event.transferId)) this.state = { ...old, conflict: { ...event } };
        break;
      case 'sftp.transfer': {
        const transfer = this.transfers.get(event.transferId);
        if (!transfer) return;
        if (event.transferState.startsWith('batch-')) {
          this.transfers.delete(event.transferId);
          this.state = {
            ...old,
            conflict: old.conflict?.transferId === event.transferId ? undefined : old.conflict,
            refreshRequests:
              event.transferState === 'batch-completed'
                ? nextSftpTransferRefreshRequests(
                    old.refreshRequests,
                    event.transferId,
                    transfer,
                    this.path(transfer.pane),
                  )
                : old.refreshRequests,
            transfers:
              event.transferState === 'batch-completed'
                ? old.transfers
                : settleSftpTransferRows(
                    old.transfers ?? [],
                    event.transferId,
                    event.transferState === 'batch-cancelled' ? 'cancelled' : 'failed',
                  ),
            transferError:
              event.transferState === 'batch-failed' ? 'File transfer failed.' : old.transferError,
          };
          if (
            event.transferState === 'batch-completed' &&
            this.path(transfer.pane) === transfer.path
          )
            this.navigate(transfer.pane, transfer.path);
        } else if (event.itemId) {
          let rows = [...(old.transfers ?? [])];
          const index = rows.findIndex(
            (row) => row.transferId === event.transferId && row.itemId === event.itemId,
          );
          const previous = index >= 0 ? rows[index] : undefined;
          const row = {
            transferId: event.transferId,
            itemId: event.itemId,
            direction: transfer.direction,
            displayName: event.displayName ?? previous?.displayName ?? 'File',
            expectedBytes: event.expectedBytes ?? previous?.expectedBytes ?? 0,
            bytesTransferred: event.bytesTransferred ?? previous?.bytesTransferred ?? 0,
            state: event.transferState as
              | 'running'
              | 'progress'
              | 'completed'
              | 'failed'
              | 'cancelled',
            ...(event.error ? { error: 'File transfer failed.' } : {}),
          };
          if (index >= 0) rows[index] = row;
          else {
            if (rows.length >= 256) {
              const terminal = rows.findIndex((r) => isSftpTransferTerminal(r.state));
              if (terminal < 0) return;
              rows.splice(terminal, 1);
            }
            rows.push(row);
          }
          this.state = { ...old, transfers: rows };
        }
        break;
      }
      default:
        return;
    }
    if (this.state !== old) this.changed();
  }
  dispose(): void {
    this.disposed = true;
    this.operations.clear();
    this.transfers.clear();
  }
}
