export type SftpPaneState = {
  status: 'opening' | 'ready' | 'failed';
  path: string;
  previousPath?: string;
  entries: WormholeSftpEntry[];
  truncated: boolean;
  quickPaths?: WormholeSftpQuickPath[];
  error?: string;
  requestId?: string;
};

export type SftpSortColumn = 'name' | 'size' | 'modified';

export const sftpVirtualRowHeight = 28;
const sftpVirtualWindowRows = 8;

export function sftpVirtualScrollAnchor(scrollTop: number): number {
  const safeScrollTop = Number.isFinite(scrollTop) ? Math.max(0, scrollTop) : 0;
  const windowHeight = sftpVirtualRowHeight * sftpVirtualWindowRows;
  return Math.floor(safeScrollTop / windowHeight) * windowHeight;
}

export function sftpVisibleEntryRange(
  entryCount: number,
  scrollTop: number,
  viewportHeight: number,
): { start: number; end: number } {
  const count = Math.max(0, entryCount);
  const firstVisible = Math.floor(sftpVirtualScrollAnchor(scrollTop) / sftpVirtualRowHeight);
  const visibleCount = Math.max(1, Math.ceil(viewportHeight / sftpVirtualRowHeight));
  return {
    start: Math.max(0, firstVisible - sftpVirtualWindowRows),
    end: Math.min(count, firstVisible + visibleCount + sftpVirtualWindowRows),
  };
}

function compareSftpValues(left: number, right: number): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareSftpNames(left: string, right: string): number {
  const insensitiveLeft = left.toLowerCase();
  const insensitiveRight = right.toLowerCase();
  if (insensitiveLeft < insensitiveRight) return -1;
  if (insensitiveLeft > insensitiveRight) return 1;
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function sftpModifiedTime(value?: string): number {
  if (!value) return 0;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
}

export function compareSftpEntries(
  left: WormholeSftpEntry,
  right: WormholeSftpEntry,
  sortColumn: SftpSortColumn,
  sortAscending: boolean,
): number {
  if (left.isDirectory !== right.isDirectory) return left.isDirectory ? -1 : 1;

  const primary =
    sortColumn === 'size'
      ? compareSftpValues(left.size, right.size)
      : sortColumn === 'modified'
        ? compareSftpValues(
            sftpModifiedTime(left.lastModifiedUtc),
            sftpModifiedTime(right.lastModifiedUtc),
          )
        : compareSftpNames(left.name, right.name);
  if (primary !== 0) return sortAscending ? primary : -primary;

  // WinUI keeps the name tie-breaker ascending even when the primary column is descending.
  return compareSftpNames(left.name, right.name);
}

export type SftpRefreshRequest = {
  id: string;
  pane: 'local' | 'remote';
  path: string;
};

export type SftpRefreshRequests = Partial<Record<'local' | 'remote', SftpRefreshRequest>>;

function matchesSftpRequest(
  state: Pick<SftpBrowserState, 'requestId'>,
  requestId?: string,
): boolean {
  return requestId === undefined ? state.requestId === undefined : state.requestId === requestId;
}

export function pruneSftpSelection(
  selected: Set<string>,
  visiblePaths: ReadonlySet<string>,
): Set<string> {
  const next = new Set([...selected].filter((path) => visiblePaths.has(path)));
  if (next.size === selected.size && [...selected].every((path) => next.has(path))) {
    return selected;
  }
  return next;
}

export function nextSftpOperationRefreshRequests(
  current: SftpRefreshRequests | undefined,
  operation: SftpRefreshRequest & { error?: string },
): SftpRefreshRequests | undefined {
  // A failed operation does not own the refresh slot. Another operation in the same pane may
  // have succeeded first, and clearing its request would leave the UI showing stale entries.
  if (operation.error) return current;
  return { ...current, [operation.pane]: operation };
}

export function nextSftpTransferRefreshRequests(
  current: SftpRefreshRequests | undefined,
  transferId: string,
  destination: SftpTransferDestination | undefined,
  activePath: string | undefined,
): SftpRefreshRequests | undefined {
  if (!destination || activePath !== destination.path) return current;
  return {
    ...current,
    [destination.pane]: {
      id: transferId,
      pane: destination.pane,
      path: activePath,
    },
  };
}

export function shouldRefreshSftpPane(
  state: Pick<SftpBrowserState, 'path' | 'local'>,
  request: SftpRefreshRequest,
): boolean {
  const activePath = request.pane === 'local' ? state.local?.path : state.path;
  return activePath === request.path;
}

export type SftpTransferRow = {
  transferId: string;
  itemId: string;
  direction: 'local-to-remote' | 'remote-to-local' | 'local-to-local';
  displayName: string;
  expectedBytes: number;
  bytesTransferred: number;
  state: 'running' | 'progress' | 'completed' | 'failed' | 'cancelled';
  error?: string;
};

export type SftpConflict = {
  transferId: string;
  itemId: string;
  direction: 'local-to-remote' | 'remote-to-local' | 'local-to-local';
  displayName: string;
  path: string;
  incomingSize: number;
  existingSize: number;
  existingIsDirectory: boolean;
};

export type SftpTransferDestination = {
  pane: 'local' | 'remote';
  path: string;
};

export type SftpBrowserState = {
  status: 'opening' | 'ready' | 'failed' | 'closing';
  path: string;
  previousPath?: string;
  entries: WormholeSftpEntry[];
  truncated: boolean;
  error?: string;
  requestId?: string;
  local?: SftpPaneState;
  transfers?: SftpTransferRow[];
  conflict?: SftpConflict;
  transferError?: string;
  transferErrorTransferId?: string;
  knownTransferIds?: Record<string, true>;
  transferDestinations?: Record<string, SftpTransferDestination>;
  knownOperationIds?: Record<string, true>;
  refreshRequests?: SftpRefreshRequests;
};

export function updateSftpTransferError(
  state: Pick<SftpBrowserState, 'transferError' | 'transferErrorTransferId'>,
  transferId: string,
  error?: string,
): Pick<SftpBrowserState, 'transferError' | 'transferErrorTransferId'> {
  if (error !== undefined) {
    return { transferError: error, transferErrorTransferId: transferId };
  }
  if (state.transferErrorTransferId !== transferId) {
    return {
      transferError: state.transferError,
      transferErrorTransferId: state.transferErrorTransferId,
    };
  }
  return { transferError: undefined, transferErrorTransferId: undefined };
}

export function settleSftpTransferRows(
  transfers: SftpTransferRow[],
  transferId: string,
  state: 'failed' | 'cancelled',
  error?: string,
): SftpTransferRow[] {
  return transfers.map((transfer) =>
    transfer.transferId === transferId && !isSftpTransferTerminal(transfer.state)
      ? { ...transfer, state, error: error ?? transfer.error }
      : transfer,
  );
}

export function removeSftpTransferRow(
  transfers: SftpTransferRow[],
  transferId: string,
  itemId: string,
): SftpTransferRow[] {
  return transfers.filter(
    (transfer) => transfer.transferId !== transferId || transfer.itemId !== itemId,
  );
}

export function sftpTransferItemKey(transferId: string, itemId: string): string {
  return `${transferId}\u0000${itemId}`;
}

export function shouldApplySftpReady(
  state: SftpBrowserState,
  path: string,
  requestId?: string,
): boolean {
  return (
    state.status !== 'closing' &&
    matchesSftpRequest(state, requestId) &&
    (requestId !== undefined || !state.path || state.path === path)
  );
}

export function shouldApplySftpError(
  state: SftpBrowserState,
  path?: string,
  requestId?: string,
): boolean {
  return (
    state.status !== 'closing' &&
    matchesSftpRequest(state, requestId) &&
    (requestId !== undefined ||
      (path === undefined ? state.path === '' : !state.path || state.path === path))
  );
}

export function shouldApplySftpFailure(
  state: SftpBrowserState | undefined,
  requestId: number,
  activeRequestId: number | undefined,
): state is SftpBrowserState {
  return state !== undefined && state.status !== 'closing' && activeRequestId === requestId;
}

export function shouldFinishSftpClose(
  state: SftpBrowserState | undefined,
  requestId: number,
  activeRequestId: number | undefined,
): boolean {
  return state?.status === 'closing' && activeRequestId === requestId;
}

export function shouldApplySftpClosed(state: SftpBrowserState | undefined): boolean {
  return state?.status === 'closing';
}

export function parentSftpPath(path: string): string {
  if (!path || path === '/') return '/';
  const withoutTrailingSlash = path.endsWith('/') ? path.slice(0, -1) : path;
  const separator = withoutTrailingSlash.lastIndexOf('/');
  return separator <= 0 ? '/' : withoutTrailingSlash.slice(0, separator);
}

export function parentLocalSftpPath(path: string): string {
  if (!path) return '';
  const normalized = path.replaceAll('/', '\\').replace(/[\\]+$/, '');
  if (/^[A-Za-z]:$/.test(normalized)) return `${normalized}\\`;
  if (/^[A-Za-z]:\\$/.test(path)) return path;
  if (/^\\\\[^\\]+\\[^\\]+$/.test(normalized)) return normalized;
  const separator = normalized.lastIndexOf('\\');
  if (separator < 0) return normalized;
  if (separator === 0) return '\\';
  if (separator === 2 && /^[A-Za-z]:/.test(normalized)) return `${normalized.slice(0, 3)}`;
  return normalized.slice(0, separator) || '\\';
}

export function isSftpTransferTerminal(state: SftpTransferRow['state']): boolean {
  return state === 'completed' || state === 'failed' || state === 'cancelled';
}
