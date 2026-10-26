import { hasSftpDragPayload } from '../sftp-dnd';
import { formatSftpDate } from '../sftp-format';
import { SftpSectionHeader } from './SftpSectionHeader';
import { type SftpSortColumn } from '../sftp-state';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { ChevronDown, ChevronRight, FolderOpen, LoaderCircle } from 'lucide-react';
import {
  beginSftpTreeRequest,
  createSftpTree,
  finishSftpTreeRequest,
  filterSftpTreeRows,
  invalidateSftpTree,
  revealSftpTreePath,
  sftpTreeRows,
  toggleSftpTreePath,
} from '../sftp-tree-state';

// Leave room for the column header and at least one directory row.
const minTreeHeight = 80;
const maxTreeHeight = 400;

export function SftpDirectoryTree({
  sessionId,
  pane,
  path,
  revision,
  height,
  onHeightChange,
  search,
  onSearchChange,
  sortColumn,
  ascending,
  onSort,
  onNavigate,
  onDrop,
}: {
  sessionId: string;
  pane: 'local' | 'remote';
  path: string;
  revision: string;
  height: number;
  onHeightChange: React.Dispatch<React.SetStateAction<number>>;
  search: string;
  onSearchChange: (value: string) => void;
  sortColumn: SftpSortColumn;
  ascending: boolean;
  onSort: (column: SftpSortColumn) => void;
  onNavigate: (path: string) => void;
  onDrop: (event: React.DragEvent<HTMLElement>, path: string) => void;
}) {
  const [tree, setTree] = useState(() => createSftpTree(pane));
  const viewport = useRef<HTMLDivElement>(null);
  const revealPending = useRef(true);
  const pending = useRef(new Map<string, string>());
  const resize = useRef<{ y: number; height: number } | undefined>(undefined);
  useEffect(() => {
    const move = (event: PointerEvent) => {
      if (resize.current) {
        revealPending.current = true;
        onHeightChange(
          Math.max(
            minTreeHeight,
            Math.min(maxTreeHeight, resize.current.height + event.clientY - resize.current.y),
          ),
        );
      }
    };
    const stop = () => {
      resize.current = undefined;
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', stop);
    return () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', stop);
    };
  }, [onHeightChange]);
  useEffect(() => {
    revealPending.current = true;
    setTree((current) => revealSftpTreePath(current, path));
  }, [path]);
  useEffect(() => {
    revealPending.current = true;
    setTree((current) => invalidateSftpTree(current));
  }, [revision]);
  useLayoutEffect(() => {
    if (viewport.current) viewport.current.scrollTop = 0;
    revealPending.current = true;
  }, [search, sortColumn, ascending]);
  useLayoutEffect(() => {
    if (!revealPending.current || tree.path !== path) return;
    const container = viewport.current;
    if (!container) return;
    container.scrollTop = 0;
    revealPending.current = false;
  }, [tree, path, height, search, sortColumn, ascending]);
  useEffect(
    () =>
      window.wormhole?.onSshEvent((event) => {
        if (event.sessionId !== sessionId || !('requestId' in event) || !event.requestId) return;
        const requestedPath = pending.current.get(event.requestId);
        if (!requestedPath) return;
        if (
          event.type !== 'sftp.ready' &&
          event.type !== 'sftp.local.ready' &&
          event.type !== 'sftp.error' &&
          event.type !== 'sftp.local.error'
        )
          return;
        pending.current.delete(event.requestId);
        setTree((current) => ({
          ...finishSftpTreeRequest(
            current,
            requestedPath,
            event.requestId!,
            'entries' in event ? event.entries : [],
            'error' in event ? event.error : undefined,
          ),
        }));
      }),
    [sessionId],
  );
  useEffect(() => {
    const api = window.wormhole;
    if (!api || tree.path !== path) return;
    const available = Math.max(0, 4 - pending.current.size);
    const pendingPaths = new Set(pending.current.values());
    const paths = sftpTreeRows(tree)
      .filter((row) => row.expanded && row.status === 'idle' && !pendingPaths.has(row.path))
      .slice(0, available)
      .map((row) => row.path);
    for (const requestedPath of paths) {
      const requestId = `tree-${crypto.randomUUID()}`;
      pending.current.set(requestId, requestedPath);
      setTree((current) => beginSftpTreeRequest(current, requestedPath, requestId));
      void api.listSftpTree(sessionId, pane, requestedPath, requestId).catch((error: unknown) => {
        pending.current.delete(requestId);
        setTree((current) => ({
          ...finishSftpTreeRequest(
            current,
            requestedPath,
            requestId,
            [],
            error instanceof Error ? error.message : String(error),
          ),
        }));
      });
    }
  }, [tree, pane, sessionId, path]);
  const rows =
    tree.path === path ? filterSftpTreeRows(sftpTreeRows(tree, sortColumn, ascending), search) : [];
  const noMatches = tree.path === path && rows.length === 0 && search.trim().length > 0;
  return (
    <div
      className="flex shrink-0 flex-col overflow-hidden rounded-sm border border-border"
      style={{ height, maxHeight: '50%' }}
    >
      <div
        ref={viewport}
        aria-label={`${pane} directory tree`}
        role="treegrid"
        aria-colcount={3}
        aria-rowcount={rows.length + (noMatches ? 2 : 1)}
        className="min-h-0 flex-1 overflow-auto [scrollbar-gutter:stable]"
      >
        <SftpSectionHeader
          pane={pane}
          kind="tree"
          sortColumn={sortColumn}
          ascending={ascending}
          onSort={onSort}
          search={search}
          onSearchChange={onSearchChange}
        />
        <div role="rowgroup" className="py-1">
          {noMatches ? (
            <div role="row" aria-rowindex={2}>
              <div
                role="gridcell"
                aria-colindex={1}
                aria-colspan={3}
                className="p-2 text-center text-xs text-muted-foreground"
              >
                No folders match your search
              </div>
            </div>
          ) : null}
          {rows.map((row, index) => (
            <div
              key={row.path}
              role="row"
              data-sftp-tree-path={row.path}
              aria-rowindex={index + 2}
              aria-expanded={row.expanded}
              aria-selected={row.path === path}
              aria-level={row.depth + 1}
              className={`grid h-7 grid-cols-[minmax(0,1fr)_5.25rem_7.75rem] items-center gap-x-2.5 px-[22px] text-xs ${row.path === path ? 'bg-accent text-accent-foreground' : ''}`}
              onDragOver={(event) => {
                if (hasSftpDragPayload(event.dataTransfer.types)) {
                  event.preventDefault();
                  event.stopPropagation();
                  event.dataTransfer.dropEffect = 'copy';
                }
              }}
              onDrop={(event) => onDrop(event, row.path)}
            >
              <div
                role="gridcell"
                aria-colindex={1}
                className="grid min-w-0 grid-cols-[1rem_minmax(0,1fr)] items-center gap-x-2.5 overflow-hidden"
                style={{ paddingLeft: row.depth * 14 }}
              >
                <button
                  type="button"
                  aria-label={`${row.expanded ? 'Collapse' : 'Expand'} ${row.path}`}
                  onClick={() => setTree((current) => toggleSftpTreePath(current, row.path))}
                  className="grid size-5 shrink-0 place-items-center justify-self-center"
                >
                  {row.status === 'loading' ? (
                    <LoaderCircle className="size-3 animate-spin" />
                  ) : row.expanded ? (
                    <ChevronDown className="size-3" />
                  ) : (
                    <ChevronRight className="size-3" />
                  )}
                </button>
                <button
                  type="button"
                  title={row.error ?? row.path}
                  onClick={() => {
                    if (row.status === 'failed') setTree((current) => invalidateSftpTree(current));
                    onNavigate(row.path);
                  }}
                  className="grid min-w-0 grid-cols-[1.5rem_minmax(0,1fr)] items-center gap-x-2.5 text-left"
                >
                  <FolderOpen className="size-3.5 shrink-0 justify-self-center text-amber-400" />
                  <span className="flex min-w-0 items-center gap-1">
                    <span className="truncate">{row.name}</span>
                    {row.error ? <span className="shrink-0 text-destructive">!</span> : null}
                  </span>
                </button>
              </div>
              <span role="gridcell" aria-colindex={2} />
              <span role="gridcell" aria-colindex={3} className="truncate text-muted-foreground">
                {formatSftpDate(row.lastModifiedUtc)}
              </span>
            </div>
          ))}
        </div>
      </div>
      <div
        role="separator"
        aria-label={`Resize ${pane} directory tree`}
        aria-orientation="horizontal"
        aria-valuemin={minTreeHeight}
        aria-valuemax={maxTreeHeight}
        aria-valuenow={height}
        tabIndex={0}
        className="h-1.5 shrink-0 cursor-row-resize bg-border hover:bg-primary/40"
        onPointerDown={(event) => {
          event.preventDefault();
          resize.current = { y: event.clientY, height };
        }}
        onKeyDown={(event) => {
          if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
            event.preventDefault();
            event.stopPropagation();
            revealPending.current = true;
            onHeightChange((current) =>
              Math.max(
                minTreeHeight,
                Math.min(maxTreeHeight, current + (event.key === 'ArrowUp' ? -10 : 10)),
              ),
            );
          }
        }}
      />
    </div>
  );
}
