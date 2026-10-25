import { hasSftpDragPayload } from '../sftp-dnd';
import { useEffect, useRef, useState } from 'react';
import { ChevronDown, ChevronRight, FolderOpen, LoaderCircle } from 'lucide-react';
import {
  beginSftpTreeRequest,
  createSftpTree,
  finishSftpTreeRequest,
  invalidateSftpTree,
  revealSftpTreePath,
  sftpTreeRows,
  toggleSftpTreePath,
} from '../sftp-tree-state';

export function SftpDirectoryTree({
  sessionId,
  pane,
  path,
  revision,
  onNavigate,
  onDrop,
}: {
  sessionId: string;
  pane: 'local' | 'remote';
  path: string;
  revision: string;
  onNavigate: (path: string) => void;
  onDrop: (event: React.DragEvent<HTMLElement>, path: string) => void;
}) {
  const [tree, setTree] = useState(() => createSftpTree(pane));
  const pending = useRef(new Map<string, string>());
  const [height, setHeight] = useState(140);
  const resize = useRef<{ y: number; height: number } | undefined>(undefined);
  useEffect(() => {
    const move = (event: PointerEvent) => {
      if (resize.current)
        setHeight(
          Math.max(60, Math.min(400, resize.current.height + event.clientY - resize.current.y)),
        );
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
  }, []);
  useEffect(() => {
    setTree((current) => revealSftpTreePath(current, path));
  }, [path]);
  useEffect(() => {
    setTree((current) => invalidateSftpTree(current));
  }, [revision]);
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
    if (!api) return;
    const available = Math.max(0, 4 - pending.current.size);
    const paths = tree.expanded
      .filter((value) => tree.nodes[value]?.status === 'idle')
      .slice(0, available);
    for (const requestedPath of paths) {
      const requestId = `tree-${crypto.randomUUID()}`;
      pending.current.set(requestId, requestedPath);
      setTree((current) => beginSftpTreeRequest(current, requestedPath, requestId));
      void api.listSftpTree(sessionId, pane, requestedPath, requestId).catch((error: unknown) => {
        pending.current.delete(requestId);
        setTree((current) =>
          finishSftpTreeRequest(
            current,
            requestedPath,
            requestId,
            [],
            error instanceof Error ? error.message : String(error),
          ),
        );
      });
    }
  }, [tree, pane, sessionId]);
  return (
    <div
      className="flex shrink-0 flex-col overflow-hidden rounded-sm border border-border"
      style={{ height, maxHeight: '50%' }}
    >
      <div
        aria-label={`${pane} directory tree`}
        role="tree"
        className="min-h-0 flex-1 overflow-auto py-1"
      >
        {sftpTreeRows(tree).map((row) => (
          <div
            key={row.path}
            role="treeitem"
            aria-expanded={row.expanded}
            aria-selected={row.path === path}
            aria-level={row.depth + 1}
            className={`flex h-7 items-center gap-1 pr-2 text-xs ${row.path === path ? 'bg-accent text-accent-foreground' : ''}`}
            style={{ paddingLeft: 4 + row.depth * 14 }}
            onDragOver={(event) => {
              if (hasSftpDragPayload(event.dataTransfer.types)) {
                event.preventDefault();
                event.stopPropagation();
                event.dataTransfer.dropEffect = 'copy';
              }
            }}
            onDrop={(event) => onDrop(event, row.path)}
          >
            <button
              type="button"
              aria-label={`${row.expanded ? 'Collapse' : 'Expand'} ${row.path}`}
              onClick={() => setTree((current) => toggleSftpTreePath(current, row.path))}
              className="grid size-5 shrink-0 place-items-center"
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
              className="flex min-w-0 flex-1 items-center gap-1 text-left"
            >
              <FolderOpen className="size-3.5 shrink-0 text-amber-400" />
              <span className="truncate">{row.name}</span>
              {row.error ? <span className="text-destructive">!</span> : null}
            </button>
          </div>
        ))}
      </div>
      <div
        role="separator"
        aria-label={`Resize ${pane} directory tree`}
        aria-orientation="horizontal"
        aria-valuemin={60}
        aria-valuemax={400}
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
            setHeight((current) =>
              Math.max(60, Math.min(400, current + (event.key === 'ArrowUp' ? -10 : 10))),
            );
          }
        }}
      />
    </div>
  );
}
