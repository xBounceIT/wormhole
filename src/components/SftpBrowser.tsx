import { SftpEditedFiles } from './SftpEditors';
import { SftpDirectoryTree } from './SftpDirectoryTree';
import { sftpShortcut } from '../sftp-tree-state';
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from './ui/resizable';
import { type SftpBrowserState } from '../sftp-state';
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type DragEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent,
} from 'react';
import {
  parentLocalSftpPath,
  parentSftpPath,
  isLocalSftpPathRoot,
  isInvalidLocalSftpDropDestination,
  isSftpTransferTerminal,
  isValidSftpNameInput,
  joinLocalSftpPath,
  nextSftpSelection,
  compareSftpEntries,
  pruneSftpSelection,
  sftpVirtualScrollAnchor,
  sftpVisibleEntryRange,
  sftpVirtualRowHeight,
  type SftpConflict,
  type SftpPaneState,
  type SftpSortColumn,
  type SftpTransferRow,
} from '../sftp-state';
import {
  AlertCircle,
  ArrowUp,
  ArrowRightLeft,
  ChevronDown,
  ChevronUp,
  Check,
  Download,
  File,
  FilePlus2,
  FolderOpen,
  FolderPlus,
  LoaderCircle,
  Pencil,
  RefreshCcw,
  Search,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
} from '@/components/ui/context-menu';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { formatSftpDate, formatSftpSize } from '../sftp-format';
import {
  externalSftpTransferItems,
  hasSftpDragPayload,
  sftpDragDataType,
  type SftpTransferItem,
} from '../sftp-dnd';
import { type ReactNode, type ComponentProps } from 'react';
type SftpBrowserSession = {
  id: string;
  title: string;
  host: string;
  backendSessionId?: string;
  sftp?: SftpBrowserState;
};
function IconButton({
  label,
  children,
  ...props
}: ComponentProps<typeof Button> & { label: string; children: ReactNode }) {
  return (
    <Button aria-label={label} title={label} size="icon-sm" variant="ghost" {...props}>
      {children}
    </Button>
  );
}
export type SftpPaneKind = 'local' | 'remote';
export type SftpOperation = 'mkdir' | 'file' | 'delete' | 'rename' | 'open';
export type SftpTransferDirection = 'local-to-remote' | 'remote-to-local' | 'local-to-local';
type SftpDragPayload = {
  sourcePane: SftpPaneKind;
  items: SftpTransferItem[];
  external: boolean;
};

function isSftpPaneRoot(pane: SftpPaneKind, path: string): boolean {
  if (pane === 'remote') return !path || path === '/';
  return isLocalSftpPathRoot(path);
}

function joinSftpPanePath(pane: SftpPaneKind, parent: string, name: string): string {
  if (pane === 'remote') return parent === '/' ? `/${name}` : `${parent}/${name}`;
  return joinLocalSftpPath(parent, name);
}

function parseSftpDragPayload(data: DataTransfer): SftpDragPayload | undefined {
  const encoded = data.getData(sftpDragDataType);
  if (encoded) {
    try {
      const parsed: unknown = JSON.parse(encoded);
      if (
        parsed &&
        typeof parsed === 'object' &&
        'sourcePane' in parsed &&
        (parsed.sourcePane === 'local' || parsed.sourcePane === 'remote') &&
        'items' in parsed &&
        Array.isArray(parsed.items)
      ) {
        const items = parsed.items.filter(
          (item): item is SftpTransferItem =>
            item &&
            typeof item === 'object' &&
            typeof item.sourcePath === 'string' &&
            typeof item.name === 'string' &&
            typeof item.isDirectory === 'boolean' &&
            typeof item.size === 'number' &&
            Number.isSafeInteger(item.size) &&
            item.size >= 0,
        );
        if (items.length > 0) {
          return { sourcePane: parsed.sourcePane, items, external: false };
        }
      }
    } catch {
      return undefined;
    }
  }

  if (data.files.length === 0) return undefined;
  const getPathForFile = window.wormhole?.getPathForFile;
  if (!getPathForFile) return undefined;
  const items = externalSftpTransferItems(
    Array.from(data.files),
    Array.from(data.items),
    getPathForFile,
  );
  return items.length > 0 ? { sourcePane: 'local', items, external: true } : undefined;
}

// Virtualization, selection, drag/drop, and keyboard navigation share one pane coordinate system;
// keeping them together prevents subtly different path and selection semantics.
// react-doctor-disable-next-line react-doctor/no-giant-component
export function SftpFilePane({
  pane,
  state,
  onNavigate,
  onRefresh,
  onOperation,
  onTransfer,
  sessionId,
  revision = '',
  onCopy,
  onEdit,
  editors = [],
}: {
  onEdit?: (entry: WormholeSftpEntry, editorId?: string) => void;
  editors?: WormholeSftpEditorSettings['editors'];
  sessionId?: string;
  revision?: string;
  onCopy?: (items: SftpTransferItem[]) => void;
  pane: SftpPaneKind;
  state: SftpPaneState;
  onNavigate: (path: string) => void;
  onRefresh: () => void;
  onOperation: (operation: SftpOperation, path: string, destinationPath?: string) => void;
  onTransfer: (payload: SftpDragPayload, destinationPath: string) => void;
}) {
  const [treeVisible, setTreeVisible] = useState(true);
  const [treeRefresh, setTreeRefresh] = useState(0);
  function refreshPane() {
    setTreeRefresh((current) => current + 1);
    onRefresh();
  }
  const [search, setSearch] = useState('');
  const [sortColumn, setSortColumn] = useState<SftpSortColumn>('name');
  const [ascending, setAscending] = useState(true);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());
  const [editingPath, setEditingPath] = useState<string>();
  const [editingName, setEditingName] = useState('');
  const [prompt, setPrompt] = useState<'folder' | 'file'>();
  const [promptValue, setPromptValue] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [dropPath, setDropPath] = useState<string>();
  const [pathInput, setPathInput] = useState({
    sourcePath: state.path,
    value: state.path,
  });
  const pathDraft = pathInput.sourcePath === state.path ? pathInput.value : state.path;
  const [listViewport, setListViewport] = useState({ height: 0, scrollTop: 0 });
  const renameCommitPath = useRef<string | undefined>(undefined);
  const selectionAnchorPath = useRef<string | undefined>(undefined);
  const listViewportRef = useRef<HTMLDivElement>(null);
  const listViewportStateRef = useRef(listViewport);

  useEffect(() => {
    const clearDropPath = () => setDropPath(undefined);
    window.addEventListener('dragend', clearDropPath);
    window.addEventListener('drop', clearDropPath, true);
    return () => {
      window.removeEventListener('dragend', clearDropPath);
      window.removeEventListener('drop', clearDropPath, true);
    };
  }, []);

  const syncListViewport = useCallback((height: number, scrollTop: number) => {
    const next = { height, scrollTop: sftpVirtualScrollAnchor(scrollTop) };
    const current = listViewportStateRef.current;
    if (current.height === next.height && current.scrollTop === next.scrollTop) return;
    listViewportStateRef.current = next;
    setListViewport(next);
  }, []);

  const normalizedSearch = search.trim().toLocaleLowerCase();
  const visibleEntries = useMemo(() => {
    const filtered = state.entries.filter((entry) =>
      entry.name.toLocaleLowerCase().includes(normalizedSearch),
    );
    return filtered.sort((left, right) => compareSftpEntries(left, right, sortColumn, ascending));
  }, [ascending, normalizedSearch, sortColumn, state.entries]);
  const visibleRange = sftpVisibleEntryRange(
    visibleEntries.length,
    listViewport.scrollTop,
    listViewport.height,
  );

  useLayoutEffect(() => {
    const viewport = listViewportRef.current;
    if (!viewport) return;
    const syncViewport = () => syncListViewport(viewport.clientHeight, viewport.scrollTop);
    syncViewport();
    const observer = new ResizeObserver(syncViewport);
    observer.observe(viewport);
    return () => observer.disconnect();
  }, [syncListViewport]);

  const validSelectedPaths = useMemo(
    () => pruneSftpSelection(selectedPaths, new Set(visibleEntries.map((entry) => entry.fullPath))),
    [selectedPaths, visibleEntries],
  );

  useEffect(() => {
    const viewport = listViewportRef.current;
    if (!viewport) return;
    viewport.scrollTop = 0;
    syncListViewport(viewport.clientHeight, 0);
  }, [normalizedSearch, state.path, syncListViewport]);

  const selectedEntries = useMemo(
    () => visibleEntries.filter((entry) => validSelectedPaths.has(entry.fullPath)),
    [validSelectedPaths, visibleEntries],
  );
  const busy = state.status === 'opening';
  const root = isSftpPaneRoot(pane, state.path);

  function changeSort(column: SftpSortColumn) {
    if (sortColumn === column) setAscending((current) => !current);
    else {
      setSortColumn(column);
      setAscending(true);
    }
  }

  function toggleSelection(entry: WormholeSftpEntry, event: MouseEvent) {
    const next = nextSftpSelection(
      validSelectedPaths,
      visibleEntries.map((candidate) => candidate.fullPath),
      entry.fullPath,
      selectionAnchorPath.current,
      { extend: event.shiftKey, toggle: event.ctrlKey || event.metaKey },
    );
    selectionAnchorPath.current = next.anchorPath;
    setSelectedPaths(next.selected);
  }

  function moveKeyboardSelection(entry: WormholeSftpEntry, event: ReactKeyboardEvent) {
    const currentIndex = visibleEntries.findIndex(
      (candidate) => candidate.fullPath === entry.fullPath,
    );
    if (currentIndex < 0) return;
    const targetIndex =
      event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? visibleEntries.length - 1
          : Math.min(
              visibleEntries.length - 1,
              Math.max(0, currentIndex + (event.key === 'ArrowUp' ? -1 : 1)),
            );
    if (targetIndex === currentIndex) return;
    event.preventDefault();
    event.stopPropagation();
    const target = visibleEntries[targetIndex];
    if (event.shiftKey) {
      const selection =
        validSelectedPaths.size > 0 ? validSelectedPaths : new Set([entry.fullPath]);
      const next = nextSftpSelection(
        selection,
        visibleEntries.map((candidate) => candidate.fullPath),
        target.fullPath,
        selectionAnchorPath.current ?? entry.fullPath,
        { extend: true, toggle: false },
      );
      selectionAnchorPath.current = next.anchorPath;
      setSelectedPaths(next.selected);
    } else if (!event.ctrlKey && !event.metaKey) {
      selectionAnchorPath.current = target.fullPath;
      setSelectedPaths(new Set([target.fullPath]));
    }
    const viewport = listViewportRef.current;
    if (viewport) {
      const rowTop = targetIndex * sftpVirtualRowHeight;
      const rowBottom = rowTop + sftpVirtualRowHeight;
      if (rowTop < viewport.scrollTop) viewport.scrollTop = rowTop;
      else if (rowBottom > viewport.scrollTop + viewport.clientHeight) {
        viewport.scrollTop = rowBottom - viewport.clientHeight;
      }
      syncListViewport(viewport.clientHeight, viewport.scrollTop);
    }
    requestAnimationFrame(() => {
      document
        .querySelector<HTMLElement>(`[data-sftp-pane="${pane}"][data-sftp-index="${targetIndex}"]`)
        ?.focus();
    });
  }

  function beginRename(entry: WormholeSftpEntry) {
    renameCommitPath.current = undefined;
    setEditingPath(entry.fullPath);
    setEditingName(entry.name);
  }

  function commitRename() {
    if (!editingPath) return;
    if (renameCommitPath.current === editingPath) return;
    renameCommitPath.current = editingPath;
    const name = editingName.trim();
    if (!isValidSftpNameInput(name, pane, state.path)) {
      setEditingPath(undefined);
      return;
    }
    const parent =
      pane === 'remote' ? parentSftpPath(editingPath) : parentLocalSftpPath(editingPath);
    onOperation('rename', editingPath, joinSftpPanePath(pane, parent, name));
    setEditingPath(undefined);
  }

  function submitPrompt() {
    const name = promptValue.trim();
    if (!prompt || !isValidSftpNameInput(name, pane, state.path)) return;
    onOperation(prompt === 'folder' ? 'mkdir' : 'file', joinSftpPanePath(pane, state.path, name));
    setPrompt(undefined);
    setPromptValue('');
  }

  function deleteSelected() {
    for (const entry of selectedEntries) onOperation('delete', entry.fullPath);
    setSelectedPaths(new Set());
    setConfirmDelete(false);
  }

  function setDragState(event: DragEvent<HTMLElement>, path?: string) {
    if (!hasSftpDragPayload(event.dataTransfer.types)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = 'copy';
    setDropPath(path ?? state.path);
  }

  function handleDrop(event: DragEvent<HTMLElement>, path?: string) {
    event.preventDefault();
    event.stopPropagation();
    setDropPath(undefined);
    const payload = parseSftpDragPayload(event.dataTransfer);
    if (payload) onTransfer(payload, path ?? state.path);
  }

  return (
    <section
      aria-label={`${pane === 'local' ? 'Local' : 'Remote'} files`}
      className={`relative flex min-h-0 min-w-0 flex-1 flex-col gap-2 overflow-hidden rounded-md ${
        dropPath === state.path ? 'bg-primary/5' : ''
      }`}
      onDragEnter={(event) => setDragState(event)}
      onDragLeave={(event) => {
        if (
          event.relatedTarget instanceof Node &&
          event.currentTarget.contains(event.relatedTarget)
        ) {
          return;
        }
        setDropPath(undefined);
      }}
      onDragOver={(event) => setDragState(event)}
      onKeyDown={(event) => {
        if (
          event.target instanceof HTMLInputElement ||
          event.target instanceof HTMLTextAreaElement
        ) {
          return;
        }
        const action = sftpShortcut(event, false);
        if (action === 'switch') {
          event.preventDefault();
          event.currentTarget
            .closest('[aria-label="SFTP browser"]')
            ?.querySelector<HTMLElement>(
              `[data-sftp-panel="${pane === 'local' ? 'remote' : 'local'}"]`,
            )
            ?.focus();
        } else if (action === 'copy') {
          event.preventDefault();
          onCopy?.(
            selectedEntries.map((entry) => ({
              sourcePath: entry.fullPath,
              name: entry.name,
              isDirectory: entry.isDirectory,
              size: entry.size,
            })),
          );
        } else if (action === 'edit') {
          event.preventDefault();
          if (selectedEntries.length === 1 && !selectedEntries[0].isDirectory)
            onEdit?.(selectedEntries[0]);
        } else if (action === 'up') {
          event.preventDefault();
          onNavigate(
            pane === 'local' ? parentLocalSftpPath(state.path) : parentSftpPath(state.path),
          );
        } else if (action === 'refresh') {
          event.preventDefault();
          refreshPane();
        } else if (action === 'mkdir') {
          event.preventDefault();
          setPrompt('folder');
          setPromptValue('');
        } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'a') {
          event.preventDefault();
          setSelectedPaths(new Set(visibleEntries.map((entry) => entry.fullPath)));
          selectionAnchorPath.current = visibleEntries[0]?.fullPath;
        } else if (event.key === 'Delete' && selectedEntries.length > 0) {
          event.preventDefault();
          setConfirmDelete(true);
        } else if (event.key === 'Escape') {
          setSelectedPaths(new Set());
          selectionAnchorPath.current = undefined;
        } else if (event.key === 'F2' && selectedEntries.length === 1) {
          event.preventDefault();
          beginRename(selectedEntries[0]);
        }
      }}
      onDrop={(event) => handleDrop(event)}
      data-sftp-panel={pane}
      tabIndex={0}
    >
      {dropPath === state.path ? (
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-0 z-10 rounded-md border border-primary/70"
        />
      ) : null}
      <div className="flex shrink-0 items-center">
        <span className="text-sm font-semibold text-foreground">
          {pane === 'local' ? 'Local' : 'Remote'}
        </span>
      </div>

      <div className="flex shrink-0 items-center gap-1">
        <IconButton
          label={`Go up in ${pane} files`}
          disabled={busy || root}
          onClick={() =>
            onNavigate(
              pane === 'remote' ? parentSftpPath(state.path) : parentLocalSftpPath(state.path),
            )
          }
        >
          <ArrowUp />
        </IconButton>
        <Input
          aria-label={`${pane === 'local' ? 'Local' : 'Remote'} path`}
          className="h-8 min-w-0 flex-1 font-mono text-[11px]"
          disabled={busy}
          onChange={(event) => setPathInput({ sourcePath: state.path, value: event.target.value })}
          onKeyDown={(event) => {
            if (event.key === 'Enter') onNavigate(pathDraft);
          }}
          value={pathDraft}
        />
        {pane === 'local' && state.quickPaths && state.quickPaths.length > 0 ? (
          <DropdownMenu>
            <Tooltip>
              <TooltipTrigger asChild>
                <DropdownMenuTrigger asChild>
                  <Button aria-label="Local quick paths" size="icon-sm" variant="ghost">
                    <ChevronDown />
                  </Button>
                </DropdownMenuTrigger>
              </TooltipTrigger>
              <TooltipContent side="bottom">Local quick paths</TooltipContent>
            </Tooltip>
            <DropdownMenuContent align="end" className="w-52">
              {state.quickPaths.map((quickPath) =>
                quickPath.isSeparator ? (
                  <DropdownMenuSeparator key="quick-path-separator" />
                ) : (
                  <DropdownMenuItem
                    key={quickPath.path}
                    onSelect={() => onNavigate(quickPath.path)}
                  >
                    {quickPath.displayName}
                  </DropdownMenuItem>
                ),
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : null}
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-1">
        <IconButton label="Home" onClick={() => onNavigate('')}>
          <FolderOpen />
        </IconButton>
        <Button
          size="sm"
          variant="ghost"
          aria-pressed={treeVisible}
          onClick={() => setTreeVisible((current) => !current)}
        >
          Tree
        </Button>
        <IconButton disabled={busy} label="Refresh" onClick={refreshPane}>
          <RefreshCcw className={busy ? 'animate-spin' : undefined} />
        </IconButton>
        <IconButton
          label="New folder"
          disabled={busy || !state.path}
          onClick={() => {
            setPrompt('folder');
            setPromptValue('');
          }}
        >
          <FolderPlus />
        </IconButton>
        <IconButton
          label="New file"
          disabled={busy || !state.path}
          onClick={() => {
            setPrompt('file');
            setPromptValue('');
          }}
        >
          <FilePlus2 />
        </IconButton>
        <IconButton
          label="Delete selected"
          disabled={busy || selectedEntries.length === 0}
          onClick={() => setConfirmDelete(true)}
        >
          <Trash2 />
        </IconButton>
        {busy ? <LoaderCircle className="ml-2 size-4 animate-spin text-muted-foreground" /> : null}
        <div className="ml-auto min-w-36 flex-1 sm:max-w-56">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3 -translate-y-1/2 text-muted-foreground" />
            <Input
              aria-label={`Search ${pane} folder`}
              className="h-8 pl-7 text-[11px]"
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search this folder"
              value={search}
            />
          </div>
        </div>
      </div>

      {sessionId && treeVisible && state.path ? (
        <SftpDirectoryTree
          sessionId={sessionId}
          pane={pane}
          path={state.path}
          revision={`${revision}:${treeRefresh}`}
          onNavigate={onNavigate}
          onDrop={handleDrop}
        />
      ) : null}
      <div
        className="min-h-0 flex-1 overflow-auto rounded-sm border border-border"
        onScroll={(event) => {
          const viewport = event.currentTarget;
          syncListViewport(viewport.clientHeight, viewport.scrollTop);
        }}
        ref={listViewportRef}
      >
        <div className="min-w-0">
          <div className="grid min-h-[34px] grid-cols-[1.5rem_minmax(0,1fr)_5.25rem_7.75rem] gap-x-2.5 border-b border-border bg-muted/20 px-[22px] py-2 font-mono text-[9px] uppercase tracking-[0.12em] text-muted-foreground">
            <span aria-hidden="true" />
            {(['name', 'size', 'modified'] as SftpSortColumn[]).map((column) => (
              <Tooltip key={column}>
                <TooltipTrigger asChild>
                  <button
                    className={`flex items-center gap-1 hover:text-foreground ${column === 'size' ? 'justify-end text-right' : 'text-left'}`}
                    onClick={() => changeSort(column)}
                    type="button"
                  >
                    {column === 'name' ? 'Name' : column === 'size' ? 'Size' : 'Modified'}
                    {sortColumn === column ? (
                      ascending ? (
                        <ChevronUp className="size-3" />
                      ) : (
                        <ChevronDown className="size-3" />
                      )
                    ) : null}
                  </button>
                </TooltipTrigger>
                <TooltipContent side="top">
                  Sort by {column === 'name' ? 'name' : column === 'size' ? 'size' : 'modified'}
                </TooltipContent>
              </Tooltip>
            ))}
          </div>
          {visibleEntries.length > 0 ? (
            <div
              className="relative"
              role="listbox"
              style={{
                contain: 'layout paint style',
                height: visibleEntries.length * sftpVirtualRowHeight,
              }}
            >
              <div
                className="absolute inset-x-0 top-0"
                style={{
                  transform: `translateY(${visibleRange.start * sftpVirtualRowHeight}px)`,
                }}
              >
                {visibleEntries.slice(visibleRange.start, visibleRange.end).map((entry, offset) => {
                  const entryIndex = visibleRange.start + offset;
                  const selected = validSelectedPaths.has(entry.fullPath);
                  const isEditing = editingPath === entry.fullPath;
                  return (
                    <ContextMenu key={entry.fullPath}>
                      <ContextMenuTrigger asChild>
                        <div
                          aria-selected={selected}
                          aria-posinset={entryIndex + 1}
                          aria-setsize={visibleEntries.length}
                          className={`grid h-7 grid-cols-[1.5rem_minmax(0,1fr)_5.25rem_7.75rem] items-center gap-x-2.5 border-b border-border/50 px-[22px] text-xs outline-none transition-colors ${
                            selected ? 'bg-primary/15 text-foreground' : 'hover:bg-muted/30'
                          } ${dropPath === entry.fullPath ? 'ring-1 ring-inset ring-primary' : ''}`}
                          draggable={!busy && !isEditing}
                          data-sftp-index={entryIndex}
                          data-sftp-pane={pane}
                          onClick={(event) => toggleSelection(entry, event)}
                          onDoubleClick={() => {
                            if (busy) return;
                            if (entry.isDirectory) onNavigate(entry.fullPath);
                            else if (pane === 'local') onOperation('open', entry.fullPath);
                          }}
                          onDragEnter={(event) => {
                            if (!entry.isDirectory) return;
                            event.stopPropagation();
                            setDragState(event, entry.fullPath);
                          }}
                          onDragOver={(event) => {
                            if (!entry.isDirectory) return;
                            event.stopPropagation();
                            setDragState(event, entry.fullPath);
                          }}
                          onDragStart={(event) => {
                            const entries =
                              selected && selectedEntries.length > 0 ? selectedEntries : [entry];
                            const payload: SftpDragPayload = {
                              sourcePane: pane,
                              items: entries.map((candidate) => ({
                                sourcePath: candidate.fullPath,
                                name: candidate.name,
                                isDirectory: candidate.isDirectory,
                                size: candidate.size,
                              })),
                              external: false,
                            };
                            event.dataTransfer.effectAllowed = 'copy';
                            event.dataTransfer.setData(sftpDragDataType, JSON.stringify(payload));
                          }}
                          onContextMenu={() => {
                            if (!selected) {
                              setSelectedPaths(new Set([entry.fullPath]));
                              selectionAnchorPath.current = entry.fullPath;
                            }
                          }}
                          onDrop={(event) =>
                            handleDrop(event, entry.isDirectory ? entry.fullPath : state.path)
                          }
                          onKeyDown={(event) => {
                            if (
                              !busy &&
                              (event.key === 'ArrowUp' ||
                                event.key === 'ArrowDown' ||
                                event.key === 'Home' ||
                                event.key === 'End')
                            ) {
                              moveKeyboardSelection(entry, event);
                              return;
                            }
                            if (
                              !busy &&
                              entry.isDirectory &&
                              (event.key === 'Enter' || event.key === ' ')
                            ) {
                              event.preventDefault();
                              onNavigate(entry.fullPath);
                            }
                          }}
                          role="option"
                          tabIndex={0}
                        >
                          <span className="flex items-center justify-center">
                            {entry.isDirectory ? (
                              <FolderOpen className="size-4 shrink-0 text-amber-400" />
                            ) : (
                              <File className="size-4 shrink-0 text-muted-foreground" />
                            )}
                          </span>
                          <span className="flex min-w-0 items-center">
                            {isEditing ? (
                              <Input
                                autoFocus
                                className="h-7 min-w-0 flex-1 text-xs"
                                onBlur={commitRename}
                                onChange={(event) => setEditingName(event.target.value)}
                                onFocus={(event) => event.currentTarget.select()}
                                onKeyDown={(event) => {
                                  if (event.key === 'Enter') commitRename();
                                  if (event.key === 'Escape') {
                                    renameCommitPath.current = editingPath;
                                    setEditingPath(undefined);
                                  }
                                }}
                                value={editingName}
                              />
                            ) : (
                              <span className="truncate text-foreground">{entry.name}</span>
                            )}
                          </span>
                          <span className="text-right text-muted-foreground">
                            {entry.isDirectory ? '' : formatSftpSize(entry.size)}
                          </span>
                          <span className="truncate text-muted-foreground">
                            {formatSftpDate(entry.lastModifiedUtc)}
                          </span>
                        </div>
                      </ContextMenuTrigger>
                      <ContextMenuContent className="w-44">
                        {entry.isDirectory || pane === 'local' ? (
                          <ContextMenuItem
                            onSelect={() =>
                              entry.isDirectory
                                ? onNavigate(entry.fullPath)
                                : onOperation('open', entry.fullPath)
                            }
                          >
                            {entry.isDirectory ? <FolderOpen /> : <File />}
                            Open
                          </ContextMenuItem>
                        ) : null}
                        {!entry.isDirectory ? (
                          <>
                            <ContextMenuItem onSelect={() => onEdit?.(entry)}>
                              Edit <span className="ml-auto">F4</span>
                            </ContextMenuItem>
                            <ContextMenuSub>
                              <ContextMenuSubTrigger>Edit with</ContextMenuSubTrigger>
                              <ContextMenuSubContent>
                                <ContextMenuItem onSelect={() => onEdit?.(entry, 'auto')}>
                                  Detected text editor
                                </ContextMenuItem>
                                <ContextMenuItem onSelect={() => onEdit?.(entry, 'system')}>
                                  System default application
                                </ContextMenuItem>
                                {editors.map((editor) => (
                                  <ContextMenuItem
                                    key={editor.id}
                                    onSelect={() => onEdit?.(entry, editor.id)}
                                  >
                                    {editor.name}
                                  </ContextMenuItem>
                                ))}
                              </ContextMenuSubContent>
                            </ContextMenuSub>
                          </>
                        ) : null}
                        <ContextMenuItem
                          onSelect={() =>
                            onCopy?.(
                              (validSelectedPaths.has(entry.fullPath)
                                ? selectedEntries
                                : [entry]
                              ).map((item) => ({
                                sourcePath: item.fullPath,
                                name: item.name,
                                isDirectory: item.isDirectory,
                                size: item.size,
                              })),
                            )
                          }
                        >
                          Copy to other panel <span className="ml-auto">F5</span>
                        </ContextMenuItem>
                        <ContextMenuItem onSelect={() => beginRename(entry)}>
                          <Pencil />
                          Rename
                        </ContextMenuItem>
                        <ContextMenuSeparator />
                        <ContextMenuItem
                          onSelect={() => {
                            if (!validSelectedPaths.has(entry.fullPath)) {
                              setSelectedPaths(new Set([entry.fullPath]));
                            }
                            setConfirmDelete(true);
                          }}
                          variant="destructive"
                        >
                          <Trash2 />
                          Delete
                        </ContextMenuItem>
                      </ContextMenuContent>
                    </ContextMenu>
                  );
                })}
              </div>
            </div>
          ) : state.entries.length > 0 && normalizedSearch ? (
            <div className="p-8 text-center text-xs text-muted-foreground">
              No files match your search
            </div>
          ) : null}
          {state.truncated ? (
            <p className="border-t border-border px-3 py-2 text-[10px] text-muted-foreground">
              Only the first 4,096 entries are shown.
            </p>
          ) : null}
        </div>
      </div>

      <div className="shrink-0 border-t border-border pt-1 text-[11px] text-muted-foreground">
        {selectedEntries.length} of {state.entries.length} selected ·{' '}
        {formatSftpSize(
          selectedEntries.reduce((total, entry) => total + (entry.isDirectory ? 0 : entry.size), 0),
        ) || '0 B'}
      </div>
      {state.error ? (
        <p className="shrink-0 pt-2 text-[11px] text-destructive">{state.error}</p>
      ) : null}

      {prompt ? (
        <div className="absolute inset-0 z-20 grid place-items-center bg-background/75 p-4 backdrop-blur-[1px]">
          <form
            className="w-full max-w-xs rounded-lg border border-border bg-card p-4 shadow-xl"
            onSubmit={(event) => {
              event.preventDefault();
              submitPrompt();
            }}
          >
            <p className="text-sm font-semibold">New {prompt === 'folder' ? 'folder' : 'file'}</p>
            <p className="mt-1 text-xs text-muted-foreground">Create it in {state.path}</p>
            <Input
              autoFocus
              className="mt-3"
              onChange={(event) => setPromptValue(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Escape') setPrompt(undefined);
              }}
              placeholder="Name"
              value={promptValue}
            />
            <div className="mt-4 flex justify-end gap-2">
              <Button onClick={() => setPrompt(undefined)} size="sm" type="button" variant="ghost">
                Cancel
              </Button>
              <Button disabled={!promptValue.trim()} size="sm" type="submit">
                Create
              </Button>
            </div>
          </form>
        </div>
      ) : null}
      {confirmDelete ? (
        <div className="absolute inset-0 z-20 grid place-items-center bg-background/75 p-4 backdrop-blur-[1px]">
          <div className="w-full max-w-xs rounded-lg border border-border bg-card p-4 shadow-xl">
            <p className="text-sm font-semibold">Delete selected items?</p>
            <p className="mt-1 text-xs text-muted-foreground">
              {selectedEntries.length} item(s) will be permanently removed.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <Button onClick={() => setConfirmDelete(false)} size="sm" variant="ghost">
                Cancel
              </Button>
              <Button onClick={deleteSelected} size="sm" variant="destructive">
                Delete
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function SftpTransferQueue({
  transfers,
  error,
  onClearError,
  onCancel,
  onRemove,
}: {
  transfers: SftpTransferRow[];
  error?: string;
  onClearError: () => void;
  onCancel: (transferId: string, itemId: string) => void;
  onRemove: (transferId: string, itemId: string) => void;
}) {
  return (
    <section
      aria-label="SFTP transfers"
      className="shrink-0 rounded-lg border border-border bg-card/30"
    >
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-foreground">
          Transfers
        </span>
        {transfers.length > 0 ? (
          <span className="text-[10px] text-muted-foreground">{transfers.length} item(s)</span>
        ) : null}
      </div>
      {error ? (
        <div className="flex items-start gap-2 border-b border-destructive/20 bg-destructive/5 px-3 py-2 text-[11px] text-destructive">
          <p className="min-w-0 flex-1">{error}</p>
          <IconButton label="Dismiss transfer error" onClick={onClearError}>
            <X />
          </IconButton>
        </div>
      ) : null}
      {transfers.length > 0 ? (
        <div className="max-h-32 divide-y divide-border/50 overflow-auto">
          {transfers.map((transfer) => {
            const terminal = isSftpTransferTerminal(transfer.state);
            const percentage =
              transfer.expectedBytes > 0
                ? Math.min(100, (transfer.bytesTransferred / transfer.expectedBytes) * 100)
                : terminal
                  ? 100
                  : 0;
            return (
              <div
                className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 px-3 py-2"
                key={`${transfer.transferId}:${transfer.itemId}`}
              >
                {terminal ? (
                  transfer.state === 'completed' ? (
                    <Check className="size-3.5 text-emerald-400" />
                  ) : transfer.state === 'cancelled' ? (
                    <X className="size-3.5 text-muted-foreground" />
                  ) : (
                    <AlertCircle className="size-3.5 text-destructive" />
                  )
                ) : transfer.direction === 'remote-to-local' ? (
                  <Download className="size-3.5 text-muted-foreground" />
                ) : (
                  <Upload className="size-3.5 text-muted-foreground" />
                )}
                <div className="min-w-0">
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="truncate">{transfer.displayName}</span>
                    <span className="shrink-0 text-[10px] text-muted-foreground">
                      {transfer.state === 'failed'
                        ? 'Failed'
                        : transfer.state === 'cancelled'
                          ? 'Cancelled'
                          : transfer.state === 'completed'
                            ? 'Done'
                            : `${Math.round(percentage)}%`}
                    </span>
                  </div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                    <div
                      className={`h-full rounded-full transition-[width] ${transfer.state === 'failed' ? 'bg-destructive' : transfer.state === 'cancelled' ? 'bg-muted-foreground' : 'bg-primary'}`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                  {transfer.error ? (
                    <p className="mt-1 truncate text-[10px] text-destructive">{transfer.error}</p>
                  ) : null}
                </div>
                <IconButton
                  label={
                    terminal ? `Remove ${transfer.displayName}` : `Cancel ${transfer.displayName}`
                  }
                  onClick={() =>
                    terminal
                      ? onRemove(transfer.transferId, transfer.itemId)
                      : onCancel(transfer.transferId, transfer.itemId)
                  }
                >
                  <X />
                </IconButton>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="px-3 py-3 text-[11px] text-muted-foreground">No active transfers.</p>
      )}
    </section>
  );
}

function SftpConflictOverlay({
  conflict,
  onDecision,
  onCancel,
}: {
  conflict: SftpConflict;
  onDecision: (decision: 'overwrite' | 'skip', applyToAll: boolean) => void;
  onCancel: () => void;
}) {
  const [applyToAll, setApplyToAll] = useState(false);
  return (
    <dialog
      open
      aria-label={`File conflict for ${conflict.displayName}`}
      className="absolute inset-0 z-40 m-0 h-full max-h-none w-full max-w-none place-items-center border-0 bg-background/80 p-6 backdrop-blur-sm open:grid"
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          event.stopPropagation();
          onCancel();
        }
      }}
    >
      <div className="w-full max-w-md rounded-xl border border-border bg-card p-5 shadow-2xl">
        <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-muted-foreground">
          File exists
        </p>
        <h3 className="mt-2 text-base font-semibold">Replace or skip this item?</h3>
        <p className="mt-2 text-sm text-muted-foreground">
          A {conflict.direction === 'local-to-remote' ? 'remote' : 'local'} item with the same name
          already exists. Overwriting will replace its contents.
        </p>
        <p className="mt-2 break-words text-sm text-foreground">{conflict.displayName}</p>
        <p className="mt-1 break-all text-xs text-muted-foreground">{conflict.path}</p>
        <div className="mt-4 grid grid-cols-2 gap-2 text-xs text-muted-foreground">
          <span>Incoming: {formatSftpSize(conflict.incomingSize)}</span>
          <span>
            Existing:{' '}
            {conflict.existingIsDirectory ? 'Folder' : formatSftpSize(conflict.existingSize)}
          </span>
        </div>
        <label className="mt-4 flex items-center gap-2 text-xs text-muted-foreground">
          <Checkbox
            checked={applyToAll}
            onCheckedChange={(checked) => setApplyToAll(checked === true)}
          />
          Apply to remaining conflicts
        </label>
        <div className="mt-5 flex justify-end gap-2">
          <Button onClick={() => onDecision('overwrite', applyToAll)} size="sm" variant="outline">
            Overwrite
          </Button>
          <Button autoFocus onClick={() => onDecision('skip', applyToAll)} size="sm">
            Skip
          </Button>
          <Button onClick={onCancel} size="sm" variant="ghost">
            Cancel
          </Button>
        </div>
      </div>
    </dialog>
  );
}

export function SftpBrowserSurface({
  session,
  onClose,
  onNavigate,
  onLocalNavigate,
  onRefresh,
  onOperation,
  onTransfer,
  onConflict,
  onTransferCancel,
  onTransferErrorClear,
  onTransferRemove,
}: {
  session: SftpBrowserSession;
  onClose: () => void;
  onNavigate: (path: string) => void;
  onLocalNavigate: (path: string) => void;
  onRefresh: (pane: SftpPaneKind) => void;
  onOperation: (
    pane: SftpPaneKind,
    operation: SftpOperation,
    path: string,
    destinationPath?: string,
  ) => void;
  onTransfer: (
    direction: SftpTransferDirection,
    destinationPath: string,
    items: SftpTransferItem[],
  ) => void;
  onConflict: (
    transferId: string,
    itemId: string,
    decision: 'overwrite' | 'skip',
    applyToAll: boolean,
  ) => void;
  onTransferCancel: (transferId: string, itemId: string) => void;
  onTransferErrorClear: () => void;
  onTransferRemove: (transferId: string, itemId: string) => void;
}) {
  const [swapped, setSwapped] = useState(false);
  const [editorSettings, setEditorSettings] = useState<WormholeSftpEditorSettings>();
  const [editError, setEditError] = useState('');
  useEffect(() => {
    void window.wormhole
      ?.readSftpEditorSettings()
      .then((settings) => {
        setEditorSettings(settings);
        setSwapped(settings.swapPanels);
      })
      .catch(() => undefined);
  }, []);
  function editFile(
    pane: SftpPaneKind,
    entry: WormholeSftpEntry,
    editorId?: string,
    allowBinary = false,
  ) {
    if (!session.backendSessionId || entry.isDirectory) return;
    setEditError('');
    void window.wormhole
      ?.sftpEdit(session.backendSessionId, {
        operation: 'start',
        pane,
        path: entry.fullPath,
        editorId,
        allowBinary,
      })
      .then((result) => {
        if (result.error?.includes('binary-file-confirmation-required')) {
          if (window.confirm(`${entry.name} looks like a binary file. Open it in the editor?`))
            editFile(pane, entry, editorId, true);
        } else setEditError(result.error ?? '');
      })
      .catch((error: unknown) =>
        setEditError(error instanceof Error ? error.message : String(error)),
      );
  }
  const [queueOpen, setQueueOpen] = useState(true);
  const browser = session.sftp!;
  const local: SftpPaneState = browser.local ?? {
    status: 'opening',
    path: '',
    entries: [],
    truncated: false,
  };
  const remote: SftpPaneState = {
    status:
      browser.status === 'failed' ? 'failed' : browser.status === 'opening' ? 'opening' : 'ready',
    path: browser.path,
    entries: browser.entries,
    truncated: browser.truncated,
    error: browser.error,
  };
  const closing = browser.status === 'closing';
  const treeRevision = JSON.stringify([
    browser.refreshRequests,
    browser.transfers
      ?.filter((transfer) => isSftpTransferTerminal(transfer.state))
      .map((transfer) => [transfer.transferId, transfer.itemId, transfer.state]),
  ]);

  function handleDrop(targetPane: SftpPaneKind, targetPath: string, payload: SftpDragPayload) {
    if (payload.sourcePane === 'remote' && targetPane === 'remote') return;
    if (
      targetPane === 'local' &&
      payload.sourcePane === 'local' &&
      isInvalidLocalSftpDropDestination(targetPath, payload.items)
    ) {
      return;
    }
    if (payload.sourcePane === 'local' && targetPane === 'remote') {
      onTransfer('local-to-remote', targetPath, payload.items);
    } else if (payload.sourcePane === 'remote' && targetPane === 'local') {
      onTransfer('remote-to-local', targetPath, payload.items);
    } else if (payload.sourcePane === 'local' && targetPane === 'local') {
      onTransfer('local-to-local', targetPath, payload.items);
    }
  }

  const localPanel = (
    <ResizablePanel key="local" minSize="20%" className="flex">
      <SftpFilePane
        onNavigate={onLocalNavigate}
        onOperation={(operation, path, destinationPath) =>
          onOperation('local', operation, path, destinationPath)
        }
        onRefresh={() => onRefresh('local')}
        onTransfer={(payload, destinationPath) => handleDrop('local', destinationPath, payload)}
        editors={editorSettings?.editors}
        onEdit={(entry, editorId) => editFile('local', entry, editorId)}
        pane="local"
        sessionId={session.backendSessionId}
        revision={treeRevision}
        onCopy={(items) => {
          if (remote.path && items.length) onTransfer('local-to-remote', remote.path, items);
        }}
        state={local}
      />
    </ResizablePanel>
  );
  const remotePanel = (
    <ResizablePanel key="remote" minSize="20%" className="flex">
      <SftpFilePane
        onNavigate={onNavigate}
        onOperation={(operation, path, destinationPath) =>
          onOperation('remote', operation, path, destinationPath)
        }
        onRefresh={() => onRefresh('remote')}
        onTransfer={(payload, destinationPath) => handleDrop('remote', destinationPath, payload)}
        editors={editorSettings?.editors}
        onEdit={(entry, editorId) => editFile('remote', entry, editorId)}
        pane="remote"
        sessionId={session.backendSessionId}
        revision={treeRevision}
        onCopy={(items) => {
          if (local.path && items.length) onTransfer('remote-to-local', local.path, items);
        }}
        state={remote}
      />
    </ResizablePanel>
  );

  return (
    <div
      aria-label="SFTP browser"
      className="relative flex h-full min-h-0 flex-col gap-3 overflow-hidden bg-background p-3"
      data-wormhole-shortcuts-disabled
    >
      <div className="flex shrink-0 items-center gap-2">
        <ArrowRightLeft className="size-4 shrink-0 text-primary" />
        <Button
          className="ml-auto"
          size="sm"
          variant="ghost"
          onClick={() => setSwapped((current) => !current)}
        >
          Swap panels
        </Button>
        <Button
          size="sm"
          variant="ghost"
          aria-expanded={queueOpen}
          onClick={() => setQueueOpen((current) => !current)}
        >
          Queue ({browser.transfers?.length ?? 0})
        </Button>
        <h2 className="truncate text-sm font-semibold">{session.title}</h2>
        <span className="truncate text-xs text-muted-foreground">{session.host || 'SSH'}</span>
      </div>

      {Object.keys(browser.knownOperationIds ?? {}).length > 0 ? (
        <p role="status" className="text-xs text-muted-foreground">
          File operation queued; waiting for the transfer queue…
        </p>
      ) : null}
      {closing ? (
        <div className="absolute inset-0 z-30 grid place-items-center bg-background/80 text-sm text-muted-foreground backdrop-blur-sm">
          <LoaderCircle className="mr-2 size-4 animate-spin" />
          Closing SFTP browser…
        </div>
      ) : null}

      <ResizablePanelGroup
        className="min-h-0 flex-1 gap-2 overflow-hidden"
        orientation="horizontal"
      >
        {swapped ? remotePanel : localPanel}
        <ResizableHandle withHandle />
        {swapped ? localPanel : remotePanel}
      </ResizablePanelGroup>

      {queueOpen && ((browser.transfers?.length ?? 0) > 0 || browser.transferError) ? (
        <SftpTransferQueue
          error={browser.transferError}
          onCancel={onTransferCancel}
          onClearError={onTransferErrorClear}
          onRemove={onTransferRemove}
          transfers={browser.transfers ?? []}
        />
      ) : null}

      {editError ? (
        <p role="alert" className="text-xs text-destructive">
          {editError}
        </p>
      ) : null}
      {session.backendSessionId ? <SftpEditedFiles sessionId={session.backendSessionId} /> : null}
      <div className="flex shrink-0 justify-end">
        <Button disabled={closing} onClick={onClose} size="sm">
          Close
        </Button>
      </div>

      {browser.conflict ? (
        <SftpConflictOverlay
          conflict={browser.conflict}
          key={`${browser.conflict.transferId}:${browser.conflict.itemId}`}
          onCancel={() =>
            onConflict(browser.conflict!.transferId, browser.conflict!.itemId, 'skip', false)
          }
          onDecision={(decision, applyToAll) =>
            onConflict(browser.conflict!.transferId, browser.conflict!.itemId, decision, applyToAll)
          }
        />
      ) : null}
    </div>
  );
}
