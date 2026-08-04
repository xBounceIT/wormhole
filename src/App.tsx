import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ComponentProps,
  type CSSProperties,
  type DragEvent,
  type FormEvent,
  type ReactNode,
} from 'react';
import wormholeIcon from '../Assets/Wormhole.png';
import {
  ArrowRightLeft,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Check,
  Copy,
  Download,
  Folder,
  FolderOpen,
  FolderPlus,
  Globe,
  KeyRound,
  Monitor,
  MoreHorizontal,
  Network,
  PanelLeft,
  Pencil,
  Plus,
  Power,
  Radio,
  RefreshCcw,
  Search,
  Settings2,
  Terminal,
  Upload,
  Wifi,
  X,
  Zap,
} from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from '@/components/ui/context-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { Kbd } from '@/components/ui/kbd';
import { Label } from '@/components/ui/label';
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from '@/components/ui/resizable';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarInput,
  SidebarInset,
} from '@/components/ui/sidebar';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { getTreeRowGeometry } from './tree-layout';

type Protocol = 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
type NavItem = 'sessions' | 'credentials' | 'tunnels' | 'settings';
type Theme = 'system' | 'light' | 'dark';
type ResolvedTheme = Exclude<Theme, 'system'>;

const themeStorageKey = 'wormhole-theme';

function isTheme(value: string | null): value is Theme {
  return value === 'system' || value === 'light' || value === 'dark';
}

function getInitialTheme(): Theme {
  if (typeof window === 'undefined') return 'dark';

  const storedTheme = window.localStorage.getItem(themeStorageKey);
  return isTheme(storedTheme) ? storedTheme : 'dark';
}

function getSystemTheme(): ResolvedTheme {
  if (typeof window === 'undefined') return 'light';

  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

type TreeNode = {
  id: string;
  name: string;
  kind: 'folder' | 'connection';
  protocol?: Protocol;
  host?: string;
  children?: TreeNode[];
};

type DropPlacement = 'inside' | 'before' | 'after';

function findTreeNode(nodes: TreeNode[], nodeId: string): TreeNode | undefined {
  for (const node of nodes) {
    if (node.id === nodeId) return node;
    if (node.children) {
      const match = findTreeNode(node.children, nodeId);
      if (match) return match;
    }
  }

  return undefined;
}

function containsTreeNode(node: TreeNode, nodeId: string): boolean {
  return Boolean(
    node.children?.some((child) => child.id === nodeId || containsTreeNode(child, nodeId)),
  );
}

function extractTreeNodes(
  nodes: TreeNode[],
  nodeIds: ReadonlySet<string>,
): { nodes: TreeNode[]; extracted: TreeNode[] } {
  const extracted: TreeNode[] = [];
  const remaining = nodes.flatMap((node) => {
    if (nodeIds.has(node.id)) {
      extracted.push(node);
      return [];
    }

    if (!node.children) return [node];

    const childResult = extractTreeNodes(node.children, nodeIds);
    extracted.push(...childResult.extracted);
    return [{ ...node, children: childResult.nodes }];
  });

  return { nodes: remaining, extracted };
}

function insertIntoTreeFolder(
  nodes: TreeNode[],
  folderId: string,
  children: TreeNode[],
): TreeNode[] {
  return nodes.map((node) => {
    if (node.id === folderId) {
      return { ...node, children: [...(node.children ?? []), ...children] };
    }

    return node.children
      ? { ...node, children: insertIntoTreeFolder(node.children, folderId, children) }
      : node;
  });
}

function insertRelativeToTreeNode(
  nodes: TreeNode[],
  targetId: string,
  children: TreeNode[],
  placement: Exclude<DropPlacement, 'inside'>,
): TreeNode[] {
  const targetIndex = nodes.findIndex((node) => node.id === targetId);
  if (targetIndex >= 0) {
    const next = [...nodes];
    next.splice(targetIndex + (placement === 'after' ? 1 : 0), 0, ...children);
    return next;
  }

  return nodes.map((node) =>
    node.children
      ? {
          ...node,
          children: insertRelativeToTreeNode(node.children, targetId, children, placement),
        }
      : node,
  );
}

function canDropTreeNodes(
  nodes: TreeNode[],
  draggedIds: readonly string[],
  targetId: string,
  placement: DropPlacement,
): boolean {
  const target = findTreeNode(nodes, targetId);
  const uniqueDraggedIds = [...new Set(draggedIds)];
  if (!target || uniqueDraggedIds.length === 0 || uniqueDraggedIds.includes(targetId)) return false;

  return uniqueDraggedIds.every((draggedId) => {
    const dragged = findTreeNode(nodes, draggedId);
    if (!dragged) return false;
    if (placement === 'inside' && target.kind !== 'folder') return false;
    if (dragged.kind === 'folder' && containsTreeNode(dragged, targetId)) return false;
    return true;
  });
}

function moveTreeNodes(
  nodes: TreeNode[],
  draggedIds: readonly string[],
  targetId: string,
  placement: DropPlacement,
): TreeNode[] {
  if (!canDropTreeNodes(nodes, draggedIds, targetId, placement)) return nodes;

  const uniqueDraggedIds = [...new Set(draggedIds)];
  const { nodes: remaining, extracted } = extractTreeNodes(nodes, new Set(uniqueDraggedIds));
  if (extracted.length !== uniqueDraggedIds.length) return nodes;

  return placement === 'inside'
    ? insertIntoTreeFolder(remaining, targetId, extracted)
    : insertRelativeToTreeNode(remaining, targetId, extracted, placement);
}

function parseDraggedNodeIds(value: string): string[] {
  if (!value) return [];

  try {
    const parsed: unknown = JSON.parse(value);
    if (Array.isArray(parsed) && parsed.every((id) => typeof id === 'string')) {
      return [...new Set(parsed)];
    }
  } catch {
    // Fall back to the single-node payload used by older drag sources.
  }

  return [value];
}

type Session = {
  id: string;
  title: string;
  protocol: Protocol;
  host: string;
  canTransfer?: boolean;
  nodeId?: string;
  backendSessionId?: string;
  status: 'connecting' | 'connected' | 'failed' | 'closed' | 'placeholder';
  output: string;
  error?: string;
  fingerprint?: string;
};

type CredentialRecord = {
  id: string;
  name: string;
  protocol: Protocol;
  username: string;
  domain?: string;
  provider: 'Local' | 'Bitwarden';
  readOnly?: boolean;
};

type TunnelRecord = {
  id: string;
  name: string;
  kind: string;
};

function newSessionToken(): string {
  return typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `ssh-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function decodeTerminalData(value: string, decoder: TextDecoder, stream: boolean): string {
  try {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return decoder.decode(bytes, { stream });
  } catch {
    return '';
  }
}

function encodeTerminalData(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function appendTerminalOutput(current: string, next: string): string {
  const combined = current + next;
  return combined.length > 256_000 ? combined.slice(-256_000) : combined;
}

const navItems: Array<{ id: NavItem; label: string; hint: string }> = [
  { id: 'credentials', label: 'Credentials', hint: 'Stored access profiles' },
  { id: 'sessions', label: 'Sessions', hint: 'Open connections' },
  { id: 'tunnels', label: 'Tunnels', hint: 'VPN and network routes' },
  { id: 'settings', label: 'Settings', hint: 'Application preferences' },
];

function protocolLabel(protocol: Protocol) {
  return { ssh: 'SSH', rdp: 'RDP', http: 'HTTP', https: 'HTTPS', vnc: 'VNC', serial: 'Serial' }[
    protocol
  ];
}

function ProtocolIcon({ protocol, size = 15 }: { protocol: Protocol; size?: number }) {
  if (protocol === 'ssh') return <Terminal size={size} />;
  if (protocol === 'rdp') return <Monitor size={size} />;
  if (protocol === 'http' || protocol === 'https') return <Globe size={size} />;
  if (protocol === 'vnc') return <Monitor size={size} />;
  return <Radio size={size} />;
}

function protocolTone(protocol: Protocol) {
  return {
    ssh: 'text-foreground',
    rdp: 'text-muted-foreground',
    http: 'text-foreground/70',
    https: 'text-foreground/80',
    vnc: 'text-muted-foreground/80',
    serial: 'text-foreground/60',
  }[protocol];
}

function filterTree(nodes: TreeNode[], query: string): TreeNode[] {
  if (!query) return nodes;

  return nodes.flatMap((node) => {
    const children = node.children ? filterTree(node.children, query) : [];
    const matches = node.name.toLowerCase().includes(query);
    return matches || children.length > 0 ? [{ ...node, children }] : [];
  });
}

function collectFolderIds(nodes: TreeNode[]): string[] {
  return nodes.flatMap((node) => [
    ...(node.kind === 'folder' ? [node.id] : []),
    ...(node.children ? collectFolderIds(node.children) : []),
  ]);
}

function collectFolders(nodes: TreeNode[]): TreeNode[] {
  return nodes.flatMap((node) =>
    node.kind === 'folder' ? [node, ...(node.children ? collectFolders(node.children) : [])] : [],
  );
}

function findFirstConnection(nodes: TreeNode[]): TreeNode | undefined {
  for (const node of nodes) {
    if (node.kind === 'connection') return node;
    if (node.children) {
      const match = findFirstConnection(node.children);
      if (match) return match;
    }
  }
  return undefined;
}

function findParentFolderId(nodes: TreeNode[], childId: string): string | undefined {
  for (const node of nodes) {
    if (node.kind === 'folder' && node.children?.some((child) => child.id === childId)) {
      return node.id;
    }

    if (node.children) {
      const parentId = findParentFolderId(node.children, childId);
      if (parentId) return parentId;
    }
  }

  return undefined;
}

function updateConnectionInTree(
  nodes: TreeNode[],
  connectionId: string,
  folderId: string,
  update: { name: string; host: string; protocol: Protocol },
): TreeNode[] {
  let editedConnection: TreeNode | undefined;

  function removeConnection(items: TreeNode[]): TreeNode[] {
    return items.flatMap((node) => {
      if (node.id === connectionId) {
        editedConnection = { ...node, ...update };
        return [];
      }

      return node.children ? [{ ...node, children: removeConnection(node.children) }] : [node];
    });
  }

  const remaining = removeConnection(nodes);
  if (!editedConnection) return nodes;

  return insertIntoTreeFolder(remaining, folderId, [editedConnection]);
}

type IconButtonProps = Omit<ComponentProps<typeof Button>, 'children' | 'size'> & {
  label: string;
  children: ReactNode;
};

function IconButton({ label, children, className, ...props }: IconButtonProps) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button aria-label={label} className={className} size="icon-sm" variant="ghost" {...props}>
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent side="bottom">{label}</TooltipContent>
    </Tooltip>
  );
}

function NodeContextMenu({
  node,
  children,
  onEdit,
  onNewConnection,
  onNewFolder,
}: {
  node: TreeNode;
  children: ReactNode;
  onEdit: () => void;
  onNewConnection: () => void;
  onNewFolder: () => void;
}) {
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
      <ContextMenuContent className="w-52">
        <ContextMenuItem onSelect={onNewFolder}>
          <FolderPlus />
          {node.kind === 'folder' ? 'New subfolder' : 'New folder'}
        </ContextMenuItem>
        <ContextMenuItem onSelect={onNewConnection}>
          <Plus />
          {node.kind === 'folder' ? 'New connection here' : 'New connection'}
        </ContextMenuItem>
        <ContextMenuSeparator />
        {node.kind === 'connection' ? (
          <>
            <ContextMenuItem>
              <KeyRound />
              Show credentials
            </ContextMenuItem>
            <ContextMenuItem>
              <Terminal />
              Duplicate connection
            </ContextMenuItem>
            <ContextMenuSeparator />
          </>
        ) : null}
        <ContextMenuItem onSelect={onEdit}>
          <Settings2 />
          Edit
        </ContextMenuItem>
        <ContextMenuItem variant="destructive">
          <X />
          Delete
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}

function SessionTabContextMenu({
  session,
  children,
  onReconnect,
  onDuplicate,
  onClose,
  onFileTransfer,
}: {
  session: Session;
  children: ReactNode;
  onReconnect: () => void;
  onDuplicate: () => void;
  onClose: () => void;
  onFileTransfer: () => void;
}) {
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
      <ContextMenuContent className="w-44">
        <ContextMenuItem onSelect={onDuplicate}>
          <Copy />
          Duplicate
        </ContextMenuItem>
        <ContextMenuItem onSelect={onReconnect}>
          <RefreshCcw />
          Reconnect
        </ContextMenuItem>
        {session.canTransfer ? (
          <ContextMenuItem onSelect={onFileTransfer}>
            <ArrowRightLeft />
            File transfer
          </ContextMenuItem>
        ) : null}
        <ContextMenuSeparator />
        <ContextMenuItem onSelect={onClose}>
          <X />
          Close
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}

function NodeTooltip({ node, children }: { node: TreeNode; children: ReactNode }) {
  if (!node.host) return children;

  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side="right">{node.host}</TooltipContent>
    </Tooltip>
  );
}

function TreeSelectionCheckbox({
  checked,
  label,
  onCheckedChange,
}: {
  checked: boolean;
  label: string;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <span
      aria-checked={checked}
      aria-label={label}
      className={[
        'relative z-30 grid size-4 shrink-0 cursor-pointer place-items-center rounded-[4px] border transition-colors outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50',
        checked
          ? 'border-primary bg-primary text-primary-foreground'
          : 'border-input bg-sidebar text-transparent hover:border-ring group-hover/button:bg-sidebar-accent',
      ].join(' ')}
      data-state={checked ? 'checked' : 'unchecked'}
      draggable={false}
      onClick={(event) => {
        event.stopPropagation();
        onCheckedChange(!checked);
      }}
      onDragStart={(event) => {
        event.preventDefault();
        event.stopPropagation();
      }}
      onKeyDown={(event) => {
        if (event.key !== ' ' && event.key !== 'Enter') return;

        event.preventDefault();
        event.stopPropagation();
        onCheckedChange(!checked);
      }}
      onPointerDown={(event) => event.stopPropagation()}
      role="checkbox"
      tabIndex={0}
    >
      {checked ? <Check className="size-3.5" /> : null}
    </span>
  );
}

function App() {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(getSystemTheme);
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [credentials, setCredentials] = useState<CredentialRecord[]>([]);
  const [tunnels, setTunnels] = useState<TunnelRecord[]>([]);
  const [workspaceStatus, setWorkspaceStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const [activePage, setActivePage] = useState<NavItem>('sessions');
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [selectedNodeId, setSelectedNodeId] = useState('');
  const [selectedTreeNodeIds, setSelectedTreeNodeIds] = useState<Set<string>>(() => new Set());
  const [searchText, setSearchText] = useState('');
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState('');
  const [quickConnectOpen, setQuickConnectOpen] = useState(false);
  const [quickConnectForm, setQuickConnectForm] = useState({
    name: '',
    host: '',
    protocol: 'ssh' as Protocol,
  });
  const [newConnectionOpen, setNewConnectionOpen] = useState(false);
  const [editingConnectionId, setEditingConnectionId] = useState<string | null>(null);
  const [newConnectionForm, setNewConnectionForm] = useState({
    name: '',
    host: '',
    protocol: 'ssh' as Protocol,
    folder: '',
  });
  const [newFolderOpen, setNewFolderOpen] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [newFolderParentId, setNewFolderParentId] = useState<string | null>(null);
  const [updateVisible, setUpdateVisible] = useState(true);
  const [draggedNodeIds, setDraggedNodeIds] = useState<string[]>([]);
  const [dropTarget, setDropTarget] = useState<{
    id: string;
    placement: DropPlacement;
  } | null>(null);
  const terminalDecoders = useRef(new Map<string, TextDecoder>());

  const visibleTree = useMemo(
    () => filterTree(tree, searchText.trim().toLowerCase()),
    [searchText, tree],
  );
  const folders = useMemo(() => collectFolders(tree), [tree]);
  const selectedSession =
    sessions.find((session) => session.id === selectedSessionId) ?? sessions[0];
  const resolvedTheme = theme === 'system' ? systemTheme : theme;

  useLayoutEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', resolvedTheme === 'dark');
    root.style.colorScheme = resolvedTheme;
  }, [resolvedTheme]);

  useEffect(() => {
    window.localStorage.setItem(themeStorageKey, theme);
  }, [theme]);

  useEffect(() => {
    let mounted = true;

    async function loadWorkspace() {
      if (!window.wormhole) {
        setWorkspaceStatus('error');
        return;
      }

      try {
        const workspace = await window.wormhole.loadWorkspace();
        if (!mounted) return;

        setTree(workspace.tree);
        setCredentials(workspace.credentials);
        setTunnels(workspace.tunnels);
        setSelectedTreeNodeIds(new Set());
        setExpanded(new Set(collectFolderIds(workspace.tree)));
        const firstConnection = findFirstConnection(workspace.tree);
        setSelectedNodeId(firstConnection?.id ?? workspace.tree[0]?.id ?? '');
        setWorkspaceStatus('ready');
      } catch {
        if (!mounted) return;
        setTree([]);
        setCredentials([]);
        setTunnels([]);
        setSelectedTreeNodeIds(new Set());
        setExpanded(new Set());
        setSelectedNodeId('');
        setWorkspaceStatus('error');
      }
    }

    void loadWorkspace();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    const decoders = terminalDecoders.current;
    const unsubscribe = window.wormhole?.onSshEvent((event) => {
      let output = '';
      if (event.type === 'connected') {
        decoders.set(event.sessionId, new TextDecoder());
      } else if (event.type === 'data') {
        const decoder = decoders.get(event.sessionId) ?? new TextDecoder();
        decoders.set(event.sessionId, decoder);
        output = decodeTerminalData(event.data, decoder, true);
      } else if (event.type === 'closed') {
        const decoder = decoders.get(event.sessionId);
        if (decoder) output = decoder.decode();
        decoders.delete(event.sessionId);
      }

      setSessions((current) =>
        current.map((session) => {
          if (session.backendSessionId !== event.sessionId) return session;
          if (event.type === 'connected') {
            return {
              ...session,
              status: 'connected',
              host: event.host,
              fingerprint: event.fingerprint,
              error: undefined,
            };
          }
          if (event.type === 'data') {
            return {
              ...session,
              output: appendTerminalOutput(session.output, output),
            };
          }
          if (event.type === 'error') {
            return {
              ...session,
              status: 'failed',
              output: appendTerminalOutput(session.output, output),
              error: event.error,
            };
          }
          return {
            ...session,
            status: 'closed',
            output: appendTerminalOutput(session.output, output),
          };
        }),
      );
    });

    return () => {
      unsubscribe?.();
      decoders.clear();
    };
  }, []);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleSystemThemeChange = (event: MediaQueryListEvent) => {
      setSystemTheme(event.matches ? 'dark' : 'light');
    };

    setSystemTheme(mediaQuery.matches ? 'dark' : 'light');
    mediaQuery.addEventListener('change', handleSystemThemeChange);
    return () => mediaQuery.removeEventListener('change', handleSystemThemeChange);
  }, []);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        openQuickConnect();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  function toggleFolder(id: string, value?: boolean) {
    setExpanded((current) => {
      const next = new Set(current);
      const shouldOpen = value ?? !next.has(id);
      if (shouldOpen) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function toggleTreeNodeSelection(id: string, checked: boolean) {
    setSelectedTreeNodeIds((current) => {
      const next = new Set(current);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function getDraggedNodeIds(node: TreeNode): string[] {
    if (!selectedTreeNodeIds.has(node.id)) return [node.id];

    const selectedIds = [...selectedTreeNodeIds].filter((id) => findTreeNode(tree, id));
    const selectedNodes = selectedIds
      .map((id) => findTreeNode(tree, id))
      .filter((selected): selected is TreeNode => Boolean(selected));

    return selectedNodes
      .filter(
        (selected) =>
          !selectedNodes.some(
            (ancestor) => ancestor.id !== selected.id && containsTreeNode(ancestor, selected.id),
          ),
      )
      .map((selected) => selected.id);
  }

  function getTreeDropPlacement(event: DragEvent<HTMLDivElement>, node: TreeNode): DropPlacement {
    const bounds = event.currentTarget.getBoundingClientRect();
    const position = (event.clientY - bounds.top) / Math.max(bounds.height, 1);

    if (node.kind === 'folder' && position > 0.25 && position < 0.75) return 'inside';
    return position < 0.5 ? 'before' : 'after';
  }

  function handleTreeDragStart(event: DragEvent<HTMLButtonElement>, node: TreeNode) {
    if (searchText.trim()) {
      event.preventDefault();
      return;
    }

    event.dataTransfer.effectAllowed = 'move';
    const draggedIds = getDraggedNodeIds(node);
    event.dataTransfer.setData('text/plain', JSON.stringify(draggedIds));
    setDraggedNodeIds(draggedIds);
    setDropTarget(null);
  }

  function handleTreeDragOver(event: DragEvent<HTMLDivElement>, node: TreeNode) {
    if (draggedNodeIds.length === 0 || searchText.trim()) return;

    const placement = getTreeDropPlacement(event, node);
    if (!canDropTreeNodes(tree, draggedNodeIds, node.id, placement)) {
      event.dataTransfer.dropEffect = 'none';
      setDropTarget(null);
      return;
    }

    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
    setDropTarget({ id: node.id, placement });
  }

  function handleTreeDragLeave(event: DragEvent<HTMLDivElement>, node: TreeNode) {
    const relatedTarget = event.relatedTarget;
    if (relatedTarget instanceof Element && event.currentTarget.contains(relatedTarget)) return;

    setDropTarget((current) => (current?.id === node.id ? null : current));
  }

  function handleTreeDrop(event: DragEvent<HTMLDivElement>, node: TreeNode) {
    event.preventDefault();
    const sourceIds =
      draggedNodeIds.length > 0
        ? draggedNodeIds
        : parseDraggedNodeIds(event.dataTransfer.getData('text/plain'));
    if (sourceIds.length === 0 || searchText.trim()) return;

    const placement = getTreeDropPlacement(event, node);
    if (!canDropTreeNodes(tree, sourceIds, node.id, placement)) return;

    setTree((current) => moveTreeNodes(current, sourceIds, node.id, placement));
    setSelectedNodeId(sourceIds[0]);
    if (placement === 'inside') toggleFolder(node.id, true);
    setDraggedNodeIds([]);
    setDropTarget(null);
  }

  function handleTreeDragEnd() {
    setDraggedNodeIds([]);
    setDropTarget(null);
  }

  function startSshSession(sessionId: string, nodeId: string) {
    const api = window.wormhole;
    if (!api) {
      setSessions((current) =>
        current.map((session) =>
          session.backendSessionId === sessionId
            ? { ...session, status: 'failed', error: 'The native SSH bridge is unavailable.' }
            : session,
        ),
      );
      return;
    }

    void api
      .openSshSession({ sessionId, nodeId, columns: 80, rows: 24 })
      .catch((error: unknown) => {
        setSessions((current) =>
          current.map((session) =>
            session.backendSessionId === sessionId
              ? {
                  ...session,
                  status: 'failed',
                  error: error instanceof Error ? error.message : String(error),
                }
              : session,
          ),
        );
      });
  }

  function openConnection(node: TreeNode) {
    if (node.kind !== 'connection' || !node.protocol) return;

    const existing = sessions.find((session) => session.id === `session-${node.id}`);
    if (existing) {
      setSelectedSessionId(existing.id);
      setActivePage('sessions');
      return;
    }

    const backendSessionId = node.protocol === 'ssh' ? newSessionToken() : undefined;
    const session: Session = {
      id: `session-${node.id}`,
      title: node.name,
      protocol: node.protocol,
      host: node.host ?? 'inherited target',
      canTransfer: node.protocol === 'ssh',
      nodeId: node.id,
      backendSessionId,
      status: node.protocol === 'ssh' ? 'connecting' : 'placeholder',
      output: '',
    };

    setSessions((current) => [...current, session]);
    setSelectedSessionId(session.id);
    setActivePage('sessions');
    if (backendSessionId) startSshSession(backendSessionId, node.id);
  }

  function closeSession(id: string) {
    const closing = sessions.find((session) => session.id === id);
    const index = sessions.findIndex((session) => session.id === id);
    const nextSessions = sessions.filter((session) => session.id !== id);
    setSessions(nextSessions);

    if (closing?.backendSessionId) {
      void window.wormhole?.closeSshSession(closing.backendSessionId);
    }

    if (selectedSessionId === id) {
      setSelectedSessionId(nextSessions[index]?.id ?? nextSessions[index - 1]?.id ?? '');
    }
  }

  function reconnectSession(id: string) {
    const source = sessions.find((session) => session.id === id);
    if (!source) return;

    if (source.backendSessionId) void window.wormhole?.closeSshSession(source.backendSessionId);
    if (source.nodeId && source.protocol === 'ssh') {
      const backendSessionId = newSessionToken();
      setSessions((current) =>
        current.map((session) =>
          session.id === id
            ? {
                ...session,
                backendSessionId,
                status: 'connecting',
                output: '',
                error: undefined,
              }
            : session,
        ),
      );
      startSshSession(backendSessionId, source.nodeId);
    }

    setSelectedSessionId(id);
    setActivePage('sessions');
  }

  function duplicateSession(id: string) {
    const source = sessions.find((session) => session.id === id);
    if (!source) return;

    const duplicate: Session = {
      ...source,
      id: `session-duplicate-${Date.now()}`,
      title: `${source.title} (copy)`,
      backendSessionId: source.protocol === 'ssh' ? newSessionToken() : undefined,
      status: source.protocol === 'ssh' ? 'connecting' : 'placeholder',
      output: '',
      error: undefined,
    };
    setSessions((current) => {
      const index = current.findIndex((session) => session.id === id);
      if (index < 0) return [...current, duplicate];

      const next = [...current];
      next.splice(index + 1, 0, duplicate);
      return next;
    });
    setSelectedSessionId(duplicate.id);
    setActivePage('sessions');
    if (duplicate.backendSessionId && duplicate.nodeId) {
      startSshSession(duplicate.backendSessionId, duplicate.nodeId);
    }
  }

  function openFileTransfer(id: string) {
    setSelectedSessionId(id);
    setActivePage('sessions');
  }

  function sendSshInput(sessionId: string, value: string) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session?.backendSessionId || session.status !== 'connected') return;

    void window.wormhole
      ?.sendSshInput(session.backendSessionId, encodeTerminalData(value))
      .catch((error: unknown) => {
        setSessions((current) =>
          current.map((candidate) =>
            candidate.id === sessionId
              ? {
                  ...candidate,
                  status: 'failed',
                  error: error instanceof Error ? error.message : String(error),
                }
              : candidate,
          ),
        );
      });
  }

  function openQuickConnect() {
    setQuickConnectForm({ name: '', host: '', protocol: 'ssh' });
    setQuickConnectOpen(true);
  }

  function getCreationFolderId(): string | undefined {
    const selectedNode = findTreeNode(tree, selectedNodeId);
    if (selectedNode?.kind === 'folder') return selectedNode.id;
    return findParentFolderId(tree, selectedNodeId) ?? folders[0]?.id;
  }

  function openNewConnection(folderId?: string) {
    setEditingConnectionId(null);
    setNewConnectionForm({
      name: '',
      host: '',
      protocol: 'ssh',
      folder: folderId ?? getCreationFolderId() ?? folders[0]?.id ?? '',
    });
    setNewConnectionOpen(true);
  }

  function openEditConnection(node: TreeNode) {
    if (node.kind !== 'connection' || !node.protocol) return;

    setSelectedNodeId(node.id);
    setEditingConnectionId(node.id);
    setNewConnectionForm({
      name: node.name,
      host: node.host ?? '',
      protocol: node.protocol,
      folder: findParentFolderId(tree, node.id) ?? folders[0]?.id ?? '',
    });
    setNewConnectionOpen(true);
  }

  function openNewFolder(parentFolderId?: string) {
    setNewFolderName('');
    setNewFolderParentId(parentFolderId ?? getCreationFolderId() ?? null);
    setNewFolderOpen(true);
  }

  function submitQuickConnect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = quickConnectForm.name.trim() || quickConnectForm.host.trim() || 'New connection';
    const host = quickConnectForm.host.trim() || 'localhost';
    const id = `session-quick-${Date.now()}`;

    setSessions((current) => [
      ...current,
      {
        id,
        title: name,
        protocol: quickConnectForm.protocol,
        host,
        canTransfer: quickConnectForm.protocol === 'ssh',
        status: 'placeholder',
        output: '',
        error:
          quickConnectForm.protocol === 'ssh'
            ? 'Quick Connect needs a saved SSH credential before it can connect.'
            : undefined,
      },
    ]);
    setSelectedSessionId(id);
    setActivePage('sessions');
    setQuickConnectOpen(false);
  }

  function submitNewConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = newConnectionForm.name.trim();
    const host = newConnectionForm.host.trim();
    const editingId = editingConnectionId;

    if (editingId) {
      const editedSessionId = `session-${editingId}`;
      const editedSession = sessions.find((session) => session.id === editedSessionId);
      if (editedSession?.backendSessionId) {
        void window.wormhole?.closeSshSession(editedSession.backendSessionId);
      }
      const backendSessionId =
        editedSession && newConnectionForm.protocol === 'ssh' ? newSessionToken() : undefined;
      setTree((current) =>
        updateConnectionInTree(current, editingId, newConnectionForm.folder, {
          name,
          host,
          protocol: newConnectionForm.protocol,
        }),
      );
      setSessions((current) =>
        current.map((session) =>
          session.id === editedSessionId
            ? {
                ...session,
                title: name,
                host,
                protocol: newConnectionForm.protocol,
                canTransfer: newConnectionForm.protocol === 'ssh',
                nodeId: editingId,
                backendSessionId,
                status: newConnectionForm.protocol === 'ssh' ? 'connecting' : 'placeholder',
                output: '',
                error: undefined,
              }
            : session,
        ),
      );
      if (backendSessionId) startSshSession(backendSessionId, editingId);
    } else {
      const id = `connection-${Date.now()}`;
      const connection: TreeNode = {
        id,
        name,
        kind: 'connection',
        protocol: newConnectionForm.protocol,
        host,
      };

      setTree((current) =>
        newConnectionForm.folder
          ? insertIntoTreeFolder(current, newConnectionForm.folder, [connection])
          : [...current, connection],
      );
      setSelectedNodeId(id);
    }

    if (newConnectionForm.folder) {
      setExpanded((current) => new Set(current).add(newConnectionForm.folder));
    }
    setEditingConnectionId(null);
    setNewConnectionOpen(false);
  }

  function submitNewFolder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = newFolderName.trim();
    if (!name) return;

    const id = `folder-${Date.now()}`;
    const folder: TreeNode = { id, name, kind: 'folder', children: [] };
    setTree((current) =>
      newFolderParentId
        ? insertIntoTreeFolder(current, newFolderParentId, [folder])
        : [...current, folder],
    );
    setExpanded((current) => {
      const next = new Set(current).add(id);
      if (newFolderParentId) next.add(newFolderParentId);
      return next;
    });
    setSelectedNodeId(id);
    setNewFolderParentId(null);
    setNewFolderOpen(false);
  }

  function renderTree(nodes: TreeNode[], depth = 0): ReactNode {
    return nodes.map((node, index) => {
      const isFolder = node.kind === 'folder';
      const protocol = node.protocol ?? 'ssh';
      const isLastSibling = index === nodes.length - 1;
      const isExpanded = searchText.trim() ? true : expanded.has(node.id);
      const hasChildren = Boolean(node.children?.length);
      const isSelected = node.kind === 'folder' && selectedNodeId === node.id;
      const creationFolderId = node.kind === 'folder' ? node.id : findParentFolderId(tree, node.id);
      const activeDropPlacement = dropTarget?.id === node.id ? dropTarget.placement : null;
      const isDragging = draggedNodeIds.includes(node.id);
      const treeDragEnabled = !searchText.trim();
      const treeGeometry = getTreeRowGeometry(depth);
      const branchGeometry = treeGeometry.branch;
      const dropIndicator =
        activeDropPlacement === 'before' ? (
          <span
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-2 top-0 z-30 h-0.5 rounded-full bg-primary"
          />
        ) : activeDropPlacement === 'after' ? (
          <span
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-2 bottom-0 z-30 h-0.5 rounded-full bg-primary"
          />
        ) : null;
      const treeCheckbox = (
        <TreeSelectionCheckbox
          checked={selectedTreeNodeIds.has(node.id)}
          label={`Select ${node.name}`}
          onCheckedChange={(checked) => toggleTreeNodeSelection(node.id, checked)}
        />
      );
      const row = (
        <Button
          aria-current={isSelected ? 'true' : undefined}
          className={[
            'relative z-10 h-8 w-full cursor-grab justify-start gap-1.5 rounded-md px-2 text-left text-xs font-medium text-sidebar-foreground/80 transition-[background-color,box-shadow,opacity] duration-150 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground aria-expanded:bg-transparent aria-expanded:text-sidebar-foreground/80 active:cursor-grabbing',
            isSelected
              ? 'bg-sidebar-accent text-sidebar-accent-foreground aria-expanded:bg-sidebar-accent aria-expanded:text-sidebar-accent-foreground'
              : '',
            isDragging ? 'opacity-40' : '',
            activeDropPlacement === 'inside'
              ? 'bg-sidebar-accent/70 text-sidebar-accent-foreground ring-1 ring-sidebar-ring'
              : '',
          ].join(' ')}
          draggable={treeDragEnabled}
          onClick={() => {
            setSelectedNodeId(node.id);
            if (isFolder) toggleFolder(node.id);
          }}
          onDragEnd={handleTreeDragEnd}
          onDragStart={(event) => handleTreeDragStart(event, node)}
          onDoubleClick={() => openConnection(node)}
          style={{ paddingLeft: `${treeGeometry.paddingLeft}px` }}
          variant="ghost"
        >
          {treeCheckbox}
          {isFolder ? (
            <span className="grid size-4 shrink-0 place-items-center text-muted-foreground">
              {hasChildren ? (
                isExpanded ? (
                  <ChevronDown size={13} />
                ) : (
                  <ChevronRight size={13} />
                )
              ) : null}
            </span>
          ) : null}
          <span
            className={[
              'grid size-5 shrink-0 place-items-center',
              isFolder ? 'text-muted-foreground' : `${protocolTone(protocol)} translate-y-px`,
            ].join(' ')}
          >
            {isFolder ? (
              isExpanded ? (
                <FolderOpen size={15} />
              ) : (
                <Folder size={15} />
              )
            ) : (
              <ProtocolIcon protocol={protocol} />
            )}
          </span>
          <span className="min-w-0 flex-1 truncate">{node.name}</span>
        </Button>
      );
      const treeVerticalGuide =
        branchGeometry && (!isFolder || !isLastSibling) ? (
          <span
            aria-hidden="true"
            className={[
              'pointer-events-none absolute top-0 z-0 w-px bg-foreground/50',
              isLastSibling ? '' : 'bottom-0',
            ].join(' ')}
            style={{
              bottom: isLastSibling ? '50%' : undefined,
              left: `${branchGeometry.left}px`,
            }}
          />
        ) : null;
      const treeRowVerticalGuide =
        branchGeometry && isFolder && isLastSibling ? (
          <span
            aria-hidden="true"
            className="pointer-events-none absolute top-0 z-0 h-1/2 w-px bg-foreground/50"
            style={{ left: `${branchGeometry.left}px` }}
          />
        ) : null;
      const treeConnector = branchGeometry ? (
        <span
          aria-hidden="true"
          className="pointer-events-none absolute top-1/2 z-0 h-px bg-foreground/50"
          style={{
            left: `${branchGeometry.connectorLeft}px`,
            width: `${branchGeometry.connectorWidth}px`,
          }}
        />
      ) : null;

      if (!isFolder) {
        return (
          <NodeContextMenu
            key={node.id}
            node={node}
            onEdit={() => openEditConnection(node)}
            onNewConnection={() => openNewConnection(creationFolderId)}
            onNewFolder={() => openNewFolder(creationFolderId)}
          >
            <div
              className="relative py-0.5"
              onDragOver={(event) => handleTreeDragOver(event, node)}
              onDragLeave={(event) => handleTreeDragLeave(event, node)}
              onDrop={(event) => handleTreeDrop(event, node)}
            >
              {dropIndicator}
              {treeVerticalGuide}
              {treeConnector}
              <NodeTooltip node={node}>
                <div>{row}</div>
              </NodeTooltip>
            </div>
          </NodeContextMenu>
        );
      }

      return (
        <Collapsible
          className="relative py-0.5"
          key={node.id}
          onOpenChange={(value) => toggleFolder(node.id, value)}
          open={isExpanded}
        >
          {treeVerticalGuide}
          <NodeContextMenu
            node={node}
            onEdit={() => openEditConnection(node)}
            onNewConnection={() => openNewConnection(creationFolderId)}
            onNewFolder={() => openNewFolder(creationFolderId)}
          >
            <div
              className="relative"
              onDragOver={(event) => handleTreeDragOver(event, node)}
              onDragLeave={(event) => handleTreeDragLeave(event, node)}
              onDrop={(event) => handleTreeDrop(event, node)}
            >
              {treeRowVerticalGuide}
              {dropIndicator}
              {treeConnector}
              <NodeTooltip node={node}>
                <div>
                  <CollapsibleTrigger asChild>{row}</CollapsibleTrigger>
                </div>
              </NodeTooltip>
            </div>
          </NodeContextMenu>
          {hasChildren ? (
            <CollapsibleContent>{renderTree(node.children!, depth + 1)}</CollapsibleContent>
          ) : null}
        </Collapsible>
      );
    });
  }

  const currentPage = navItems.find((item) => item.id === activePage)!;

  return (
    <TooltipProvider delayDuration={300}>
      <div className="flex h-full min-w-[960px] flex-col bg-background font-sans text-foreground">
        <header className="relative flex h-12 shrink-0 items-center border-b border-border bg-background px-3 text-foreground [-webkit-app-region:drag]">
          <div className="flex min-w-0 items-center gap-2.5 [-webkit-app-region:no-drag]">
            <div className="grid size-8 shrink-0 place-items-center rounded-md p-1">
              <img alt="" className="size-full object-contain" src={wormholeIcon} />
            </div>
            <span className="text-sm font-semibold tracking-tight">Wormhole</span>
            {updateVisible ? (
              <Button
                className="h-7 gap-1.5 rounded-md border-border bg-background px-2.5 text-[10px] font-semibold text-foreground hover:bg-muted hover:text-foreground"
                onClick={() => setUpdateVisible(false)}
                size="sm"
                variant="outline"
              >
                <Download data-icon="inline-start" />
                Update
              </Button>
            ) : null}
          </div>
        </header>

        <ResizablePanelGroup className="min-h-0 flex-1" orientation="horizontal">
          <ResizablePanel defaultSize="24%" maxSize="36%" minSize="18%">
            <SidebarProvider
              className="h-full min-h-0"
              style={{ '--sidebar-width': '100%' } as CSSProperties}
            >
              <Sidebar className="relative w-full border-r-0" collapsible="none">
                <SidebarHeader className="gap-3 p-3">
                  <div className="flex items-end justify-between gap-2 px-1">
                    <div>
                      <h1 className="text-sm font-semibold tracking-tight">Connections</h1>
                    </div>
                    <div className="flex items-center gap-0.5">
                      <IconButton
                        label="Expand all folders"
                        onClick={() => setExpanded(new Set(collectFolderIds(tree)))}
                      >
                        <ChevronDown />
                      </IconButton>
                      <IconButton
                        label="Collapse all folders"
                        onClick={() => setExpanded(new Set())}
                      >
                        <ChevronUp />
                      </IconButton>
                      <DropdownMenu>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <DropdownMenuTrigger asChild>
                              <Button
                                aria-label="Import connections"
                                size="icon-sm"
                                variant="ghost"
                              >
                                <Upload />
                              </Button>
                            </DropdownMenuTrigger>
                          </TooltipTrigger>
                          <TooltipContent side="bottom">Import connections</TooltipContent>
                        </Tooltip>
                        <DropdownMenuContent align="end" className="w-52">
                          <DropdownMenuItem>
                            <Upload />
                            Import from mRemoteNG
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                      <IconButton label="New folder" onClick={() => openNewFolder()}>
                        <FolderPlus />
                      </IconButton>
                      <IconButton label="New connection" onClick={() => openNewConnection()}>
                        <Plus />
                      </IconButton>
                    </div>
                  </div>
                  <Button
                    className="w-full justify-center gap-2"
                    onClick={openQuickConnect}
                    size="sm"
                  >
                    <Zap data-icon="inline-start" />
                    Quick Connect
                    <Kbd>Ctrl K</Kbd>
                  </Button>
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-2.5 top-1/2 z-10 size-3.5 -translate-y-1/2 text-muted-foreground" />
                    <SidebarInput
                      aria-label="Search connections"
                      className="h-9 bg-background/60 pl-8 pr-8 text-xs shadow-none"
                      onChange={(event) => setSearchText(event.target.value)}
                      placeholder="Search connections"
                      value={searchText}
                    />
                    {searchText ? (
                      <IconButton
                        label="Clear search"
                        className="absolute right-1 top-1/2 size-7 -translate-y-1/2 text-muted-foreground"
                        onClick={() => setSearchText('')}
                      >
                        <X />
                      </IconButton>
                    ) : null}
                  </div>
                  {searchText ? (
                    <p className="px-1 text-[10px] text-muted-foreground">
                      {visibleTree.length === 0
                        ? 'No matches'
                        : `Showing matches for “${searchText}”`}
                    </p>
                  ) : null}
                </SidebarHeader>

                <SidebarContent className="min-h-0 overflow-hidden px-2">
                  <ScrollArea className="min-h-0 flex-1 px-1">
                    {visibleTree.length > 0 ? (
                      renderTree(visibleTree)
                    ) : (
                      <p className="px-3 py-8 text-center text-xs text-muted-foreground">
                        {workspaceStatus === 'loading'
                          ? 'Loading connections…'
                          : workspaceStatus === 'error'
                            ? 'Unable to load connections.'
                            : 'Nothing here yet.'}
                      </p>
                    )}
                  </ScrollArea>
                </SidebarContent>

                <SidebarFooter className="gap-2 border-t border-sidebar-border p-2">
                  <SidebarGroup className="p-0">
                    <SidebarMenu>
                      {navItems.map((item) => (
                        <SidebarMenuItem key={item.id}>
                          <SidebarMenuButton
                            isActive={activePage === item.id}
                            onClick={() => setActivePage(item.id)}
                            size="sm"
                            tooltip={item.hint}
                          >
                            {item.id === 'credentials' ? <KeyRound /> : null}
                            {item.id === 'sessions' ? <PanelLeft /> : null}
                            {item.id === 'tunnels' ? <Network /> : null}
                            {item.id === 'settings' ? <Settings2 /> : null}
                            <span>{item.label}</span>
                          </SidebarMenuButton>
                          {item.id === 'sessions' && sessions.length > 0 ? (
                            <SidebarMenuBadge>{sessions.length}</SidebarMenuBadge>
                          ) : null}
                        </SidebarMenuItem>
                      ))}
                    </SidebarMenu>
                  </SidebarGroup>
                </SidebarFooter>
              </Sidebar>
            </SidebarProvider>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel minSize="54%">
            <SidebarInset className="min-h-0 min-w-0 rounded-none bg-background">
              {activePage === 'sessions' ? (
                <SessionsPage
                  onCloseSession={closeSession}
                  onDuplicateSession={duplicateSession}
                  onOpenFileTransfer={openFileTransfer}
                  onOpenQuickConnect={openQuickConnect}
                  onReconnectSession={reconnectSession}
                  onSelectSession={setSelectedSessionId}
                  onSshInput={sendSshInput}
                  selectedSession={selectedSession}
                  sessions={sessions}
                />
              ) : activePage === 'settings' ? (
                <SettingsPage onThemeChange={setTheme} theme={theme} />
              ) : activePage === 'credentials' ? (
                <CredentialsPage initialCredentials={credentials} />
              ) : activePage === 'tunnels' ? (
                <TunnelsPage tunnels={tunnels} />
              ) : (
                <UtilityPage item={currentPage} sessions={sessions} />
              )}
            </SidebarInset>
          </ResizablePanel>
        </ResizablePanelGroup>

        <Dialog onOpenChange={setQuickConnectOpen} open={quickConnectOpen}>
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Quick Connect</DialogTitle>
              <DialogDescription>
                Start a temporary session without adding it to your connection tree.
              </DialogDescription>
            </DialogHeader>
            <form className="grid gap-4" onSubmit={submitQuickConnect}>
              <div className="grid gap-2">
                <Label htmlFor="quick-name">Connection name</Label>
                <Input
                  autoFocus
                  id="quick-name"
                  onChange={(event) =>
                    setQuickConnectForm((form) => ({ ...form, name: event.target.value }))
                  }
                  placeholder="e.g. staging gateway"
                  value={quickConnectForm.name}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="quick-host">Host or address</Label>
                <Input
                  id="quick-host"
                  onChange={(event) =>
                    setQuickConnectForm((form) => ({ ...form, host: event.target.value }))
                  }
                  placeholder="hostname, IP, or COM port"
                  required
                  value={quickConnectForm.host}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="quick-protocol">Protocol</Label>
                <Select
                  onValueChange={(protocol: Protocol) =>
                    setQuickConnectForm((form) => ({ ...form, protocol }))
                  }
                  value={quickConnectForm.protocol}
                >
                  <SelectTrigger id="quick-protocol">
                    <SelectValue placeholder="Select protocol" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ssh">SSH</SelectItem>
                    <SelectItem value="rdp">RDP</SelectItem>
                    <SelectItem value="http">HTTP</SelectItem>
                    <SelectItem value="https">HTTPS</SelectItem>
                    <SelectItem value="vnc">VNC</SelectItem>
                    <SelectItem value="serial">Serial</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <DialogFooter>
                <Button onClick={() => setQuickConnectOpen(false)} type="button" variant="ghost">
                  Cancel
                </Button>
                <Button type="submit">
                  <Power data-icon="inline-start" />
                  Connect
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            setNewConnectionOpen(open);
            if (!open) setEditingConnectionId(null);
          }}
          open={newConnectionOpen}
        >
          <DialogContent className="flex h-[min(36rem,calc(100vh-2rem))] max-h-[calc(100vh-2rem)] flex-col overflow-hidden border-border/70 bg-card text-card-foreground sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>
                {editingConnectionId ? 'Edit connection' : 'New connection'}
              </DialogTitle>
              <DialogDescription>
                {editingConnectionId
                  ? 'Update the connection settings used by this tree item.'
                  : 'Save a connection to the tree for reuse later.'}
              </DialogDescription>
            </DialogHeader>
            <form className="flex min-h-0 flex-1 flex-col gap-4" onSubmit={submitNewConnection}>
              <Tabs
                className="flex min-h-0 flex-1 flex-col gap-0 overflow-hidden"
                defaultValue="general"
                key={newConnectionForm.protocol}
              >
                <TabsList
                  className="h-9 w-full shrink-0 justify-start gap-1 overflow-x-auto overflow-y-hidden rounded-none border-b border-border p-0"
                  variant="line"
                >
                  <TabsTrigger className="flex-none px-3 text-xs after:bottom-0" value="general">
                    General
                  </TabsTrigger>
                  {newConnectionForm.protocol === 'serial' ? (
                    <TabsTrigger className="flex-none px-3 text-xs after:bottom-0" value="serial">
                      Serial
                    </TabsTrigger>
                  ) : null}
                  {newConnectionForm.protocol === 'rdp' ? (
                    <>
                      <TabsTrigger
                        className="flex-none px-3 text-xs after:bottom-0"
                        value="display"
                      >
                        Display
                      </TabsTrigger>
                      <TabsTrigger
                        className="flex-none px-3 text-xs after:bottom-0"
                        value="resources"
                      >
                        Local Resources
                      </TabsTrigger>
                      <TabsTrigger
                        className="flex-none px-3 text-xs after:bottom-0"
                        value="experience"
                      >
                        Experience
                      </TabsTrigger>
                      <TabsTrigger
                        className="flex-none px-3 text-xs after:bottom-0"
                        value="advanced"
                      >
                        Advanced
                      </TabsTrigger>
                    </>
                  ) : null}
                </TabsList>

                <TabsContent className="min-h-0 flex-1 overflow-y-auto px-1 py-4" value="general">
                  <div className="grid gap-4">
                    <div className="grid gap-2">
                      <Label htmlFor="connection-name">Connection name</Label>
                      <Input
                        autoFocus
                        id="connection-name"
                        onChange={(event) =>
                          setNewConnectionForm((form) => ({ ...form, name: event.target.value }))
                        }
                        placeholder="e.g. production gateway"
                        required
                        value={newConnectionForm.name}
                      />
                    </div>

                    <div className="grid gap-3 sm:grid-cols-[120px_minmax(0,1fr)]">
                      <div className="grid gap-2">
                        <Label htmlFor="connection-protocol">Protocol</Label>
                        <Select
                          onValueChange={(protocol: Protocol) =>
                            setNewConnectionForm((form) => ({ ...form, protocol }))
                          }
                          value={newConnectionForm.protocol}
                        >
                          <SelectTrigger id="connection-protocol" className="w-full">
                            <SelectValue placeholder="Select protocol" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="ssh">SSH</SelectItem>
                            <SelectItem value="rdp">RDP</SelectItem>
                            <SelectItem value="http">HTTP</SelectItem>
                            <SelectItem value="https">HTTPS</SelectItem>
                            <SelectItem value="vnc">VNC</SelectItem>
                            <SelectItem value="serial">Serial</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="connection-host">
                          {newConnectionForm.protocol === 'serial'
                            ? 'Serial line'
                            : 'Host or address'}
                        </Label>
                        <Input
                          id="connection-host"
                          onChange={(event) =>
                            setNewConnectionForm((form) => ({ ...form, host: event.target.value }))
                          }
                          placeholder={
                            newConnectionForm.protocol === 'serial'
                              ? 'COM1'
                              : newConnectionForm.protocol === 'http' ||
                                  newConnectionForm.protocol === 'https'
                                ? '10.0.0.1:8443'
                                : 'hostname or IP address'
                          }
                          required
                          value={newConnectionForm.host}
                        />
                      </div>
                    </div>

                    {newConnectionForm.protocol === 'http' ||
                    newConnectionForm.protocol === 'https' ? (
                      <p className="text-[11px] leading-relaxed text-muted-foreground">
                        Enter the host or IP. Include a port if the appliance uses a non-standard
                        one, for example 10.0.0.1:8443.
                      </p>
                    ) : null}

                    <div className="grid max-w-[280px] gap-2">
                      <Label htmlFor="connection-folder">Folder</Label>
                      <Select
                        onValueChange={(folder) =>
                          setNewConnectionForm((form) => ({ ...form, folder }))
                        }
                        value={newConnectionForm.folder}
                      >
                        <SelectTrigger id="connection-folder" className="w-full">
                          <SelectValue placeholder="Select folder" />
                        </SelectTrigger>
                        <SelectContent>
                          {folders.map((folder) => (
                            <SelectItem key={folder.id} value={folder.id}>
                              {folder.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    {newConnectionForm.protocol === 'https' ? (
                      <label className="flex items-center gap-2 text-xs">
                        <Checkbox />
                        <span>Ignore certificate errors</span>
                      </label>
                    ) : null}
                  </div>
                </TabsContent>

                {newConnectionForm.protocol === 'serial' ? (
                  <TabsContent className="min-h-0 flex-1 overflow-y-auto px-1 py-4" value="serial">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="grid gap-2">
                        <Label htmlFor="serial-baud">Speed (baud)</Label>
                        <Input defaultValue="9600" id="serial-baud" inputMode="numeric" />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="serial-data-bits">Data bits</Label>
                        <Select defaultValue="8">
                          <SelectTrigger id="serial-data-bits">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="7">7</SelectItem>
                            <SelectItem value="8">8</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="serial-stop-bits">Stop bits</Label>
                        <Select defaultValue="1">
                          <SelectTrigger id="serial-stop-bits">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="1">1</SelectItem>
                            <SelectItem value="2">2</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="serial-parity">Parity</Label>
                        <Select defaultValue="none">
                          <SelectTrigger id="serial-parity">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="none">None</SelectItem>
                            <SelectItem value="even">Even</SelectItem>
                            <SelectItem value="odd">Odd</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2 sm:col-span-2">
                        <Label htmlFor="serial-flow">Flow control</Label>
                        <Select defaultValue="none">
                          <SelectTrigger id="serial-flow" className="sm:max-w-[240px]">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="none">None</SelectItem>
                            <SelectItem value="hardware">Hardware</SelectItem>
                            <SelectItem value="software">Software</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </TabsContent>
                ) : null}

                {newConnectionForm.protocol === 'rdp' ? (
                  <>
                    <TabsContent
                      className="min-h-0 flex-1 overflow-y-auto px-1 py-4"
                      value="display"
                    >
                      <div className="grid gap-4 sm:grid-cols-2">
                        <div className="grid gap-2">
                          <Label htmlFor="rdp-display">Display configuration</Label>
                          <Select defaultValue="fit">
                            <SelectTrigger id="rdp-display">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="fit">Fit to window</SelectItem>
                              <SelectItem value="full">Full screen</SelectItem>
                              <SelectItem value="custom">Custom size</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="grid gap-2">
                          <Label htmlFor="rdp-color-depth">Color depth</Label>
                          <Select defaultValue="32">
                            <SelectTrigger id="rdp-color-depth">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="32">32-bit</SelectItem>
                              <SelectItem value="16">16-bit</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <label className="flex items-center gap-2 text-xs sm:col-span-2">
                          <Checkbox />
                          <span>Use all my monitors</span>
                        </label>
                      </div>
                    </TabsContent>
                    <TabsContent
                      className="min-h-0 flex-1 overflow-y-auto px-1 py-4"
                      value="resources"
                    >
                      <div className="grid gap-4">
                        <div className="grid gap-2 sm:max-w-[320px]">
                          <Label htmlFor="rdp-audio-playback">Remote audio playback</Label>
                          <Select defaultValue="local">
                            <SelectTrigger id="rdp-audio-playback">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="local">Play on this device</SelectItem>
                              <SelectItem value="remote">Play on remote device</SelectItem>
                              <SelectItem value="none">Do not play</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="grid gap-2 sm:max-w-[320px]">
                          <Label htmlFor="rdp-keyboard">Apply Windows key combinations</Label>
                          <Select defaultValue="full">
                            <SelectTrigger id="rdp-keyboard">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="full">On this computer</SelectItem>
                              <SelectItem value="remote">On the remote computer</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="grid gap-2 sm:grid-cols-2">
                          {['Clipboard', 'Printers', 'Smart cards', 'Serial / parallel ports'].map(
                            (label) => (
                              <label className="flex items-center gap-2 text-xs" key={label}>
                                <Checkbox defaultChecked={label === 'Clipboard'} />
                                <span>{label}</span>
                              </label>
                            ),
                          )}
                        </div>
                      </div>
                    </TabsContent>
                    <TabsContent
                      className="min-h-0 flex-1 overflow-y-auto px-1 py-4"
                      value="experience"
                    >
                      <div className="grid gap-4">
                        <div className="grid gap-2 sm:max-w-[320px]">
                          <Label htmlFor="rdp-connection-speed">Connection speed</Label>
                          <Select defaultValue="broadband">
                            <SelectTrigger id="rdp-connection-speed">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="broadband">Broadband</SelectItem>
                              <SelectItem value="lan">LAN</SelectItem>
                              <SelectItem value="custom">Custom</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="grid gap-2 sm:grid-cols-2">
                          {[
                            'Desktop background',
                            'Font smoothing',
                            'Desktop composition',
                            'Visual styles',
                          ].map((label) => (
                            <label className="flex items-center gap-2 text-xs" key={label}>
                              <Checkbox />
                              <span>{label}</span>
                            </label>
                          ))}
                        </div>
                      </div>
                    </TabsContent>
                    <TabsContent
                      className="min-h-0 flex-1 overflow-y-auto px-1 py-4"
                      value="advanced"
                    >
                      <div className="grid gap-4">
                        <div className="grid gap-2 sm:max-w-[320px]">
                          <Label htmlFor="rdp-authentication">Server authentication</Label>
                          <Select defaultValue="warn">
                            <SelectTrigger id="rdp-authentication">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="warn">Warn if authentication fails</SelectItem>
                              <SelectItem value="connect">Connect and do not warn</SelectItem>
                              <SelectItem value="never">Never connect</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <label className="flex items-center gap-2 text-xs">
                          <Checkbox />
                          <span>Open with system Remote Desktop (mstsc.exe)</span>
                        </label>
                        <label className="flex items-center gap-2 text-xs">
                          <Checkbox />
                          <span>Reconnect if the connection is dropped</span>
                        </label>
                      </div>
                    </TabsContent>
                  </>
                ) : null}
              </Tabs>
              <DialogFooter>
                <Button
                  onClick={() => {
                    setNewConnectionOpen(false);
                    setEditingConnectionId(null);
                  }}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button type="submit">
                  {editingConnectionId ? (
                    <Check data-icon="inline-start" />
                  ) : (
                    <Plus data-icon="inline-start" />
                  )}
                  {editingConnectionId ? 'Save changes' : 'Save connection'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            setNewFolderOpen(open);
            if (!open) setNewFolderParentId(null);
          }}
          open={newFolderOpen}
        >
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-sm">
            <DialogHeader>
              <DialogTitle>New folder</DialogTitle>
              <DialogDescription>Create a folder for organizing connections.</DialogDescription>
            </DialogHeader>
            <form className="grid gap-4" onSubmit={submitNewFolder}>
              <div className="grid gap-2">
                <Label htmlFor="folder-name">Folder name</Label>
                <Input
                  autoFocus
                  id="folder-name"
                  onChange={(event) => setNewFolderName(event.target.value)}
                  placeholder="e.g. Staging"
                  required
                  value={newFolderName}
                />
              </div>
              <DialogFooter>
                <Button onClick={() => setNewFolderOpen(false)} type="button" variant="ghost">
                  Cancel
                </Button>
                <Button type="submit">
                  <FolderPlus data-icon="inline-start" />
                  Create folder
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>
    </TooltipProvider>
  );
}

function SshTerminalSurface({
  session,
  onInput,
}: {
  session: Session;
  onInput: (sessionId: string, value: string) => void;
}) {
  const [command, setCommand] = useState('');
  const surfaceRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const surface = surfaceRef.current;
    const backendSessionId = session.backendSessionId;
    if (
      !surface ||
      !backendSessionId ||
      session.status !== 'connected' ||
      typeof ResizeObserver === 'undefined'
    )
      return;

    const resize = () => {
      const columns = Math.max(1, Math.floor(surface.clientWidth / 7.2));
      const rows = Math.max(1, Math.floor((surface.clientHeight - 72) / 17));
      const api = window.wormhole;
      if (!api) return;
      void api.resizeSshSession(backendSessionId, columns, rows).catch(() => {
        // A resize can race with a remote close; the closed event owns the visible session state.
      });
    };
    const observer = new ResizeObserver(resize);
    observer.observe(surface);
    resize();
    return () => observer.disconnect();
  }, [session.backendSessionId, session.status]);

  function submitCommand() {
    if (!command || session.status !== 'connected') return;
    onInput(session.id, `${command}\r`);
    setCommand('');
  }

  return (
    <div
      className="flex min-h-0 flex-1 flex-col bg-[#090909] text-zinc-100"
      onClick={() => inputRef.current?.focus()}
      ref={surfaceRef}
    >
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-white/10 px-4 font-mono text-[10px] text-zinc-400">
        <span
          className={`size-1.5 rounded-full ${
            session.status === 'connected'
              ? 'bg-emerald-400'
              : session.status === 'connecting'
                ? 'animate-pulse bg-amber-400'
                : 'bg-red-400'
          }`}
        />
        <span>{session.host}</span>
        <span className="text-zinc-600">·</span>
        <span>{session.status}</span>
        {session.fingerprint ? (
          <span className="ml-auto truncate text-zinc-600" title={session.fingerprint}>
            {session.fingerprint}
          </span>
        ) : null}
      </div>
      <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap px-4 py-3 font-mono text-[12px] leading-relaxed">
        {session.output ||
          (session.status === 'connecting'
            ? 'Connecting to SSH server…'
            : session.error || (session.status === 'closed' ? 'SSH session closed.' : ''))}
      </pre>
      <form
        className="flex shrink-0 items-end gap-2 border-t border-white/10 p-3"
        onSubmit={(event) => {
          event.preventDefault();
          submitCommand();
        }}
      >
        <span className="pb-2 font-mono text-xs text-emerald-400">$</span>
        <Textarea
          aria-label="SSH terminal input"
          className="min-h-9 resize-none border-white/10 bg-white/5 font-mono text-xs text-zinc-100 placeholder:text-zinc-600 focus-visible:ring-white/20"
          disabled={session.status !== 'connected'}
          onChange={(event) => setCommand(event.target.value)}
          onKeyDown={(event) => {
            if (event.ctrlKey && event.key.toLowerCase() === 'c') {
              event.preventDefault();
              onInput(session.id, '\u0003');
              setCommand('');
            } else if (event.key === 'Enter' && !event.shiftKey) {
              event.preventDefault();
              submitCommand();
            }
          }}
          placeholder={
            session.status === 'connected'
              ? 'Type a command and press Enter'
              : 'Terminal unavailable'
          }
          ref={inputRef}
          rows={1}
          value={command}
        />
        <Button disabled={session.status !== 'connected' || !command} size="sm" type="submit">
          Send
        </Button>
      </form>
    </div>
  );
}

function SessionsPage({
  sessions,
  selectedSession,
  onCloseSession,
  onDuplicateSession,
  onOpenFileTransfer,
  onSelectSession,
  onOpenQuickConnect,
  onReconnectSession,
  onSshInput,
}: {
  sessions: Session[];
  selectedSession?: Session;
  onCloseSession: (id: string) => void;
  onDuplicateSession: (id: string) => void;
  onOpenFileTransfer: (id: string) => void;
  onSelectSession: (id: string) => void;
  onOpenQuickConnect: () => void;
  onReconnectSession: (id: string) => void;
  onSshInput: (sessionId: string, value: string) => void;
}) {
  if (!selectedSession || sessions.length === 0) {
    return (
      <section className="flex h-full flex-col items-center justify-center bg-background p-8 text-center">
        <div className="mb-4 grid size-16 place-items-center rounded-full border border-border bg-card text-foreground shadow-sm">
          <PanelLeft className="size-7" />
        </div>
        <p className="mb-1 font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">
          Sessions
        </p>
        <h2 className="text-lg font-semibold tracking-tight">No active sessions</h2>
        <p className="mb-5 mt-2 max-w-sm text-xs leading-relaxed text-muted-foreground">
          Pick a connection from the tree or use Quick Connect to start a session.
        </p>
        <Button onClick={onOpenQuickConnect}>
          <Zap data-icon="inline-start" />
          Quick Connect
        </Button>
      </section>
    );
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <Tabs
        className="flex min-h-0 flex-1 flex-col gap-0"
        onValueChange={onSelectSession}
        value={selectedSession.id}
      >
        <div className="flex h-9 shrink-0 items-stretch justify-between border-b border-border bg-card/35">
          <TabsList
            className="h-full min-w-0 flex-1 items-stretch justify-start gap-0 rounded-none bg-transparent p-0"
            variant="line"
          >
            {sessions.map((session) => (
              <SessionTabContextMenu
                key={session.id}
                onClose={() => onCloseSession(session.id)}
                onDuplicate={() => onDuplicateSession(session.id)}
                onFileTransfer={() => onOpenFileTransfer(session.id)}
                onReconnect={() => onReconnectSession(session.id)}
                session={session}
              >
                <div className="relative flex h-full min-w-[12rem] max-w-[17rem] flex-1 border-r border-border/60">
                  <TabsTrigger
                    className="h-full min-w-0 justify-start gap-0 rounded-none border-0 px-4 py-0 pr-14 text-left text-muted-foreground after:z-10 after:bottom-[-1px] hover:bg-muted/20 data-active:bg-card/70 data-active:text-foreground"
                    onAuxClick={(event) => {
                      if (event.button !== 1) return;
                      event.preventDefault();
                      onCloseSession(session.id);
                    }}
                    value={session.id}
                  >
                    <span className="min-w-0 flex-1 truncate text-xs font-semibold">
                      {session.title}
                    </span>
                  </TabsTrigger>
                  <div className="absolute right-1.5 top-1/2 z-20 flex -translate-y-1/2 items-center gap-0.5 bg-transparent">
                    {session.canTransfer ? (
                      <IconButton
                        label={`Open file transfer for ${session.title}`}
                        onClick={() => onOpenFileTransfer(session.id)}
                      >
                        <ArrowRightLeft />
                      </IconButton>
                    ) : null}
                    <IconButton
                      label={`Close ${session.title}`}
                      className="text-muted-foreground hover:bg-transparent hover:text-foreground dark:hover:bg-transparent"
                      onClick={() => onCloseSession(session.id)}
                    >
                      <X />
                    </IconButton>
                  </div>
                </div>
              </SessionTabContextMenu>
            ))}
          </TabsList>
        </div>
        {selectedSession.protocol === 'ssh' ? (
          <SshTerminalSurface onInput={onSshInput} session={selectedSession} />
        ) : (
          <div className="flex min-h-0 flex-1 items-center justify-center bg-background p-8 text-center">
            <div>
              <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">
                {protocolLabel(selectedSession.protocol)} session
              </p>
              <p className="mt-2 text-xs text-muted-foreground">
                This protocol surface is still being migrated to the Electron shell.
              </p>
            </div>
          </div>
        )}
      </Tabs>
    </section>
  );
}

function CredentialsPage({ initialCredentials }: { initialCredentials: CredentialRecord[] }) {
  const [credentials, setCredentials] = useState(initialCredentials);
  const [searchText, setSearchText] = useState('');
  const [selectedCredentials, setSelectedCredentials] = useState<string[]>([]);

  useEffect(() => {
    setCredentials(initialCredentials);
    setSelectedCredentials([]);
  }, [initialCredentials]);

  const filteredCredentials = useMemo(() => {
    const query = searchText.trim().toLowerCase();
    if (!query) return credentials;

    return credentials.filter((credential) =>
      [credential.name, credential.username, credential.domain, credential.provider]
        .filter(Boolean)
        .some((value) => value!.toLowerCase().includes(query)),
    );
  }, [credentials, searchText]);

  const allVisibleSelected =
    filteredCredentials.length > 0 &&
    filteredCredentials.every((credential) => selectedCredentials.includes(credential.id));

  function toggleCredential(id: string, checked: boolean) {
    setSelectedCredentials((current) =>
      checked ? [...new Set([...current, id])] : current.filter((selectedId) => selectedId !== id),
    );
  }

  function deleteSelectedCredentials() {
    setCredentials((current) =>
      current.filter((credential) => !selectedCredentials.includes(credential.id)),
    );
    setSelectedCredentials([]);
  }

  return (
    <section className="flex h-full min-h-0 flex-col overflow-hidden px-6 py-5">
      <h2 className="shrink-0 text-2xl font-semibold tracking-tight">Credentials</h2>

      <div className="mt-4 flex shrink-0 flex-wrap items-center gap-2">
        <Input
          aria-label="Search credentials"
          className="h-9 min-w-60 max-w-xl flex-1"
          onChange={(event) => setSearchText(event.target.value)}
          placeholder="Search credentials"
          value={searchText}
        />
        <Button
          onClick={() =>
            setSelectedCredentials(
              allVisibleSelected ? [] : filteredCredentials.map((credential) => credential.id),
            )
          }
          size="sm"
          variant="outline"
        >
          <Check data-icon="inline-start" />
          Select all
        </Button>
        <Button size="sm">
          <Plus data-icon="inline-start" />
          Add credential
        </Button>
      </div>

      {selectedCredentials.length > 0 ? (
        <div className="mt-3 flex shrink-0 flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-muted/30 px-3 py-2">
          <div className="flex items-center gap-2 text-xs text-foreground/80">
            <Check className="size-3.5" />
            <span>{selectedCredentials.length} credential(s) selected</span>
          </div>
          <div className="flex gap-2">
            <Button onClick={() => setSelectedCredentials([])} size="sm" variant="ghost">
              Clear
            </Button>
            <Button onClick={deleteSelectedCredentials} size="sm" variant="destructive">
              <X data-icon="inline-start" />
              Delete selected
            </Button>
          </div>
        </div>
      ) : null}

      <div className="min-h-0 flex-1">
        {filteredCredentials.length === 0 ? (
          <div className="flex h-full items-center justify-center px-6 text-center">
            <div className="max-w-[420px] space-y-3">
              <KeyRound className="mx-auto size-12 text-muted-foreground/50" />
              <h3 className="text-sm font-semibold">
                {credentials.length === 0
                  ? 'No credentials yet'
                  : 'No credentials match your search'}
              </h3>
              <p className="text-xs leading-relaxed text-muted-foreground">
                {credentials.length === 0
                  ? 'Add a credential to reuse a username and password across SSH, RDP, and VNC connections.'
                  : 'Try a different name, username, domain, or provider.'}
              </p>
            </div>
          </div>
        ) : (
          <ScrollArea className="mt-4 h-full">
            <div className="grid grid-cols-[repeat(auto-fill,minmax(280px,1fr))] gap-4 pb-5 pr-2">
              {filteredCredentials.map((credential) => (
                <Card className="min-h-44 transition-colors hover:bg-muted/50" key={credential.id}>
                  <CardHeader>
                    <CardTitle className="min-w-0 truncate text-sm">{credential.name}</CardTitle>
                    <CardAction>
                      <Badge className="shrink-0" variant="secondary">
                        {protocolLabel(credential.protocol)}
                      </Badge>
                    </CardAction>
                    <CardDescription className="flex min-w-0 items-center gap-1.5 text-xs">
                      <KeyRound className="size-3 shrink-0" />
                      <span className="truncate">{credential.username}</span>
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="flex-1 space-y-2">
                    <div className="flex flex-wrap gap-2">
                      {credential.domain ? (
                        <Badge variant="outline">Domain · {credential.domain}</Badge>
                      ) : null}
                      <Badge variant="outline">{credential.provider}</Badge>
                    </div>
                  </CardContent>
                  <CardFooter className="justify-between gap-2">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Checkbox
                          aria-label={`Select ${credential.name}`}
                          checked={selectedCredentials.includes(credential.id)}
                          onCheckedChange={(checked) =>
                            toggleCredential(credential.id, checked === true)
                          }
                        />
                      </TooltipTrigger>
                      <TooltipContent side="bottom">Select credential</TooltipContent>
                    </Tooltip>
                    <div className="flex items-center gap-1">
                      <IconButton disabled={credential.readOnly} label={`Edit ${credential.name}`}>
                        <Pencil />
                      </IconButton>
                      <IconButton
                        disabled={credential.readOnly}
                        label={`Delete ${credential.name}`}
                      >
                        <X />
                      </IconButton>
                    </div>
                  </CardFooter>
                </Card>
              ))}
            </div>
          </ScrollArea>
        )}
      </div>
    </section>
  );
}

function TunnelsPage({ tunnels }: { tunnels: TunnelRecord[] }) {
  const [searchText, setSearchText] = useState('');
  const filteredTunnels = useMemo(() => {
    const query = searchText.trim().toLowerCase();
    return query
      ? tunnels.filter((tunnel) =>
          [tunnel.name, tunnel.kind].some((value) => value.toLowerCase().includes(query)),
        )
      : tunnels;
  }, [searchText, tunnels]);

  return (
    <section className="flex h-full min-h-0 flex-col overflow-hidden px-6 py-4">
      <h2 className="shrink-0 text-2xl font-semibold tracking-tight">VPN tunnels</h2>

      <div className="mt-3 flex shrink-0 flex-wrap items-center gap-2">
        <Input
          aria-label="Search tunnels"
          className="h-8 min-w-52 max-w-[480px] flex-1"
          onChange={(event) => setSearchText(event.target.value)}
          placeholder="Search tunnels"
          value={searchText}
        />
        <Button size="sm">
          <Plus data-icon="inline-start" />
          Add VPN tunnel
        </Button>
      </div>

      <div className="min-h-0 flex-1">
        {filteredTunnels.length === 0 ? (
          <div className="flex h-full items-center justify-center px-6 text-center">
            <div className="max-w-[420px] space-y-3">
              <Network className="mx-auto size-12 text-muted-foreground/50" />
              <h3 className="text-sm font-semibold">
                {tunnels.length === 0 ? 'No VPN tunnels yet' : 'No tunnels match your search'}
              </h3>
              <p className="text-xs leading-relaxed text-muted-foreground">
                {tunnels.length === 0
                  ? 'Add a VPN tunnel to route a connection through an in-process userspace endpoint.'
                  : 'Try a different tunnel name or provider.'}
              </p>
            </div>
          </div>
        ) : (
          <ScrollArea className="mt-3 h-full">
            <div className="grid grid-cols-[repeat(auto-fill,minmax(260px,1fr))] gap-3 pb-4 pr-2">
              {filteredTunnels.map((tunnel) => (
                <Card
                  className="min-h-[140px] max-w-[260px] transition-colors hover:bg-muted/50"
                  key={tunnel.id}
                  size="sm"
                >
                  <CardHeader className="grid grid-cols-[1fr_auto] gap-1">
                    <CardTitle className="min-w-0 truncate text-xs font-semibold">
                      {tunnel.name}
                    </CardTitle>
                    <CardAction>
                      <Badge className="shrink-0 text-[10px]" variant="outline">
                        {tunnel.kind}
                      </Badge>
                    </CardAction>
                    <CardDescription className="flex min-w-0 items-center gap-1.5 text-[11px]">
                      <Network className="size-3 shrink-0" />
                      <span className="truncate">In-process userspace tunnel</span>
                    </CardDescription>
                  </CardHeader>
                  <CardFooter className="mt-auto justify-end gap-0.5">
                    <IconButton label={`Test ${tunnel.name}`}>
                      <RefreshCcw />
                    </IconButton>
                    <IconButton label={`Edit ${tunnel.name}`}>
                      <Settings2 />
                    </IconButton>
                    <IconButton label={`Delete ${tunnel.name}`}>
                      <X />
                    </IconButton>
                  </CardFooter>
                </Card>
              ))}
            </div>
          </ScrollArea>
        )}
      </div>
    </section>
  );
}

function SettingsSection({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <section className="space-y-3">
      <div className="space-y-1">
        <h3 className="text-sm font-semibold tracking-tight">{title}</h3>
        {description ? (
          <p className="text-[11px] leading-relaxed text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {children}
    </section>
  );
}

function SettingsSwitch({
  label,
  description,
  checked,
  onCheckedChange,
}: {
  label: string;
  description?: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-6 rounded-lg border border-border/70 bg-card/40 px-3 py-3">
      <div className="min-w-0 space-y-1">
        <p className="text-xs font-medium">{label}</p>
        {description ? (
          <p className="text-[11px] leading-relaxed text-muted-foreground">{description}</p>
        ) : null}
      </div>
      <Switch aria-label={label} checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  );
}

function SettingsTabPanel({ value, children }: { value: string; children: ReactNode }) {
  return (
    <TabsContent
      className="min-h-0 flex-1 overflow-hidden data-[state=inactive]:hidden"
      value={value}
    >
      <ScrollArea className="h-full">
        <div className="max-w-[720px] space-y-7 px-1 py-5 pb-12">{children}</div>
      </ScrollArea>
    </TabsContent>
  );
}

function SettingsPage({
  theme,
  onThemeChange,
}: {
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
}) {
  const [confirmOnTabClose, setConfirmOnTabClose] = useState(true);
  const [autoCopyOnSelect, setAutoCopyOnSelect] = useState(false);
  const [promptBeforeTunnelConnect, setPromptBeforeTunnelConnect] = useState(true);
  const [authMethod, setAuthMethod] = useState('disabled');
  const [helloFallback, setHelloFallback] = useState('pin');
  const [idleTimeout, setIdleTimeout] = useState('15');
  const [bitwardenEnabled, setBitwardenEnabled] = useState(false);
  const [bitwardenPath, setBitwardenPath] = useState('bw');
  const [browserExtensionEnabled, setBrowserExtensionEnabled] = useState(false);
  const [autoCheckUpdates, setAutoCheckUpdates] = useState(true);
  const [retentionDays, setRetentionDays] = useState('14');
  const [mcpEnabled, setMcpEnabled] = useState(false);
  const [mcpPort, setMcpPort] = useState('8765');
  const [mcpClient, setMcpClient] = useState('codex');

  return (
    <section className="flex h-full min-h-0 flex-col overflow-hidden p-6">
      <h2 className="shrink-0 text-2xl font-semibold tracking-tight">Settings</h2>

      <Tabs className="mt-4 min-h-0 flex-1 gap-0" defaultValue="general">
        <TabsList
          className="h-9 w-full shrink-0 items-stretch justify-start gap-1 overflow-x-auto overflow-y-hidden rounded-none border-b border-border p-0"
          variant="line"
        >
          <TabsTrigger
            className="h-full flex-none rounded-none border-0 bg-transparent px-3 py-0 text-xs after:bottom-0 data-[state=active]:bg-transparent data-[state=active]:text-foreground data-[state=active]:after:opacity-100 focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none"
            value="general"
          >
            General
          </TabsTrigger>
          <TabsTrigger
            className="h-full flex-none rounded-none border-0 bg-transparent px-3 py-0 text-xs after:bottom-0 data-[state=active]:bg-transparent data-[state=active]:text-foreground data-[state=active]:after:opacity-100 focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none"
            value="security"
          >
            Security
          </TabsTrigger>
          <TabsTrigger
            className="h-full flex-none rounded-none border-0 bg-transparent px-3 py-0 text-xs after:bottom-0 data-[state=active]:bg-transparent data-[state=active]:text-foreground data-[state=active]:after:opacity-100 focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none"
            value="extensions"
          >
            Extensions
          </TabsTrigger>
          <TabsTrigger
            className="h-full flex-none rounded-none border-0 bg-transparent px-3 py-0 text-xs after:bottom-0 data-[state=active]:bg-transparent data-[state=active]:text-foreground data-[state=active]:after:opacity-100 focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none"
            value="updates"
          >
            Updates
          </TabsTrigger>
          <TabsTrigger
            className="h-full flex-none rounded-none border-0 bg-transparent px-3 py-0 text-xs after:bottom-0 data-[state=active]:bg-transparent data-[state=active]:text-foreground data-[state=active]:after:opacity-100 focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none"
            value="logs"
          >
            Logs
          </TabsTrigger>
          <TabsTrigger
            className="h-full flex-none rounded-none border-0 bg-transparent px-3 py-0 text-xs after:bottom-0 data-[state=active]:bg-transparent data-[state=active]:text-foreground data-[state=active]:after:opacity-100 focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none"
            value="backup"
          >
            Backup &amp; Restore
          </TabsTrigger>
          <TabsTrigger
            className="h-full flex-none rounded-none border-0 bg-transparent px-3 py-0 text-xs after:bottom-0 data-[state=active]:bg-transparent data-[state=active]:text-foreground data-[state=active]:after:opacity-100 focus-visible:border-transparent focus-visible:ring-0 focus-visible:outline-none"
            value="mcp"
          >
            AI Agent (MCP)
          </TabsTrigger>
        </TabsList>

        <SettingsTabPanel value="general">
          <SettingsSection title="Appearance">
            <div className="grid max-w-60 gap-2">
              <Label htmlFor="settings-theme">Theme</Label>
              <Select
                onValueChange={(value) => {
                  if (isTheme(value)) onThemeChange(value);
                }}
                value={theme}
              >
                <SelectTrigger id="settings-theme" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="system">System default</SelectItem>
                  <SelectItem value="light">Light</SelectItem>
                  <SelectItem value="dark">Dark</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </SettingsSection>

          <SettingsSection title="Tabs">
            <SettingsSwitch
              checked={confirmOnTabClose}
              description="Ask before closing a connected session tab."
              label="Confirm before closing a connected tab"
              onCheckedChange={setConfirmOnTabClose}
            />
          </SettingsSection>

          <SettingsSection title="Terminal">
            <SettingsSwitch
              checked={autoCopyOnSelect}
              description="Copy selected terminal text to the clipboard automatically."
              label="Auto-copy selection to clipboard"
              onCheckedChange={setAutoCopyOnSelect}
            />
          </SettingsSection>

          <SettingsSection title="VPN">
            <SettingsSwitch
              checked={promptBeforeTunnelConnect}
              description="Ask whether to start a configured tunnel before connecting to a target."
              label="Ask whether to use the tunnel when connecting"
              onCheckedChange={setPromptBeforeTunnelConnect}
            />
          </SettingsSection>
        </SettingsTabPanel>

        <SettingsTabPanel value="security">
          <SettingsSection
            description="Protect the local Wormhole workspace when the app is unattended."
            title="App authentication"
          >
            <p className="text-[11px] text-muted-foreground">
              Authentication is disabled in this migration preview.
            </p>
            <div className="grid max-w-64 gap-2">
              <Label htmlFor="settings-auth-method">Unlock method</Label>
              <Select onValueChange={setAuthMethod} value={authMethod}>
                <SelectTrigger id="settings-auth-method" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="disabled">Disabled</SelectItem>
                  <SelectItem value="pin">PIN</SelectItem>
                  <SelectItem value="password">Password</SelectItem>
                  <SelectItem value="hello">Windows Hello</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {authMethod === 'hello' ? (
              <div className="space-y-3 rounded-lg border border-border/70 bg-card/40 p-3">
                <p className="text-[11px] text-muted-foreground">
                  Windows Hello status will be checked by the native implementation.
                </p>
                <div className="grid max-w-64 gap-2">
                  <Label htmlFor="settings-hello-fallback">Windows Hello fallback</Label>
                  <Select onValueChange={setHelloFallback} value={helloFallback}>
                    <SelectTrigger id="settings-hello-fallback" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="pin">PIN</SelectItem>
                      <SelectItem value="password">Password</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button size="sm" variant="outline">
                  Refresh Windows Hello status
                </Button>
              </div>
            ) : null}

            <div className="grid max-w-64 gap-2">
              <Label htmlFor="settings-idle-timeout">Lock after inactivity</Label>
              <Select
                disabled={authMethod === 'disabled'}
                onValueChange={setIdleTimeout}
                value={idleTimeout}
              >
                <SelectTrigger id="settings-idle-timeout" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  <SelectItem value="1">1 minute</SelectItem>
                  <SelectItem value="5">5 minutes</SelectItem>
                  <SelectItem value="15">15 minutes</SelectItem>
                  <SelectItem value="30">30 minutes</SelectItem>
                  <SelectItem value="60">60 minutes</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button disabled={authMethod === 'disabled'} size="sm">
                Set authentication secret
              </Button>
              <Button disabled={authMethod === 'disabled'} size="sm" variant="outline">
                Test unlock
              </Button>
            </div>
          </SettingsSection>
        </SettingsTabPanel>

        <SettingsTabPanel value="extensions">
          <SettingsSection
            description="Use Bitwarden for credential passwords and HTTPS browser sessions."
            title="Bitwarden"
          >
            <SettingsSection title="Credential vault">
              <SettingsSwitch
                checked={bitwardenEnabled}
                description="Resolve saved credential passwords through the bw CLI."
                label="Enable Bitwarden Password Manager"
                onCheckedChange={setBitwardenEnabled}
              />
              <div className="grid gap-2">
                <Label htmlFor="settings-bitwarden-path">bw.exe path</Label>
                <Input
                  id="settings-bitwarden-path"
                  onChange={(event) => setBitwardenPath(event.target.value)}
                  placeholder="bw"
                  spellCheck={false}
                  value={bitwardenPath}
                />
              </div>
              <p className="text-[11px] text-muted-foreground">
                Bitwarden CLI is not connected in this preview.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline">
                  Refresh status
                </Button>
                <Button size="sm" variant="outline">
                  Install / Update CLI
                </Button>
                <Button size="sm" variant="outline">
                  Log in
                </Button>
                <Button size="sm" variant="outline">
                  Unlock
                </Button>
                <Button size="sm" variant="outline">
                  Sync
                </Button>
              </div>
            </SettingsSection>

            <SettingsSection title="Browser extension">
              <SettingsSwitch
                checked={browserExtensionEnabled}
                description="Use the official Bitwarden extension inside HTTPS sessions."
                label="Enable Bitwarden in HTTPS windows"
                onCheckedChange={setBrowserExtensionEnabled}
              />
              <p className="text-[11px] text-muted-foreground">
                No browser extension is installed in this preview.
              </p>
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                Turning this on installs the official extension automatically in the native app.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline">
                  Install / Update
                </Button>
                <Button size="sm" variant="outline">
                  Import ZIP
                </Button>
                <Button size="sm" variant="outline">
                  Use folder
                </Button>
              </div>
            </SettingsSection>
          </SettingsSection>
        </SettingsTabPanel>

        <SettingsTabPanel value="updates">
          <SettingsSection title="Wormhole updates">
            <p className="text-xs font-medium">Wormhole 0.9.1 · Electron migration preview</p>
            <p className="text-[11px] text-muted-foreground">
              Last checked: never in this preview.
            </p>
            <SettingsSwitch
              checked={autoCheckUpdates}
              description="Check for a newer Wormhole build when the app starts."
              label="Automatically check for updates on startup"
              onCheckedChange={setAutoCheckUpdates}
            />
            <div className="flex flex-wrap gap-2">
              <Button size="sm">Check now</Button>
              <Button size="sm" variant="outline">
                Install update
              </Button>
              <Button size="sm" variant="outline">
                View release notes
              </Button>
            </div>
            <p className="text-[11px] text-muted-foreground">No update has been downloaded.</p>
            <Card className="border-border/70 bg-card/40 p-4 shadow-none">
              <p className="text-xs font-semibold">Release notes</p>
              <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                Update information will appear here after the native update service reports a new
                release.
              </p>
            </Card>
          </SettingsSection>
        </SettingsTabPanel>

        <SettingsTabPanel value="logs">
          <SettingsSection title="Current log">
            <div className="grid gap-2">
              <Label htmlFor="settings-log-file">Today&apos;s log file</Label>
              <Input
                id="settings-log-file"
                readOnly
                spellCheck={false}
                value="%LOCALAPPDATA%\\Wormhole\\logs\\wormhole.log"
              />
            </div>
            <div className="flex flex-wrap gap-2">
              <Button size="sm">Open today&apos;s log</Button>
              <Button size="sm" variant="outline">
                Open log folder
              </Button>
            </div>
          </SettingsSection>

          <SettingsSection title="Rotation">
            <div className="grid max-w-52 gap-2">
              <Label htmlFor="settings-retention">Retain daily log files</Label>
              <Input
                id="settings-retention"
                min="1"
                max="365"
                onChange={(event) => setRetentionDays(event.target.value)}
                type="number"
                value={retentionDays}
              />
            </div>
            <p className="text-[11px] leading-relaxed text-muted-foreground">
              Logs rotate daily. Retention changes are saved by the native implementation.
            </p>
          </SettingsSection>
        </SettingsTabPanel>

        <SettingsTabPanel value="backup">
          <SettingsSection title="Backup &amp; Restore">
            <p className="max-w-2xl text-xs leading-relaxed text-muted-foreground">
              Export your connections, credentials, SSH keys, and VPN tunnels to a JSON file, or
              restore a backup from another installation. Existing items with the same ID are kept;
              the import never overwrites.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button size="sm">Export backup...</Button>
              <Button size="sm" variant="outline">
                Import backup...
              </Button>
            </div>
          </SettingsSection>
        </SettingsTabPanel>

        <SettingsTabPanel value="mcp">
          <SettingsSection
            description="Let an approved local AI agent control already-open SSH sessions."
            title="AI Agent (MCP)"
          >
            <p className="text-xs leading-relaxed text-muted-foreground">
              The local MCP server listens on localhost only and requires a bearer token. The first
              time an agent touches a session, Wormhole asks you to approve it.
            </p>
            <SettingsSwitch
              checked={mcpEnabled}
              description="Start the localhost MCP server for this app session."
              label="Enable MCP server"
              onCheckedChange={setMcpEnabled}
            />
            <div className="grid max-w-52 gap-2">
              <Label htmlFor="settings-mcp-port">Port</Label>
              <Input
                disabled={mcpEnabled}
                id="settings-mcp-port"
                max="65535"
                min="1"
                onChange={(event) => setMcpPort(event.target.value)}
                type="number"
                value={mcpPort}
              />
            </div>
            <p className="text-[11px] text-muted-foreground">MCP server is stopped.</p>
            <div className="grid gap-2">
              <Label htmlFor="settings-mcp-endpoint">Endpoint</Label>
              <div className="flex gap-2">
                <Input
                  className="min-w-0"
                  id="settings-mcp-endpoint"
                  readOnly
                  value={`http://127.0.0.1:${mcpPort}/mcp`}
                />
                <Button className="shrink-0" size="sm" variant="outline">
                  Copy
                </Button>
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="settings-mcp-token">Bearer token</Label>
              <div className="flex flex-wrap gap-2">
                <Input
                  className="min-w-64 flex-1"
                  id="settings-mcp-token"
                  placeholder="•••••••• (hidden — click Reveal)"
                  readOnly
                  type="password"
                />
                <Button size="sm" variant="outline">
                  Reveal / hide
                </Button>
                <Button size="sm" variant="outline">
                  Copy
                </Button>
                <Button size="sm" variant="outline">
                  Regenerate
                </Button>
              </div>
            </div>
            <div className="grid max-w-60 gap-2">
              <Label htmlFor="settings-mcp-client">Client</Label>
              <Select onValueChange={setMcpClient} value={mcpClient}>
                <SelectTrigger id="settings-mcp-client" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="claude-code">Claude Code CLI</SelectItem>
                  <SelectItem value="claude-desktop">Claude Desktop</SelectItem>
                  <SelectItem value="codex">Codex</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <p className="text-[11px] leading-relaxed text-muted-foreground">
              Choose a client to generate its local MCP configuration.
            </p>
            <div className="grid gap-2">
              <Label htmlFor="settings-mcp-config">Codex configuration</Label>
              <Textarea
                className="min-h-48 resize-none font-mono text-[11px]"
                id="settings-mcp-config"
                readOnly
                value={
                  '{\n  "mcpServers": {\n    "wormhole": {\n      "url": "http://127.0.0.1:8765/mcp"\n    }\n  }\n}'
                }
              />
              <Button className="w-fit" size="sm" variant="outline">
                Copy config
              </Button>
            </div>
          </SettingsSection>
        </SettingsTabPanel>
      </Tabs>
    </section>
  );
}

function UtilityPage({
  item,
  sessions,
}: {
  item: { id: NavItem; label: string; hint: string };
  sessions: Session[];
}) {
  const details = {
    credentials: {
      kicker: 'Access',
      title: 'Credentials',
      description: 'Keep reusable login profiles close to the connections that need them.',
      cards: ['Local vault', 'Bitwarden cache', 'Inherited profiles'],
    },
    tunnels: {
      kicker: 'Routing',
      title: 'Tunnels',
      description:
        'Secure routes are shared across sessions and released when the last tab closes.',
      cards: ['WireGuard', 'OpenVPN', 'Cisco Secure Client'],
    },
    settings: {
      kicker: 'Preferences',
      title: 'Settings',
      description: 'Tune the shell, terminal behavior, and security defaults for this machine.',
      cards: ['Appearance', 'Security', 'Updates'],
    },
    sessions: {
      kicker: 'Open sessions',
      title: 'Sessions',
      description: `${sessions.length} session${sessions.length === 1 ? '' : 's'} open in this window.`,
      cards: ['Active sessions', 'Layouts', 'Recent connections'],
    },
  }[item.id];

  return (
    <section className="h-full overflow-auto p-8 lg:px-[6vw]">
      <div className="flex max-w-2xl items-start">
        <div>
          <p className="mb-1 font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">
            {details.kicker}
          </p>
          <h2 className="text-2xl font-semibold tracking-tight">{details.title}</h2>
          <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
            {details.description}
          </p>
        </div>
      </div>
      <div className="mt-8 grid max-w-4xl gap-2 md:grid-cols-3">
        {details.cards.map((card, index) => (
          <Card
            className="relative min-h-32 justify-end border-border/70 bg-card/60 p-4 shadow-none transition-colors hover:bg-card"
            key={card}
          >
            <span className="absolute right-4 top-4 font-mono text-[9px] text-muted-foreground">
              0{index + 1}
            </span>
            <strong className="text-xs">{card}</strong>
            <span className="text-[10px] text-muted-foreground">Ready for migration</span>
            <MoreHorizontal className="absolute bottom-4 right-4 size-4 text-muted-foreground" />
          </Card>
        ))}
      </div>
      <Alert className="mt-6 max-w-4xl">
        <Wifi />
        <div>
          <AlertTitle className="text-xs">WinUI implementation remains active</AlertTitle>
          <AlertDescription className="text-[10px]">
            This Electron surface is intentionally beside the existing desktop shell. The next
            migration step can replace the remaining provider actions one surface at a time.
          </AlertDescription>
        </div>
      </Alert>
    </section>
  );
}

export default App;
