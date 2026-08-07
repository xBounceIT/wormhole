import {
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ComponentProps,
  type CSSProperties,
  type DragEvent,
  type FormEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent,
  type ReactNode,
} from 'react';
import './index.css';
import wormholeIcon from '../Assets/wormhole-logo-transparent.png';
import { backupExportPasswordsMatch } from './backup-state';
import { mergeCredential } from './credential-state';
import {
  parentLocalSftpPath,
  parentSftpPath,
  isSftpTransferTerminal,
  shouldApplySftpClosed,
  shouldApplySftpError,
  shouldApplySftpFailure,
  shouldApplySftpReady,
  shouldFinishSftpClose,
  shouldRefreshSftpPane,
  nextSftpOperationRefreshRequests,
  nextSftpTransferRefreshRequests,
  compareSftpEntries,
  pruneSftpSelection,
  removeSftpTransferRow,
  settleSftpTransferRows,
  sftpVirtualScrollAnchor,
  sftpVisibleEntryRange,
  sftpTransferItemKey,
  sftpVirtualRowHeight,
  updateSftpTransferError,
  type SftpBrowserState,
  type SftpConflict,
  type SftpPaneState,
  type SftpSortColumn,
  type SftpTransferDestination,
  type SftpTransferRow,
} from './sftp-state';
import {
  AlertCircle,
  ArrowUp,
  ArrowRightLeft,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Check,
  Copy,
  Download,
  File,
  FilePlus2,
  FlaskConical,
  Folder,
  FolderOpen,
  FolderPlus,
  Globe,
  Info,
  KeyRound,
  LoaderCircle,
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
  Trash2,
  Upload,
  Wifi,
  X,
  XCircle,
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
  DropdownMenuSeparator,
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
import { findParentFolderId } from './tree-parent';
import {
  quickConnectSupportsTunnel,
  quickConnectTunnelId,
  type QuickConnectProtocol,
} from './quick-connect-state';
import { VncSurface } from './components/VncSurface';
import { RdpSurface, type RdpUiStatus } from './components/RdpSurface';
import { WebSurface } from './components/WebSurface';
import { ConnectionStepper } from './components/ConnectionStepper';
import {
  applyTheme,
  getInitialTheme,
  getSystemTheme,
  isTheme,
  themeStorageKey,
  type ResolvedTheme,
  type Theme,
} from './theme';
import { applyRdpBackendEvent } from './rdp-state';
import { formatSftpDate, formatSftpSize } from './sftp-format';
import { hasSftpDragPayload, sftpDragDataType } from './sftp-dnd';
import { cn } from '@/lib/utils';
import { WebSessionAttemptTracker } from '../electron/web-session-attempt';
import {
  isTunnelTestCancellation,
  isTunnelTestNotice,
  missingTunnelFields,
  normalizeTunnelEditorSettings,
  tunnelModeFor,
  tunnelValueFor,
  userFacingTunnelError,
  type TunnelMode,
} from './tunnel-state';

type Protocol = QuickConnectProtocol;
type AutoSudoMode = 'inherit' | 'on' | 'off';
type NavItem = 'sessions' | 'credentials' | 'tunnels' | 'settings';
type AuthPromptKind = 'lock' | 'confirmation';

type SerialSettings = {
  baudRate: number;
  dataBits: number;
  stopBits: number;
  parity: number;
  flowControl: number;
};

const defaultSerialSettings: SerialSettings = {
  baudRate: 9600,
  dataBits: 8,
  stopBits: 1,
  parity: 0,
  flowControl: 0,
};

const rootFolderSelectionValue = '__wormhole-root__';

function serialSettingsFromNode(
  node: Pick<
    TreeNode,
    'serialBaudRate' | 'serialDataBits' | 'serialStopBits' | 'serialParity' | 'serialFlowControl'
  >,
): SerialSettings {
  return {
    baudRate:
      node.serialBaudRate && node.serialBaudRate > 0
        ? node.serialBaudRate
        : defaultSerialSettings.baudRate,
    dataBits:
      node.serialDataBits && node.serialDataBits >= 5 && node.serialDataBits <= 8
        ? node.serialDataBits
        : defaultSerialSettings.dataBits,
    stopBits:
      node.serialStopBits === 1 || node.serialStopBits === 2 || node.serialStopBits === 3
        ? node.serialStopBits
        : defaultSerialSettings.stopBits,
    parity:
      node.serialParity !== undefined && node.serialParity >= 0 && node.serialParity <= 4
        ? node.serialParity
        : defaultSerialSettings.parity,
    flowControl:
      node.serialFlowControl !== undefined &&
      node.serialFlowControl >= 0 &&
      node.serialFlowControl <= 3
        ? node.serialFlowControl
        : defaultSerialSettings.flowControl,
  };
}

type AuthPromptRequest = {
  kind: AuthPromptKind;
  reason: string;
  autoWindowsHello: boolean;
};

type TreeNode = {
  id: string;
  name: string;
  kind: 'folder' | 'connection';
  protocol?: Protocol;
  host?: string;
  port?: number;
  serialBaudRate?: number;
  serialDataBits?: number;
  serialStopBits?: number;
  serialParity?: number;
  serialFlowControl?: number;
  httpIgnoreCertErrors?: boolean;
  sshAutoSudo?: boolean | null;
  tunnelEnabled?: boolean | null;
  tunnelConfigId?: string;
  persisted?: boolean;
  children?: TreeNode[];
};

function autoSudoModeFor(value: boolean | null | undefined): AutoSudoMode {
  return value === true ? 'on' : value === false ? 'off' : 'inherit';
}

function autoSudoValueFor(mode: AutoSudoMode): boolean | null {
  return mode === 'on' ? true : mode === 'off' ? false : null;
}

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

function collectTreeNodeIds(node: TreeNode): string[] {
  return [node.id, ...(node.children?.flatMap(collectTreeNodeIds) ?? [])];
}

function removeTreeNode(nodes: TreeNode[], nodeId: string): TreeNode[] {
  return nodes.flatMap((node) => {
    if (node.id === nodeId) return [];
    return node.children ? [{ ...node, children: removeTreeNode(node.children, nodeId) }] : [node];
  });
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
  nodeId?: string;
  port?: number;
  canTransfer?: boolean;
  backendSessionId?: string;
  status: 'connecting' | 'connected' | 'failed' | 'closed' | 'placeholder';
  terminalFrame?: WormholeSshTerminalFrame;
  tunnelProgress?: { phase: string; detail?: string } | null;
  tunnelConfigId?: string;
  serialSettings?: SerialSettings;
  sftp?: SftpBrowserState;
  error?: string;
  fingerprint?: string;
  hostKeyMismatch?: {
    expected: string;
    received: string;
  };
  rdpStatus?: RdpUiStatus;
  rdpBackend?: 'activex' | 'freerdp';
  rdpError?: string;
  rdpProfile?: WormholeRdpProfile;
  webTargetNodeId?: string;
  webIgnoreCertErrors?: boolean;
  webUrl?: string;
  webCanGoBack?: boolean;
  webCanGoForward?: boolean;
};

type RdpCredentials = {
  username: string;
  domain: string;
  password: string;
};

type CredentialRecord = {
  id: string;
  name: string;
  protocol: Protocol;
  username: string;
  domain?: string;
  provider: 'Local' | 'Bitwarden';
  canEdit: boolean;
  canDelete: boolean;
};

type CredentialDialogState =
  | { kind: 'credentials'; result: WormholeWorkspaceCredentialReveal }
  | { kind: 'error'; message: string };
type CredentialCopyField = 'username' | 'secret';

type CredentialDraft = {
  name: string;
  protocol: 'ssh' | 'rdp' | 'vnc';
  username: string;
  domain: string;
  password: string;
};

function emptyCredentialDraft(): CredentialDraft {
  return { name: '', protocol: 'ssh', username: '', domain: '', password: '' };
}

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

function encodeTerminalData(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function createBlankTerminalCells(columns: number, rows: number): WormholeSshTerminalCell[] {
  return Array.from({ length: columns * rows }, () => ({
    character: ' ',
    foreground: 0xff80,
    background: 0xff81,
  }));
}

function applySshTerminalFrame(
  previous: WormholeSshTerminalFrame | undefined,
  incoming: WormholeSshTerminalFrame,
): WormholeSshTerminalFrame {
  const cellCount = incoming.columns * incoming.rows;
  const hasMatchingPrevious =
    previous &&
    previous.columns === incoming.columns &&
    previous.rows === incoming.rows &&
    previous.cells?.length === cellCount;
  const cells =
    incoming.full && incoming.cells?.length === cellCount
      ? incoming.cells.slice()
      : hasMatchingPrevious
        ? previous.cells!.slice()
        : createBlankTerminalCells(incoming.columns, incoming.rows);

  for (const change of incoming.changes) {
    if (change.index < 0 || change.index >= cells.length) continue;
    cells[change.index] = {
      character: change.character,
      foreground: change.foreground,
      background: change.background,
    };
  }

  const sameViewport = previous?.columns === incoming.columns && previous.rows === incoming.rows;
  let scrollback: WormholeSshTerminalScrollbackLine[];
  if (incoming.scrollbackReset) {
    scrollback = incoming.scrollback?.slice(-terminalMaxScrollbackLines) ?? [];
  } else if (sameViewport) {
    scrollback = incoming.scrollback?.length
      ? [...(previous?.scrollback ?? []), ...incoming.scrollback].slice(-terminalMaxScrollbackLines)
      : (previous?.scrollback ?? []);
  } else {
    scrollback = incoming.scrollback?.slice(-terminalMaxScrollbackLines) ?? [];
  }
  return { ...incoming, full: true, cells, scrollback };
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

function updateConnectionInTree(
  nodes: TreeNode[],
  connectionId: string,
  folderId: string,
  update: {
    name: string;
    host: string;
    protocol: Protocol;
    serialSettings?: SerialSettings;
    sshAutoSudo: boolean | null;
    httpIgnoreCertErrors?: boolean;
    tunnelEnabled: boolean | null;
    tunnelConfigId: string;
  },
): TreeNode[] {
  let editedConnection: TreeNode | undefined;

  function removeConnection(items: TreeNode[]): TreeNode[] {
    return items.flatMap((node) => {
      if (node.id === connectionId) {
        const { serialSettings, ...baseUpdate } = update;
        editedConnection = {
          ...node,
          ...baseUpdate,
          ...(serialSettings
            ? {
                serialBaudRate: serialSettings.baudRate,
                serialDataBits: serialSettings.dataBits,
                serialStopBits: serialSettings.stopBits,
                serialParity: serialSettings.parity,
                serialFlowControl: serialSettings.flowControl,
              }
            : {}),
        };
        return [];
      }

      return node.children ? [{ ...node, children: removeConnection(node.children) }] : [node];
    });
  }

  const remaining = removeConnection(nodes);
  if (!editedConnection) return nodes;

  return folderId
    ? insertIntoTreeFolder(remaining, folderId, [editedConnection])
    : [...remaining, editedConnection];
}

function updateFolderInTree(
  nodes: TreeNode[],
  folderId: string,
  update: {
    name: string;
    sshAutoSudo: boolean | null;
    tunnelEnabled: boolean | null;
    tunnelConfigId: string;
  },
): TreeNode[] {
  return nodes.map((node) => {
    if (node.id === folderId) return { ...node, ...update };
    return node.children
      ? { ...node, children: updateFolderInTree(node.children, folderId, update) }
      : node;
  });
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

function CredentialValueRow({
  id,
  label,
  value,
  copied,
  onCopy,
}: {
  id: string;
  label: string;
  value: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="grid gap-1.5">
      <Label className="text-[11px] text-muted-foreground" htmlFor={id}>
        {label}
      </Label>
      <div className="flex items-center gap-2">
        <Input
          aria-label={label}
          className="min-w-0 font-mono text-xs"
          id={id}
          readOnly
          spellCheck={false}
          value={value}
        />
        <Button onClick={onCopy} size="sm" type="button" variant="outline">
          {copied ? <Check data-icon="inline-start" /> : <Copy data-icon="inline-start" />}
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
    </div>
  );
}

function AutoSudoField({
  id,
  mode,
  onChange,
  scope,
}: {
  id: string;
  mode: AutoSudoMode;
  onChange: (mode: AutoSudoMode) => void;
  scope: 'connection' | 'folder';
}) {
  const isFolder = scope === 'folder';
  const inheritLabel = isFolder ? 'Inherit from parent' : 'Inherit from folder';
  const description =
    mode === 'on'
      ? isFolder
        ? 'SSH descendants that inherit this setting run “sudo su” on connect and send the saved password only at the sudo prompt.'
        : 'Runs “sudo su” on connect and sends the saved password only at the sudo prompt. If sudo does not prompt, nothing is sent.'
      : mode === 'off'
        ? 'Never runs sudo automatically on connect.'
        : isFolder
          ? 'SSH descendants that inherit this setting follow the parent folder.'
          : 'Follows the parent folder’s Auto sudo setting.';

  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{isFolder ? 'Auto sudo default (SSH)' : 'Auto sudo (SSH)'}</Label>
      <Select onValueChange={(value) => onChange(value as AutoSudoMode)} value={mode}>
        <SelectTrigger className="w-full sm:max-w-[280px]" id={id}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="inherit">{inheritLabel}</SelectItem>
          <SelectItem value="on">On</SelectItem>
          <SelectItem value="off">Off</SelectItem>
        </SelectContent>
      </Select>
      <p className="text-[11px] leading-relaxed text-muted-foreground">{description}</p>
    </div>
  );
}

function NodeContextMenu({
  node,
  children,
  onEdit,
  onNewConnection,
  onNewFolder,
  onShowCredentials,
  onDuplicateConnection,
  onDelete,
}: {
  node: TreeNode;
  children: ReactNode;
  onEdit: () => void;
  onNewConnection: () => void;
  onNewFolder: () => void;
  onShowCredentials?: () => void;
  onDuplicateConnection?: () => void;
  onDelete: () => void;
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
            <ContextMenuItem onSelect={() => onShowCredentials?.()}>
              <KeyRound />
              Show credentials
            </ContextMenuItem>
            <ContextMenuItem onSelect={() => onDuplicateConnection?.()}>
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
        <ContextMenuItem onSelect={onDelete} variant="destructive">
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
        {session.canTransfer && session.status === 'connected' ? (
          <ContextMenuItem onSelect={onFileTransfer}>
            <ArrowRightLeft />
            SFTP browser
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
      <TooltipContent side="left">{node.host}</TooltipContent>
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

function AuthPrompt({
  state,
  request,
  onResult,
}: {
  state: WormholeAuthState;
  request: AuthPromptRequest;
  onResult: (succeeded: boolean) => void;
}) {
  const [secret, setSecret] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [helloBusy, setHelloBusy] = useState(false);
  const helloInFlight = useRef(false);
  const method: WormholeAuthFallback =
    state.mode === 'password' || (state.mode === 'windowsHello' && state.fallback === 'password')
      ? 'password'
      : 'pin';
  const isHelloMode = state.mode === 'windowsHello';
  const fallbackName = method === 'pin' ? 'Wormhole PIN' : 'Wormhole password';

  async function tryWindowsHello() {
    if (helloInFlight.current || !window.wormhole) return;

    helloInFlight.current = true;
    setHelloBusy(true);
    setStatus('Waiting for Windows Hello…');
    try {
      const availability = await window.wormhole.checkWindowsHello();
      if (!availability.available) {
        setStatus(`${availability.message} You can use your ${fallbackName} instead.`);
        return;
      }
      const result = await window.wormhole.verifyWindowsHello();
      if (result.succeeded) {
        onResult(true);
        return;
      }
      setStatus(result.message || `Windows Hello didn't recognize you. Use your ${fallbackName}.`);
    } catch {
      setStatus(`Windows Hello isn't available right now. Use your ${fallbackName}.`);
    } finally {
      helloInFlight.current = false;
      setHelloBusy(false);
    }
  }

  useEffect(() => {
    setSecret('');
    setStatus('');
    if (request.autoWindowsHello && isHelloMode) void tryWindowsHello();
    // The prompt is intentionally restarted when the configured mode changes. The callback is
    // local to this prompt instance and does not need to be a stable dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request.reason, request.autoWindowsHello, isHelloMode, method]);

  async function submitSecret(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || !secret || !window.wormhole) return;

    setBusy(true);
    setStatus('Checking…');
    try {
      const result = await window.wormhole.verifyAuth({ method, secret });
      if (result.succeeded) {
        onResult(true);
        return;
      }
      setSecret('');
      setStatus(result.message || (method === 'pin' ? 'Invalid PIN.' : 'Invalid password.'));
    } catch {
      setStatus("Wormhole couldn't check your PIN. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      aria-describedby="auth-prompt-description"
      aria-labelledby="auth-prompt-title"
      aria-modal="true"
      className="fixed inset-0 z-[100] flex items-center justify-center bg-background/85 p-5 backdrop-blur-md"
      role="dialog"
    >
      <Card className="w-full max-w-[400px] gap-0 border-border/80 bg-card py-0 shadow-[0_24px_80px_rgba(0,0,0,0.45)]">
        <CardHeader className="gap-3 px-5 py-5">
          <div className="flex items-start gap-3">
            <div className="grid size-9 shrink-0 place-items-center rounded-lg border border-border/70 bg-muted/60 text-foreground">
              <KeyRound className="size-4" />
            </div>
            <div className="min-w-0 space-y-1">
              <CardTitle className="text-base" id="auth-prompt-title">
                {request.kind === 'lock' ? 'Wormhole is locked' : 'Unlock Wormhole'}
              </CardTitle>
              <CardDescription className="text-xs leading-relaxed">
                {request.reason}
              </CardDescription>
            </div>
          </div>
          <p className="text-xs leading-relaxed text-muted-foreground" id="auth-prompt-description">
            {isHelloMode
              ? `Windows Hello will open now. You can also use your ${fallbackName} below.`
              : `Enter your ${fallbackName} to continue.`}
          </p>
        </CardHeader>
        <CardContent className="space-y-4 border-t border-border/60 px-5 py-4">
          {isHelloMode ? (
            <div className="space-y-2 rounded-lg border border-border/70 bg-background/50 p-3">
              <p className="text-[11px] text-muted-foreground">{state.windowsHello.message}</p>
              <Button
                className="w-full"
                disabled={helloBusy}
                onClick={() => void tryWindowsHello()}
                size="sm"
                type="button"
                variant="outline"
              >
                {helloBusy ? (
                  <LoaderCircle className="animate-spin" data-icon="inline-start" />
                ) : (
                  <KeyRound data-icon="inline-start" />
                )}
                {helloBusy ? 'Waiting for Windows Hello…' : 'Use Windows Hello'}
              </Button>
            </div>
          ) : null}
          <form className="space-y-3" onSubmit={submitSecret}>
            <div className="grid gap-2">
              <Label htmlFor="auth-secret">{fallbackName}</Label>
              {isHelloMode && method === 'pin' ? (
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  Use the PIN you created in Wormhole, not your Windows PIN.
                </p>
              ) : null}
              <Input
                autoFocus={!isHelloMode || !request.autoWindowsHello}
                autoComplete="current-password"
                id="auth-secret"
                inputMode={method === 'pin' ? 'numeric' : undefined}
                onChange={(event) => setSecret(event.target.value)}
                placeholder={`Enter your ${method === 'pin' ? 'Wormhole PIN' : 'password'}`}
                type="password"
                value={secret}
              />
            </div>
            {status ? (
              <p
                className={`text-[11px] ${helloBusy || busy ? 'text-muted-foreground' : 'text-destructive'}`}
                role={helloBusy || busy ? 'status' : 'alert'}
              >
                {status}
              </p>
            ) : null}
            <div className="flex justify-end gap-2 pt-1">
              {request.kind === 'confirmation' ? (
                <Button onClick={() => onResult(false)} size="sm" type="button" variant="ghost">
                  Cancel
                </Button>
              ) : null}
              <Button disabled={busy || !secret} size="sm" type="submit">
                {request.kind === 'confirmation' ? 'Confirm' : 'Unlock'}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

type WormholeAppProps = {
  initialAuthState: WormholeAuthState;
  initialWorkspace: WormholeWorkspaceSnapshot;
  initialSettings: WormholeAppSettings;
};

function App({ initialAuthState, initialWorkspace, initialSettings }: WormholeAppProps) {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(getSystemTheme);
  const [tree, setTree] = useState<TreeNode[]>(initialWorkspace.tree);
  const [credentials, setCredentials] = useState<CredentialRecord[]>(initialWorkspace.credentials);
  const [tunnels, setTunnels] = useState<TunnelRecord[]>(initialWorkspace.tunnels);
  const [authState, setAuthState] = useState<WormholeAuthState | null>(initialAuthState);
  const [authGate, setAuthGate] = useState<'locked' | 'unlocked'>('unlocked');
  const [lockReason, setLockReason] = useState('Unlock Wormhole to continue.');
  const [authPrompt, setAuthPrompt] = useState<AuthPromptRequest | null>(null);
  const [mcpApprovals, setMcpApprovals] = useState<WormholeMcpApproval[]>([]);
  const [tunnelPrompts, setTunnelPrompts] = useState<WormholeTunnelPrompt[]>([]);
  const [tunnelPromptValue, setTunnelPromptValue] = useState('');
  const [routePrompts, setRoutePrompts] = useState<
    Array<{
      sessionId: string;
      leaseId: string;
      promptId: string;
      connectionName?: string;
      tunnelName?: string;
    }>
  >([]);
  const activeTunnelPromptId = tunnelPrompts[0]?.promptId;
  useEffect(() => {
    setTunnelPromptValue('');
  }, [activeTunnelPromptId]);
  const authPromptResolver = useRef<((succeeded: boolean) => void) | null>(null);
  const idleCheckInFlight = useRef(false);
  const lastActivityAt = useRef(Date.now());
  const webSessionAttempts = useRef(new WebSessionAttemptTracker());
  const [activePage, setActivePage] = useState<NavItem>('sessions');
  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set(collectFolderIds(initialWorkspace.tree)),
  );
  const [selectedNodeId, setSelectedNodeId] = useState(
    () => findFirstConnection(initialWorkspace.tree)?.id ?? initialWorkspace.tree[0]?.id ?? '',
  );
  const [selectedTreeNodeIds, setSelectedTreeNodeIds] = useState<Set<string>>(() => new Set());
  const [searchText, setSearchText] = useState('');
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState('');
  const [rdpCredentials, setRdpCredentials] = useState<Record<string, RdpCredentials>>({});
  const [rdpCredentialPrompt, setRdpCredentialPrompt] = useState<string | null>(null);
  const [rdpCredentialForm, setRdpCredentialForm] = useState<RdpCredentials>({
    username: '',
    domain: '',
    password: '',
  });
  const [quickConnectOpen, setQuickConnectOpen] = useState(false);
  const [quickConnectForm, setQuickConnectForm] = useState({
    name: '',
    host: '',
    protocol: 'ssh' as Protocol,
    tunnel: 'off' as TunnelMode,
    httpIgnoreCertErrors: false,
    serial: { ...defaultSerialSettings },
  });
  const [newConnectionOpen, setNewConnectionOpen] = useState(false);
  const [editingConnectionId, setEditingConnectionId] = useState<string | null>(null);
  const [folderDetailsOpen, setFolderDetailsOpen] = useState(false);
  const [editingFolderId, setEditingFolderId] = useState<string | null>(null);
  const [folderDetailsForm, setFolderDetailsForm] = useState({
    name: '',
    sshAutoSudo: 'inherit' as AutoSudoMode,
    tunnel: 'inherit' as TunnelMode,
  });
  const [editorError, setEditorError] = useState('');
  const [editorBusy, setEditorBusy] = useState(false);
  const [credentialDialog, setCredentialDialog] = useState<CredentialDialogState | null>(null);
  const [copiedCredentialField, setCopiedCredentialField] = useState<CredentialCopyField | null>(
    null,
  );
  const [credentialRevealBusy, setCredentialRevealBusy] = useState(false);
  const credentialRevealRequest = useRef(0);
  const copiedCredentialTimer = useRef<number | undefined>(undefined);
  const [pendingDeleteNode, setPendingDeleteNode] = useState<TreeNode | null>(null);
  const [deleteNodeBusy, setDeleteNodeBusy] = useState(false);
  const [deleteNodeError, setDeleteNodeError] = useState('');
  const [newConnectionForm, setNewConnectionForm] = useState({
    name: '',
    host: '',
    protocol: 'ssh' as Protocol,
    folder: '',
    sshAutoSudo: 'inherit' as AutoSudoMode,
    httpIgnoreCertErrors: false,
    tunnel: 'inherit' as TunnelMode,
    serial: { ...defaultSerialSettings },
  });
  const [newFolderOpen, setNewFolderOpen] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [newFolderParentId, setNewFolderParentId] = useState<string | null>(null);
  const [updateCurrentVersion, setUpdateCurrentVersion] = useState('');
  const [updateResult, setUpdateResult] = useState<WormholeUpdateCheckResult | null>(null);
  const [autoCheckForUpdates, setAutoCheckForUpdates] = useState(
    initialSettings.autoCheckForUpdates,
  );
  const [skippedUpdateVersion, setSkippedUpdateVersion] = useState<string | null>(
    initialSettings.skippedUpdateVersion,
  );
  const [lastUpdateCheck, setLastUpdateCheck] = useState<string | null>(
    initialSettings.lastUpdateCheck,
  );
  const [updateBusy, setUpdateBusy] = useState(false);
  const [updateStatus, setUpdateStatus] = useState('');
  const [updateDownloadProgress, setUpdateDownloadProgress] = useState<number | null>(null);
  const [settingsUpdatesRequest, setSettingsUpdatesRequest] = useState(0);
  const [draggedNodeIds, setDraggedNodeIds] = useState<string[]>([]);
  const [dropTarget, setDropTarget] = useState<{
    id: string;
    placement: DropPlacement;
  } | null>(null);
  const sftpRequestSequence = useRef(0);
  const sftpRequestIds = useRef(new Map<string, number>());
  const sftpPaneRequestSequence = useRef(0);
  const sftpCancelRequests = useRef(new Set<string>());
  const sftpRefreshHandlers = useRef<
    | {
        local: (sessionId: string, path: string) => void;
        remote: (sessionId: string, path: string) => void;
      }
    | undefined
  >(undefined);
  const visibleTree = useMemo(
    () => filterTree(tree, searchText.trim().toLowerCase()),
    [searchText, tree],
  );
  const folders = useMemo(() => collectFolders(tree), [tree]);
  const selectedSession =
    sessions.find((session) => session.id === selectedSessionId) ?? sessions[0];
  const resolvedTheme = theme === 'system' ? systemTheme : theme;

  useLayoutEffect(() => {
    applyTheme(resolvedTheme);
  }, [resolvedTheme]);

  useEffect(() => {
    window.localStorage.setItem(themeStorageKey, theme);
  }, [theme]);

  useEffect(() => {
    if (!window.wormhole) return;
    let active = true;

    void window.wormhole
      .updateStatus()
      .then(({ currentVersion, result }) => {
        if (!active) return;
        setUpdateCurrentVersion(currentVersion);
        setUpdateResult(result);
      })
      .catch(() => {
        // The settings page still exposes "Check now" when status cannot be read.
      });
    const unsubscribeResult = window.wormhole.onUpdateResult((result) => {
      setUpdateResult(result);
    });
    const unsubscribeProgress = window.wormhole.onUpdateProgress(({ downloaded, total }) => {
      setUpdateDownloadProgress(total > 0 ? Math.min(1, downloaded / total) : null);
    });
    return () => {
      active = false;
      unsubscribeResult();
      unsubscribeProgress();
    };
  }, []);

  const updateBannerVisible = Boolean(
    updateResult?.isUpdateAvailable &&
    updateResult.latestVersion &&
    updateResult.latestVersion !== skippedUpdateVersion,
  );

  async function handleCheckForUpdates() {
    if (!window.wormhole || updateBusy) return;
    setUpdateBusy(true);
    setUpdateStatus('Checking for updates…');
    try {
      const result = await window.wormhole.checkForUpdates();
      setUpdateResult(result);
      setUpdateStatus(
        result.checkFailed
          ? "Couldn't reach the update server. Try again later."
          : result.isUpdateAvailable
            ? `Update available: ${result.latestVersion}`
            : "You're on the latest version.",
      );
      const settings = await window.wormhole.readAppSettings();
      setLastUpdateCheck(settings.lastUpdateCheck);
    } catch {
      setUpdateStatus("Couldn't reach the update server. Try again later.");
    } finally {
      setUpdateBusy(false);
    }
  }

  function handleDismissUpdate() {
    const latest = updateResult?.latestVersion;
    if (!latest) return;
    setSkippedUpdateVersion(latest);
    void window.wormhole?.setUpdatePreferences({ skippedUpdateVersion: latest }).catch(() => {
      // A failed save leaves the local state; the next settings read re-syncs it.
    });
  }

  async function handleInstallUpdate() {
    const latest = updateResult;
    if (
      !window.wormhole ||
      !latest?.isUpdateAvailable ||
      !latest.installerUrl ||
      !latest.installerFileName ||
      updateBusy
    ) {
      return;
    }
    setUpdateBusy(true);
    setUpdateDownloadProgress(0);
    setUpdateStatus('Downloading…');
    try {
      const installerPath = await window.wormhole.downloadUpdate({
        installerUrl: latest.installerUrl,
        installerFileName: latest.installerFileName,
        ...(latest.installerSha256 ? { installerSha256: latest.installerSha256 } : {}),
        ...(latest.installerSize != null ? { installerSize: latest.installerSize } : {}),
      });
      setUpdateStatus('Launching installer…');
      // The app quits immediately after launching the installer, so the IPC reply may never
      // arrive. Fire it and let the status line speak for itself.
      void window.wormhole.installUpdate(installerPath);
    } catch (error) {
      setUpdateStatus(`Install failed: ${error instanceof Error ? error.message : String(error)}`);
      setUpdateBusy(false);
      setUpdateDownloadProgress(null);
    }
  }

  function handleSetAutoCheckForUpdates(enabled: boolean) {
    setAutoCheckForUpdates(enabled);
    void window.wormhole?.setUpdatePreferences({ autoCheckForUpdates: enabled }).catch(() => {
      // A failed save leaves the local switch state; the next settings read re-syncs it.
    });
  }

  function handleOpenReleaseNotes() {
    const url = updateResult?.releaseUrl;
    if (!url) return;
    void window.wormhole?.openExternal(url).catch(() => {
      // The release page is a convenience; a failure is not user-actionable here.
    });
  }

  const requestAuthentication = useCallback(
    (reason: string) => {
      if (!authState?.configured || authState.mode === 'disabled') return Promise.resolve(true);

      return new Promise<boolean>((resolve) => {
        authPromptResolver.current = resolve;
        setAuthPrompt({ kind: 'confirmation', reason, autoWindowsHello: true });
      });
    },
    [authState],
  );

  function handleAuthPromptResult(succeeded: boolean) {
    const activePrompt =
      authPrompt ??
      (authGate === 'locked' && authState?.configured
        ? { kind: 'lock' as const, reason: lockReason, autoWindowsHello: true }
        : null);
    if (!activePrompt) return;

    if (activePrompt.kind === 'lock') {
      if (succeeded) {
        setAuthGate('unlocked');
        setLockReason('Unlock Wormhole to continue.');
        lastActivityAt.current = Date.now();
      }
      return;
    }

    authPromptResolver.current?.(succeeded);
    authPromptResolver.current = null;
    setAuthPrompt(null);
  }

  async function resolveMcpApproval(approved: boolean) {
    const approval = mcpApprovals[0];
    if (!approval || !window.wormhole) return;
    try {
      await window.wormhole.respondMcpApproval(approval.requestId, approved);
    } catch {
      // A lock or disconnected SSH session can invalidate the prompt before the user clicks it.
    } finally {
      setMcpApprovals((current) => current.filter((item) => item.requestId !== approval.requestId));
    }
  }

  async function resolveTunnelPrompt(cancelled: boolean) {
    const prompt = tunnelPrompts[0];
    if (!prompt || !window.wormhole) return;
    try {
      await window.wormhole.respondTunnelPrompt({
        leaseId: prompt.sessionId,
        promptId: prompt.promptId,
        value: cancelled ? '' : prompt.confirmation ? 'accept' : tunnelPromptValue,
        cancelled,
      });
    } catch {
      // The tunnel may have failed or timed out while the user was answering.
    } finally {
      setTunnelPrompts((current) => current.filter((item) => item.promptId !== prompt.promptId));
      setTunnelPromptValue('');
    }
  }

  async function resolveTunnelRoute(choice: 'tunnel' | 'direct' | 'cancel') {
    const prompt = routePrompts[0];
    if (!prompt || !window.wormhole) return;
    try {
      await window.wormhole.respondTunnelRoute({
        leaseId: prompt.leaseId,
        promptId: prompt.promptId,
        choice,
      });
    } catch {
      // The tunnel may have failed or timed out while the user was answering.
    } finally {
      setRoutePrompts((current) => current.filter((item) => item.promptId !== prompt.promptId));
    }
  }

  useEffect(() => {
    const markActivity = () => {
      lastActivityAt.current = Date.now();
    };
    window.addEventListener('keydown', markActivity);
    window.addEventListener('pointerdown', markActivity);
    window.addEventListener('touchstart', markActivity);
    return () => {
      window.removeEventListener('keydown', markActivity);
      window.removeEventListener('pointerdown', markActivity);
      window.removeEventListener('touchstart', markActivity);
    };
  }, []);

  useEffect(() => {
    const unsubscribe = window.wormhole?.onSshEvent((event) => {
      setSessions((current) =>
        current.map((session) => {
          if (session.backendSessionId !== event.sessionId) return session;
          if (event.type === 'tunnel.progress') {
            return {
              ...session,
              tunnelProgress: { phase: event.phase, detail: event.detail },
            };
          }
          if (event.type === 'connected') {
            return {
              ...session,
              status: 'connected',
              host: event.host,
              fingerprint: event.fingerprint,
              hostKeyMismatch: undefined,
              tunnelProgress: null,
              error: undefined,
            };
          }
          if (event.type === 'screen') {
            if (session.status !== 'connected') return session;
            return {
              ...session,
              terminalFrame: applySshTerminalFrame(session.terminalFrame, event.frame),
            };
          }
          if (event.type === 'sftp.opening') {
            const requestMatches =
              event.requestId === undefined
                ? session.sftp?.requestId === undefined
                : session.sftp?.requestId === event.requestId;
            if (!session.sftp || session.sftp.status === 'closing' || !requestMatches) {
              return session;
            }
            return {
              ...session,
              sftp: {
                ...session.sftp,
                status: 'opening',
                path: session.sftp?.path ?? '',
                entries: session.sftp?.entries ?? [],
                truncated: false,
                error: undefined,
                requestId: event.requestId ?? session.sftp.requestId,
              },
            };
          }
          if (event.type === 'sftp.ready') {
            if (!session.sftp || !shouldApplySftpReady(session.sftp, event.path, event.requestId)) {
              return session;
            }
            return {
              ...session,
              sftp: {
                ...session.sftp,
                status: 'ready',
                path: event.path,
                previousPath: undefined,
                entries: event.entries,
                truncated: event.truncated,
                error: undefined,
                requestId: event.requestId ?? session.sftp.requestId,
              },
            };
          }
          if (event.type === 'sftp.error') {
            if (session.sftp?.status === 'closing') {
              return { ...session, sftp: undefined };
            }
            if (!session.sftp || !shouldApplySftpError(session.sftp, event.path, event.requestId)) {
              return session;
            }
            return {
              ...session,
              sftp: {
                ...session.sftp,
                status: 'failed',
                path: session.sftp.previousPath ?? session.sftp.path,
                previousPath: undefined,
                entries: session.sftp?.entries ?? [],
                truncated: session.sftp?.truncated ?? false,
                error: event.error,
              },
            };
          }
          if (event.type === 'sftp.local.ready') {
            if (!session.sftp || session.sftp.status === 'closing') return session;
            if (session.sftp.local?.requestId && session.sftp.local.requestId !== event.requestId) {
              return session;
            }
            return {
              ...session,
              sftp: {
                ...session.sftp,
                local: {
                  status: 'ready',
                  path: event.path,
                  previousPath: undefined,
                  entries: event.entries,
                  truncated: event.truncated,
                  quickPaths: event.quickPaths ?? session.sftp.local?.quickPaths,
                  requestId: event.requestId,
                },
              },
            };
          }
          if (event.type === 'sftp.local.error') {
            if (!session.sftp || session.sftp.status === 'closing') return session;
            if (session.sftp.local?.requestId && session.sftp.local.requestId !== event.requestId) {
              return session;
            }
            const local = session.sftp.local ?? {
              status: 'opening' as const,
              path: event.path ?? '',
              entries: [],
              truncated: false,
            };
            return {
              ...session,
              sftp: {
                ...session.sftp,
                local: {
                  ...local,
                  status: 'failed',
                  path: local.previousPath ?? local.path,
                  previousPath: undefined,
                  error: event.error,
                  requestId: event.requestId,
                },
              },
            };
          }
          if (event.type === 'sftp.operation') {
            if (
              !session.sftp ||
              session.sftp.status === 'closing' ||
              !session.sftp.knownOperationIds?.[event.requestId]
            ) {
              return session;
            }
            const knownOperationIds = { ...(session.sftp.knownOperationIds ?? {}) };
            delete knownOperationIds[event.requestId];
            const currentPane: SftpPaneState =
              event.pane === 'local'
                ? (session.sftp.local ?? {
                    status: 'ready',
                    path: '',
                    entries: [],
                    truncated: false,
                  })
                : {
                    status: session.sftp.status === 'failed' ? 'failed' : 'ready',
                    path: session.sftp.path,
                    entries: session.sftp.entries,
                    truncated: session.sftp.truncated,
                    error: session.sftp.error,
                  };
            const nextPane = {
              ...currentPane,
              status: event.error ? ('failed' as const) : ('ready' as const),
              error: event.error,
            };
            return {
              ...session,
              sftp: {
                ...session.sftp,
                ...(event.pane === 'local'
                  ? { local: nextPane }
                  : {
                      status: event.error ? ('failed' as const) : ('ready' as const),
                      error: event.error,
                    }),
                knownOperationIds,
                refreshRequests: nextSftpOperationRefreshRequests(session.sftp.refreshRequests, {
                  id: event.requestId,
                  pane: event.pane,
                  path: currentPane.path,
                  error: event.error,
                }),
              },
            };
          }
          if (event.type === 'sftp.conflict') {
            if (
              !session.sftp ||
              session.sftp.status === 'closing' ||
              !session.sftp.knownTransferIds?.[event.transferId]
            ) {
              return session;
            }
            const conflict: SftpConflict = {
              transferId: event.transferId,
              itemId: event.itemId,
              direction: event.direction,
              displayName: event.displayName,
              path: event.path,
              incomingSize: event.incomingSize,
              existingSize: event.existingSize,
              existingIsDirectory: event.existingIsDirectory,
            };
            return { ...session, sftp: { ...session.sftp, conflict } };
          }
          if (event.type === 'sftp.transfer') {
            if (
              event.transferState === 'batch-failed' ||
              event.transferState === 'batch-completed' ||
              event.transferState === 'batch-cancelled'
            ) {
              clearSftpCancelRequestsForTransfer(sftpCancelRequests.current, event.transferId);
            }
            if (
              event.itemId &&
              sftpCancelRequests.current.has(sftpTransferItemKey(event.transferId, event.itemId))
            ) {
              if (
                event.transferState === 'completed' ||
                event.transferState === 'failed' ||
                event.transferState === 'cancelled'
              ) {
                sftpCancelRequests.current.delete(
                  sftpTransferItemKey(event.transferId, event.itemId),
                );
              }
              return session;
            }
            if (
              !session.sftp ||
              session.sftp.status === 'closing' ||
              !session.sftp.knownTransferIds?.[event.transferId]
            ) {
              return session;
            }
            if (
              event.transferState === 'batch-failed' ||
              event.transferState === 'batch-completed' ||
              event.transferState === 'batch-cancelled'
            ) {
              const knownTransferIds = { ...(session.sftp.knownTransferIds ?? {}) };
              delete knownTransferIds[event.transferId];
              const { [event.transferId]: destination, ...transferDestinations } =
                session.sftp.transferDestinations ?? {};
              const currentPath =
                destination?.pane === 'local' ? session.sftp.local?.path : session.sftp.path;
              const refreshRequests = nextSftpTransferRefreshRequests(
                session.sftp.refreshRequests,
                event.transferId,
                destination,
                currentPath,
              );
              return {
                ...session,
                sftp: {
                  ...session.sftp,
                  knownTransferIds,
                  transferDestinations:
                    Object.keys(transferDestinations).length > 0 ? transferDestinations : undefined,
                  refreshRequests,
                  ...updateSftpTransferError(
                    session.sftp,
                    event.transferId,
                    event.transferState === 'batch-failed' ? event.error : undefined,
                  ),
                  conflict:
                    session.sftp.conflict?.transferId === event.transferId
                      ? undefined
                      : session.sftp.conflict,
                  transfers:
                    event.transferState === 'batch-failed'
                      ? settleSftpTransferRows(
                          session.sftp.transfers ?? [],
                          event.transferId,
                          'failed',
                          event.error,
                        )
                      : event.transferState === 'batch-cancelled'
                        ? settleSftpTransferRows(
                            session.sftp.transfers ?? [],
                            event.transferId,
                            'cancelled',
                          )
                        : session.sftp.transfers,
                },
              } as Session;
            }
            if (!event.itemId || !event.direction || !event.displayName) return session;
            const transfers = [...(session.sftp.transfers ?? [])];
            const index = transfers.findIndex(
              (transfer) =>
                transfer.transferId === event.transferId && transfer.itemId === event.itemId,
            );
            const previous = index >= 0 ? transfers[index] : undefined;
            const nextTransfer: SftpTransferRow = {
              transferId: event.transferId,
              itemId: event.itemId,
              direction: event.direction,
              displayName: event.displayName,
              expectedBytes: event.expectedBytes ?? previous?.expectedBytes ?? 0,
              bytesTransferred: event.bytesTransferred ?? previous?.bytesTransferred ?? 0,
              state:
                event.transferState === 'progress'
                  ? 'progress'
                  : event.transferState === 'running'
                    ? 'running'
                    : event.transferState,
              error: event.error,
            };
            if (index >= 0) transfers[index] = nextTransfer;
            else transfers.push(nextTransfer);
            return {
              ...session,
              sftp: {
                ...session.sftp,
                transfers,
                ...updateSftpTransferError(session.sftp, event.transferId),
                conflict:
                  session.sftp.conflict?.transferId === event.transferId &&
                  session.sftp.conflict.itemId === event.itemId &&
                  event.transferState !== 'failed'
                    ? undefined
                    : session.sftp.conflict,
              },
            } as Session;
          }
          if (event.type === 'sftp.closed') {
            return shouldApplySftpClosed(session.sftp) ? { ...session, sftp: undefined } : session;
          }
          if (event.type === 'error') {
            return {
              ...session,
              status: 'failed',
              sftp: undefined,
              tunnelProgress: null,
              hostKeyMismatch:
                event.hostKeyExpected && event.hostKeyReceived
                  ? { expected: event.hostKeyExpected, received: event.hostKeyReceived }
                  : undefined,
              error: event.error,
            };
          }
          return {
            ...session,
            status: 'closed',
            sftp: undefined,
            tunnelProgress: null,
          };
        }),
      );
    });

    return () => {
      unsubscribe?.();
    };
  }, []);

  useEffect(() => {
    const unsubscribe = window.wormhole?.onSerialEvent((event) => {
      setSessions((current) =>
        current.map((session) => {
          if (session.backendSessionId !== event.sessionId) return session;
          if (event.type === 'connected') {
            return {
              ...session,
              status: 'connected',
              host: event.portName,
              serialSettings: {
                baudRate: event.baudRate,
                dataBits: event.dataBits,
                stopBits: event.stopBits,
                parity: event.parity,
                flowControl: event.flowControl,
              },
              error: undefined,
            };
          }
          if (event.type === 'screen') {
            if (session.status !== 'connected') return session;
            return {
              ...session,
              terminalFrame: applySshTerminalFrame(session.terminalFrame, event.frame),
            };
          }
          if (event.type === 'error') {
            return { ...session, status: 'failed', error: event.error };
          }
          return { ...session, status: 'closed' };
        }),
      );
    });

    const unsubscribeMcp = window.wormhole?.onMcpApproval((approval) => {
      setMcpApprovals((current) =>
        current.some((pending) => pending.requestId === approval.requestId)
          ? current
          : [...current, approval],
      );
    });
    const unsubscribeBackend = window.wormhole?.onBackendEvent((event) => {
      if (event.type === 'tunnel.progress' && event.sessionId && event.phase) {
        const phase = event.phase;
        const detail = event.detail;
        setSessions((current) =>
          current.map((session) =>
            session.backendSessionId === event.sessionId || session.id === event.sessionId
              ? { ...session, tunnelProgress: { phase, detail } }
              : session,
          ),
        );
        return;
      }
      if (event.type === 'tunnel.route' && event.sessionId && event.leaseId && event.promptId) {
        const routePrompt = {
          sessionId: event.sessionId,
          leaseId: event.leaseId,
          promptId: event.promptId,
          connectionName: event.connectionName,
          tunnelName: event.tunnelName,
        };
        setRoutePrompts((current) =>
          current.some((item) => item.promptId === routePrompt.promptId)
            ? current
            : [...current, routePrompt],
        );
        return;
      }
      if (event.type === 'tunnel.route-closed' && event.promptId) {
        setRoutePrompts((current) => current.filter((item) => item.promptId !== event.promptId));
        return;
      }
      if (event.type === 'tunnel.prompt-closed' && event.promptId) {
        setTunnelPrompts((current) => current.filter((item) => item.promptId !== event.promptId));
        return;
      }
      if (
        event.type !== 'tunnel.prompt' ||
        !event.sessionId ||
        !event.promptId ||
        !event.title ||
        typeof event.message !== 'string' ||
        typeof event.secret !== 'boolean' ||
        (event.confirmation !== undefined && typeof event.confirmation !== 'boolean') ||
        (event.acceptLabel !== undefined && typeof event.acceptLabel !== 'string')
      ) {
        return;
      }
      const prompt: WormholeTunnelPrompt = {
        type: 'tunnel.prompt',
        sessionId: event.sessionId,
        promptId: event.promptId,
        title: event.title,
        message: event.message,
        secret: event.secret,
        confirmation: event.confirmation === true,
        acceptLabel: event.acceptLabel,
      };
      setTunnelPrompts((current) =>
        current.some((item) => item.promptId === prompt.promptId) ? current : [...current, prompt],
      );
    });
    return () => {
      unsubscribe?.();
      unsubscribeMcp?.();
      unsubscribeBackend?.();
    };
  }, []);

  useEffect(() => {
    const timeoutMinutes = authState?.idleTimeoutMinutes;
    if (
      authGate !== 'unlocked' ||
      !authState?.configured ||
      timeoutMinutes === null ||
      timeoutMinutes === undefined
    ) {
      return;
    }

    const checkIdle = async () => {
      if (idleCheckInFlight.current || !window.wormhole) return;
      idleCheckInFlight.current = true;
      try {
        const systemIdle = await window.wormhole.getSystemIdleSeconds();
        const localIdle = Math.max(0, (Date.now() - lastActivityAt.current) / 1000);
        if (Math.max(systemIdle.seconds, localIdle) >= timeoutMinutes * 60) {
          try {
            await window.wormhole.lockAuthentication();
            setLockReason('Locked after inactivity.');
            setAuthGate('locked');
          } catch {
            // Do not present a lock screen until the native session confirms that it is locked.
          }
        }
      } catch {
        // A failed idle sample must not lock a user out. The native verifier remains required
        // when the app next starts or when the user manually changes security settings.
      } finally {
        idleCheckInFlight.current = false;
      }
    };

    const timer = window.setInterval(() => void checkIdle(), 15_000);
    return () => window.clearInterval(timer);
  }, [authGate, authState]);

  useEffect(() => {
    if (authGate === 'unlocked') return;
    credentialRevealRequest.current += 1;
    if (copiedCredentialTimer.current !== undefined) {
      window.clearTimeout(copiedCredentialTimer.current);
      copiedCredentialTimer.current = undefined;
    }
    sftpRequestIds.current.clear();
    sftpCancelRequests.current.clear();
    setQuickConnectOpen(false);
    setNewConnectionOpen(false);
    setFolderDetailsOpen(false);
    setNewFolderOpen(false);
    setEditingConnectionId(null);
    setEditingFolderId(null);
    setNewFolderParentId(null);
    setEditorError('');
    setCredentialDialog(null);
    setCopiedCredentialField(null);
    setPendingDeleteNode(null);
    setDeleteNodeError('');
    setSessions((current) => {
      if (!current.some((session) => session.sftp)) return current;
      return current.map((session) => ({ ...session, sftp: undefined }));
    });
    setMcpApprovals([]);
  }, [authGate]);

  useEffect(
    () => () => {
      if (copiedCredentialTimer.current !== undefined) {
        window.clearTimeout(copiedCredentialTimer.current);
      }
    },
    [],
  );

  useEffect(() => {
    const unsubscribe = window.wormhole?.onRdpEvent((event) => {
      if (!event.sessionId) return;
      setSessions((current) =>
        current.map((session) => {
          if (session.id !== event.sessionId) return session;
          const next = applyRdpBackendEvent(session, event);
          return next.rdpStatus === 'connected' ||
            next.rdpStatus === 'failed' ||
            next.rdpStatus === 'disconnected'
            ? { ...next, tunnelProgress: null }
            : next;
        }),
      );
    });
    return unsubscribe;
  }, []);

  useEffect(() => {
    const unsubscribe = window.wormhole?.onWebEvent((event) => {
      setSessions((current) =>
        current.map((session) => {
          if (
            session.id !== event.sessionId ||
            !webSessionAttempts.current.isCurrent(event.sessionId, event.attempt)
          ) {
            return session;
          }
          if (event.type === 'failed') {
            return {
              ...session,
              status: 'failed',
              error: event.error || 'The browser could not open this connection.',
              tunnelProgress: null,
              webUrl: event.url || session.webUrl,
              webCanGoBack: event.canGoBack,
              webCanGoForward: event.canGoForward,
            };
          }
          return {
            ...session,
            status: event.type === 'connected' ? 'connected' : session.status,
            error: undefined,
            tunnelProgress: event.type === 'connected' ? null : session.tunnelProgress,
            webUrl: event.url || session.webUrl,
            webCanGoBack: event.canGoBack,
            webCanGoForward: event.canGoForward,
          };
        }),
      );
    });
    return unsubscribe;
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

  function startSerialSession(
    sessionId: string,
    nodeId: string | undefined,
    portName: string,
    settings: SerialSettings,
  ) {
    const api = window.wormhole;
    if (!api) {
      setSessions((current) =>
        current.map((session) =>
          session.backendSessionId === sessionId
            ? { ...session, status: 'failed', error: 'The native serial bridge is unavailable.' }
            : session,
        ),
      );
      return;
    }

    const request = nodeId
      ? { sessionId, nodeId, columns: 80, rows: 24 }
      : { sessionId, portName, settings, columns: 80, rows: 24 };
    void api.openSerialSession(request).catch((error: unknown) => {
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

  function savedSerialNodeId(nodeId: string | undefined): string | undefined {
    return nodeId && !nodeId.startsWith('connection-') ? nodeId : undefined;
  }

  function startWebSession(session: Session) {
    const generation = webSessionAttempts.current.begin(session.id);
    const api = window.wormhole;
    if (!api) {
      setSessions((current) =>
        webSessionAttempts.current.isCurrent(session.id, generation)
          ? current.map((candidate) =>
              candidate.id === session.id
                ? {
                    ...candidate,
                    status: 'failed',
                    error: 'The native web browser bridge is unavailable.',
                  }
                : candidate,
            )
          : current,
      );
      return;
    }

    const request = session.webTargetNodeId
      ? { sessionId: session.id, attempt: generation, nodeId: session.webTargetNodeId }
      : {
          sessionId: session.id,
          attempt: generation,
          address: session.host,
          protocol: session.protocol as 'http' | 'https',
          ignoreCertErrors: session.webIgnoreCertErrors === true,
          tunnelConfigId: session.tunnelConfigId,
        };

    void api.openWebSession(request).then(
      (target) => {
        setSessions((current) =>
          webSessionAttempts.current.isCurrent(session.id, generation)
            ? current.map((candidate) =>
                candidate.id === session.id
                  ? {
                      ...candidate,
                      webUrl: target.url,
                      webIgnoreCertErrors: target.ignoreCertErrors,
                    }
                  : candidate,
              )
            : current,
        );
      },
      (error: unknown) => {
        setSessions((current) =>
          webSessionAttempts.current.isCurrent(session.id, generation)
            ? current.map((candidate) =>
                candidate.id === session.id
                  ? {
                      ...candidate,
                      status: 'failed',
                      error: error instanceof Error ? error.message : String(error),
                    }
                  : candidate,
              )
            : current,
        );
      },
    );
  }

  async function closeWebSession(sessionId: string): Promise<void> {
    webSessionAttempts.current.cancel(sessionId);
    await window.wormhole?.closeWebSession(sessionId);
  }

  function defaultRdpProfile(session: Session, credentials?: RdpCredentials): WormholeRdpProfile {
    return {
      nodeId: session.nodeId,
      name: session.title,
      host: session.host,
      username: credentials?.username || undefined,
      domain: credentials?.domain || undefined,
      password: credentials?.password || undefined,
      screenSize: 'Full connection content',
      colorDepth: 32,
      redirectClipboard: true,
      connectionSpeed: 7,
      desktopBackground: true,
      fontSmoothing: true,
      desktopComposition: true,
      windowDrag: true,
      menuAnimation: true,
      visualStyles: true,
      bitmapCaching: true,
      autoReconnect: true,
      serverAuthentication: 2,
      gatewayBypassLocal: true,
      tunnelConfigId: session.tunnelConfigId,
      tunnelEnabled: session.tunnelConfigId ? true : undefined,
    };
  }

  function requestRdpCredentials(sessionId: string) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session || session.protocol !== 'rdp') return;
    const existing = rdpCredentials[sessionId];
    setRdpCredentialForm(
      existing ?? {
        username: '',
        domain: '',
        password: '',
      },
    );
    setRdpCredentialPrompt(sessionId);
    setSelectedSessionId(sessionId);
    setActivePage('sessions');
  }

  function startRdpSession(sessionId: string, credentials: RdpCredentials) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session || session.protocol !== 'rdp') return;

    const normalizedCredentials = {
      username: credentials.username.trim(),
      domain: credentials.domain.trim(),
      password: credentials.password,
    };
    setRdpCredentials((current) => ({ ...current, [sessionId]: normalizedCredentials }));
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === sessionId
          ? {
              ...candidate,
              rdpStatus: 'starting',
              rdpError: undefined,
              tunnelProgress: null,
              rdpProfile: defaultRdpProfile(candidate, normalizedCredentials),
            }
          : candidate,
      ),
    );

    if (!window.wormhole) {
      setSessions((current) =>
        current.map((candidate) =>
          candidate.id === sessionId
            ? {
                ...candidate,
                rdpStatus: 'failed',
                rdpError: 'The native RDP bridge is unavailable.',
              }
            : candidate,
        ),
      );
      return;
    }

    void window.wormhole
      .startRdpSession({
        sessionId,
        profile: defaultRdpProfile(session, normalizedCredentials),
      })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : 'The RDP backend could not start.';
        setSessions((current) =>
          current.map((candidate) =>
            candidate.id === sessionId
              ? { ...candidate, rdpStatus: 'failed', rdpError: message }
              : candidate,
          ),
        );
      });
  }

  function retryRdpSession(sessionId: string) {
    const credentials = rdpCredentials[sessionId];
    if (credentials) {
      startRdpSession(sessionId, credentials);
    } else {
      requestRdpCredentials(sessionId);
    }
  }

  function submitRdpCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!rdpCredentialPrompt) return;
    const sessionId = rdpCredentialPrompt;
    setRdpCredentialPrompt(null);
    startRdpSession(sessionId, rdpCredentialForm);
  }

  function openConnection(node: TreeNode) {
    if (node.kind !== 'connection' || !node.protocol) return;

    const existing = sessions.find((session) => session.id === `session-${node.id}`);
    if (existing) {
      setSelectedSessionId(existing.id);
      setActivePage('sessions');
      if (existing.protocol === 'rdp' && existing.rdpStatus !== 'connected') {
        requestRdpCredentials(existing.id);
      }
      return;
    }

    const backendSessionId =
      node.protocol === 'ssh' || node.protocol === 'serial' ? newSessionToken() : undefined;
    const serialSettings = node.protocol === 'serial' ? serialSettingsFromNode(node) : undefined;
    const session: Session = {
      id: `session-${node.id}`,
      title: node.name,
      protocol: node.protocol,
      host: node.host ?? '',
      nodeId: node.id,
      port: node.port,
      canTransfer: node.protocol === 'ssh',
      backendSessionId,
      status:
        node.protocol === 'ssh' ||
        node.protocol === 'serial' ||
        node.protocol === 'http' ||
        node.protocol === 'https'
          ? 'connecting'
          : 'placeholder',
      serialSettings,
      rdpStatus: node.protocol === 'rdp' ? 'idle' : undefined,
      webTargetNodeId:
        (node.protocol === 'http' || node.protocol === 'https') && node.persisted
          ? node.id
          : undefined,
      webIgnoreCertErrors: node.protocol === 'https' && node.httpIgnoreCertErrors === true,
    };

    setSessions((current) => [...current, session]);
    setSelectedSessionId(session.id);
    setActivePage('sessions');
    if (backendSessionId && session.protocol === 'ssh') startSshSession(backendSessionId, node.id);
    if (backendSessionId && session.protocol === 'serial') {
      startSerialSession(
        backendSessionId,
        savedSerialNodeId(node.id),
        session.host,
        serialSettings ?? defaultSerialSettings,
      );
    }
    if (session.protocol === 'rdp') {
      setRdpCredentialForm({ username: '', domain: '', password: '' });
      setRdpCredentialPrompt(session.id);
    }
    if (session.protocol === 'http' || session.protocol === 'https') startWebSession(session);
  }

  function closeSession(id: string) {
    const closing = sessions.find((session) => session.id === id);
    if (closing?.protocol === 'rdp') {
      void window.wormhole
        ?.commandRdpSession({ sessionId: id, operation: 'disconnect' })
        .catch(() => undefined);
    }
    if (closing?.protocol === 'http' || closing?.protocol === 'https') {
      void closeWebSession(closing.id).catch(() => undefined);
    }
    const index = sessions.findIndex((session) => session.id === id);
    const nextSessions = sessions.filter((session) => session.id !== id);
    setSessions(nextSessions);
    sftpRequestIds.current.delete(id);
    clearSftpCancelRequestsForBrowser(sftpCancelRequests.current, closing?.sftp);

    if (closing?.backendSessionId) {
      if (closing.protocol === 'serial') {
        void window.wormhole?.closeSerialSession(closing.backendSessionId);
      } else {
        void window.wormhole?.closeSshSession(closing.backendSessionId);
      }
    }

    if (selectedSessionId === id) {
      setSelectedSessionId(nextSessions[index]?.id ?? nextSessions[index - 1]?.id ?? '');
    }
    setRdpCredentials((current) => {
      if (!(id in current)) return current;
      const next = { ...current };
      delete next[id];
      return next;
    });
  }

  function closeSessionsForNodeIds(nodeIds: ReadonlySet<string>) {
    const closing = sessions.filter((session) => session.nodeId && nodeIds.has(session.nodeId));
    if (closing.length === 0) return;
    const closingIds = new Set(closing.map((session) => session.id));
    const selectedIndex = sessions.findIndex((session) => session.id === selectedSessionId);

    for (const session of closing) {
      if (session.protocol === 'rdp') {
        void window.wormhole
          ?.commandRdpSession({ sessionId: session.id, operation: 'disconnect' })
          .catch(() => undefined);
      }
      if (session.protocol === 'http' || session.protocol === 'https') {
        void closeWebSession(session.id).catch(() => undefined);
      }
      if (session.backendSessionId) {
        if (session.protocol === 'serial') {
          void window.wormhole?.closeSerialSession(session.backendSessionId);
        } else {
          void window.wormhole?.closeSshSession(session.backendSessionId);
        }
      }
      sftpRequestIds.current.delete(session.id);
      clearSftpCancelRequestsForBrowser(sftpCancelRequests.current, session.sftp);
    }

    const nextSessions = sessions.filter((session) => !closingIds.has(session.id));
    setSessions(nextSessions);
    setSelectedSessionId((current) => {
      if (!closingIds.has(current)) return current;
      return nextSessions[selectedIndex]?.id ?? nextSessions[selectedIndex - 1]?.id ?? '';
    });
    setRdpCredentialPrompt((current) => (current && closingIds.has(current) ? null : current));
    setRoutePrompts((current) => current.filter((prompt) => !closingIds.has(prompt.sessionId)));
    setRdpCredentials((current) => {
      const next = { ...current };
      for (const id of closingIds) delete next[id];
      return next;
    });
  }

  function reconnectSession(id: string) {
    const source = sessions.find((session) => session.id === id);
    if (!source) return;

    if (source.backendSessionId) {
      if (source.protocol === 'serial') {
        void window.wormhole?.closeSerialSession(source.backendSessionId);
      } else {
        void window.wormhole?.closeSshSession(source.backendSessionId);
      }
    }
    if (source.protocol === 'http' || source.protocol === 'https') {
      const restarted: Session = {
        ...source,
        status: 'connecting',
        error: undefined,
        webCanGoBack: false,
        webCanGoForward: false,
      };
      setSessions((current) => current.map((session) => (session.id === id ? restarted : session)));
      void closeWebSession(source.id)
        .catch(() => undefined)
        .finally(() => startWebSession(restarted));
    }
    clearSftpCancelRequestsForBrowser(sftpCancelRequests.current, source.sftp);
    if (source.nodeId && source.protocol === 'ssh') {
      const backendSessionId = newSessionToken();
      setSessions((current) =>
        current.map((session) =>
          session.id === id
            ? {
                ...session,
                backendSessionId,
                status: 'connecting',
                terminalFrame: undefined,
                sftp: undefined,
                error: undefined,
                hostKeyMismatch: undefined,
              }
            : session,
        ),
      );
      startSshSession(backendSessionId, source.nodeId);
    }
    if (source.protocol === 'serial') {
      const backendSessionId = newSessionToken();
      setSessions((current) =>
        current.map((session) =>
          session.id === id
            ? {
                ...session,
                backendSessionId,
                status: 'connecting',
                terminalFrame: undefined,
                error: undefined,
              }
            : session,
        ),
      );
      startSerialSession(
        backendSessionId,
        savedSerialNodeId(source.nodeId),
        source.host,
        source.serialSettings ?? defaultSerialSettings,
      );
    }

    setSelectedSessionId(id);
    setActivePage('sessions');
    const session = sessions.find((candidate) => candidate.id === id);
    if (session?.protocol === 'rdp') retryRdpSession(id);
  }

  function duplicateSession(id: string) {
    const source = sessions.find((session) => session.id === id);
    if (!source) return;

    const duplicate: Session = {
      ...source,
      id: `session-duplicate-${newSessionToken()}`,
      title: `${source.title} (copy)`,
      backendSessionId:
        source.protocol === 'ssh' || source.protocol === 'serial' ? newSessionToken() : undefined,
      status:
        source.protocol === 'ssh' || source.protocol === 'serial' ? 'connecting' : 'placeholder',
      terminalFrame: undefined,
      sftp: undefined,
      error: undefined,
      hostKeyMismatch: undefined,
      rdpStatus: source.protocol === 'rdp' ? 'idle' : source.rdpStatus,
      rdpError: undefined,
      serialSettings: source.serialSettings
        ? { ...source.serialSettings }
        : source.protocol === 'serial'
          ? { ...defaultSerialSettings }
          : undefined,
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
    if (duplicate.backendSessionId && duplicate.nodeId && duplicate.protocol === 'ssh') {
      startSshSession(duplicate.backendSessionId, duplicate.nodeId);
    }
    if (duplicate.backendSessionId && duplicate.protocol === 'serial') {
      startSerialSession(
        duplicate.backendSessionId,
        savedSerialNodeId(duplicate.nodeId),
        duplicate.host,
        duplicate.serialSettings ?? defaultSerialSettings,
      );
    }
    if (duplicate.protocol === 'rdp') {
      const existing = rdpCredentials[id];
      setRdpCredentialForm(existing ?? { username: '', domain: '', password: '' });
      setRdpCredentialPrompt(duplicate.id);
    }
  }

  function openFileTransfer(id: string) {
    const session = sessions.find((candidate) => candidate.id === id);
    if (
      !session ||
      session.protocol !== 'ssh' ||
      !session.backendSessionId ||
      session.status !== 'connected'
    ) {
      return;
    }
    setSelectedSessionId(id);
    setActivePage('sessions');
    if (session.sftp) return;
    const requestId = nextSftpRequestId(id);
    const localRequestId = nextSftpPaneRequestId();
    const remoteRequestId = `sftp-remote-${requestId}`;

    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === id
          ? {
              ...candidate,
              sftp: {
                status: 'opening',
                path: '',
                entries: [],
                truncated: false,
                requestId: remoteRequestId,
                local: {
                  status: 'opening',
                  path: '',
                  entries: [],
                  truncated: false,
                  requestId: localRequestId,
                },
                transfers: [],
                transferError: undefined,
                transferErrorTransferId: undefined,
                conflict: undefined,
                knownTransferIds: {},
                knownOperationIds: {},
              },
            }
          : candidate,
      ),
    );
    const api = window.wormhole;
    if (!api) {
      setSftpFailure(id, requestId, 'The native SFTP bridge is unavailable.');
      return;
    }
    void api.openSftpBrowser(session.backendSessionId, remoteRequestId).catch((error: unknown) => {
      setSftpFailure(id, requestId, error instanceof Error ? error.message : String(error));
    });
    void api
      .listLocalSftpDirectory(session.backendSessionId, '', localRequestId)
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        setSessions((current) =>
          current.map((candidate) => {
            if (candidate.id !== id || !candidate.sftp || candidate.sftp.status === 'closing') {
              return candidate;
            }
            const local = candidate.sftp.local;
            if (local?.requestId !== localRequestId) return candidate;
            return {
              ...candidate,
              sftp: {
                ...candidate.sftp,
                local: { ...local, status: 'failed', error: message },
              },
            };
          }),
        );
      });
  }

  function nextSftpRequestId(sessionId: string): number {
    const requestId = ++sftpRequestSequence.current;
    sftpRequestIds.current.set(sessionId, requestId);
    return requestId;
  }

  function nextSftpPaneRequestId(): string {
    return `sftp-pane-${++sftpPaneRequestSequence.current}`;
  }

  function setSftpFailure(sessionId: string, requestId: number, error: string) {
    setSessions((current) =>
      current.map((session) =>
        session.id === sessionId &&
        shouldApplySftpFailure(session.sftp, requestId, sftpRequestIds.current.get(sessionId))
          ? {
              ...session,
              sftp: {
                ...session.sftp,
                status: 'failed',
                path: session.sftp.previousPath ?? session.sftp.path,
                previousPath: undefined,
                entries: session.sftp?.entries ?? [],
                truncated: session.sftp?.truncated ?? false,
                error,
              },
            }
          : session,
      ),
    );
  }

  function closeSftpBrowser(id: string) {
    const session = sessions.find((candidate) => candidate.id === id);
    if (!session?.backendSessionId) return;
    clearSftpCancelRequestsForBrowser(sftpCancelRequests.current, session.sftp);
    const requestId = nextSftpRequestId(id);
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === id && candidate.sftp
          ? { ...candidate, sftp: { ...candidate.sftp, status: 'closing', error: undefined } }
          : candidate,
      ),
    );
    const api = window.wormhole;
    if (!api) {
      setSessions((current) =>
        current.map((candidate) =>
          candidate.id === id &&
          shouldFinishSftpClose(candidate.sftp, requestId, sftpRequestIds.current.get(id))
            ? { ...candidate, sftp: undefined }
            : candidate,
        ),
      );
      return;
    }
    void api.closeSftpBrowser(session.backendSessionId).catch(() => {
      setSessions((current) =>
        current.map((candidate) =>
          candidate.id === id &&
          shouldFinishSftpClose(candidate.sftp, requestId, sftpRequestIds.current.get(id))
            ? { ...candidate, sftp: undefined }
            : candidate,
        ),
      );
    });
  }

  function requestSftpDirectory(sessionId: string, path: string) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (
      !session?.backendSessionId ||
      session.protocol !== 'ssh' ||
      !session.sftp ||
      session.sftp.status === 'closing'
    ) {
      return;
    }
    const requestId = nextSftpRequestId(sessionId);
    const wireRequestId = `sftp-remote-${requestId}`;
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === sessionId
          ? {
              ...candidate,
              sftp: {
                ...candidate.sftp!,
                status: 'opening',
                error: undefined,
                previousPath: candidate.sftp!.previousPath ?? candidate.sftp!.path,
                path,
                requestId: wireRequestId,
              },
            }
          : candidate,
      ),
    );
    const api = window.wormhole;
    if (!api) {
      setSftpFailure(sessionId, requestId, 'The native SFTP bridge is unavailable.');
      return;
    }
    void api
      .listSftpDirectory(session.backendSessionId, path, wireRequestId)
      .catch((error: unknown) => {
        setSftpFailure(
          sessionId,
          requestId,
          error instanceof Error ? error.message : String(error),
        );
      });
  }

  function refreshSftpBrowser(id: string) {
    const session = sessions.find((candidate) => candidate.id === id);
    if (!session?.sftp || session.sftp.status === 'closing') return;
    if (!session.sftp.path) {
      const requestId = nextSftpRequestId(id);
      const remoteRequestId = `sftp-remote-${requestId}`;
      setSessions((current) =>
        current.map((candidate) =>
          candidate.id === id
            ? {
                ...candidate,
                sftp: {
                  ...candidate.sftp!,
                  status: 'opening',
                  error: undefined,
                  requestId: remoteRequestId,
                },
              }
            : candidate,
        ),
      );
      const api = window.wormhole;
      if (!api || !session.backendSessionId) {
        setSftpFailure(id, requestId, 'The native SFTP bridge is unavailable.');
        return;
      }
      void api
        .openSftpBrowser(session.backendSessionId, remoteRequestId)
        .catch((error: unknown) => {
          setSftpFailure(id, requestId, error instanceof Error ? error.message : String(error));
        });
      return;
    }
    requestSftpDirectory(id, session.sftp.path);
  }

  function requestLocalSftpDirectory(sessionId: string, path: string) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (
      !session?.backendSessionId ||
      session.protocol !== 'ssh' ||
      !session.sftp ||
      session.sftp.status === 'closing'
    ) {
      return;
    }
    const requestId = nextSftpPaneRequestId();
    setSessions((current) =>
      current.map((candidate) => {
        if (candidate.id !== sessionId || !candidate.sftp) return candidate;
        const local = candidate.sftp.local ?? {
          status: 'ready' as const,
          path,
          entries: [],
          truncated: false,
        };
        return {
          ...candidate,
          sftp: {
            ...candidate.sftp,
            local: {
              ...local,
              status: 'opening',
              previousPath: local.previousPath ?? local.path,
              path,
              error: undefined,
              requestId,
            },
          },
        };
      }),
    );
    const api = window.wormhole;
    if (!api) {
      setSessions((current) =>
        current.map((candidate) =>
          candidate.id === sessionId && candidate.sftp?.local?.requestId === requestId
            ? {
                ...candidate,
                sftp: {
                  ...candidate.sftp,
                  local: {
                    ...candidate.sftp.local,
                    status: 'failed',
                    path: candidate.sftp.local.previousPath ?? candidate.sftp.local.path,
                    previousPath: undefined,
                    error: 'The native SFTP bridge is unavailable.',
                  },
                },
              }
            : candidate,
        ),
      );
      return;
    }
    void api
      .listLocalSftpDirectory(session.backendSessionId, path, requestId)
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        setSessions((current) =>
          current.map((candidate) =>
            candidate.id === sessionId && candidate.sftp?.local?.requestId === requestId
              ? {
                  ...candidate,
                  sftp: {
                    ...candidate.sftp,
                    local: {
                      ...candidate.sftp.local,
                      status: 'failed',
                      path: candidate.sftp.local.previousPath ?? candidate.sftp.local.path,
                      previousPath: undefined,
                      error: message,
                    },
                  },
                }
              : candidate,
          ),
        );
      });
  }

  function operateSftp(
    sessionId: string,
    pane: 'local' | 'remote',
    operation: 'mkdir' | 'file' | 'delete' | 'rename' | 'open',
    path: string,
    destinationPath?: string,
  ) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session?.backendSessionId || !session.sftp || session.sftp.status === 'closing') return;
    const requestId = nextSftpPaneRequestId();
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === sessionId && candidate.sftp
          ? {
              ...candidate,
              sftp: {
                ...candidate.sftp,
                knownOperationIds: {
                  ...(candidate.sftp.knownOperationIds ?? {}),
                  [requestId]: true,
                },
              },
            }
          : candidate,
      ),
    );
    const api = window.wormhole;
    if (!api) {
      setSessions((current) =>
        current.map((candidate) => {
          if (candidate.id !== sessionId || !candidate.sftp) return candidate;
          const knownOperationIds = { ...(candidate.sftp.knownOperationIds ?? {}) };
          delete knownOperationIds[requestId];
          if (pane === 'local') {
            const local = candidate.sftp.local ?? {
              status: 'ready' as const,
              path: '',
              entries: [],
              truncated: false,
            };
            return {
              ...candidate,
              sftp: {
                ...candidate.sftp,
                knownOperationIds,
                local: {
                  ...local,
                  status: 'failed',
                  error: 'The native SFTP bridge is unavailable.',
                },
              },
            };
          }
          return {
            ...candidate,
            sftp: {
              ...candidate.sftp,
              knownOperationIds,
              status: 'failed',
              error: 'The native SFTP bridge is unavailable.',
            },
          };
        }),
      );
      return;
    }
    void api
      .operateSftp(session.backendSessionId, {
        requestId,
        pane,
        operation,
        path,
        destinationPath,
      })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        setSessions((current) =>
          current.map((candidate) => {
            if (
              candidate.id !== sessionId ||
              !candidate.sftp ||
              !candidate.sftp.knownOperationIds?.[requestId]
            ) {
              return candidate;
            }
            const knownOperationIds = { ...(candidate.sftp.knownOperationIds ?? {}) };
            delete knownOperationIds[requestId];
            if (pane === 'local') {
              const local = candidate.sftp.local ?? {
                status: 'ready' as const,
                path: '',
                entries: [],
                truncated: false,
              };
              return {
                ...candidate,
                sftp: {
                  ...candidate.sftp,
                  knownOperationIds,
                  local: { ...local, status: 'failed', error: message },
                },
              };
            }
            return {
              ...candidate,
              sftp: { ...candidate.sftp, knownOperationIds, status: 'failed', error: message },
            };
          }),
        );
      });
  }

  function startSftpTransfer(
    sessionId: string,
    direction: 'local-to-remote' | 'remote-to-local' | 'local-to-local',
    destinationPath: string,
    items: Array<{
      sourcePath: string;
      name: string;
      isDirectory: boolean;
      size: number;
    }>,
  ) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session?.backendSessionId || !session.sftp || session.sftp.status === 'closing') return;
    const transferId = `sftp-transfer-${++sftpPaneRequestSequence.current}`;
    const destination: SftpTransferDestination = {
      pane: direction === 'local-to-remote' ? 'remote' : 'local',
      path: destinationPath,
    };
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === sessionId && candidate.sftp
          ? {
              ...candidate,
              sftp: {
                ...candidate.sftp,
                knownTransferIds: {
                  ...(candidate.sftp.knownTransferIds ?? {}),
                  [transferId]: true,
                },
                transferDestinations: {
                  ...(candidate.sftp.transferDestinations ?? {}),
                  [transferId]: destination,
                },
              },
            }
          : candidate,
      ),
    );
    const api = window.wormhole;
    if (!api) {
      setSessions((current) =>
        current.map((candidate) => {
          if (candidate.id !== sessionId || !candidate.sftp) return candidate;
          const knownTransferIds = { ...(candidate.sftp.knownTransferIds ?? {}) };
          delete knownTransferIds[transferId];
          const { [transferId]: _, ...transferDestinations } =
            candidate.sftp.transferDestinations ?? {};
          return {
            ...candidate,
            sftp: {
              ...candidate.sftp,
              knownTransferIds,
              transferDestinations:
                Object.keys(transferDestinations).length > 0 ? transferDestinations : undefined,
              transferErrorTransferId: transferId,
              transferError: 'The native SFTP bridge is unavailable.',
            },
          };
        }),
      );
      return;
    }
    void api
      .startSftpTransfer(session.backendSessionId, {
        transferId,
        direction,
        destinationPath,
        items,
      })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        setSessions((current) =>
          current.map((candidate) => {
            if (
              candidate.id !== sessionId ||
              !candidate.sftp ||
              !candidate.sftp.knownTransferIds?.[transferId]
            ) {
              return candidate;
            }
            const knownTransferIds = { ...(candidate.sftp.knownTransferIds ?? {}) };
            delete knownTransferIds[transferId];
            const { [transferId]: _, ...transferDestinations } =
              candidate.sftp.transferDestinations ?? {};
            return {
              ...candidate,
              sftp: {
                ...candidate.sftp,
                knownTransferIds,
                transferDestinations:
                  Object.keys(transferDestinations).length > 0 ? transferDestinations : undefined,
                transferErrorTransferId: transferId,
                transferError: message,
              },
            };
          }),
        );
      });
  }

  function decideSftpConflict(
    sessionId: string,
    transferId: string,
    itemId: string,
    decision: 'overwrite' | 'skip',
    applyToAll: boolean,
  ) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session?.backendSessionId) return;
    const conflict = session.sftp?.conflict;
    if (!conflict || conflict.transferId !== transferId || conflict.itemId !== itemId) {
      return;
    }
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === sessionId &&
        candidate.sftp &&
        candidate.sftp.conflict?.transferId === transferId &&
        candidate.sftp.conflict.itemId === itemId
          ? { ...candidate, sftp: { ...candidate.sftp, conflict: undefined } }
          : candidate,
      ),
    );
    const api = window.wormhole;
    if (!api) {
      setSessions((current) =>
        current.map((candidate) =>
          candidate.id === sessionId && candidate.sftp
            ? {
                ...candidate,
                sftp: {
                  ...candidate.sftp,
                  conflict: candidate.sftp.conflict ?? conflict,
                  transferError: 'The native SFTP bridge is unavailable.',
                  transferErrorTransferId: transferId,
                },
              }
            : candidate,
        ),
      );
      return;
    }
    void api
      .decideSftpConflict(session.backendSessionId, transferId, itemId, decision, applyToAll)
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        setSessions((current) =>
          current.map((candidate) => {
            if (
              candidate.id !== sessionId ||
              !candidate.sftp ||
              !candidate.sftp.knownTransferIds?.[transferId]
            ) {
              return candidate;
            }
            return {
              ...candidate,
              sftp: {
                ...candidate.sftp,
                conflict: candidate.sftp.conflict ?? conflict,
                transferError: message,
                transferErrorTransferId: transferId,
              },
            };
          }),
        );
      });
  }

  function cancelSftpTransfer(sessionId: string, transferId: string, itemId: string) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session?.backendSessionId) return;
    const cancelledTransfer = (session.sftp?.transfers ?? []).find(
      (transfer) => transfer.transferId === transferId && transfer.itemId === itemId,
    );
    if (!cancelledTransfer) return;
    const cancelKey = sftpTransferItemKey(transferId, itemId);
    sftpCancelRequests.current.add(cancelKey);
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === sessionId && candidate.sftp
          ? {
              ...candidate,
              sftp: {
                ...candidate.sftp,
                transfers: removeSftpTransferRow(
                  candidate.sftp.transfers ?? [],
                  transferId,
                  itemId,
                ),
              },
            }
          : candidate,
      ),
    );
    const api = window.wormhole;
    if (!api) {
      sftpCancelRequests.current.delete(cancelKey);
      setSessions((current) =>
        current.map((candidate) => {
          if (candidate.id !== sessionId || !candidate.sftp) return candidate;
          const transfers = candidate.sftp.transfers ?? [];
          return {
            ...candidate,
            sftp: {
              ...candidate.sftp,
              transfers: transfers.some(
                (transfer) => transfer.transferId === transferId && transfer.itemId === itemId,
              )
                ? transfers
                : [...transfers, cancelledTransfer],
              transferError: 'The native SFTP bridge is unavailable.',
              transferErrorTransferId: transferId,
            },
          };
        }),
      );
      return;
    }
    void api
      .cancelSftpTransfer(session.backendSessionId, transferId, itemId)
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        if (!sftpCancelRequests.current.has(cancelKey)) return;
        sftpCancelRequests.current.delete(cancelKey);
        setSessions((current) =>
          current.map((candidate) => {
            if (candidate.id !== sessionId || !candidate.sftp) return candidate;
            const transfers = candidate.sftp.transfers ?? [];
            return {
              ...candidate,
              sftp: {
                ...candidate.sftp,
                transfers: transfers.some(
                  (transfer) => transfer.transferId === transferId && transfer.itemId === itemId,
                )
                  ? transfers
                  : [...transfers, cancelledTransfer],
                transferError: message,
                transferErrorTransferId: transferId,
              },
            };
          }),
        );
      });
  }

  function removeSftpTransfer(sessionId: string, transferId: string, itemId: string) {
    setSessions((current) =>
      current.map((candidate) => {
        if (candidate.id !== sessionId || !candidate.sftp) return candidate;
        return {
          ...candidate,
          sftp: {
            ...candidate.sftp,
            transfers: (candidate.sftp.transfers ?? []).filter(
              (transfer) => transfer.transferId !== transferId || transfer.itemId !== itemId,
            ),
          },
        };
      }),
    );
  }

  function clearSftpTransferError(sessionId: string) {
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === sessionId && candidate.sftp
          ? {
              ...candidate,
              sftp: {
                ...candidate.sftp,
                transferError: undefined,
                transferErrorTransferId: undefined,
              },
            }
          : candidate,
      ),
    );
  }

  sftpRefreshHandlers.current = {
    local: requestLocalSftpDirectory,
    remote: requestSftpDirectory,
  };

  useEffect(() => {
    const pending = sessions.find((session) => {
      const requests = session.sftp?.refreshRequests;
      return requests && (requests.local !== undefined || requests.remote !== undefined);
    });
    const requests = pending?.sftp?.refreshRequests;
    const request = requests?.local ?? requests?.remote;
    if (!pending || !request) return;
    const shouldRefresh = shouldRefreshSftpPane(pending.sftp!, request);

    setSessions((current) =>
      current.map((session) =>
        session.id === pending.id &&
        session.sftp?.refreshRequests?.[request.pane]?.id === request.id
          ? {
              ...session,
              sftp: {
                ...session.sftp,
                refreshRequests: {
                  ...session.sftp.refreshRequests,
                  [request.pane]: undefined,
                },
              },
            }
          : session,
      ),
    );
    if (!shouldRefresh) return;
    const refresh = sftpRefreshHandlers.current;
    if (request.pane === 'local') refresh?.local(pending.id, request.path);
    else refresh?.remote(pending.id, request.path);
  }, [sessions]);

  function sendSshInput(sessionId: string, value: string) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session?.backendSessionId || session.status !== 'connected') return;
    const backendSessionId = session.backendSessionId;

    void window.wormhole
      ?.sendSshInput(backendSessionId, encodeTerminalData(value))
      .catch((error: unknown) => {
        setSessions((current) =>
          current.map((candidate) =>
            candidate.id === sessionId && candidate.backendSessionId === backendSessionId
              ? {
                  ...candidate,
                  status: 'failed',
                  sftp: undefined,
                  error: error instanceof Error ? error.message : String(error),
                }
              : candidate,
          ),
        );
      });
  }

  function sendSerialInput(sessionId: string, value: string) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session?.backendSessionId || session.status !== 'connected') return;

    void window.wormhole
      ?.sendSerialInput(session.backendSessionId, encodeTerminalData(value))
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

  async function trustSshHostKey(
    sessionId: string,
    mismatch: NonNullable<Session['hostKeyMismatch']>,
  ) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session?.nodeId) return;
    try {
      if (!window.wormhole) throw new Error('The native SSH bridge is unavailable.');
      await window.wormhole.trustSshHostKey({
        nodeId: session.nodeId,
        expected: mismatch.expected,
        received: mismatch.received,
      });
      reconnectSession(sessionId);
    } catch (error: unknown) {
      setSessions((current) =>
        current.map((candidate) =>
          candidate.id === sessionId
            ? {
                ...candidate,
                error: error instanceof Error ? error.message : String(error),
                hostKeyMismatch: mismatch,
              }
            : candidate,
        ),
      );
    }
  }

  function openQuickConnect() {
    setQuickConnectForm({
      name: '',
      host: '',
      protocol: 'ssh',
      tunnel: 'off',
      httpIgnoreCertErrors: false,
      serial: { ...defaultSerialSettings },
    });
    setQuickConnectOpen(true);
  }

  function applyWorkspaceSnapshot(workspace: WormholeWorkspaceSnapshot) {
    const nextTree = workspace.tree as TreeNode[];
    setTree(nextTree);
    setCredentials(workspace.credentials as CredentialRecord[]);
    setTunnels(workspace.tunnels as TunnelRecord[]);
    setExpanded(
      (current) =>
        new Set([...current].filter((id) => findTreeNode(nextTree, id)?.kind === 'folder')),
    );
    setSelectedTreeNodeIds(
      (current) => new Set([...current].filter((id) => Boolean(findTreeNode(nextTree, id)))),
    );
    setSelectedNodeId(
      (current) =>
        findTreeNode(nextTree, current)?.id ??
        findFirstConnection(nextTree)?.id ??
        nextTree[0]?.id ??
        '',
    );
  }

  function applyDeletedTreeState(nextTree: TreeNode[]) {
    setTree(nextTree);
    setExpanded(
      (current) =>
        new Set([...current].filter((id) => findTreeNode(nextTree, id)?.kind === 'folder')),
    );
    setSelectedTreeNodeIds(
      (current) => new Set([...current].filter((id) => Boolean(findTreeNode(nextTree, id)))),
    );
    setSelectedNodeId(
      (current) =>
        findTreeNode(nextTree, current)?.id ??
        findFirstConnection(nextTree)?.id ??
        nextTree[0]?.id ??
        '',
    );
  }

  function openNewConnection(folderId?: string | null) {
    setEditingConnectionId(null);
    setEditorError('');
    setNewConnectionForm({
      name: '',
      host: '',
      protocol: 'ssh',
      folder: folderId ?? '',
      sshAutoSudo: 'inherit',
      httpIgnoreCertErrors: false,
      tunnel: 'inherit',
      serial: { ...defaultSerialSettings },
    });
    setNewConnectionOpen(true);
  }

  async function showConnectionCredentials(node: TreeNode) {
    const api = window.wormhole;
    if (node.kind !== 'connection' || !api || credentialRevealBusy) return;

    const requestId = ++credentialRevealRequest.current;
    setCredentialRevealBusy(true);
    try {
      const result = await api.showWorkspaceCredentials({ nodeId: node.id });
      if (credentialRevealRequest.current !== requestId) return;
      setCopiedCredentialField(null);
      setCredentialDialog({ kind: 'credentials', result });
    } catch (error: unknown) {
      if (credentialRevealRequest.current !== requestId) return;
      setCredentialDialog({
        kind: 'error',
        message:
          error instanceof Error ? error.message : 'Could not show the connection credentials.',
      });
    } finally {
      setCredentialRevealBusy(false);
    }
  }

  function closeCredentialDialog() {
    credentialRevealRequest.current += 1;
    setCredentialDialog(null);
    setCopiedCredentialField(null);
    if (copiedCredentialTimer.current !== undefined) {
      window.clearTimeout(copiedCredentialTimer.current);
      copiedCredentialTimer.current = undefined;
    }
  }

  async function copyCredentialValue(field: CredentialCopyField, value: string) {
    try {
      await copyTextToClipboard(value);
      setCopiedCredentialField(field);
      if (copiedCredentialTimer.current !== undefined) {
        window.clearTimeout(copiedCredentialTimer.current);
      }
      copiedCredentialTimer.current = window.setTimeout(() => {
        copiedCredentialTimer.current = undefined;
        setCopiedCredentialField(null);
      }, 1600);
    } catch {
      setCredentialDialog({
        kind: 'error',
        message: `Could not copy the ${field === 'username' ? 'username' : 'password'} to the clipboard.`,
      });
    }
  }

  function openDeleteNode(node: TreeNode) {
    if (deleteNodeBusy) return;
    setDeleteNodeError('');
    setPendingDeleteNode(findTreeNode(tree, node.id) ?? node);
  }

  async function confirmDeleteNode() {
    const node = pendingDeleteNode;
    if (!node || deleteNodeBusy) return;

    setDeleteNodeBusy(true);
    setDeleteNodeError('');
    try {
      const deletedNodeIds = new Set(collectTreeNodeIds(node));
      if (node.persisted) {
        const api = window.wormhole;
        if (!api) throw new Error('The native workspace bridge is unavailable.');
        const result = await api.deleteWorkspaceNode({ nodeId: node.id });
        if (!result.deleted) throw new Error('The workspace node was not deleted.');
        closeSessionsForNodeIds(deletedNodeIds);
        applyDeletedTreeState(removeTreeNode(tree, node.id));
        setPendingDeleteNode(null);
        try {
          applyWorkspaceSnapshot(await api.loadWorkspace());
        } catch {
          // The delete is already committed. The local tree has been updated above, so a
          // transient refresh failure must not leave a deleted node visible or invite a retry.
        }
      } else {
        closeSessionsForNodeIds(deletedNodeIds);
        applyDeletedTreeState(removeTreeNode(tree, node.id));
        setPendingDeleteNode(null);
      }
    } catch (error: unknown) {
      setDeleteNodeError(error instanceof Error ? error.message : 'Could not delete the node.');
    } finally {
      setDeleteNodeBusy(false);
    }
  }

  function duplicateConnection(node: TreeNode) {
    if (node.kind !== 'connection') return;
    const api = window.wormhole;
    if (node.persisted) {
      if (!api) {
        setEditorError('The native workspace bridge is unavailable.');
        return;
      }
      void api
        .duplicateWorkspaceNode({ nodeId: node.id })
        .then(async ({ nodeId, name }) => {
          try {
            applyWorkspaceSnapshot(await api.loadWorkspace());
          } catch (error: unknown) {
            const duplicate: TreeNode = {
              ...node,
              id: nodeId,
              name,
              persisted: true,
              children: undefined,
            };
            setTree((current) =>
              findTreeNode(current, nodeId)
                ? current
                : insertRelativeToTreeNode(current, node.id, [duplicate], 'after'),
            );
            setEditorError(
              `Connection duplicated, but the workspace could not be refreshed: ${
                error instanceof Error ? error.message : 'unknown error'
              }`,
            );
          }
          setSelectedNodeId(nodeId);
          setSelectedTreeNodeIds(new Set());
        })
        .catch((error: unknown) => {
          setEditorError(
            error instanceof Error ? error.message : 'Could not duplicate the connection.',
          );
        });
      return;
    }

    const duplicate: TreeNode = {
      ...node,
      id: `connection-duplicate-${newSessionToken()}`,
      name: `${node.name} (copy)`,
      persisted: false,
      children: undefined,
    };
    setTree((current) => insertRelativeToTreeNode(current, node.id, [duplicate], 'after'));
    setSelectedNodeId(duplicate.id);
    setSelectedTreeNodeIds(new Set());
  }

  function openEditConnection(node: TreeNode) {
    if (node.kind !== 'connection' || !node.protocol) return;

    setSelectedNodeId(node.id);
    setEditingConnectionId(node.id);
    setEditorError('');
    setNewConnectionForm({
      name: node.name,
      host: node.host ?? '',
      protocol: node.protocol,
      folder: findParentFolderId(tree, node.id) ?? '',
      sshAutoSudo: autoSudoModeFor(node.sshAutoSudo),
      httpIgnoreCertErrors: node.httpIgnoreCertErrors === true,
      tunnel: tunnelModeFor(node),
      serial: serialSettingsFromNode(node),
    });
    setNewConnectionOpen(true);
  }

  function openEditFolder(node: TreeNode) {
    if (node.kind !== 'folder') return;

    setSelectedNodeId(node.id);
    setEditingFolderId(node.id);
    setEditorError('');
    setFolderDetailsForm({
      name: node.name,
      sshAutoSudo: autoSudoModeFor(node.sshAutoSudo),
      tunnel: tunnelModeFor(node),
    });
    setFolderDetailsOpen(true);
  }

  function openEditNode(node: TreeNode) {
    if (node.kind === 'folder') {
      openEditFolder(node);
    } else {
      openEditConnection(node);
    }
  }

  async function persistNodeSshAutoSudo(nodeId: string, mode: AutoSudoMode): Promise<boolean> {
    if (!window.wormhole) {
      setEditorError('The native workspace bridge is unavailable.');
      return false;
    }
    try {
      const result = await window.wormhole.updateWorkspaceNodeSshSettings({
        nodeId,
        sshAutoSudo: autoSudoValueFor(mode),
      });
      if (!result.updated) {
        setEditorError('The workspace did not save the Auto sudo setting.');
        return false;
      }
      return true;
    } catch (error: unknown) {
      setEditorError(
        error instanceof Error ? error.message : 'Could not save the Auto sudo setting.',
      );
      return false;
    }
  }

  async function persistNodeHttpIgnoreCertErrors(
    nodeId: string,
    value: boolean | null,
  ): Promise<boolean> {
    if (!window.wormhole) {
      setEditorError('The native workspace bridge is unavailable.');
      return false;
    }
    try {
      const result = await window.wormhole.updateWorkspaceNodeWebSettings({
        nodeId,
        httpIgnoreCertErrors: value,
      });
      if (!result.updated) {
        setEditorError('The workspace did not save the certificate setting.');
        return false;
      }
      return true;
    } catch (error: unknown) {
      setEditorError(
        error instanceof Error ? error.message : 'Could not save the certificate setting.',
      );
      return false;
    }
  }

  async function persistNodeTunnel(nodeId: string, mode: TunnelMode): Promise<boolean> {
    if (!window.wormhole) {
      setEditorError('The native workspace bridge is unavailable.');
      return false;
    }
    try {
      const result = await window.wormhole.updateWorkspaceNodeTunnelSettings({
        nodeId,
        ...tunnelValueFor(mode),
      });
      if (!result.updated) {
        setEditorError('The workspace did not save the VPN tunnel setting.');
        return false;
      }
      return true;
    } catch (error: unknown) {
      setEditorError(
        error instanceof Error ? error.message : 'Could not save the VPN tunnel setting.',
      );
      return false;
    }
  }

  function openNewFolder(parentFolderId?: string | null) {
    setNewFolderName('');
    setNewFolderParentId(parentFolderId ?? null);
    setEditorError('');
    setNewFolderOpen(true);
  }

  function submitQuickConnect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = quickConnectForm.name.trim() || quickConnectForm.host.trim() || 'New connection';
    const host = quickConnectForm.host.trim() || 'localhost';
    const id = `session-quick-${newSessionToken()}`;
    const backendSessionId = quickConnectForm.protocol === 'serial' ? newSessionToken() : undefined;

    const session: Session = {
      id,
      title: name,
      protocol: quickConnectForm.protocol,
      host,
      tunnelConfigId: quickConnectTunnelId(quickConnectForm.protocol, quickConnectForm.tunnel),
      canTransfer: quickConnectForm.protocol === 'ssh',
      backendSessionId,
      status:
        quickConnectForm.protocol === 'serial' ||
        quickConnectForm.protocol === 'http' ||
        quickConnectForm.protocol === 'https'
          ? 'connecting'
          : 'placeholder',
      serialSettings:
        quickConnectForm.protocol === 'serial' ? { ...quickConnectForm.serial } : undefined,
      error:
        quickConnectForm.protocol === 'ssh'
          ? 'Quick Connect needs a saved SSH credential before it can connect.'
          : undefined,
      rdpStatus: quickConnectForm.protocol === 'rdp' ? 'idle' : undefined,
      webIgnoreCertErrors:
        quickConnectForm.protocol === 'https' && quickConnectForm.httpIgnoreCertErrors,
    };
    setSessions((current) => [...current, session]);
    setSelectedSessionId(id);
    setActivePage('sessions');
    setQuickConnectOpen(false);
    if (backendSessionId) {
      startSerialSession(backendSessionId, undefined, host, quickConnectForm.serial);
    }
    if (quickConnectForm.protocol === 'rdp') {
      setRdpCredentialForm({ username: '', domain: '', password: '' });
      setRdpCredentialPrompt(id);
    }
    if (quickConnectForm.protocol === 'http' || quickConnectForm.protocol === 'https') {
      startWebSession(session);
    }
  }

  async function submitNewConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (editorBusy) return;
    const name = newConnectionForm.name.trim();
    const host = newConnectionForm.host.trim();
    const editingId = editingConnectionId;
    setEditorBusy(true);
    setEditorError('');

    try {
      const connectionAutoSudo =
        newConnectionForm.protocol === 'ssh' ? newConnectionForm.sshAutoSudo : 'inherit';
      const connectionTunnel =
        newConnectionForm.protocol === 'serial' ? 'off' : newConnectionForm.tunnel;
      if (editingId) {
        const editedNode = findTreeNode(tree, editingId);
        if (
          editedNode?.persisted &&
          !(await persistNodeSshAutoSudo(editingId, connectionAutoSudo))
        ) {
          return;
        }
        const editsWebConnection =
          editedNode?.protocol === 'http' ||
          editedNode?.protocol === 'https' ||
          newConnectionForm.protocol === 'http' ||
          newConnectionForm.protocol === 'https';
        if (
          editedNode?.persisted &&
          editsWebConnection &&
          !(await persistNodeHttpIgnoreCertErrors(
            editingId,
            newConnectionForm.protocol === 'https' ? newConnectionForm.httpIgnoreCertErrors : null,
          ))
        ) {
          return;
        }
        if (editedNode?.persisted && !(await persistNodeTunnel(editingId, connectionTunnel))) {
          return;
        }
        const editedSessionId = `session-${editingId}`;
        const editedSession = sessions.find((session) => session.id === editedSessionId);
        if (editedSession?.backendSessionId) {
          if (editedSession.protocol === 'serial') {
            void window.wormhole?.closeSerialSession(editedSession.backendSessionId);
          } else {
            void window.wormhole?.closeSshSession(editedSession.backendSessionId);
          }
        }
        if (editedSession?.protocol === 'http' || editedSession?.protocol === 'https') {
          await closeWebSession(editedSession.id).catch(() => undefined);
        }
        clearSftpCancelRequestsForBrowser(sftpCancelRequests.current, editedSession?.sftp);
        const backendSessionId =
          editedSession &&
          (newConnectionForm.protocol === 'ssh' || newConnectionForm.protocol === 'serial')
            ? newSessionToken()
            : undefined;
        setTree((current) =>
          updateConnectionInTree(current, editingId, newConnectionForm.folder, {
            name,
            host,
            protocol: newConnectionForm.protocol,
            sshAutoSudo: autoSudoValueFor(connectionAutoSudo),
            httpIgnoreCertErrors:
              newConnectionForm.protocol === 'https'
                ? newConnectionForm.httpIgnoreCertErrors
                : undefined,
            ...tunnelValueFor(connectionTunnel),
            serialSettings:
              newConnectionForm.protocol === 'serial' ? newConnectionForm.serial : undefined,
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
                  status:
                    newConnectionForm.protocol === 'ssh' ||
                    newConnectionForm.protocol === 'serial' ||
                    newConnectionForm.protocol === 'http' ||
                    newConnectionForm.protocol === 'https'
                      ? 'connecting'
                      : 'placeholder',
                  terminalFrame: undefined,
                  sftp: undefined,
                  error: undefined,
                  serialSettings:
                    newConnectionForm.protocol === 'serial'
                      ? { ...newConnectionForm.serial }
                      : undefined,
                  webTargetNodeId:
                    (newConnectionForm.protocol === 'http' ||
                      newConnectionForm.protocol === 'https') &&
                    editedNode?.persisted
                      ? editingId
                      : undefined,
                  webIgnoreCertErrors:
                    newConnectionForm.protocol === 'https'
                      ? newConnectionForm.httpIgnoreCertErrors
                      : undefined,
                }
              : session,
          ),
        );
        if (backendSessionId && newConnectionForm.protocol === 'ssh') {
          startSshSession(backendSessionId, editingId);
        }
        if (backendSessionId && newConnectionForm.protocol === 'serial') {
          startSerialSession(
            backendSessionId,
            savedSerialNodeId(editingId),
            host,
            newConnectionForm.serial,
          );
        }
        if (
          editedSession &&
          (newConnectionForm.protocol === 'http' || newConnectionForm.protocol === 'https')
        ) {
          startWebSession({
            ...editedSession,
            title: name,
            host,
            protocol: newConnectionForm.protocol,
            status: 'connecting',
            webTargetNodeId: editedNode?.persisted ? editingId : undefined,
            webIgnoreCertErrors:
              newConnectionForm.protocol === 'https'
                ? newConnectionForm.httpIgnoreCertErrors
                : undefined,
          });
        }
      } else {
        const id = `connection-${Date.now()}`;
        const connection: TreeNode = {
          id,
          name,
          kind: 'connection',
          protocol: newConnectionForm.protocol,
          host,
          sshAutoSudo: autoSudoValueFor(connectionAutoSudo),
          httpIgnoreCertErrors:
            newConnectionForm.protocol === 'https'
              ? newConnectionForm.httpIgnoreCertErrors
              : undefined,
          ...tunnelValueFor(connectionTunnel),
          ...(newConnectionForm.protocol === 'serial'
            ? {
                serialBaudRate: newConnectionForm.serial.baudRate,
                serialDataBits: newConnectionForm.serial.dataBits,
                serialStopBits: newConnectionForm.serial.stopBits,
                serialParity: newConnectionForm.serial.parity,
                serialFlowControl: newConnectionForm.serial.flowControl,
              }
            : {}),
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
    } finally {
      setEditorBusy(false);
    }
  }

  async function submitFolderDetails(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (editorBusy || !editingFolderId) return;
    const name = folderDetailsForm.name.trim();
    if (!name) return;

    setEditorBusy(true);
    setEditorError('');
    try {
      const folder = findTreeNode(tree, editingFolderId);
      if (!folder) return;
      if (
        folder.persisted &&
        !(await persistNodeSshAutoSudo(editingFolderId, folderDetailsForm.sshAutoSudo))
      ) {
        return;
      }
      if (
        folder.persisted &&
        !(await persistNodeTunnel(editingFolderId, folderDetailsForm.tunnel))
      ) {
        return;
      }
      setTree((current) =>
        updateFolderInTree(current, editingFolderId, {
          name,
          sshAutoSudo: autoSudoValueFor(folderDetailsForm.sshAutoSudo),
          ...tunnelValueFor(folderDetailsForm.tunnel),
        }),
      );
      setFolderDetailsOpen(false);
      setEditingFolderId(null);
    } finally {
      setEditorBusy(false);
    }
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
            'relative z-10 h-8 w-full cursor-grab justify-start gap-1.5 rounded-md px-2 text-left !text-xs font-medium text-sidebar-foreground/80 transition-[background-color,box-shadow,opacity] duration-150 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground aria-expanded:bg-transparent aria-expanded:text-sidebar-foreground/80 active:cursor-grabbing',
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
          {isFolder && hasChildren ? (
            <span className="grid size-4 shrink-0 place-items-center text-muted-foreground">
              {isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
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
            onDuplicateConnection={() => duplicateConnection(node)}
            onDelete={() => openDeleteNode(node)}
            onEdit={() => openEditNode(node)}
            onNewConnection={() => openNewConnection(creationFolderId)}
            onNewFolder={() => openNewFolder(creationFolderId)}
            onShowCredentials={() => showConnectionCredentials(node)}
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
            onDelete={() => openDeleteNode(node)}
            onEdit={() => openEditNode(node)}
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

  async function createCredential(draft: CredentialDraft): Promise<void> {
    if (!window.wormhole) throw new Error('The native credential bridge is unavailable.');
    const credential = (await window.wormhole.createCredential(draft)) as CredentialRecord;
    setCredentials((current) => mergeCredential(current, credential));
  }

  async function updateCredential(id: string, draft: CredentialDraft): Promise<void> {
    if (!window.wormhole) throw new Error('The native credential bridge is unavailable.');
    const credential = (await window.wormhole.updateCredential({
      ...draft,
      id,
    })) as CredentialRecord;
    setCredentials((current) => mergeCredential(current, credential));
  }

  async function deleteSavedCredential(id: string): Promise<void> {
    if (!window.wormhole) throw new Error('The native credential bridge is unavailable.');
    const result = await window.wormhole.deleteCredential({ id });
    if (!result.deleted) throw new Error(result.error ?? 'The credential was not deleted.');
    setCredentials((current) => current.filter((credential) => credential.id !== id));
  }

  const currentPage = navItems.find((item) => item.id === activePage)!;
  const visibleAuthPrompt =
    authPrompt ??
    (authGate === 'locked' && authState?.configured
      ? { kind: 'lock' as const, reason: lockReason, autoWindowsHello: true }
      : null);
  const credentialResult =
    credentialDialog?.kind === 'credentials' ? credentialDialog.result : null;
  const deleteNodeDescendantCount = pendingDeleteNode
    ? collectTreeNodeIds(pendingDeleteNode).length - 1
    : 0;

  return (
    <TooltipProvider delayDuration={300}>
      {visibleAuthPrompt && authState ? (
        <AuthPrompt
          onResult={handleAuthPromptResult}
          request={visibleAuthPrompt}
          state={authState}
        />
      ) : null}
      <Dialog
        onOpenChange={(open) => {
          if (!open) closeCredentialDialog();
        }}
        open={credentialDialog !== null}
      >
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-lg">
          {credentialResult ? (
            <>
              <DialogHeader>
                <DialogTitle>
                  Credentials — {credentialResult.connectionName || 'Connection'}
                </DialogTitle>
                <DialogDescription>
                  {credentialResult.found
                    ? credentialResult.credentialName
                      ? `Stored credential: ${credentialResult.credentialName}`
                      : 'Stored connection credentials.'
                    : 'This connection has no stored credentials to show.'}
                </DialogDescription>
              </DialogHeader>
              {credentialResult.found ? (
                <div className="space-y-4">
                  {credentialResult.username ? (
                    <CredentialValueRow
                      copied={copiedCredentialField === 'username'}
                      id="revealed-credential-username"
                      label="Username"
                      onCopy={() =>
                        void copyCredentialValue('username', credentialResult.username ?? '')
                      }
                      value={credentialResult.username}
                    />
                  ) : null}
                  {credentialResult.domain ? (
                    <div className="grid gap-1.5">
                      <Label className="text-[11px] text-muted-foreground">Domain</Label>
                      <p className="rounded-md border border-border/70 bg-muted/20 px-3 py-2 font-mono text-xs">
                        {credentialResult.domain}
                      </p>
                    </div>
                  ) : null}
                  {credentialResult.secret ? (
                    <CredentialValueRow
                      copied={copiedCredentialField === 'secret'}
                      id="revealed-credential-secret"
                      label={credentialResult.secretLabel || 'Password'}
                      onCopy={() =>
                        void copyCredentialValue('secret', credentialResult.secret ?? '')
                      }
                      value={credentialResult.secret}
                    />
                  ) : (
                    <p className="rounded-md border border-border/70 bg-muted/20 px-3 py-2 text-xs text-muted-foreground">
                      No stored password or key passphrase is available for this connection.
                    </p>
                  )}
                </div>
              ) : (
                <p className="rounded-md border border-border/70 bg-muted/20 px-3 py-3 text-xs text-muted-foreground">
                  There is no stored password or key passphrase to show.
                </p>
              )}
              <DialogFooter>
                <Button onClick={closeCredentialDialog} type="button" variant="outline">
                  Close
                </Button>
              </DialogFooter>
            </>
          ) : (
            <>
              <DialogHeader>
                <DialogTitle>Couldn&apos;t show credentials</DialogTitle>
                <DialogDescription>
                  Wormhole could not read the credentials for this connection.
                </DialogDescription>
              </DialogHeader>
              <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-3 text-xs text-destructive">
                {credentialDialog?.kind === 'error' ? credentialDialog.message : null}
              </p>
              <DialogFooter>
                <Button onClick={closeCredentialDialog} type="button" variant="outline">
                  Close
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
      <Dialog
        onOpenChange={(open) => {
          if (!open && !deleteNodeBusy) {
            setPendingDeleteNode(null);
            setDeleteNodeError('');
          }
        }}
        open={pendingDeleteNode !== null}
      >
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              Delete {pendingDeleteNode?.kind === 'folder' ? 'folder' : 'connection'}
            </DialogTitle>
            <DialogDescription>
              {pendingDeleteNode?.kind === 'folder' && deleteNodeDescendantCount > 0
                ? `Delete “${pendingDeleteNode.name}” and its ${deleteNodeDescendantCount} ${deleteNodeDescendantCount === 1 ? 'child' : 'children'}? This cannot be undone.`
                : `Delete “${pendingDeleteNode?.name ?? 'this item'}”? This cannot be undone.`}
            </DialogDescription>
          </DialogHeader>
          {deleteNodeError ? (
            <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-3 text-xs text-destructive">
              {deleteNodeError}
            </p>
          ) : null}
          <DialogFooter>
            <Button
              disabled={deleteNodeBusy}
              onClick={() => {
                setPendingDeleteNode(null);
                setDeleteNodeError('');
              }}
              type="button"
              variant="ghost"
            >
              Cancel
            </Button>
            <Button
              disabled={deleteNodeBusy}
              onClick={() => void confirmDeleteNode()}
              type="button"
              variant="destructive"
            >
              {deleteNodeBusy ? 'Deleting…' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog
        onOpenChange={(open) => {
          if (!open) void resolveTunnelPrompt(true);
        }}
        open={tunnelPrompts.length > 0}
      >
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (tunnelPrompts[0]?.confirmation || tunnelPromptValue.trim()) {
                void resolveTunnelPrompt(false);
              }
            }}
          >
            <DialogHeader>
              <DialogTitle>{tunnelPrompts[0]?.title || 'VPN authentication'}</DialogTitle>
              <DialogDescription>
                {tunnelPrompts[0]?.message || 'Enter the value requested by the VPN gateway.'}
              </DialogDescription>
            </DialogHeader>
            {!tunnelPrompts[0]?.confirmation ? (
              <Input
                autoComplete="one-time-code"
                autoFocus
                onChange={(event) => setTunnelPromptValue(event.target.value)}
                type={tunnelPrompts[0]?.secret ? 'password' : 'text'}
                value={tunnelPromptValue}
              />
            ) : null}
            <DialogFooter>
              <Button onClick={() => void resolveTunnelPrompt(true)} type="button" variant="ghost">
                Cancel
              </Button>
              <Button
                disabled={!tunnelPrompts[0]?.confirmation && !tunnelPromptValue.trim()}
                type="submit"
              >
                {tunnelPrompts[0]?.acceptLabel || 'Continue'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog
        onOpenChange={(open) => {
          if (!open) void resolveTunnelRoute('cancel');
        }}
        open={routePrompts.length > 0}
      >
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
          <DialogHeader>
            <DialogTitle>VPN tunnel</DialogTitle>
            <DialogDescription>
              {routePrompts[0]?.tunnelName
                ? `“${routePrompts[0].connectionName || 'the target'}” is set to connect through
                    the VPN tunnel “${routePrompts[0].tunnelName}”. Start the tunnel and connect
                    through it, or connect directly to the target?`
                : `“${routePrompts[0]?.connectionName || 'the target'}” is set to connect through
                    the VPN tunnel. Start the tunnel and connect through it, or connect directly
                    to the target?`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button onClick={() => void resolveTunnelRoute('cancel')} type="button" variant="ghost">
              Cancel
            </Button>
            <Button
              onClick={() => void resolveTunnelRoute('direct')}
              type="button"
              variant="outline"
            >
              Connect directly
            </Button>
            <Button onClick={() => void resolveTunnelRoute('tunnel')} type="button">
              Use tunnel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog
        onOpenChange={(open) => {
          if (!open) void resolveMcpApproval(false);
        }}
        open={mcpApprovals.length > 0}
      >
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Allow AI agent control?</DialogTitle>
            <DialogDescription>
              An MCP client is requesting access to one of Wormhole&apos;s live SSH sessions.
            </DialogDescription>
          </DialogHeader>
          {mcpApprovals[0] ? (
            <div className="space-y-3 rounded-lg border border-border/70 bg-muted/20 p-3 text-xs">
              <div className="flex items-start gap-2">
                <AlertCircle className="mt-0.5 size-4 shrink-0 text-amber-400" />
                <div className="min-w-0 space-y-1">
                  <p className="font-medium">{mcpApprovals[0].title || 'SSH session'}</p>
                  <p className="break-all text-muted-foreground">
                    {mcpApprovals[0].username}@{mcpApprovals[0].host}:{mcpApprovals[0].port}
                  </p>
                  <p className="text-muted-foreground">
                    Requested tool: <span className="font-mono">{mcpApprovals[0].tool}</span>
                  </p>
                </div>
              </div>
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                Allowing this request grants the MCP client access to this session for the rest of
                the session&apos;s lifetime. MCP tools can run only while Wormhole is unlocked.
              </p>
            </div>
          ) : null}
          <DialogFooter>
            <Button onClick={() => void resolveMcpApproval(false)} type="button" variant="ghost">
              Deny
            </Button>
            <Button onClick={() => void resolveMcpApproval(true)} type="button">
              Allow
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <div
        aria-hidden={authGate !== 'unlocked'}
        className="flex h-full min-w-[960px] flex-col bg-background font-sans text-foreground"
        inert={authGate !== 'unlocked'}
      >
        <header className="relative flex h-12 shrink-0 items-center border-b border-border bg-background px-3 text-foreground [-webkit-app-region:drag]">
          <div className="flex min-w-0 items-center gap-2.5 [-webkit-app-region:no-drag]">
            <div className="grid size-8 shrink-0 place-items-center rounded-md p-1">
              <img alt="" className="size-full object-contain" src={wormholeIcon} />
            </div>
            <span className="select-none text-sm font-semibold tracking-tight">Wormhole</span>
            {updateBannerVisible ? (
              <Button
                className="h-7 gap-1.5 rounded-md border-border bg-background px-2.5 text-[10px] font-semibold text-foreground hover:bg-muted hover:text-foreground"
                onClick={() => {
                  setSettingsUpdatesRequest((request) => request + 1);
                  setActivePage('settings');
                }}
                size="sm"
                variant="outline"
              >
                <Download data-icon="inline-start" />
                Update
              </Button>
            ) : null}
          </div>
        </header>

        <ResizablePanelGroup className="h-full min-h-0 flex-1" orientation="horizontal">
          <ResizablePanel className="min-h-0" defaultSize="24%" maxSize="36%" minSize="18%">
            <SidebarProvider
              className="h-full min-h-0"
              style={{ '--sidebar-width': '100%' } as CSSProperties}
            >
              <Sidebar className="relative w-full border-r-0" collapsible="none">
                <SidebarHeader className="gap-3 p-3">
                  <div className="flex items-center justify-between gap-2 px-1">
                    <div>
                      <h1 className="!text-xs font-semibold tracking-tight">Connections</h1>
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
                      <IconButton label="New folder" onClick={() => openNewFolder(null)}>
                        <FolderPlus />
                      </IconButton>
                      <IconButton label="New connection" onClick={() => openNewConnection(null)}>
                        <Plus />
                      </IconButton>
                    </div>
                  </div>
                  <Button
                    className="w-full justify-center gap-2 !text-xs"
                    onClick={openQuickConnect}
                    size="default"
                  >
                    <Zap data-icon="inline-start" />
                    Quick Connect
                    <Kbd>Ctrl K</Kbd>
                  </Button>
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-2.5 top-1/2 z-10 size-3.5 -translate-y-1/2 text-muted-foreground" />
                    <SidebarInput
                      aria-label="Search connections"
                      className="bg-background/60 pl-8 pr-8 !text-xs shadow-none"
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
                    <p className="px-1 text-xs text-muted-foreground">
                      {visibleTree.length === 0
                        ? 'No matches'
                        : `Showing matches for “${searchText}”`}
                    </p>
                  ) : null}
                </SidebarHeader>

                <SidebarContent className="min-h-0 overflow-hidden px-2">
                  <ContextMenu>
                    <ContextMenuTrigger asChild>
                      <div className="flex min-h-0 flex-1 flex-col">
                        <ScrollArea className="min-h-0 flex-1 px-1">
                          {visibleTree.length > 0 ? (
                            renderTree(visibleTree)
                          ) : (
                            <p className="px-3 py-8 text-center text-xs text-muted-foreground">
                              Nothing here yet.
                            </p>
                          )}
                        </ScrollArea>
                      </div>
                    </ContextMenuTrigger>
                    <ContextMenuContent className="w-52">
                      <ContextMenuItem onSelect={() => openNewFolder(null)}>
                        <FolderPlus />
                        New folder
                      </ContextMenuItem>
                      <ContextMenuItem onSelect={() => openNewConnection(null)}>
                        <Plus />
                        New connection
                      </ContextMenuItem>
                    </ContextMenuContent>
                  </ContextMenu>
                </SidebarContent>

                <SidebarFooter className="gap-2 border-t border-sidebar-border p-2">
                  <SidebarGroup className="p-0">
                    <SidebarMenu>
                      {navItems.map((item) => (
                        <SidebarMenuItem key={item.id}>
                          <SidebarMenuButton
                            className="!text-xs"
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
          <ResizablePanel className="min-h-0" minSize="54%">
            <SidebarInset className="h-full min-h-0 min-w-0 rounded-none bg-background">
              {activePage === 'sessions' ? (
                <SessionsPage
                  onCloseSession={closeSession}
                  onConnectRdp={requestRdpCredentials}
                  onDuplicateSession={duplicateSession}
                  onCloseSftpBrowser={closeSftpBrowser}
                  onOpenFileTransfer={openFileTransfer}
                  onOpenQuickConnect={openQuickConnect}
                  onReconnectSession={reconnectSession}
                  onRetryRdp={retryRdpSession}
                  onSelectSession={setSelectedSessionId}
                  onSerialInput={sendSerialInput}
                  onSftpLocalNavigate={requestLocalSftpDirectory}
                  onSftpOperation={operateSftp}
                  onSftpTransfer={startSftpTransfer}
                  onSftpConflict={decideSftpConflict}
                  onSftpTransferCancel={cancelSftpTransfer}
                  onSftpTransferErrorClear={clearSftpTransferError}
                  onSftpTransferRemove={removeSftpTransfer}
                  onSftpNavigate={requestSftpDirectory}
                  onSftpRefresh={refreshSftpBrowser}
                  onSshInput={sendSshInput}
                  onTrustSshHostKey={trustSshHostKey}
                  isAuthorized={authGate === 'unlocked'}
                  isWebSurfaceVisible={
                    !quickConnectOpen &&
                    !newConnectionOpen &&
                    !folderDetailsOpen &&
                    !newFolderOpen &&
                    !authPrompt &&
                    !rdpCredentialPrompt
                  }
                  selectedSession={selectedSession}
                  sessions={sessions}
                />
              ) : activePage === 'settings' ? (
                <SettingsPage
                  authGate={authGate}
                  authState={authState}
                  onAuthStateChange={setAuthState}
                  onBackupImported={(workspace) => {
                    setTree(workspace.tree);
                    setCredentials(workspace.credentials);
                    setTunnels(workspace.tunnels);
                    setExpanded(
                      (current) => new Set([...current, ...collectFolderIds(workspace.tree)]),
                    );
                    setSelectedNodeId((current) =>
                      findTreeNode(workspace.tree, current)
                        ? current
                        : (findFirstConnection(workspace.tree)?.id ?? workspace.tree[0]?.id ?? ''),
                    );
                    setSelectedTreeNodeIds(
                      (current) =>
                        new Set([...current].filter((id) => findTreeNode(workspace.tree, id))),
                    );
                  }}
                  onRequestAuthentication={requestAuthentication}
                  onThemeChange={setTheme}
                  onCheckForUpdates={() => void handleCheckForUpdates()}
                  onDismissUpdate={handleDismissUpdate}
                  onInstallUpdate={() => void handleInstallUpdate()}
                  onOpenReleaseNotes={handleOpenReleaseNotes}
                  onSetAutoCheckForUpdates={handleSetAutoCheckForUpdates}
                  settingsUpdatesRequest={settingsUpdatesRequest}
                  theme={theme}
                  update={{
                    autoCheckForUpdates,
                    busy: updateBusy,
                    currentVersion: updateCurrentVersion,
                    downloadProgress: updateDownloadProgress,
                    lastUpdateCheck,
                    result: updateResult,
                    skippedUpdateVersion,
                    status: updateStatus,
                  }}
                />
              ) : activePage === 'credentials' ? (
                <CredentialsPage
                  initialCredentials={credentials}
                  onCreate={createCredential}
                  onDelete={deleteSavedCredential}
                  onUpdate={updateCredential}
                />
              ) : activePage === 'tunnels' ? (
                <TunnelsPage
                  onTunnelCreated={(tunnel) =>
                    setTunnels((current) =>
                      [...current, tunnel].sort((left, right) =>
                        left.name.localeCompare(right.name),
                      ),
                    )
                  }
                  onTunnelDeleted={(id) =>
                    setTunnels((current) => current.filter((tunnel) => tunnel.id !== id))
                  }
                  onTunnelUpdated={(tunnel) =>
                    setTunnels((current) =>
                      current
                        .map((item) => (item.id === tunnel.id ? tunnel : item))
                        .sort((left, right) => left.name.localeCompare(right.name)),
                    )
                  }
                  tunnels={tunnels}
                />
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
                  placeholder={
                    quickConnectForm.protocol === 'http' || quickConnectForm.protocol === 'https'
                      ? '10.0.0.1:8443'
                      : 'hostname, IP, or COM port'
                  }
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
              {quickConnectSupportsTunnel(quickConnectForm.protocol) ? (
                <div className="grid gap-2">
                  <Label htmlFor="quick-tunnel-route">VPN route</Label>
                  <Select
                    onValueChange={(tunnel) => setQuickConnectForm((form) => ({ ...form, tunnel }))}
                    value={quickConnectForm.tunnel}
                  >
                    <SelectTrigger id="quick-tunnel-route">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="off">No VPN tunnel</SelectItem>
                      {tunnels.map((tunnel) => (
                        <SelectItem key={tunnel.id} value={tunnel.id}>
                          {tunnel.name} · {tunnel.kind}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-[11px] leading-relaxed text-muted-foreground">
                    The selected VPN tunnel starts before this temporary connection.
                  </p>
                </div>
              ) : null}
              {quickConnectForm.protocol === 'https' ? (
                <label className="flex items-center gap-2 text-xs">
                  <Checkbox
                    checked={quickConnectForm.httpIgnoreCertErrors}
                    onCheckedChange={(checked) =>
                      setQuickConnectForm((form) => ({
                        ...form,
                        httpIgnoreCertErrors: checked === true,
                      }))
                    }
                  />
                  <span>Ignore certificate errors</span>
                </label>
              ) : null}
              {quickConnectForm.protocol === 'serial' ? (
                <div className="grid gap-3 rounded-lg border border-border/70 bg-background/35 p-3 sm:grid-cols-2">
                  <div className="grid gap-2">
                    <Label htmlFor="quick-serial-baud">Speed (baud)</Label>
                    <Input
                      id="quick-serial-baud"
                      inputMode="numeric"
                      onChange={(event) =>
                        setQuickConnectForm((form) => ({
                          ...form,
                          serial: { ...form.serial, baudRate: Number(event.target.value) || 0 },
                        }))
                      }
                      value={String(quickConnectForm.serial.baudRate)}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="quick-serial-data-bits">Data bits</Label>
                    <Select
                      onValueChange={(value) =>
                        setQuickConnectForm((form) => ({
                          ...form,
                          serial: { ...form.serial, dataBits: Number(value) },
                        }))
                      }
                      value={String(quickConnectForm.serial.dataBits)}
                    >
                      <SelectTrigger id="quick-serial-data-bits">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="5">5</SelectItem>
                        <SelectItem value="6">6</SelectItem>
                        <SelectItem value="7">7</SelectItem>
                        <SelectItem value="8">8</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="quick-serial-stop-bits">Stop bits</Label>
                    <Select
                      onValueChange={(value) =>
                        setQuickConnectForm((form) => ({
                          ...form,
                          serial: { ...form.serial, stopBits: Number(value) },
                        }))
                      }
                      value={String(quickConnectForm.serial.stopBits)}
                    >
                      <SelectTrigger id="quick-serial-stop-bits">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="1">1</SelectItem>
                        <SelectItem value="2">2</SelectItem>
                        <SelectItem value="3">1.5</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="quick-serial-parity">Parity</Label>
                    <Select
                      onValueChange={(value) =>
                        setQuickConnectForm((form) => ({
                          ...form,
                          serial: { ...form.serial, parity: Number(value) },
                        }))
                      }
                      value={String(quickConnectForm.serial.parity)}
                    >
                      <SelectTrigger id="quick-serial-parity">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="0">None</SelectItem>
                        <SelectItem value="1">Odd</SelectItem>
                        <SelectItem value="2">Even</SelectItem>
                        <SelectItem value="3">Mark</SelectItem>
                        <SelectItem value="4">Space</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2 sm:col-span-2">
                    <Label htmlFor="quick-serial-flow">Flow control</Label>
                    <Select
                      onValueChange={(value) =>
                        setQuickConnectForm((form) => ({
                          ...form,
                          serial: { ...form.serial, flowControl: Number(value) },
                        }))
                      }
                      value={String(quickConnectForm.serial.flowControl)}
                    >
                      <SelectTrigger id="quick-serial-flow" className="sm:max-w-[240px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="0">None</SelectItem>
                        <SelectItem value="1">Software (XON/XOFF)</SelectItem>
                        <SelectItem value="2">Hardware (RTS/CTS)</SelectItem>
                        <SelectItem value="3">DSR/DTR</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              ) : null}
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
            if (!open) {
              setEditingConnectionId(null);
              setEditorError('');
            }
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
                            setNewConnectionForm((form) => ({
                              ...form,
                              host: event.target.value,
                            }))
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
                          setNewConnectionForm((form) => ({
                            ...form,
                            folder: folder === rootFolderSelectionValue ? '' : folder,
                          }))
                        }
                        value={newConnectionForm.folder || rootFolderSelectionValue}
                      >
                        <SelectTrigger id="connection-folder" className="w-full">
                          <SelectValue placeholder="Root" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={rootFolderSelectionValue}>Root</SelectItem>
                          {folders.map((folder) => (
                            <SelectItem key={folder.id} value={folder.id}>
                              {folder.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    {newConnectionForm.protocol === 'ssh' ? (
                      <AutoSudoField
                        id="connection-auto-sudo"
                        mode={newConnectionForm.sshAutoSudo}
                        onChange={(sshAutoSudo) =>
                          setNewConnectionForm((form) => ({ ...form, sshAutoSudo }))
                        }
                        scope="connection"
                      />
                    ) : null}

                    <TunnelRouteField
                      disabled={newConnectionForm.protocol === 'serial'}
                      id="connection-tunnel-route"
                      mode={
                        newConnectionForm.protocol === 'serial' ? 'off' : newConnectionForm.tunnel
                      }
                      onChange={(tunnel) => setNewConnectionForm((form) => ({ ...form, tunnel }))}
                      scope="connection"
                      tunnels={tunnels}
                    />

                    {newConnectionForm.protocol === 'https' ? (
                      <label className="flex items-center gap-2 text-xs">
                        <Checkbox
                          checked={newConnectionForm.httpIgnoreCertErrors}
                          onCheckedChange={(checked) =>
                            setNewConnectionForm((form) => ({
                              ...form,
                              httpIgnoreCertErrors: checked === true,
                            }))
                          }
                        />
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
                        <Input
                          id="serial-baud"
                          inputMode="numeric"
                          onChange={(event) =>
                            setNewConnectionForm((form) => ({
                              ...form,
                              serial: {
                                ...form.serial,
                                baudRate: Number(event.target.value) || 0,
                              },
                            }))
                          }
                          value={String(newConnectionForm.serial.baudRate)}
                        />
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="serial-data-bits">Data bits</Label>
                        <Select
                          onValueChange={(value) =>
                            setNewConnectionForm((form) => ({
                              ...form,
                              serial: { ...form.serial, dataBits: Number(value) },
                            }))
                          }
                          value={String(newConnectionForm.serial.dataBits)}
                        >
                          <SelectTrigger id="serial-data-bits">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="5">5</SelectItem>
                            <SelectItem value="6">6</SelectItem>
                            <SelectItem value="7">7</SelectItem>
                            <SelectItem value="8">8</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="serial-stop-bits">Stop bits</Label>
                        <Select
                          onValueChange={(value) =>
                            setNewConnectionForm((form) => ({
                              ...form,
                              serial: { ...form.serial, stopBits: Number(value) },
                            }))
                          }
                          value={String(newConnectionForm.serial.stopBits)}
                        >
                          <SelectTrigger id="serial-stop-bits">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="1">1</SelectItem>
                            <SelectItem value="2">2</SelectItem>
                            <SelectItem value="3">1.5</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2">
                        <Label htmlFor="serial-parity">Parity</Label>
                        <Select
                          onValueChange={(value) =>
                            setNewConnectionForm((form) => ({
                              ...form,
                              serial: { ...form.serial, parity: Number(value) },
                            }))
                          }
                          value={String(newConnectionForm.serial.parity)}
                        >
                          <SelectTrigger id="serial-parity">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="0">None</SelectItem>
                            <SelectItem value="1">Odd</SelectItem>
                            <SelectItem value="2">Even</SelectItem>
                            <SelectItem value="3">Mark</SelectItem>
                            <SelectItem value="4">Space</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="grid gap-2 sm:col-span-2">
                        <Label htmlFor="serial-flow">Flow control</Label>
                        <Select
                          onValueChange={(value) =>
                            setNewConnectionForm((form) => ({
                              ...form,
                              serial: { ...form.serial, flowControl: Number(value) },
                            }))
                          }
                          value={String(newConnectionForm.serial.flowControl)}
                        >
                          <SelectTrigger id="serial-flow" className="sm:max-w-[240px]">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="0">None</SelectItem>
                            <SelectItem value="1">Software (XON/XOFF)</SelectItem>
                            <SelectItem value="2">Hardware (RTS/CTS)</SelectItem>
                            <SelectItem value="3">DSR/DTR</SelectItem>
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
              {editorError ? <p className="text-[11px] text-destructive">{editorError}</p> : null}
              <DialogFooter>
                <Button
                  disabled={editorBusy}
                  onClick={() => {
                    setNewConnectionOpen(false);
                    setEditingConnectionId(null);
                  }}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button disabled={editorBusy} type="submit">
                  {editingConnectionId ? (
                    <Check data-icon="inline-start" />
                  ) : (
                    <Plus data-icon="inline-start" />
                  )}
                  {editorBusy
                    ? 'Saving…'
                    : editingConnectionId
                      ? 'Save changes'
                      : 'Save connection'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            setFolderDetailsOpen(open);
            if (!open) {
              setEditingFolderId(null);
              setEditorError('');
            }
          }}
          open={folderDetailsOpen}
        >
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-xl">
            <DialogHeader>
              <DialogTitle>Folder details</DialogTitle>
              <DialogDescription>
                Set defaults inherited by SSH connections inside this folder.
              </DialogDescription>
            </DialogHeader>
            <form className="grid gap-4" onSubmit={submitFolderDetails}>
              <div className="grid gap-2">
                <Label htmlFor="folder-details-name">Folder name</Label>
                <Input
                  autoFocus
                  id="folder-details-name"
                  onChange={(event) =>
                    setFolderDetailsForm((form) => ({ ...form, name: event.target.value }))
                  }
                  required
                  value={folderDetailsForm.name}
                />
              </div>
              <AutoSudoField
                id="folder-auto-sudo"
                mode={folderDetailsForm.sshAutoSudo}
                onChange={(sshAutoSudo) =>
                  setFolderDetailsForm((form) => ({ ...form, sshAutoSudo }))
                }
                scope="folder"
              />
              <TunnelRouteField
                id="folder-tunnel-route"
                mode={folderDetailsForm.tunnel}
                onChange={(tunnel) => setFolderDetailsForm((form) => ({ ...form, tunnel }))}
                scope="folder"
                tunnels={tunnels}
              />
              {editorError ? <p className="text-[11px] text-destructive">{editorError}</p> : null}
              <DialogFooter>
                <Button
                  disabled={editorBusy}
                  onClick={() => setFolderDetailsOpen(false)}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button disabled={editorBusy} type="submit">
                  <Check data-icon="inline-start" />
                  {editorBusy ? 'Saving…' : 'Save changes'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            setRdpCredentialPrompt(open ? rdpCredentialPrompt : null);
          }}
          open={rdpCredentialPrompt !== null}
        >
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
            <DialogHeader>
              <DialogTitle>RDP credentials</DialogTitle>
              <DialogDescription>
                Credentials stay in memory for this app session and are passed directly to the
                native RDP provider.
              </DialogDescription>
            </DialogHeader>
            <form className="grid gap-4" onSubmit={submitRdpCredentials}>
              <div className="grid gap-2">
                <Label htmlFor="rdp-username">Username</Label>
                <Input
                  autoFocus
                  id="rdp-username"
                  onChange={(event) =>
                    setRdpCredentialForm((form) => ({ ...form, username: event.target.value }))
                  }
                  placeholder="user or DOMAIN\\user"
                  required
                  value={rdpCredentialForm.username}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="rdp-domain">Domain</Label>
                <Input
                  id="rdp-domain"
                  onChange={(event) =>
                    setRdpCredentialForm((form) => ({ ...form, domain: event.target.value }))
                  }
                  placeholder="Optional"
                  value={rdpCredentialForm.domain}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="rdp-password">Password</Label>
                <Input
                  id="rdp-password"
                  onChange={(event) =>
                    setRdpCredentialForm((form) => ({ ...form, password: event.target.value }))
                  }
                  type="password"
                  value={rdpCredentialForm.password}
                />
              </div>
              <DialogFooter>
                <Button onClick={() => setRdpCredentialPrompt(null)} type="button" variant="ghost">
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

const terminalFontSize = 13;
const terminalFontFamily = '"Cascadia Mono", "Consolas", monospace';
const terminalFallbackCellWidth = 8;
const terminalLineHeight = 18;
const terminalMaxScrollbackLines = 5000;
const terminalScrollbackChunkSize = 128;
const terminalDefaultForeground = 0xff80;
const terminalDefaultBackground = 0xff81;
const terminalAnsiPalette = [
  '#1d2021',
  '#cc241d',
  '#98971a',
  '#d79921',
  '#458588',
  '#b16286',
  '#689d6a',
  '#a89984',
  '#928374',
  '#fb4934',
  '#b8bb26',
  '#fabd2f',
  '#83a598',
  '#d3869b',
  '#8ec07c',
  '#ebdbb2',
];

function terminalColor(value: number, fallback: string): string {
  if (value === terminalDefaultForeground || value === terminalDefaultBackground) return fallback;
  if (value < 16) return terminalAnsiPalette[value] ?? fallback;
  if (value < 232) {
    const color = value - 16;
    const red = Math.floor(color / 36);
    const green = Math.floor((color % 36) / 6);
    const blue = color % 6;
    const channel = (component: number) => (component === 0 ? 0 : 55 + component * 40);
    return `rgb(${channel(red)} ${channel(green)} ${channel(blue)})`;
  }
  if (value < 256) {
    const gray = 8 + (value - 232) * 10;
    return `rgb(${gray} ${gray} ${gray})`;
  }
  return fallback;
}

function measureTerminalCellWidth(): number {
  if (typeof document === 'undefined') return terminalFallbackCellWidth;
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d');
  if (!context) return terminalFallbackCellWidth;
  context.font = `${terminalFontSize}px ${terminalFontFamily}`;
  const width = context.measureText('0').width;
  return Number.isFinite(width) && width > 0 ? width : terminalFallbackCellWidth;
}

function terminalWheelDelta(
  surface: HTMLElement,
  value: number,
  deltaMode: number,
  axis: 'x' | 'y',
): number {
  if (deltaMode === 1)
    return value * (axis === 'y' ? terminalLineHeight : terminalFallbackCellWidth);
  if (deltaMode === 2) return value * (axis === 'y' ? surface.clientHeight : surface.clientWidth);
  return value;
}

function terminalIsAtBottom(surface: HTMLElement): boolean {
  return surface.scrollHeight - surface.scrollTop - surface.clientHeight <= terminalLineHeight;
}

type TerminalTextRun = {
  text: string;
  foreground: string;
  background: string;
  cursor: boolean;
  cellCount: number;
};

function terminalTextRuns(frame: WormholeSshTerminalFrame, row: number): TerminalTextRun[] {
  const runs: TerminalTextRun[] = [];
  const offset = row * frame.columns;
  for (let column = 0; column < frame.columns; column++) {
    const cell = frame.cells?.[offset + column];
    if (!cell) continue;
    const cursor = frame.cursorVisible && frame.cursorX === column && frame.cursorY === row;
    const foreground = cursor
      ? terminalColor(cell.background, '#090909')
      : terminalColor(cell.foreground, '#e5e7eb');
    const background = cursor ? '#e5e7eb' : terminalColor(cell.background, '#090909');
    const previous = runs[runs.length - 1];
    if (
      previous &&
      previous.foreground === foreground &&
      previous.background === background &&
      previous.cursor === cursor
    ) {
      previous.text += cell.character || ' ';
      previous.cellCount += 1;
    } else {
      runs.push({ text: cell.character || ' ', foreground, background, cursor, cellCount: 1 });
    }
  }
  return runs;
}

const TerminalScrollback = memo(function TerminalScrollback({
  lines,
}: {
  lines?: WormholeSshTerminalScrollbackLine[];
}) {
  if (!lines?.length) return null;

  const chunks = [];
  for (let start = 0; start < lines.length; start += terminalScrollbackChunkSize) {
    const chunk = lines.slice(start, start + terminalScrollbackChunkSize);
    chunks.push(
      <div
        className="terminal-scrollback-chunk"
        key={start}
        style={{ height: `${chunk.length * terminalLineHeight}px` }}
      >
        {chunk.map((line, index) => {
          const runs = line.runs.length
            ? line.runs
            : [
                {
                  text: ' ',
                  cells: 1,
                  foreground: terminalDefaultForeground,
                  background: terminalDefaultBackground,
                },
              ];
          return (
            <div className="flex h-[18px] min-w-max whitespace-pre" key={start + index}>
              {runs.map((run, runIndex) => (
                <span
                  className="block flex-none overflow-hidden"
                  key={`${start + index}-${runIndex}`}
                  style={{
                    backgroundColor: terminalColor(run.background, '#090909'),
                    color: terminalColor(run.foreground, '#e5e7eb'),
                    height: `${terminalLineHeight}px`,
                    width: `${run.cells}ch`,
                  }}
                >
                  {run.text}
                </span>
              ))}
            </div>
          );
        })}
      </div>,
    );
  }

  return (
    <div aria-label="SSH terminal scrollback" className="terminal-scrollback">
      {chunks}
    </div>
  );
});

const TerminalTextGrid = memo(function TerminalTextGrid({
  frame,
}: {
  frame?: WormholeSshTerminalFrame;
}) {
  if (!frame?.cells) return null;
  return (
    <div
      className="min-h-full min-w-max select-text"
      style={{
        fontFamily: terminalFontFamily,
        fontSize: `${terminalFontSize}px`,
        fontSynthesis: 'none',
        lineHeight: `${terminalLineHeight}px`,
        textRendering: 'geometricPrecision',
        fontVariantLigatures: 'none',
      }}
    >
      <TerminalScrollback lines={frame.scrollback} />
      {Array.from({ length: frame.rows }, (_, row) => (
        <div className="flex h-[18px] min-w-max whitespace-pre" key={row}>
          {terminalTextRuns(frame, row).map((run, index) => (
            <span
              className={`block flex-none overflow-hidden ${run.cursor ? 'terminal-cursor' : ''}`}
              key={`${row}-${index}`}
              style={{
                backgroundColor: run.background,
                color: run.foreground,
                height: `${terminalLineHeight}px`,
                width: `${run.cellCount}ch`,
              }}
            >
              {run.text}
            </span>
          ))}
        </div>
      ))}
    </div>
  );
});

function terminalCsiWithModifier(final: string, event: React.KeyboardEvent, appCursor: boolean) {
  const modifier = 1 + (event.shiftKey ? 1 : 0) + (event.altKey ? 2 : 0) + (event.ctrlKey ? 4 : 0);
  if (modifier === 1 && appCursor) return `\u001bO${final}`;
  if (modifier === 1) return `\u001b[${final}`;
  return `\u001b[1;${modifier}${final}`;
}

function terminalKeyData(event: React.KeyboardEvent, appCursor: boolean): string | undefined {
  if (event.nativeEvent.isComposing || event.metaKey) return undefined;
  const key = event.key;
  if (event.ctrlKey && !event.altKey) {
    if (key === ' ') return '\u0000';
    if (key.length === 1) {
      const code = key.toUpperCase().charCodeAt(0);
      if (code >= 65 && code <= 90) return String.fromCharCode(code - 64);
      return (
        {
          '@': '\u0000',
          '[': '\u001b',
          '\\': '\u001c',
          ']': '\u001d',
          '^': '\u001e',
          _: '\u001f',
        } as Record<string, string>
      )[key];
    }
  }

  if (key === 'Enter') return '\r';
  if (key === 'Backspace') return '\u007f';
  if (key === 'Tab') return event.shiftKey ? '\u001b[Z' : '\t';
  if (key === 'Escape') return '\u001b';
  if (key === 'ArrowUp') return terminalCsiWithModifier('A', event, appCursor);
  if (key === 'ArrowDown') return terminalCsiWithModifier('B', event, appCursor);
  if (key === 'ArrowRight') return terminalCsiWithModifier('C', event, appCursor);
  if (key === 'ArrowLeft') return terminalCsiWithModifier('D', event, appCursor);
  if (key === 'Home') return terminalCsiWithModifier('H', event, appCursor);
  if (key === 'End') return terminalCsiWithModifier('F', event, appCursor);
  if (key === 'Insert') return '\u001b[2~';
  if (key === 'Delete') return '\u001b[3~';
  if (key === 'PageUp') return '\u001b[5~';
  if (key === 'PageDown') return '\u001b[6~';
  if (key === 'F1') return '\u001bOP';
  if (key === 'F2') return '\u001bOQ';
  if (key === 'F3') return '\u001bOR';
  if (key === 'F4') return '\u001bOS';
  if (key === 'F5') return '\u001b[15~';
  if (key === 'F6') return '\u001b[17~';
  if (key === 'F7') return '\u001b[18~';
  if (key === 'F8') return '\u001b[19~';
  if (key === 'F9') return '\u001b[20~';
  if (key === 'F10') return '\u001b[21~';
  if (key === 'F11') return '\u001b[23~';
  if (key === 'F12') return '\u001b[24~';
  if (key.length === 1) return event.altKey ? `\u001b${key}` : key;
  return undefined;
}

function SshTerminalSurface({
  session,
  isActive,
  onInput,
  onReconnect,
  onTrustHostKey,
  isSerial = false,
}: {
  session: Session;
  isActive: boolean;
  onInput: (sessionId: string, value: string) => void;
  onReconnect: (sessionId: string) => void;
  onTrustHostKey?: (sessionId: string, mismatch: NonNullable<Session['hostKeyMismatch']>) => void;
  isSerial?: boolean;
}) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const resizeSignatureRef = useRef('');
  const stickToBottomRef = useRef(true);

  useEffect(() => {
    const surface = surfaceRef.current;
    const backendSessionId = session.backendSessionId;
    if (
      !isActive ||
      !surface ||
      !backendSessionId ||
      session.status !== 'connected' ||
      typeof ResizeObserver === 'undefined'
    )
      return;

    resizeSignatureRef.current = '';
    let retryFrame: number | undefined;
    const resize = () => {
      const cellWidth = measureTerminalCellWidth();
      if (surface.clientWidth < cellWidth || surface.clientHeight < terminalLineHeight) {
        if (retryFrame === undefined) {
          retryFrame = requestAnimationFrame(() => {
            retryFrame = undefined;
            resize();
          });
        }
        return;
      }
      const columns = Math.max(1, Math.floor(surface.clientWidth / cellWidth));
      const rows = Math.max(1, Math.floor(surface.clientHeight / terminalLineHeight));
      const signature = `${columns}x${rows}`;
      if (signature === resizeSignatureRef.current) return;
      resizeSignatureRef.current = signature;
      const resizeRequest = isSerial
        ? window.wormhole?.resizeSerialSession(backendSessionId, columns, rows)
        : window.wormhole?.resizeSshSession(backendSessionId, columns, rows);
      void resizeRequest?.catch(() => {
        // A resize can race with a close; the closed event owns the visible session state.
      });
    };
    const observer = new ResizeObserver(resize);
    observer.observe(surface);
    resize();
    return () => {
      observer.disconnect();
      if (retryFrame !== undefined) cancelAnimationFrame(retryFrame);
    };
  }, [isActive, isSerial, session.backendSessionId, session.status]);

  useEffect(() => {
    stickToBottomRef.current = true;
  }, [session.backendSessionId, session.status]);

  useEffect(() => {
    if (!isActive || session.status !== 'connected') return;
    const surface = surfaceRef.current;
    if (!surface) return;
    if (session.terminalFrame?.viewportReset) stickToBottomRef.current = true;
    if (!stickToBottomRef.current) return;
    surface.scrollTop = surface.scrollHeight;
  }, [
    isActive,
    session.backendSessionId,
    session.status,
    session.terminalFrame?.viewportReset,
    session.terminalFrame?.sequence,
  ]);

  useEffect(() => {
    if (!isActive || session.status !== 'connected') return;
    const surface = surfaceRef.current;
    if (!surface) return;

    const handleWheel = (event: WheelEvent) => {
      const maxScrollTop = Math.max(0, surface.scrollHeight - surface.clientHeight);
      const maxScrollLeft = Math.max(0, surface.scrollWidth - surface.clientWidth);
      const rawDeltaX = terminalWheelDelta(surface, event.deltaX, event.deltaMode, 'x');
      const rawDeltaY = terminalWheelDelta(surface, event.deltaY, event.deltaMode, 'y');
      const deltaX = Number.isFinite(rawDeltaX) ? rawDeltaX : 0;
      const deltaY = Number.isFinite(rawDeltaY) ? rawDeltaY : 0;
      if ((maxScrollTop <= 0 && maxScrollLeft <= 0) || (deltaX === 0 && deltaY === 0)) return;

      const nextScrollLeft = Math.min(maxScrollLeft, Math.max(0, surface.scrollLeft + deltaX));
      const nextScrollTop = Math.min(maxScrollTop, Math.max(0, surface.scrollTop + deltaY));

      // Keep the terminal as the scroll owner. This is deliberately a native,
      // non-passive listener because Chromium can make delegated React wheel
      // listeners passive, which lets the surrounding layout consume the wheel.
      event.preventDefault();
      event.stopPropagation();

      surface.scrollLeft = nextScrollLeft;
      surface.scrollTop = nextScrollTop;
      stickToBottomRef.current = terminalIsAtBottom(surface);
    };

    surface.addEventListener('wheel', handleWheel, { passive: false });
    return () => surface.removeEventListener('wheel', handleWheel);
  }, [isActive, session.status]);

  useEffect(() => {
    if (!isActive || session.status !== 'connected') return;
    const surface = surfaceRef.current;
    if (!surface) return;
    const focus = () => surface.focus({ preventScroll: true });
    const frame = requestAnimationFrame(focus);
    return () => cancelAnimationFrame(frame);
  }, [isActive, session.backendSessionId, session.status]);

  const isConnected = session.status === 'connected';
  if (!isConnected) {
    const isConnecting = session.status === 'connecting';
    const isFailed = session.status === 'failed';
    const hostKeyMismatch = !isSerial && isFailed ? session.hostKeyMismatch : undefined;
    const showTunnelStepper = isConnecting && !isSerial && Boolean(session.tunnelProgress);
    const title = isConnecting
      ? isSerial
        ? 'Opening serial port'
        : 'Connecting to SSH'
      : isFailed
        ? isSerial
          ? 'Serial connection failed'
          : 'SSH connection failed'
        : isSerial
          ? 'Serial session closed'
          : 'SSH session closed';
    const message = hostKeyMismatch
      ? 'The server identity changed. Verify the new fingerprint before trusting it.'
      : session.error ||
        (isConnecting
          ? isSerial
            ? 'Opening the local serial line.'
            : 'Opening a secure shell session.'
          : isSerial
            ? 'The serial port closed the session.'
            : 'The remote host closed the connection.');

    return (
      <div
        aria-label={isSerial ? 'Serial connection state' : 'SSH connection state'}
        className="flex h-full min-h-0 min-w-0 flex-1 items-center justify-center overflow-auto bg-[#090909] px-6 py-10 text-zinc-100"
        ref={surfaceRef}
      >
        {showTunnelStepper ? (
          <ConnectionStepper tunnelProgress={session.tunnelProgress} />
        ) : (
          <div className="flex w-full max-w-2xl flex-col items-center text-center">
            <div
              className={`mb-5 grid size-14 place-items-center rounded-full border ${
                isFailed
                  ? 'border-red-400/20 bg-red-400/10 text-red-300'
                  : 'border-white/10 bg-white/[0.06] text-zinc-300'
              }`}
            >
              {isConnecting ? (
                <LoaderCircle className="size-6 animate-spin" />
              ) : isFailed ? (
                <AlertCircle className="size-6" />
              ) : (
                <Terminal className="size-6" />
              )}
            </div>
            <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-zinc-500">
              {isSerial ? 'Serial terminal' : 'Secure shell'}
            </p>
            <h3 className="mt-2 text-sm font-semibold text-zinc-100">{title}</h3>
            <p className="mt-2 max-w-xl break-words text-sm leading-relaxed text-zinc-400">
              {message}
            </p>
            <p className="mt-3 max-w-xl truncate font-mono text-[10px] text-zinc-600">
              {session.host || 'inherited target'}
            </p>
            {hostKeyMismatch ? (
              <div className="mt-5 w-full max-w-xl rounded-lg border border-amber-400/20 bg-amber-400/[0.06] p-4 text-left">
                <p className="text-xs font-semibold text-amber-200">Host key changed</p>
                <p className="mt-1 text-[11px] leading-relaxed text-amber-100/65">
                  Only trust this key if you verified the server was rebuilt, rekeyed, or moved to a
                  new host.
                </p>
                <div className="mt-3 grid gap-2 font-mono text-[10px]">
                  <div className="grid gap-1 sm:grid-cols-[5rem_minmax(0,1fr)] sm:items-start sm:gap-3">
                    <span className="text-zinc-500">Saved</span>
                    <code className="break-all text-zinc-300">{hostKeyMismatch.expected}</code>
                  </div>
                  <div className="grid gap-1 sm:grid-cols-[5rem_minmax(0,1fr)] sm:items-start sm:gap-3">
                    <span className="text-amber-300/70">Presented</span>
                    <code className="break-all text-amber-100">{hostKeyMismatch.received}</code>
                  </div>
                </div>
                <div className="mt-4 flex justify-end">
                  <Button
                    onClick={() => onTrustHostKey?.(session.id, hostKeyMismatch)}
                    size="sm"
                    variant="secondary"
                  >
                    <RefreshCcw data-icon="inline-start" />
                    Trust new key & reconnect
                  </Button>
                </div>
              </div>
            ) : isConnecting ? (
              <div className="mt-6 flex items-center gap-2 text-[10px] text-zinc-500">
                <span className="size-1.5 animate-pulse rounded-full bg-amber-400" />
                {isSerial ? 'Opening local serial line' : 'Negotiating secure session'}
              </div>
            ) : (
              <Button
                className="mt-6"
                onClick={() => onReconnect(session.id)}
                size="sm"
                variant="secondary"
              >
                <RefreshCcw data-icon="inline-start" />
                Reconnect
              </Button>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <div
      aria-label={isSerial ? 'Live serial terminal' : 'Live SSH terminal'}
      className="terminal-scrollbar h-full min-h-0 min-w-0 flex-1 cursor-text overflow-x-auto overflow-y-auto overscroll-contain bg-[#090909] text-[#e5e7eb] outline-none"
      onClick={(event) => event.currentTarget.focus({ preventScroll: true })}
      onKeyDown={(event) => {
        const data = terminalKeyData(event, session.terminalFrame?.applicationCursor ?? false);
        if (data === undefined) return;
        event.preventDefault();
        onInput(session.id, data);
      }}
      onPaste={(event) => {
        const text = event.clipboardData.getData('text');
        if (!text) return;
        event.preventDefault();
        onInput(session.id, text);
      }}
      onCompositionEnd={(event) => {
        if (event.data) onInput(session.id, event.data);
      }}
      onScroll={(event) => {
        const surface = event.currentTarget;
        stickToBottomRef.current = terminalIsAtBottom(surface);
      }}
      ref={surfaceRef}
      role="application"
      style={{ overflowAnchor: 'none', scrollbarGutter: 'stable' }}
      tabIndex={0}
    >
      <TerminalTextGrid frame={session.terminalFrame} />
    </div>
  );
}

type SftpPaneKind = 'local' | 'remote';
type SftpOperation = 'mkdir' | 'file' | 'delete' | 'rename' | 'open';
type SftpTransferDirection = 'local-to-remote' | 'remote-to-local' | 'local-to-local';
type SftpTransferItem = {
  sourcePath: string;
  name: string;
  isDirectory: boolean;
  size: number;
};
type SftpDragPayload = {
  sourcePane: SftpPaneKind;
  items: SftpTransferItem[];
  external: boolean;
};

function clearSftpCancelRequestsForTransfer(requests: Set<string>, transferId: string) {
  const prefix = `${transferId}\u0000`;
  for (const request of requests) {
    if (request.startsWith(prefix)) requests.delete(request);
  }
}

function clearSftpCancelRequestsForBrowser(
  requests: Set<string>,
  browser: Pick<SftpBrowserState, 'knownTransferIds'> | undefined,
) {
  for (const transferId of Object.keys(browser?.knownTransferIds ?? {})) {
    clearSftpCancelRequestsForTransfer(requests, transferId);
  }
}

function isSftpPaneRoot(pane: SftpPaneKind, path: string): boolean {
  if (pane === 'remote') return !path || path === '/';
  const normalized = path.replaceAll('/', '\\').replace(/[\\]+$/, '');
  return (
    !path ||
    /^[A-Za-z]:$/.test(normalized) ||
    /^\\\\[^\\]+\\[^\\]+$/.test(normalized) ||
    parentLocalSftpPath(path) === path
  );
}

function joinSftpPanePath(pane: SftpPaneKind, parent: string, name: string): string {
  if (pane === 'remote') return parent === '/' ? `/${name}` : `${parent}/${name}`;
  const separator = parent.includes('\\') ? '\\' : '/';
  return parent.endsWith('\\') || parent.endsWith('/')
    ? `${parent}${name}`
    : `${parent}${separator}${name}`;
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
  const items = Array.from(data.files)
    .map((file) => {
      const candidate = file as File & { path?: string };
      const transferItem = Array.from(data.items).find(
        (item) => item.getAsFile()?.name === file.name,
      ) as
        | (DataTransferItem & {
            webkitGetAsEntry?: () => { isDirectory?: boolean } | null;
          })
        | undefined;
      const fileSystemEntry = transferItem?.webkitGetAsEntry?.();
      return {
        sourcePath: candidate.path || file.name,
        name: file.name,
        isDirectory: fileSystemEntry?.isDirectory === true,
        size: file.size,
      } satisfies SftpTransferItem;
    })
    .filter((item) => item.sourcePath.length > 0);
  return items.length > 0 ? { sourcePane: 'local', items, external: true } : undefined;
}

function normalizeLocalDropPath(value: string): string {
  const normalized = value.replaceAll('/', '\\');
  if (/^[A-Za-z]:\\$/.test(normalized)) return normalized;
  return normalized.replace(/[\\]+$/, '');
}

function localDropPathContains(parent: string, candidate: string): boolean {
  const normalizedParent = normalizeLocalDropPath(parent).toLowerCase();
  const normalizedCandidate = normalizeLocalDropPath(candidate).toLowerCase();
  if (normalizedParent === normalizedCandidate) return true;
  const prefix = normalizedParent.endsWith('\\') ? normalizedParent : `${normalizedParent}\\`;
  return normalizedCandidate.startsWith(prefix);
}

function isInvalidLocalDropDestination(destination: string, items: SftpTransferItem[]): boolean {
  if (!/^(?:[A-Za-z]:[\\/]|\\\\)/.test(destination)) return false;
  for (const item of items) {
    if (!/^(?:[A-Za-z]:[\\/]|\\\\)/.test(item.sourcePath)) continue;
    const target = joinSftpPanePath('local', destination, item.name);
    if (localDropPathContains(item.sourcePath, target)) return true;
    if (item.isDirectory && localDropPathContains(item.sourcePath, destination)) return true;
  }
  return false;
}

function isValidSftpNameInput(name: string): boolean {
  return (
    name.length > 0 &&
    name !== '.' &&
    name !== '..' &&
    !name.includes('/') &&
    !name.includes('\\') &&
    !name.includes(':') &&
    !name.includes(String.fromCharCode(0))
  );
}

function SftpFilePane({
  pane,
  state,
  onNavigate,
  onRefresh,
  onOperation,
  onTransfer,
}: {
  pane: SftpPaneKind;
  state: SftpPaneState;
  onNavigate: (path: string) => void;
  onRefresh: () => void;
  onOperation: (operation: SftpOperation, path: string, destinationPath?: string) => void;
  onTransfer: (payload: SftpDragPayload, destinationPath: string) => void;
}) {
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
  const [pathDraft, setPathDraft] = useState(state.path);
  const [listViewport, setListViewport] = useState({ height: 0, scrollTop: 0 });
  const renameCommitPath = useRef<string | undefined>(undefined);
  const selectionAnchorPath = useRef<string | undefined>(undefined);
  const listViewportRef = useRef<HTMLDivElement>(null);
  const listViewportStateRef = useRef(listViewport);

  const syncListViewport = useCallback((height: number, scrollTop: number) => {
    const next = { height, scrollTop: sftpVirtualScrollAnchor(scrollTop) };
    const current = listViewportStateRef.current;
    if (current.height === next.height && current.scrollTop === next.scrollTop) return;
    listViewportStateRef.current = next;
    setListViewport(next);
  }, []);

  useEffect(() => {
    setSelectedPaths((current) => {
      const available = new Set(state.entries.map((entry) => entry.fullPath));
      return pruneSftpSelection(current, available);
    });
    setPathDraft(state.path);
  }, [state.entries, state.path]);

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

  useEffect(() => {
    setSelectedPaths((current) =>
      pruneSftpSelection(current, new Set(visibleEntries.map((entry) => entry.fullPath))),
    );
  }, [visibleEntries]);

  useEffect(() => {
    const viewport = listViewportRef.current;
    if (!viewport) return;
    viewport.scrollTop = 0;
    syncListViewport(viewport.clientHeight, 0);
  }, [normalizedSearch, state.path, syncListViewport]);

  const selectedEntries = useMemo(
    () => visibleEntries.filter((entry) => selectedPaths.has(entry.fullPath)),
    [selectedPaths, visibleEntries],
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
    setSelectedPaths((current) => {
      const next = new Set(current);
      if (event.shiftKey && selectedEntries.length > 0) {
        const anchorPath = selectionAnchorPath.current ?? selectedEntries[0].fullPath;
        const anchor = visibleEntries.findIndex((candidate) => candidate.fullPath === anchorPath);
        const target = visibleEntries.findIndex(
          (candidate) => candidate.fullPath === entry.fullPath,
        );
        if (anchor >= 0 && target >= 0) {
          const [from, to] = anchor < target ? [anchor, target] : [target, anchor];
          for (const candidate of visibleEntries.slice(from, to + 1)) next.add(candidate.fullPath);
          return next;
        }
      }
      if (event.ctrlKey || event.metaKey) {
        if (next.has(entry.fullPath)) next.delete(entry.fullPath);
        else next.add(entry.fullPath);
      } else {
        next.clear();
        next.add(entry.fullPath);
      }
      if (!event.shiftKey) selectionAnchorPath.current = entry.fullPath;
      return next;
    });
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
      const anchorPath = selectionAnchorPath.current ?? entry.fullPath;
      const anchorIndex = visibleEntries.findIndex(
        (candidate) => candidate.fullPath === anchorPath,
      );
      if (anchorIndex >= 0) {
        const [from, to] =
          anchorIndex < targetIndex ? [anchorIndex, targetIndex] : [targetIndex, anchorIndex];
        setSelectedPaths(
          new Set(visibleEntries.slice(from, to + 1).map((candidate) => candidate.fullPath)),
        );
      }
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
    if (!isValidSftpNameInput(name)) {
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
    if (!prompt || !isValidSftpNameInput(name)) return;
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
      className={`relative flex min-h-0 min-w-0 flex-1 flex-col gap-2 overflow-hidden ${
        dropPath === state.path ? 'rounded-md bg-primary/5 ring-1 ring-primary/70' : ''
      }`}
      onDragLeave={() => setDropPath(undefined)}
      onDragOver={(event) => setDragState(event)}
      onKeyDown={(event) => {
        if (
          event.target instanceof HTMLInputElement ||
          event.target instanceof HTMLTextAreaElement
        ) {
          return;
        }
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'a') {
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
      tabIndex={-1}
    >
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
          onChange={(event) => setPathDraft(event.target.value)}
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
              {state.quickPaths.map((quickPath, index) =>
                quickPath.isSeparator ? (
                  <DropdownMenuSeparator key={`separator-${index}`} />
                ) : (
                  <DropdownMenuItem
                    key={`${quickPath.path}:${index}`}
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
        <IconButton disabled={busy} label="Refresh" onClick={onRefresh}>
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

      <div
        className="min-h-0 flex-1 overflow-auto rounded-sm border border-border"
        onDragOver={(event) => setDragState(event)}
        onDrop={(event) => handleDrop(event)}
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
                  willChange: 'transform',
                }}
              >
                {visibleEntries.slice(visibleRange.start, visibleRange.end).map((entry, offset) => {
                  const entryIndex = visibleRange.start + offset;
                  const selected = selectedPaths.has(entry.fullPath);
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
                          onDragEnd={() => setDropPath(undefined)}
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
                        <ContextMenuItem onSelect={() => beginRename(entry)}>
                          <Pencil />
                          Rename
                        </ContextMenuItem>
                        <ContextMenuSeparator />
                        <ContextMenuItem
                          onSelect={() => {
                            if (!selectedPaths.has(entry.fullPath)) {
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
  useEffect(() => setApplyToAll(false), [conflict.itemId, conflict.transferId]);
  return (
    <div
      className="absolute inset-0 z-40 grid place-items-center bg-background/80 p-6 backdrop-blur-sm"
      onKeyDown={(event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          onDecision('skip', applyToAll);
        } else if (event.key === 'Escape') {
          event.preventDefault();
          onCancel();
        }
      }}
      tabIndex={-1}
    >
      <div className="w-full max-w-md rounded-xl border border-border bg-card p-5 shadow-2xl">
        <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-muted-foreground">
          File exists
        </p>
        <h3 className="mt-2 text-base font-semibold">Replace or skip this item?</h3>
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
    </div>
  );
}

function SftpBrowserSurface({
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
  session: Session;
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

  function handleDrop(targetPane: SftpPaneKind, targetPath: string, payload: SftpDragPayload) {
    if (payload.sourcePane === targetPane && !payload.external) return;
    if (
      targetPane === 'local' &&
      payload.sourcePane === 'local' &&
      isInvalidLocalDropDestination(targetPath, payload.items)
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

  return (
    <div
      aria-label="SFTP browser"
      className="relative flex h-full min-h-0 flex-col gap-3 overflow-hidden bg-background"
    >
      <div className="flex shrink-0 items-center gap-2">
        <ArrowRightLeft className="size-4 shrink-0 text-primary" />
        <DialogTitle className="truncate text-sm font-semibold">{session.title}</DialogTitle>
        <DialogDescription className="truncate text-xs text-muted-foreground">
          {session.host || 'SSH'}
        </DialogDescription>
      </div>

      {closing ? (
        <div className="absolute inset-0 z-30 grid place-items-center bg-background/80 text-sm text-muted-foreground backdrop-blur-sm">
          <LoaderCircle className="mr-2 size-4 animate-spin" />
          Closing SFTP browser…
        </div>
      ) : null}

      <div className="grid min-h-0 flex-1 grid-cols-2 gap-4 overflow-hidden">
        <SftpFilePane
          onNavigate={onLocalNavigate}
          onOperation={(operation, path, destinationPath) =>
            onOperation('local', operation, path, destinationPath)
          }
          onRefresh={() => onRefresh('local')}
          onTransfer={(payload, destinationPath) => handleDrop('local', destinationPath, payload)}
          pane="local"
          state={local}
        />
        <SftpFilePane
          onNavigate={onNavigate}
          onOperation={(operation, path, destinationPath) =>
            onOperation('remote', operation, path, destinationPath)
          }
          onRefresh={() => onRefresh('remote')}
          onTransfer={(payload, destinationPath) => handleDrop('remote', destinationPath, payload)}
          pane="remote"
          state={remote}
        />
      </div>

      {(browser.transfers?.length ?? 0) > 0 || browser.transferError ? (
        <SftpTransferQueue
          error={browser.transferError}
          onCancel={onTransferCancel}
          onClearError={onTransferErrorClear}
          onRemove={onTransferRemove}
          transfers={browser.transfers ?? []}
        />
      ) : null}

      <div className="flex shrink-0 justify-end">
        <Button disabled={closing} onClick={onClose} size="sm">
          Close
        </Button>
      </div>

      {browser.conflict ? (
        <SftpConflictOverlay
          conflict={browser.conflict}
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

function SessionsPage({
  isAuthorized,
  isWebSurfaceVisible,
  sessions,
  selectedSession,
  onCloseSession,
  onConnectRdp,
  onDuplicateSession,
  onCloseSftpBrowser,
  onOpenFileTransfer,
  onSelectSession,
  onOpenQuickConnect,
  onReconnectSession,
  onSftpLocalNavigate,
  onSftpOperation,
  onSftpTransfer,
  onSftpConflict,
  onSftpTransferCancel,
  onSftpTransferErrorClear,
  onSftpTransferRemove,
  onSftpNavigate,
  onSftpRefresh,
  onSshInput,
  onSerialInput,
  onTrustSshHostKey,
  onRetryRdp,
}: {
  isAuthorized: boolean;
  isWebSurfaceVisible: boolean;
  sessions: Session[];
  selectedSession?: Session;
  onCloseSession: (id: string) => void;
  onConnectRdp: (id: string) => void;
  onDuplicateSession: (id: string) => void;
  onCloseSftpBrowser: (id: string) => void;
  onOpenFileTransfer: (id: string) => void;
  onSelectSession: (id: string) => void;
  onOpenQuickConnect: () => void;
  onReconnectSession: (id: string) => void;
  onSftpLocalNavigate: (sessionId: string, path: string) => void;
  onSftpOperation: (
    sessionId: string,
    pane: SftpPaneKind,
    operation: SftpOperation,
    path: string,
    destinationPath?: string,
  ) => void;
  onSftpTransfer: (
    sessionId: string,
    direction: SftpTransferDirection,
    destinationPath: string,
    items: SftpTransferItem[],
  ) => void;
  onSftpConflict: (
    sessionId: string,
    transferId: string,
    itemId: string,
    decision: 'overwrite' | 'skip',
    applyToAll: boolean,
  ) => void;
  onSftpTransferCancel: (sessionId: string, transferId: string, itemId: string) => void;
  onSftpTransferErrorClear: (sessionId: string) => void;
  onSftpTransferRemove: (sessionId: string, transferId: string, itemId: string) => void;
  onSftpNavigate: (sessionId: string, path: string) => void;
  onSftpRefresh: (id: string) => void;
  onSshInput: (sessionId: string, value: string) => void;
  onSerialInput: (sessionId: string, value: string) => void;
  onTrustSshHostKey: (sessionId: string, mismatch: NonNullable<Session['hostKeyMismatch']>) => void;
  onRetryRdp: (id: string) => void;
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
    <section className="flex h-full min-h-0 min-w-0 flex-col">
      <Tabs
        className="flex h-full min-h-0 flex-1 flex-col gap-0"
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
                    <span className="min-w-0 flex-1 truncate !text-xs font-semibold">
                      {session.title}
                    </span>
                  </TabsTrigger>
                  <div className="absolute right-1.5 top-1/2 z-20 flex -translate-y-1/2 items-center gap-0.5 bg-transparent">
                    {session.canTransfer && session.status === 'connected' ? (
                      <IconButton
                        label={`Open SFTP browser for ${session.title}`}
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
        {sessions.map((session) => (
          <TabsContent
            className="flex h-full min-h-0 flex-1 flex-col"
            forceMount
            key={session.id}
            value={session.id}
          >
            {session.protocol === 'ssh' ? (
              <>
                <SshTerminalSurface
                  isActive={session.id === selectedSession.id}
                  onInput={onSshInput}
                  onReconnect={onReconnectSession}
                  onTrustHostKey={onTrustSshHostKey}
                  session={session}
                />
                {session.sftp && session.id === selectedSession.id ? (
                  <Dialog
                    onOpenChange={(open) => {
                      if (!open) onCloseSftpBrowser(session.id);
                    }}
                    open
                  >
                    <DialogContent
                      className="flex h-[88vh] max-h-[900px] min-h-[560px] w-[92vw] max-w-[1720px] flex-col overflow-hidden border-border/80 bg-background p-5 sm:max-w-none"
                      showCloseButton={false}
                    >
                      <SftpBrowserSurface
                        onClose={() => onCloseSftpBrowser(session.id)}
                        onConflict={(transferId, itemId, decision, applyToAll) =>
                          onSftpConflict(session.id, transferId, itemId, decision, applyToAll)
                        }
                        onLocalNavigate={(path) => onSftpLocalNavigate(session.id, path)}
                        onNavigate={(path) => onSftpNavigate(session.id, path)}
                        onOperation={(pane, operation, path, destinationPath) =>
                          onSftpOperation(session.id, pane, operation, path, destinationPath)
                        }
                        onRefresh={(pane) =>
                          pane === 'local'
                            ? onSftpLocalNavigate(session.id, session.sftp?.local?.path ?? '')
                            : onSftpRefresh(session.id)
                        }
                        onTransfer={(direction, destinationPath, items) =>
                          onSftpTransfer(session.id, direction, destinationPath, items)
                        }
                        onTransferCancel={(transferId, itemId) =>
                          onSftpTransferCancel(session.id, transferId, itemId)
                        }
                        onTransferErrorClear={() => onSftpTransferErrorClear(session.id)}
                        onTransferRemove={(transferId, itemId) =>
                          onSftpTransferRemove(session.id, transferId, itemId)
                        }
                        session={session}
                      />
                    </DialogContent>
                  </Dialog>
                ) : null}
              </>
            ) : session.protocol === 'serial' ? (
              <SshTerminalSurface
                isActive={session.id === selectedSession.id}
                isSerial
                onInput={onSerialInput}
                onReconnect={onReconnectSession}
                session={session}
              />
            ) : session.protocol === 'rdp' ? (
              <RdpSurface
                backend={session.rdpBackend}
                error={session.rdpError}
                isActive={session.id === selectedSession.id}
                isAuthorized={isAuthorized}
                onConnect={() => onConnectRdp(session.id)}
                onRetry={() => onRetryRdp(session.id)}
                sessionId={session.id}
                status={session.rdpStatus ?? 'idle'}
                tunnelProgress={session.tunnelProgress}
              />
            ) : session.protocol === 'vnc' ? (
              <VncSurface
                session={{
                  id: session.id,
                  nodeId: session.nodeId,
                  host: session.host,
                  port: session.port,
                  tunnelConfigId: session.tunnelConfigId,
                  tunnelProgress: session.tunnelProgress,
                }}
              />
            ) : session.protocol === 'http' || session.protocol === 'https' ? (
              <WebSurface
                isActive={session.id === selectedSession.id}
                isAuthorized={isAuthorized && isWebSurfaceVisible}
                onReconnect={onReconnectSession}
                session={session}
              />
            ) : (
              <div
                aria-label="Connection canvas"
                className="grid h-full place-items-center bg-background p-8 text-center"
              >
                <div>
                  <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">
                    {protocolLabel(session.protocol)}
                  </p>
                  <p className="mt-2 text-sm font-medium">Protocol surface ready for migration</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {session.host || 'inherited target'}:{session.port ?? 'default'}
                  </p>
                </div>
              </div>
            )}
          </TabsContent>
        ))}
      </Tabs>
    </section>
  );
}

function CredentialsPage({
  initialCredentials,
  onCreate,
  onUpdate,
  onDelete,
}: {
  initialCredentials: CredentialRecord[];
  onCreate: (draft: CredentialDraft) => Promise<void>;
  onUpdate: (id: string, draft: CredentialDraft) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}) {
  const [searchText, setSearchText] = useState('');
  const [selectedCredentials, setSelectedCredentials] = useState<string[]>([]);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingCredential, setEditingCredential] = useState<CredentialRecord | null>(null);
  const [credentialForm, setCredentialForm] = useState<CredentialDraft>(emptyCredentialDraft);
  const [pendingDeletion, setPendingDeletion] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [operationError, setOperationError] = useState('');

  useEffect(() => {
    setSelectedCredentials([]);
  }, [initialCredentials]);

  const credentials = initialCredentials;

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
  const deletableSelectedCredentials = selectedCredentials.filter((id) => {
    const credential = credentials.find((candidate) => candidate.id === id);
    return credential?.canDelete;
  });

  const deletingCredentials = pendingDeletion
    .map((id) => credentials.find((credential) => credential.id === id))
    .filter((credential): credential is CredentialRecord => Boolean(credential));

  function toggleCredential(id: string, checked: boolean) {
    setSelectedCredentials((current) =>
      checked ? [...new Set([...current, id])] : current.filter((selectedId) => selectedId !== id),
    );
  }

  function openNewCredential() {
    setEditingCredential(null);
    setCredentialForm(emptyCredentialDraft());
    setOperationError('');
    setEditorOpen(true);
  }

  function openEditCredential(credential: CredentialRecord) {
    if (!credential.canEdit) return;
    const protocol = credential.protocol as CredentialDraft['protocol'];
    setEditingCredential(credential);
    setCredentialForm({
      name: credential.name,
      protocol,
      username: credential.username === 'No username' ? '' : credential.username,
      domain: credential.domain ?? '',
      // The credential editor never reads saved secrets. Editing intentionally asks for a replacement.
      password: '',
    });
    setOperationError('');
    setEditorOpen(true);
  }

  function closeCredentialEditor() {
    setEditorOpen(false);
    setEditingCredential(null);
    setCredentialForm(emptyCredentialDraft());
    setOperationError('');
  }

  async function submitCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const draft: CredentialDraft = {
      name: credentialForm.name.trim(),
      protocol: credentialForm.protocol,
      username: credentialForm.protocol === 'vnc' ? '' : credentialForm.username.trim(),
      domain: credentialForm.protocol === 'rdp' ? credentialForm.domain.trim() : '',
      password: credentialForm.password,
    };
    if (!draft.name || !draft.password) {
      setOperationError('Enter a name and password.');
      return;
    }
    if (draft.protocol !== 'vnc' && !draft.username) {
      setOperationError('SSH and RDP credentials need a username.');
      return;
    }
    if (draft.protocol === 'rdp' && !draft.domain) {
      setOperationError('RDP credentials need a domain.');
      return;
    }
    setBusy(true);
    setOperationError('');
    try {
      if (editingCredential) {
        await onUpdate(editingCredential.id, draft);
      } else {
        await onCreate(draft);
      }
      closeCredentialEditor();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : 'Could not save the credential.');
    } finally {
      setBusy(false);
    }
  }

  async function deletePendingCredentials() {
    if (busy || pendingDeletion.length === 0) return;
    const ids = pendingDeletion.filter((id) => {
      const credential = credentials.find((candidate) => candidate.id === id);
      return credential?.canDelete;
    });
    if (ids.length === 0) {
      setPendingDeletion([]);
      return;
    }
    setBusy(true);
    setOperationError('');
    const failures: string[] = [];
    for (const id of ids) {
      try {
        await onDelete(id);
      } catch (error) {
        const name = credentials.find((credential) => credential.id === id)?.name ?? 'Credential';
        const message = error instanceof Error ? error.message : 'Could not delete the credential.';
        failures.push(`${name}: ${message}`);
      }
    }
    setSelectedCredentials([]);
    setPendingDeletion([]);
    setBusy(false);
    if (failures.length > 0) setOperationError(failures.join(' '));
  }

  return (
    <>
      <section className="flex h-full min-h-0 flex-col overflow-hidden px-6 py-5">
        <h2 className="shrink-0 text-xl font-semibold tracking-tight">Credentials</h2>

        <div className="mt-4 flex shrink-0 flex-wrap items-center gap-2">
          <Input
            aria-label="Search credentials"
            className="!text-xs min-w-60 max-w-xl flex-1"
            onChange={(event) => setSearchText(event.target.value)}
            placeholder="Search credentials"
            value={searchText}
          />
          <Button
            className="!text-xs"
            onClick={() =>
              setSelectedCredentials(
                allVisibleSelected ? [] : filteredCredentials.map((credential) => credential.id),
              )
            }
            size="default"
            variant="outline"
          >
            <Check data-icon="inline-start" />
            Select all
          </Button>
          <Button className="!text-xs" onClick={openNewCredential} size="default">
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
              <Button
                className="!text-xs"
                onClick={() => setSelectedCredentials([])}
                size="default"
                variant="ghost"
              >
                Clear
              </Button>
              <Button
                className="!text-xs"
                disabled={deletableSelectedCredentials.length === 0}
                onClick={() => setPendingDeletion(deletableSelectedCredentials)}
                size="default"
                variant="destructive"
              >
                <X data-icon="inline-start" />
                Delete selected
              </Button>
            </div>
          </div>
        ) : null}

        {operationError ? <p className="mt-3 text-xs text-destructive">{operationError}</p> : null}

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
                  <Card
                    className="min-h-44 transition-colors hover:bg-muted/50"
                    key={credential.id}
                  >
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
                        <IconButton
                          disabled={!credential.canEdit}
                          label={`Edit ${credential.name}`}
                          onClick={() => openEditCredential(credential)}
                        >
                          <Pencil />
                        </IconButton>
                        <IconButton
                          disabled={!credential.canDelete}
                          label={`Delete ${credential.name}`}
                          onClick={() => setPendingDeletion([credential.id])}
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

      <Dialog
        onOpenChange={(open) => {
          if (!busy) {
            if (open) setEditorOpen(true);
            else closeCredentialEditor();
          }
        }}
        open={editorOpen}
      >
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editingCredential ? 'Edit credential' : 'Add credential'}</DialogTitle>
            <DialogDescription>
              {editingCredential
                ? 'Enter a replacement password. Saved passwords are never returned to the renderer.'
                : 'Store a reusable local password for SSH, RDP, or VNC.'}
            </DialogDescription>
          </DialogHeader>
          <form className="grid gap-4" onSubmit={submitCredential}>
            <div className="grid gap-2">
              <Label htmlFor="credential-name">Name</Label>
              <Input
                autoFocus
                id="credential-name"
                maxLength={256}
                onChange={(event) =>
                  setCredentialForm((form) => ({ ...form, name: event.target.value }))
                }
                placeholder="Production SSH"
                required
                value={credentialForm.name}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="credential-protocol">Protocol</Label>
              <Select
                onValueChange={(value) =>
                  setCredentialForm((form) => ({
                    ...form,
                    protocol: value as CredentialDraft['protocol'],
                  }))
                }
                value={credentialForm.protocol}
              >
                <SelectTrigger id="credential-protocol">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ssh">SSH</SelectItem>
                  <SelectItem value="rdp">RDP</SelectItem>
                  <SelectItem value="vnc">VNC</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {credentialForm.protocol !== 'vnc' ? (
              <div className="grid gap-2">
                <Label htmlFor="credential-username">Username</Label>
                <Input
                  autoComplete="username"
                  id="credential-username"
                  maxLength={512}
                  onChange={(event) =>
                    setCredentialForm((form) => ({ ...form, username: event.target.value }))
                  }
                  placeholder="user"
                  required
                  value={credentialForm.username}
                />
              </div>
            ) : null}
            {credentialForm.protocol === 'rdp' ? (
              <div className="grid gap-2">
                <Label htmlFor="credential-domain">Domain</Label>
                <Input
                  id="credential-domain"
                  maxLength={512}
                  onChange={(event) =>
                    setCredentialForm((form) => ({ ...form, domain: event.target.value }))
                  }
                  placeholder="CORP"
                  required
                  value={credentialForm.domain}
                />
              </div>
            ) : null}
            <div className="grid gap-2">
              <Label htmlFor="credential-password">
                {editingCredential ? 'Replacement password' : 'Password'}
              </Label>
              <Input
                autoComplete="new-password"
                id="credential-password"
                maxLength={4096}
                onChange={(event) =>
                  setCredentialForm((form) => ({ ...form, password: event.target.value }))
                }
                required
                type="password"
                value={credentialForm.password}
              />
            </div>
            {operationError ? (
              <p className="text-[11px] text-destructive">{operationError}</p>
            ) : null}
            <DialogFooter>
              <Button disabled={busy} onClick={closeCredentialEditor} type="button" variant="ghost">
                Cancel
              </Button>
              <Button disabled={busy} type="submit">
                {busy ? 'Saving…' : editingCredential ? 'Save changes' : 'Add credential'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        onOpenChange={(open) => {
          if (!busy && !open) setPendingDeletion([]);
        }}
        open={pendingDeletion.length > 0}
      >
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>
              Delete credential{deletingCredentials.length === 1 ? '' : 's'}
            </DialogTitle>
            <DialogDescription>
              {deletingCredentials.length === 1
                ? `Delete “${deletingCredentials[0].name}”? This cannot be undone.`
                : `Delete ${deletingCredentials.length} credentials? This cannot be undone.`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              disabled={busy}
              onClick={() => setPendingDeletion([])}
              type="button"
              variant="ghost"
            >
              Cancel
            </Button>
            <Button
              disabled={busy || deletingCredentials.length === 0}
              onClick={deletePendingCredentials}
              variant="destructive"
            >
              {busy ? 'Deleting…' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

const tunnelKinds = [
  { value: 0, label: 'WireGuard' },
  { value: 1, label: 'OpenVPN' },
  { value: 2, label: 'Fortinet' },
  { value: 3, label: 'WatchGuard' },
  { value: 4, label: 'Stormshield' },
  { value: 5, label: 'Azure VPN' },
  { value: 6, label: 'Cisco Secure Client' },
] as const;

type TunnelEditorValue = {
  id?: string;
  name: string;
  kind: number;
  settings: Record<string, unknown>;
};

type TunnelField = {
  key: string;
  label: string;
  section?: string;
  type?: 'password' | 'textarea' | 'number' | 'checkbox' | 'select';
  options?: { value: number; label: string }[];
  placeholder?: string;
  hint?: string;
};

function tunnelKindLabel(kind: number) {
  return tunnelKinds.find((item) => item.value === kind)?.label ?? 'Unknown';
}

function TunnelRouteField({
  id,
  mode,
  onChange,
  scope,
  tunnels,
  disabled = false,
}: {
  id: string;
  mode: TunnelMode;
  onChange: (mode: TunnelMode) => void;
  scope: 'connection' | 'folder';
  tunnels: TunnelRecord[];
  disabled?: boolean;
}) {
  const isFolder = scope === 'folder';
  const description =
    mode === 'off'
      ? 'Always connect directly for this item and its descendants that inherit the route.'
      : mode === 'inherit'
        ? isFolder
          ? 'Follows the VPN route configured by the parent folder.'
          : 'Follows the VPN route configured by the containing folder.'
        : 'The native backend establishes this userspace VPN route before connecting.';
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{isFolder ? 'VPN route default' : 'VPN route'}</Label>
      <Select disabled={disabled} onValueChange={onChange} value={mode}>
        <SelectTrigger className="w-full sm:max-w-[360px]" id={id}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="inherit">
            {isFolder ? 'Inherit from parent' : 'Inherit from folder'}
          </SelectItem>
          <SelectItem value="off">No VPN tunnel</SelectItem>
          {tunnels.map((tunnel) => (
            <SelectItem key={tunnel.id} value={tunnel.id}>
              {tunnel.name} · {tunnel.kind}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-[11px] leading-relaxed text-muted-foreground">{description}</p>
    </div>
  );
}

function tunnelEditorFields(kind: number): TunnelField[] {
  switch (kind) {
    case 0:
      return [
        {
          key: 'InterfacePrivateKey',
          label: 'Private key (base64)',
          section: 'Interface',
          type: 'password',
        },
        {
          key: 'InterfaceAddress',
          label: 'Address (e.g. 10.0.0.2/32)',
          section: 'Interface',
          placeholder: '10.0.0.2/32',
        },
        { key: 'Mtu', label: 'MTU (optional)', section: 'Interface', type: 'number' },
        {
          key: 'Dns',
          label: 'DNS (comma-separated, optional)',
          section: 'Interface',
          placeholder: '1.1.1.1, 2606:4700:4700::1111',
        },
        { key: 'PeerPublicKey', label: 'Public key (base64)', section: 'Peer' },
        {
          key: 'PeerPresharedKey',
          label: 'Preshared key (base64, optional)',
          section: 'Peer',
          type: 'password',
        },
        {
          key: 'PeerEndpoint',
          label: 'Endpoint (host:port)',
          section: 'Peer',
          placeholder: 'vpn.example.com:51820',
        },
        {
          key: 'AllowedIps',
          label: 'Allowed IPs (comma-separated)',
          section: 'Peer',
          placeholder: 'leave blank to route all traffic (0.0.0.0/0, ::/0)',
        },
        {
          key: 'PersistentKeepaliveSeconds',
          label: 'Persistent keepalive seconds (optional)',
          section: 'Peer',
          type: 'number',
        },
      ];
    case 1:
      return [
        {
          key: 'ProfileOvpn',
          label: 'OpenVPN profile (.ovpn contents)',
          section: 'Profile',
          type: 'textarea',
          placeholder: 'client\nproto udp\nremote vpn.example.com 1194\n...',
          hint: 'Paste the full .ovpn profile.',
        },
        {
          key: 'Username',
          label: 'Username',
          section: 'Authentication',
          placeholder: 'leave blank for certificate-only auth',
        },
        { key: 'Password', label: 'Password', section: 'Authentication', type: 'password' },
      ];
    case 2:
      return [
        { key: 'Host', label: 'Host', section: 'Gateway', placeholder: 'vpn.example.com' },
        { key: 'Port', label: 'Port', section: 'Gateway', type: 'number', placeholder: '443' },
        { key: 'Username', label: 'Username', section: 'Credentials' },
        { key: 'Password', label: 'Password', section: 'Credentials', type: 'password' },
        { key: 'Realm', label: 'Realm (optional)', section: 'Credentials' },
        {
          key: 'UseSingleSignOn',
          label: 'Enable single sign-on (SSO) for the VPN tunnel',
          section: 'Single sign-on',
          type: 'checkbox',
        },
        {
          key: 'UseExternalBrowser',
          label: 'Use external browser for SAML authentication',
          section: 'Single sign-on',
          type: 'checkbox',
        },
        {
          key: 'SamlRedirectPort',
          label: 'SAML callback port',
          section: 'Single sign-on',
          type: 'number',
          placeholder: '8020',
        },
        {
          key: 'TotpSecret',
          label: 'TOTP shared secret (Base32, optional)',
          section: 'Advanced',
          type: 'password',
          hint: 'used by username/password authentication',
        },
        {
          key: 'TrustServerCertificate',
          label: 'Trust server certificate (skip verification)',
          section: 'Advanced',
          type: 'checkbox',
        },
        {
          key: 'ServerCertSha256Pin',
          label: 'Server certificate SHA-256 pin (hex, optional)',
          section: 'Advanced',
        },
      ];
    case 3:
      return [
        {
          key: 'AuthMode',
          label: 'Authentication mode',
          section: 'Gateway',
          type: 'select',
          options: [
            { value: 0, label: 'Automatic' },
            { value: 1, label: 'Username and password' },
            { value: 2, label: 'SAML' },
          ],
        },
        { key: 'Server', label: 'Server', section: 'Gateway', placeholder: 'firebox.example.com' },
        { key: 'Port', label: 'Port', section: 'Gateway', type: 'number', placeholder: '443' },
        { key: 'Username', label: 'Username', section: 'Credentials' },
        {
          key: 'Password',
          label: 'Password',
          section: 'Credentials',
          type: 'password',
          hint: 'not required for SAML',
        },
        {
          key: 'Domain',
          label: 'Authentication domain override',
          section: 'Advanced',
          placeholder: 'auto-detect',
        },
        { key: 'CaPem', label: 'CA certificate (PEM)', section: 'Advanced', type: 'textarea' },
        {
          key: 'ClientCertPem',
          label: 'Client certificate (PEM)',
          section: 'Advanced',
          type: 'textarea',
        },
        {
          key: 'ClientKeyPem',
          label: 'Client private key (PEM)',
          section: 'Advanced',
          type: 'textarea',
        },
        {
          key: 'ProfileOvpn',
          label: 'Imported .ovpn fallback (optional)',
          section: 'Advanced',
          type: 'textarea',
        },
        {
          key: 'VerifyX509Name',
          label: 'verify-x509-name subject (advanced)',
          section: 'Advanced',
          placeholder: 'leave default unless the Firebox uses a custom server cert',
        },
        {
          key: 'TrustServerCertificate',
          label: 'Trust the server certificate on the pre-auth login',
          section: 'Advanced',
          type: 'checkbox',
        },
      ];
    case 4:
      return [
        {
          key: 'Mode',
          label: 'Connection mode',
          section: 'Connection mode',
          type: 'select',
          options: [
            { value: 0, label: 'Automatic — authenticate & fetch config' },
            { value: 1, label: 'Import — paste a downloaded .ovpn' },
          ],
        },
        { key: 'Server', label: 'Server', section: 'Gateway', placeholder: 'rpv.example.com' },
        { key: 'Port', label: 'Port', section: 'Gateway', type: 'number', placeholder: '443' },
        { key: 'Description', label: 'Description (optional)', section: 'Gateway' },
        {
          key: 'UseSingleSignOn',
          label: 'Connect with single sign-on',
          section: 'Authentication',
          type: 'checkbox',
        },
        { key: 'Username', label: 'Username', section: 'Authentication' },
        { key: 'Password', label: 'Password', section: 'Authentication', type: 'password' },
        { key: 'UseOtp', label: 'Use an OTP', section: 'Authentication', type: 'checkbox' },
        {
          key: 'ProfileOvpn',
          label: 'OpenVPN profile (.ovpn contents)',
          section: 'Profile',
          type: 'textarea',
          placeholder: 'client\ndev tun\nremote rpv.example.com 443 tcp\n...',
        },
        {
          key: 'CaPem',
          label: 'Firewall CA certificate (PEM, for automatic mode)',
          section: 'Advanced',
          type: 'textarea',
          placeholder: 'paste the SNS portal CA so its TLS cert validates (CN = appliance serial)',
        },
        {
          key: 'TrustServerCertificate',
          label: 'Trust server certificate (skip ALL TLS checks)',
          section: 'Advanced',
          type: 'checkbox',
        },
        {
          key: 'OpenVpnTransportOverride',
          label: 'OpenVPN transport override',
          section: 'Advanced',
          type: 'select',
          options: [
            { value: 0, label: 'Auto — use profile order' },
            { value: 1, label: 'Force TCP' },
            { value: 2, label: 'Force UDP' },
          ],
        },
        {
          key: 'OpenVpnCompressionFramingOverride',
          label: 'OpenVPN compression/framing',
          section: 'Advanced',
          type: 'select',
          options: [
            { value: 0, label: 'Preserve profile compression/framing' },
            { value: 1, label: 'Add legacy no-compression stub' },
          ],
        },
        {
          key: 'AppToken',
          label: 'Portal app token (advanced)',
          section: 'Advanced',
          placeholder: 'sslclient',
        },
      ];
    case 5:
      return [
        {
          key: 'Servers',
          label: 'Server FQDN(s) (comma-separated)',
          section: 'Gateway',
          placeholder: 'gateway.vpn.azure.com, backup.vpn.azure.com',
        },
        {
          key: 'Protocol',
          label: 'Transport',
          section: 'Gateway',
          type: 'select',
          options: [
            { value: 0, label: 'TCP (default)' },
            { value: 1, label: 'UDP' },
          ],
        },
        { key: 'TenantId', label: 'Tenant ID', section: 'Microsoft Entra ID' },
        { key: 'Audience', label: 'Audience', section: 'Microsoft Entra ID' },
        {
          key: 'ApplicationId',
          label: 'Application (client) ID override',
          section: 'Advanced',
          placeholder: 'leave blank to use the audience as the client id',
        },
        {
          key: 'Issuer',
          label: 'Issuer',
          section: 'Advanced',
          placeholder: 'https://sts.windows.net/{tenant}/',
        },
        {
          key: 'ServerSecretHex',
          label: 'Server secret (tls-auth key, 512 hex chars, optional)',
          section: 'Advanced',
          type: 'textarea',
        },
        {
          key: 'CaPem',
          label: 'CA certificate override (PEM, optional)',
          section: 'Advanced',
          type: 'textarea',
          placeholder: 'leave blank to validate against DigiCert Global Root G2',
        },
      ];
    case 6:
      return [
        { key: 'Host', label: 'Host', section: 'Gateway', placeholder: 'vpn.example.com' },
        { key: 'Port', label: 'Port', section: 'Gateway', type: 'number', placeholder: '443' },
        {
          key: 'Group',
          label: 'Group / connection profile (optional)',
          section: 'Gateway',
          placeholder: 'leave blank for the gateway default',
        },
        { key: 'Username', label: 'Username', section: 'Credentials' },
        { key: 'Password', label: 'Password', section: 'Credentials', type: 'password' },
        {
          key: 'TotpSecret',
          label: 'TOTP shared secret (Base32, optional)',
          section: 'Two-factor & advanced',
          type: 'password',
        },
        {
          key: 'SecondaryPassword',
          label: 'Secondary password (optional)',
          section: 'Two-factor & advanced',
          type: 'password',
        },
        {
          key: 'TrustServerCertificate',
          label: 'Trust server certificate (skip verification)',
          section: 'Two-factor & advanced',
          type: 'checkbox',
        },
        {
          key: 'ServerCertSha256Pin',
          label: 'Server certificate SHA-256 pin (hex, optional)',
          section: 'Two-factor & advanced',
        },
      ];
    default:
      return [];
  }
}

function tunnelDefaultSettings(kind: number): Record<string, unknown> {
  switch (kind) {
    case 2:
      return { Port: 443, UseExternalBrowser: true, SamlRedirectPort: 8020 };
    case 3:
      return {
        Port: 443,
        AuthMode: 0,
        VerifyX509Name: '/O=WatchGuard_Technologies/OU=Fireware/CN=Fireware_SSLVPN_Server',
      };
    case 4:
      return {
        Port: 443,
        Mode: 0,
        OpenVpnTransportOverride: 0,
        OpenVpnCompressionFramingOverride: 0,
        AppToken: 'sslclient',
      };
    case 5:
      return { Protocol: 0 };
    case 6:
      return { Port: 443 };
    default:
      return {};
  }
}

function blankTunnelEditor(): TunnelEditorValue {
  return { name: '', kind: 0, settings: tunnelDefaultSettings(0) };
}

function tunnelEditorFromDetails(details: WormholeTunnelDetails): TunnelEditorValue {
  return {
    id: details.id,
    name: details.name,
    kind: details.kind,
    settings: { ...tunnelDefaultSettings(details.kind), ...details.settings },
  };
}

function tunnelSettingText(settings: Record<string, unknown>, key: string): string {
  const value = settings[key];
  return Array.isArray(value)
    ? value.join(', ')
    : typeof value === 'string' || typeof value === 'number'
      ? String(value)
      : '';
}

function TunnelFieldRow({
  field,
  value,
  disabled,
  onChange,
}: {
  field: TunnelField;
  value: Record<string, unknown>;
  disabled?: boolean;
  onChange: (key: string, next: unknown) => void;
}) {
  return (
    <div className={field.type === 'textarea' ? 'grid gap-2 md:col-span-2' : 'grid gap-2'}>
      <Label htmlFor={`tunnel-${field.key}`}>{field.label}</Label>
      {field.type === 'checkbox' ? (
        <Checkbox
          checked={value[field.key] === true}
          disabled={disabled}
          id={`tunnel-${field.key}`}
          onCheckedChange={(checked) => onChange(field.key, checked === true)}
        />
      ) : field.type === 'select' ? (
        <Select
          disabled={disabled}
          onValueChange={(next) => onChange(field.key, Number(next))}
          value={String(value[field.key] ?? field.options?.[0]?.value ?? '')}
        >
          <SelectTrigger id={`tunnel-${field.key}`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {field.options?.map((option) => (
              <SelectItem key={option.value} value={String(option.value)}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ) : field.type === 'textarea' ? (
        <Textarea
          className="min-h-28 font-mono text-xs"
          disabled={disabled}
          id={`tunnel-${field.key}`}
          onChange={(event) => onChange(field.key, event.target.value)}
          placeholder={field.placeholder}
          value={tunnelSettingText(value, field.key)}
        />
      ) : (
        <Input
          disabled={disabled}
          id={`tunnel-${field.key}`}
          onChange={(event) => onChange(field.key, event.target.value)}
          placeholder={field.placeholder}
          type={
            field.type === 'password' ? 'password' : field.type === 'number' ? 'number' : 'text'
          }
          value={tunnelSettingText(value, field.key)}
        />
      )}
      {field.hint ? <p className="text-[11px] text-muted-foreground">{field.hint}</p> : null}
    </div>
  );
}

function TunnelSection({
  title,
  children,
  className,
}: {
  title?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn('grid gap-3', className)}>
      {title ? (
        <h4 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
          {title}
        </h4>
      ) : null}
      <div className="grid gap-4 md:grid-cols-2">{children}</div>
    </section>
  );
}

function TunnelAdvanced({
  label,
  open,
  onOpenChange,
  children,
}: {
  label: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: ReactNode;
}) {
  return (
    <Collapsible
      className="rounded-lg border border-border/70 bg-muted/20 px-3 py-2"
      onOpenChange={onOpenChange}
      open={open}
    >
      <CollapsibleTrigger className="flex w-full items-center justify-between text-xs font-medium">
        <span>{label}</span>
        <ChevronDown className={cn('size-3.5 transition-transform', open ? 'rotate-180' : '')} />
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="mt-3 grid gap-4 md:grid-cols-2">{children}</div>
      </CollapsibleContent>
    </Collapsible>
  );
}

function TunnelEditorDialog({
  initial,
  open,
  onOpenChange,
  onSaved,
}: {
  initial: TunnelEditorValue;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved: (tunnel: TunnelRecord) => void;
}) {
  const [value, setValue] = useState<TunnelEditorValue>(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const missing = useMemo(() => missingTunnelFields(value), [value]);
  const canSave = missing.length === 0;
  const fields = tunnelEditorFields(value.kind);
  const fieldByKey = (key: string) => fields.find((field) => field.key === key);
  const rows = (
    section: string,
    options?: {
      disabled?: (field: TunnelField) => boolean;
      hidden?: (field: TunnelField) => boolean;
    },
  ) =>
    fields
      .filter((field) => field.section === section && !options?.hidden?.(field))
      .map((field) => (
        <TunnelFieldRow
          disabled={options?.disabled?.(field)}
          field={field}
          key={field.key}
          onChange={setSetting}
          value={value.settings}
        />
      ));
  const useSso = value.settings.UseSingleSignOn === true;
  const useExternalBrowser = useSso && value.settings.UseExternalBrowser === true;
  const watchguardAdvancedHasValues =
    value.kind === 3 &&
    ['Domain', 'CaPem', 'ClientCertPem', 'ClientKeyPem'].some(
      (key) => typeof value.settings[key] === 'string' && (value.settings[key] as string).trim(),
    );

  useEffect(() => {
    if (open) setAdvancedOpen(watchguardAdvancedHasValues);
  }, [open, value.kind, watchguardAdvancedHasValues]);

  useEffect(() => {
    if (open) {
      setValue(initial);
      setError('');
    } else {
      // Drop decrypted passwords, private keys, and profiles from renderer state as soon as
      // the editor closes. The native store remains the source of truth for the next edit.
      setValue(blankTunnelEditor());
    }
  }, [initial, open]);

  function setSetting(key: string, next: unknown) {
    setValue((current) => ({
      ...current,
      settings: { ...current.settings, [key]: next },
    }));
  }

  async function runTunnelImport<T>(
    action: () => Promise<T | null>,
    fallback: string,
  ): Promise<T | null> {
    const api = window.wormhole;
    if (!api) {
      setError('The native VPN bridge is unavailable.');
      return null;
    }
    setBusy(true);
    setError('');
    try {
      return await action();
    } catch (importError) {
      setError(importError instanceof Error ? userFacingTunnelError(importError) : fallback);
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function importWatchguardProfile() {
    const imported = await runTunnelImport(
      () => window.wormhole?.importWatchguardProfile() ?? Promise.resolve(null),
      'Could not import the WatchGuard profile.',
    );
    if (!imported) return;
    setValue((current) => ({
      ...current,
      settings: {
        ...current.settings,
        Server: imported.server,
        Port: imported.port,
        ProfileOvpn: imported.profileOvpn,
      },
    }));
  }

  async function importAzureVpnProfile() {
    const imported = await runTunnelImport(
      () => window.wormhole?.importAzureVpnProfile() ?? Promise.resolve(null),
      'Could not import the Azure VPN profile.',
    );
    if (!imported) return;
    setValue((current) => ({
      ...current,
      name: current.name || imported.name || '',
      settings: { ...current.settings, ...imported.settings },
    }));
  }

  async function importOvpnProfile() {
    const imported = await runTunnelImport(
      () => window.wormhole?.importOvpnProfile() ?? Promise.resolve(null),
      'Could not import the OpenVPN profile.',
    );
    if (!imported) return;
    setValue((current) => ({
      ...current,
      settings: { ...current.settings, ProfileOvpn: imported.contents },
    }));
  }

  async function importCiscoProfile() {
    const imported = await runTunnelImport(
      () => window.wormhole?.importCiscoProfile() ?? Promise.resolve(null),
      'Could not import the AnyConnect profile.',
    );
    if (!imported) return;
    setValue((current) => ({
      ...current,
      name: current.name || imported.profileName || '',
      settings: {
        ...current.settings,
        Host: imported.host,
        Port: imported.port,
        Group: imported.group ?? '',
      },
    }));
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canSave) return;
    if (
      value.id &&
      value.kind !== initial.kind &&
      !window.confirm(
        `Change VPN type from ${tunnelKindLabel(initial.kind)} to ${tunnelKindLabel(value.kind)}? The previous provider credentials will be discarded.`,
      )
    ) {
      return;
    }
    const api = window.wormhole;
    if (!api) {
      setError('The native VPN bridge is unavailable.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const settings = normalizeTunnelEditorSettings(value.kind, value.settings);
      const saved = value.id
        ? await api.updateTunnel({ id: value.id, name: value.name, kind: value.kind, settings })
        : await api.createTunnel({ name: value.name, kind: value.kind, settings });
      onSaved({ id: saved.id, name: saved.name, kind: tunnelKindLabel(saved.kind) });
      onOpenChange(false);
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Could not save VPN tunnel.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="flex max-h-[calc(100dvh-2rem)] w-full max-w-[min(48rem,calc(100vw-2rem))] flex-col overflow-hidden border-border/70 bg-card sm:max-w-[min(48rem,calc(100vw-2rem))]">
        <DialogHeader>
          <DialogTitle>{value.id ? 'Edit VPN tunnel' : 'Add VPN tunnel'}</DialogTitle>
          <DialogDescription>
            Tunnel credentials stay in the native encrypted store and never enter the connection
            tree.
          </DialogDescription>
        </DialogHeader>
        <form className="flex min-h-0 flex-1 flex-col gap-4" onSubmit={submit}>
          <div className="grid gap-3 md:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="tunnel-name">Name</Label>
              <Input
                id="tunnel-name"
                onChange={(event) =>
                  setValue((current) => ({ ...current, name: event.target.value }))
                }
                placeholder="e.g. corporate VPN"
                required
                value={value.name}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="tunnel-kind">VPN type</Label>
              <Select
                onValueChange={(next) =>
                  setValue((current) => ({
                    ...current,
                    kind: Number(next),
                    settings: tunnelDefaultSettings(Number(next)),
                  }))
                }
                value={String(value.kind)}
              >
                <SelectTrigger id="tunnel-kind">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {tunnelKinds.map((kind) => (
                    <SelectItem key={kind.value} value={String(kind.value)}>
                      {kind.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          {value.kind === 3 ? (
            <div className="flex items-center justify-between gap-3 rounded-lg border border-border/70 bg-muted/20 px-3 py-2">
              <p className="text-[11px] text-muted-foreground">
                Import a Firebox <span className="font-mono">.wgssl</span> bundle; key material is
                parsed by Go and kept in the encrypted tunnel payload.
              </p>
              <Button
                disabled={busy}
                onClick={() => void importWatchguardProfile()}
                size="sm"
                type="button"
                variant="outline"
              >
                <Upload data-icon="inline-start" />
                Import .wgssl
              </Button>
            </div>
          ) : null}
          {value.kind === 5 ? (
            <div className="flex items-center justify-between gap-3 rounded-lg border border-border/70 bg-muted/20 px-3 py-2">
              <p className="text-[11px] text-muted-foreground">
                Import <span className="font-mono">azurevpnconfig.xml</span> from the Azure portal;
                Microsoft Entra tokens are cached separately in the protected native store.
              </p>
              <Button
                disabled={busy}
                onClick={() => void importAzureVpnProfile()}
                size="sm"
                type="button"
                variant="outline"
              >
                <Upload data-icon="inline-start" />
                Import XML
              </Button>
            </div>
          ) : null}
          {value.kind === 6 ? (
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border/70 bg-muted/20 px-3 py-2">
              <p className="text-[11px] text-muted-foreground">
                Import a Cisco Secure Client / AnyConnect profile XML; gateway and group fields are
                filled by the native parser.
              </p>
              <Button
                disabled={busy}
                onClick={() => void importCiscoProfile()}
                size="sm"
                type="button"
                variant="outline"
              >
                <Upload data-icon="inline-start" />
                Import AnyConnect profile XML…
              </Button>
            </div>
          ) : null}
          {missing.length > 0 ? (
            <p className="rounded-md border border-border/70 bg-muted/20 px-3 py-2 text-[11px] text-muted-foreground">
              To save this tunnel, fill in: {missing.join(', ')}.
            </p>
          ) : null}
          <ScrollArea className="min-h-0 flex-1 pr-3">
            <div className="grid gap-5 py-1">
              {value.kind === 0 ? (
                <>
                  <TunnelSection title="Interface">{rows('Interface')}</TunnelSection>
                  <TunnelSection title="Peer">{rows('Peer')}</TunnelSection>
                </>
              ) : null}
              {value.kind === 1 ? (
                <>
                  <div className="grid gap-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Label htmlFor="tunnel-ProfileOvpn">OpenVPN profile (.ovpn contents)</Label>
                      <Button
                        disabled={busy}
                        onClick={() => void importOvpnProfile()}
                        size="sm"
                        type="button"
                        variant="outline"
                      >
                        <Upload data-icon="inline-start" />
                        Import from file…
                      </Button>
                    </div>
                    {rows('Profile')}
                  </div>
                  <TunnelSection title="Authentication (optional)">
                    {rows('Authentication')}
                  </TunnelSection>
                </>
              ) : null}
              {value.kind === 2 ? (
                <>
                  <TunnelSection title="Gateway">{rows('Gateway')}</TunnelSection>
                  <TunnelSection title="Credentials">
                    {rows('Credentials', {
                      disabled: (field) =>
                        field.key === 'Realm'
                          ? useExternalBrowser &&
                            !(
                              typeof value.settings.Realm === 'string' &&
                              value.settings.Realm.trim()
                            )
                          : useSso,
                    })}
                  </TunnelSection>
                  <div className="grid gap-2 rounded-lg border border-border/70 bg-muted/20 px-3 py-2">
                    {rows('Single sign-on', {
                      disabled: (field) => field.key === 'UseExternalBrowser' && !useSso,
                      hidden: (field) => field.key === 'SamlRedirectPort' && !useExternalBrowser,
                    })}
                    <p className="text-[11px] leading-relaxed text-muted-foreground">
                      The embedded option uses a dedicated WebView2 profile. External-browser
                      authentication requires the callback port configured on the FortiGate.
                    </p>
                  </div>
                  <TunnelAdvanced
                    label="Advanced"
                    onOpenChange={setAdvancedOpen}
                    open={advancedOpen}
                  >
                    {rows('Advanced', {
                      disabled: (field) => field.key === 'TotpSecret' && useSso,
                    })}
                  </TunnelAdvanced>
                </>
              ) : null}
              {value.kind === 3 ? (
                <>
                  <TunnelSection title="Gateway">{rows('Gateway')}</TunnelSection>
                  <TunnelSection title="Credentials">{rows('Credentials')}</TunnelSection>
                  <TunnelAdvanced
                    label="Manual profile fallback & advanced"
                    onOpenChange={setAdvancedOpen}
                    open={advancedOpen}
                  >
                    {rows('Advanced')}
                  </TunnelAdvanced>
                </>
              ) : null}
              {value.kind === 4 ? (
                <>
                  <TunnelSection>{rows('Connection mode')}</TunnelSection>
                  <TunnelSection title="Gateway">{rows('Gateway')}</TunnelSection>
                  <TunnelSection title="Authentication">
                    {fieldByKey('UseSingleSignOn') ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div>
                            <TunnelFieldRow
                              disabled
                              field={fieldByKey('UseSingleSignOn')!}
                              onChange={setSetting}
                              value={value.settings}
                            />
                          </div>
                        </TooltipTrigger>
                        <TooltipContent side="bottom">
                          Single sign-on (browser/OIDC) is not yet supported — use username/password
                          or import a profile.
                        </TooltipContent>
                      </Tooltip>
                    ) : null}
                    {rows('Authentication', {
                      hidden: (field) => field.key === 'UseSingleSignOn',
                    })}
                  </TunnelSection>
                  {value.settings.Mode === 1 ? (
                    <div className="grid gap-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <Label htmlFor="tunnel-ProfileOvpn">Profile</Label>
                        <Button
                          disabled={busy}
                          onClick={() => void importOvpnProfile()}
                          size="sm"
                          type="button"
                          variant="outline"
                        >
                          <Upload data-icon="inline-start" />
                          Import from file…
                        </Button>
                      </div>
                      {rows('Profile')}
                    </div>
                  ) : null}
                  <TunnelAdvanced
                    label="Certificates & advanced"
                    onOpenChange={setAdvancedOpen}
                    open={advancedOpen}
                  >
                    {rows('Advanced')}
                  </TunnelAdvanced>
                </>
              ) : null}
              {value.kind === 5 ? (
                <>
                  <TunnelSection title="Gateway">{rows('Gateway')}</TunnelSection>
                  <TunnelSection title="Microsoft Entra ID">
                    {rows('Microsoft Entra ID')}
                  </TunnelSection>
                  <TunnelAdvanced
                    label="Advanced"
                    onOpenChange={setAdvancedOpen}
                    open={advancedOpen}
                  >
                    {rows('Advanced')}
                  </TunnelAdvanced>
                </>
              ) : null}
              {value.kind === 6 ? (
                <>
                  <TunnelSection title="Gateway">{rows('Gateway')}</TunnelSection>
                  <TunnelSection title="Credentials">{rows('Credentials')}</TunnelSection>
                  <TunnelAdvanced
                    label="Two-factor & advanced"
                    onOpenChange={setAdvancedOpen}
                    open={advancedOpen}
                  >
                    <p className="text-[11px] leading-relaxed text-muted-foreground md:col-span-2">
                      If the gateway prompts for a second factor, provide a TOTP secret (a code is
                      generated automatically) or a static secondary password. SAML single sign-on
                      and client-certificate authentication are not supported.
                    </p>
                    {rows('Two-factor & advanced')}
                  </TunnelAdvanced>
                </>
              ) : null}
            </div>
          </ScrollArea>
          {error ? <p className="text-[11px] text-destructive">{error}</p> : null}
          <DialogFooter>
            <Button
              disabled={busy}
              onClick={() => onOpenChange(false)}
              type="button"
              variant="ghost"
            >
              Cancel
            </Button>
            <Button disabled={busy || !canSave} type="submit">
              {value.id ? <Check data-icon="inline-start" /> : <Plus data-icon="inline-start" />}
              {busy
                ? 'Saving…'
                : value.id
                  ? 'Save changes'
                  : canSave
                    ? 'Add VPN tunnel'
                    : 'Fill in required fields'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function TunnelsPage({
  tunnels,
  onTunnelCreated,
  onTunnelUpdated,
  onTunnelDeleted,
}: {
  tunnels: TunnelRecord[];
  onTunnelCreated: (tunnel: TunnelRecord) => void;
  onTunnelUpdated: (tunnel: TunnelRecord) => void;
  onTunnelDeleted: (id: string) => void;
}) {
  const [searchText, setSearchText] = useState('');
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorValue, setEditorValue] = useState<TunnelEditorValue>(blankTunnelEditor);
  const [actionError, setActionError] = useState('');
  const [testState, setTestState] = useState<{
    tunnel: TunnelRecord;
    status: 'connecting' | 'connected' | 'notice' | 'cancelled' | 'failed';
    error?: string;
  } | null>(null);
  const testAttemptRef = useRef(0);
  const filteredTunnels = useMemo(() => {
    const query = searchText.trim().toLowerCase();
    return query
      ? tunnels.filter((tunnel) =>
          [tunnel.name, tunnel.kind].some((value) => value.toLowerCase().includes(query)),
        )
      : tunnels;
  }, [searchText, tunnels]);

  function addTunnel() {
    setActionError('');
    setEditorValue(blankTunnelEditor());
    setEditorOpen(true);
  }

  function setTunnelEditorOpen(open: boolean) {
    setEditorOpen(open);
    if (!open) setEditorValue(blankTunnelEditor());
  }

  async function editTunnel(tunnel: TunnelRecord) {
    const api = window.wormhole;
    if (!api) {
      setActionError('The native VPN bridge is unavailable.');
      return;
    }
    setActionError('');
    try {
      setEditorValue(tunnelEditorFromDetails(await api.readTunnel(tunnel.id)));
      setEditorOpen(true);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not read VPN tunnel.');
    }
  }

  async function deleteTunnel(tunnel: TunnelRecord) {
    const api = window.wormhole;
    if (!api || !window.confirm(`Delete VPN tunnel “${tunnel.name}”? This cannot be undone.`))
      return;
    setActionError('');
    try {
      const result = await api.deleteTunnel(tunnel.id);
      if (!result.deleted) {
        setActionError(result.error ?? 'Could not delete VPN tunnel.');
        return;
      }
      onTunnelDeleted(tunnel.id);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Could not delete VPN tunnel.');
    }
  }

  async function testTunnel(tunnel: TunnelRecord) {
    const api = window.wormhole;
    if (!api || testState) {
      if (!api) setActionError('The native VPN bridge is unavailable.');
      return;
    }
    setActionError('');
    const attempt = ++testAttemptRef.current;
    setTestState({ tunnel, status: 'connecting' });
    try {
      const result = await api.testTunnel(tunnel.id);
      if (attempt !== testAttemptRef.current) return;
      if (!result.connected) {
        const message = result.error || 'The VPN tunnel test failed.';
        setTestState((current) =>
          current
            ? {
                ...current,
                status: isTunnelTestCancellation(message)
                  ? 'cancelled'
                  : isTunnelTestNotice(message)
                    ? 'notice'
                    : 'failed',
                error: message,
              }
            : current,
        );
        return;
      }
      setTestState((current) => (current ? { ...current, status: 'connected' } : current));
    } catch (error) {
      if (attempt !== testAttemptRef.current) return;
      const message = userFacingTunnelError(error) || 'The VPN tunnel test failed.';
      setTestState((current) =>
        current
          ? {
              ...current,
              status: isTunnelTestCancellation(message)
                ? 'cancelled'
                : isTunnelTestNotice(message)
                  ? 'notice'
                  : 'failed',
              error: message,
            }
          : current,
      );
    }
  }

  return (
    <section className="flex h-full min-h-0 flex-col overflow-hidden px-6 py-4">
      <h2 className="shrink-0 text-xl font-semibold tracking-tight">VPN tunnels</h2>

      <div className="mt-3 flex shrink-0 flex-wrap items-center gap-2">
        <Input
          aria-label="Search tunnels"
          className="!text-xs min-w-52 max-w-[480px] flex-1"
          onChange={(event) => setSearchText(event.target.value)}
          placeholder="Search tunnels"
          value={searchText}
        />
        <Button className="!text-xs" onClick={addTunnel} size="default">
          <Plus data-icon="inline-start" />
          Add VPN tunnel
        </Button>
      </div>
      {actionError ? <p className="mt-2 text-[11px] text-muted-foreground">{actionError}</p> : null}

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
                    <IconButton
                      label={`Test ${tunnel.name}`}
                      onClick={() => void testTunnel(tunnel)}
                    >
                      <FlaskConical />
                    </IconButton>
                    <IconButton
                      label={`Edit ${tunnel.name}`}
                      onClick={() => void editTunnel(tunnel)}
                    >
                      <Pencil />
                    </IconButton>
                    <IconButton
                      label={`Delete ${tunnel.name}`}
                      onClick={() => void deleteTunnel(tunnel)}
                    >
                      <X />
                    </IconButton>
                  </CardFooter>
                </Card>
              ))}
            </div>
          </ScrollArea>
        )}
      </div>
      <TunnelEditorDialog
        initial={editorValue}
        onOpenChange={setTunnelEditorOpen}
        onSaved={(tunnel) => (editorValue.id ? onTunnelUpdated(tunnel) : onTunnelCreated(tunnel))}
        open={editorOpen}
      />
      <Dialog
        onOpenChange={(open) => {
          if (!open) setTestState(null);
        }}
        open={testState !== null}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Test VPN tunnel</DialogTitle>
            <DialogDescription>{testState?.tunnel.name}</DialogDescription>
          </DialogHeader>
          <div className="flex min-h-24 items-center gap-3 rounded-lg border border-border/70 bg-muted/20 px-4 py-3">
            {testState?.status === 'connecting' ? (
              <>
                <LoaderCircle className="size-5 shrink-0 animate-spin text-muted-foreground" />
                <p className="text-sm">Connecting to the VPN gateway…</p>
              </>
            ) : testState?.status === 'connected' ? (
              <>
                <CheckCircle2 className="size-5 shrink-0 text-emerald-500" />
                <p className="text-sm">VPN tunnel connected successfully.</p>
              </>
            ) : testState?.status === 'cancelled' ? (
              <>
                <Info className="size-5 shrink-0 text-muted-foreground" />
                <div className="min-w-0 space-y-1">
                  <p className="text-sm font-medium">Test cancelled.</p>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    You stopped the authentication prompt — no changes were made.
                  </p>
                </div>
              </>
            ) : testState?.status === 'notice' ? (
              <>
                <Info className="size-5 shrink-0 text-emerald-500" />
                <div className="min-w-0 space-y-1">
                  <p className="text-sm font-medium">VPN preparation completed.</p>
                  <p className="text-xs leading-relaxed text-muted-foreground">{testState.error}</p>
                </div>
              </>
            ) : (
              <>
                <XCircle className="size-5 shrink-0 text-destructive" />
                <div className="min-w-0 space-y-1">
                  <p className="text-sm font-medium">The test didn't go through.</p>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    {testState?.error}
                  </p>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    Check the gateway settings and credentials, then try again.
                  </p>
                </div>
              </>
            )}
          </div>
          <DialogFooter>
            <Button onClick={() => setTestState(null)} type="button">
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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

type McpClient = 'claude-code' | 'claude-desktop' | 'codex';

const mcpTokenPlaceholder = '<bearer-token — click Reveal or Copy config>';

function buildMcpConfig(client: McpClient, endpoint: string, token: string): string {
  if (client === 'codex') {
    const escapeToml = (value: string) => value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
    return (
      '[mcp_servers.wormhole]\n' +
      `url = "${escapeToml(endpoint)}"\n` +
      `http_headers = { Authorization = "${escapeToml(`Bearer ${token}`)}" }\n`
    );
  }

  if (client === 'claude-desktop') {
    return JSON.stringify(
      {
        mcpServers: {
          wormhole: {
            command: 'cmd',
            args: [
              '/c',
              'npx',
              'mcp-remote@latest',
              endpoint,
              '--header',
              'Authorization:${WORMHOLE_MCP_TOKEN}',
            ],
            env: { WORMHOLE_MCP_TOKEN: `Bearer ${token}` },
          },
        },
      },
      null,
      2,
    );
  }

  return JSON.stringify(
    {
      mcpServers: {
        wormhole: {
          type: 'http',
          url: endpoint,
          headers: { Authorization: `Bearer ${token}` },
        },
      },
    },
    null,
    2,
  );
}

function mcpClientCopyDetails(client: McpClient): { label: string; caption: string } {
  switch (client) {
    case 'claude-desktop':
      return {
        label: 'Claude Desktop config (claude_desktop_config.json)',
        caption:
          'Claude Desktop launches stdio servers, so this bridges through mcp-remote (requires Node.js / npx).',
      };
    case 'codex':
      return {
        label: 'Codex config (~/.codex/config.toml)',
        caption:
          'Codex speaks Streamable HTTP directly. Add this to ~/.codex/config.toml — it is TOML, not JSON.',
      };
    default:
      return {
        label: 'Claude Code config (.mcp.json)',
        caption:
          'Claude Code speaks Streamable HTTP directly. Add this to .mcp.json (project) or ~/.claude.json.',
      };
  }
}

async function copyTextToClipboard(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const textarea = document.createElement('textarea');
  textarea.value = value;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand('copy');
  textarea.remove();
  if (!copied) throw new Error('Clipboard access is unavailable.');
}

function authSecretLabel(method: WormholeAuthFallback): string {
  return method === 'pin' ? 'PIN' : 'password';
}

function authModeLabel(mode: WormholeAuthMode): string {
  switch (mode) {
    case 'pin':
      return 'PIN';
    case 'password':
      return 'password';
    case 'windowsHello':
      return 'Windows Hello';
    default:
      return 'disabled';
  }
}

function authStateHasSecret(
  state: WormholeAuthState | null,
  method: WormholeAuthFallback,
): boolean {
  return method === 'pin' ? Boolean(state?.hasPin) : Boolean(state?.hasPassword);
}

function AuthSecretDialog({
  error,
  method,
  onOpenChange,
  onSubmit,
  open,
  busy,
}: {
  error: string;
  method: WormholeAuthFallback;
  onOpenChange: (open: boolean) => void;
  onSubmit: (secret: string) => Promise<void>;
  open: boolean;
  busy: boolean;
}) {
  const [secret, setSecret] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [validationError, setValidationError] = useState('');

  useEffect(() => {
    if (!open) {
      setSecret('');
      setConfirmation('');
      setValidationError('');
    }
  }, [open]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    if (!secret) {
      setValidationError(`Enter a ${authSecretLabel(method)}.`);
      return;
    }
    if (secret !== confirmation) {
      setValidationError('The entries do not match.');
      return;
    }
    setValidationError('');
    await onSubmit(secret);
  }

  const secretLabel = authSecretLabel(method);

  return (
    <Dialog onOpenChange={(nextOpen) => !busy && onOpenChange(nextOpen)} open={open}>
      <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>Set your Wormhole {secretLabel}</DialogTitle>
          <DialogDescription>
            {method === 'pin'
              ? 'Choose a PIN just for Wormhole. Do not use your Windows PIN.'
              : 'Choose a password just for Wormhole.'}
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit}>
          <div className="grid gap-2">
            <Label htmlFor="auth-new-secret">{secretLabel}</Label>
            <Input
              autoFocus
              autoComplete="new-password"
              id="auth-new-secret"
              inputMode={method === 'pin' ? 'numeric' : undefined}
              onChange={(event) => setSecret(event.target.value)}
              placeholder={method === 'pin' ? '4–12 digits' : 'At least 8 characters'}
              type="password"
              value={secret}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="auth-confirm-secret">Confirm {secretLabel}</Label>
            <Input
              autoComplete="new-password"
              id="auth-confirm-secret"
              inputMode={method === 'pin' ? 'numeric' : undefined}
              onChange={(event) => setConfirmation(event.target.value)}
              type="password"
              value={confirmation}
            />
          </div>
          {validationError || error ? (
            <p className="text-[11px] text-destructive">{validationError || error}</p>
          ) : null}
          <DialogFooter>
            <Button
              disabled={busy}
              onClick={() => onOpenChange(false)}
              type="button"
              variant="outline"
            >
              Cancel
            </Button>
            <Button disabled={busy || !secret || !confirmation} type="submit">
              {busy ? 'Saving…' : 'Save'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function formatLastUpdateCheck(stamp: string | null): string {
  if (!stamp) return 'Last checked: never';
  const date = new Date(stamp);
  if (Number.isNaN(date.getTime())) return 'Last checked: never';
  return `Last checked: ${date.toLocaleString()}`;
}

const markdownInlinePattern = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`|\[[^\]]+\]\(https?:\/\/[^)\s]+\))/;

function renderMarkdownInline(text: string, keyPrefix: string): ReactNode[] {
  return text.split(markdownInlinePattern).flatMap((part, index) => {
    const key = `${keyPrefix}:${index}`;
    if (!part) return [];
    if (part.startsWith('`') && part.endsWith('`') && part.length >= 2) {
      return <code key={key}>{part.slice(1, -1)}</code>;
    }
    if (part.startsWith('**') && part.endsWith('**') && part.length >= 4) {
      return <strong key={key}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('*') && part.endsWith('*') && part.length >= 2) {
      return <em key={key}>{part.slice(1, -1)}</em>;
    }
    const link = part.match(/^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/);
    if (link) {
      const url = link[2];
      return (
        <a
          className="text-foreground underline decoration-border underline-offset-2 hover:text-foreground/80"
          href={url}
          key={key}
          onClick={(event) => {
            event.preventDefault();
            void window.wormhole?.openExternal(url).catch(() => {
              // Opening the release page is a convenience; a failure is not actionable here.
            });
          }}
          rel="noreferrer"
          target="_blank"
        >
          {link[1]}
        </a>
      );
    }
    return <span key={key}>{part}</span>;
  });
}

// ReleaseNotesMarkdown is a deliberately small markdown renderer for GitHub release bodies:
// headings, bullet/numbered lists, fenced code blocks, paragraphs, and inline
// bold/italic/code/links. It never injects raw HTML.
function ReleaseNotesMarkdown({ markdown }: { markdown: string }) {
  return useMemo(() => {
    const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
    const blocks: ReactNode[] = [];
    let sequence = 0;
    let listType: 'ul' | 'ol' | null = null;
    let listItems: string[] = [];
    let paragraph: string[] = [];
    let codeLines: string[] | null = null;

    const flushParagraph = () => {
      if (paragraph.length === 0) return;
      const text = paragraph.join(' ').trim();
      paragraph = [];
      if (!text) return;
      blocks.push(<p key={sequence}>{renderMarkdownInline(text, `p:${sequence}`)}</p>);
      sequence += 1;
    };
    const flushList = () => {
      if (!listType) return;
      const items = listItems;
      const type = listType;
      listType = null;
      listItems = [];
      blocks.push(
        type === 'ol' ? (
          <ol className="list-decimal space-y-0.5 pl-4" key={sequence}>
            {items.map((item, index) => (
              <li key={index}>{renderMarkdownInline(item, `li:${sequence}:${index}`)}</li>
            ))}
          </ol>
        ) : (
          <ul className="list-disc space-y-0.5 pl-4" key={sequence}>
            {items.map((item, index) => (
              <li key={index}>{renderMarkdownInline(item, `li:${sequence}:${index}`)}</li>
            ))}
          </ul>
        ),
      );
      sequence += 1;
    };

    for (const line of lines) {
      if (codeLines) {
        if (line.trim().startsWith('```')) {
          blocks.push(
            <pre
              className="overflow-x-auto rounded-md bg-muted/70 p-3 font-mono text-[10px] leading-relaxed"
              key={sequence}
            >
              {codeLines.join('\n')}
            </pre>,
          );
          sequence += 1;
          codeLines = null;
        } else {
          codeLines.push(line);
        }
        continue;
      }
      if (line.trim().startsWith('```')) {
        flushParagraph();
        flushList();
        codeLines = [];
        continue;
      }
      const heading = line.match(/^(#{1,6})\s+(.+)$/);
      if (heading) {
        flushParagraph();
        flushList();
        blocks.push(
          <p className="text-xs font-semibold text-foreground" key={sequence}>
            {renderMarkdownInline(heading[2], `h:${sequence}`)}
          </p>,
        );
        sequence += 1;
        continue;
      }
      const unordered = line.match(/^[-*]\s+(.+)$/);
      const ordered = line.match(/^\d+\.\s+(.+)$/);
      if (unordered || ordered) {
        flushParagraph();
        const type: 'ul' | 'ol' = ordered ? 'ol' : 'ul';
        if (listType !== type) flushList();
        listType = type;
        listItems.push((unordered ?? ordered)![1]);
        continue;
      }
      if (line.trim() === '') {
        flushParagraph();
        flushList();
        continue;
      }
      flushList();
      paragraph.push(line);
    }
    flushParagraph();
    flushList();
    if (codeLines) {
      blocks.push(
        <pre
          className="overflow-x-auto rounded-md bg-muted/70 p-3 font-mono text-[10px] leading-relaxed"
          key={sequence}
        >
          {codeLines.join('\n')}
        </pre>,
      );
    }
    return blocks.length > 0 ? blocks : <p>No release notes were provided.</p>;
  }, [markdown]);
}

function SettingsPage({
  theme,
  onThemeChange,
  authGate,
  authState,
  onAuthStateChange,
  onBackupImported,
  onRequestAuthentication,
  onCheckForUpdates,
  onDismissUpdate,
  onInstallUpdate,
  onOpenReleaseNotes,
  onSetAutoCheckForUpdates,
  settingsUpdatesRequest,
  update,
}: {
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
  authGate: 'loading' | 'locked' | 'unlocked' | 'error';
  authState: WormholeAuthState | null;
  onAuthStateChange: (state: WormholeAuthState) => void;
  onBackupImported: (workspace: WormholeWorkspaceSnapshot) => void;
  onRequestAuthentication: (reason: string) => Promise<boolean>;
  onCheckForUpdates: () => void;
  onDismissUpdate: () => void;
  onInstallUpdate: () => void;
  onOpenReleaseNotes: () => void;
  onSetAutoCheckForUpdates: (enabled: boolean) => void;
  settingsUpdatesRequest: number;
  update: {
    currentVersion: string;
    result: WormholeUpdateCheckResult | null;
    autoCheckForUpdates: boolean;
    lastUpdateCheck: string | null;
    skippedUpdateVersion: string | null;
    busy: boolean;
    status: string;
    downloadProgress: number | null;
  };
}) {
  const [activeTab, setActiveTab] = useState('general');
  const [confirmOnTabClose, setConfirmOnTabClose] = useState(true);
  const [autoCopyOnSelect, setAutoCopyOnSelect] = useState(false);
  const [promptBeforeTunnelConnect, setPromptBeforeTunnelConnect] = useState(true);
  const [authMethod, setAuthMethod] = useState<WormholeAuthMode>(authState?.mode ?? 'disabled');
  const [helloFallback, setHelloFallback] = useState<WormholeAuthFallback>(
    authState?.fallback ?? 'pin',
  );
  const [idleTimeout, setIdleTimeout] = useState<number | null>(
    authState?.idleTimeoutMinutes ?? 15,
  );
  const [securityBusy, setSecurityBusy] = useState(false);
  const [securityError, setSecurityError] = useState('');
  const [securityMessage, setSecurityMessage] = useState('');
  const [secretDialog, setSecretDialog] = useState<WormholeAuthFallback | null>(null);
  const pendingSecretAction = useRef<(() => Promise<void>) | null>(null);
  const helloStatusMode = useRef<WormholeAuthMode | null>(null);
  const [bitwardenEnabled, setBitwardenEnabled] = useState(false);
  const [bitwardenPath, setBitwardenPath] = useState('bw');
  const [browserExtensionEnabled, setBrowserExtensionEnabled] = useState(false);
  const [retentionDays, setRetentionDays] = useState('14');
  const [mcpState, setMcpState] = useState<WormholeMcpStatus | null>(null);
  const [mcpPort, setMcpPort] = useState('8765');
  const [mcpToken, setMcpToken] = useState('');
  const [mcpTokenRevealed, setMcpTokenRevealed] = useState(false);
  const [mcpClient, setMcpClient] = useState<McpClient>('codex');
  const [mcpBusy, setMcpBusy] = useState(false);
  const [mcpError, setMcpError] = useState('');
  const [mcpMessage, setMcpMessage] = useState('');
  const [logsInfo, setLogsInfo] = useState<WormholeLogsInfo | null>(null);
  const [logsOpenBusy, setLogsOpenBusy] = useState(false);
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [logLevel, setLogLevelState] = useState('info');
  const [logsError, setLogsError] = useState('');
  const [backupExportOpen, setBackupExportOpen] = useState(false);
  const [backupExportPassword, setBackupExportPassword] = useState('');
  const [backupExportConfirmation, setBackupExportConfirmation] = useState('');
  const [backupExportBusy, setBackupExportBusy] = useState(false);
  const [backupExportError, setBackupExportError] = useState('');
  const [backupExportResult, setBackupExportResult] = useState<WormholeBackupExportResult | null>(
    null,
  );
  const [backupImportOpen, setBackupImportOpen] = useState(false);
  const [backupImportPickerBusy, setBackupImportPickerBusy] = useState(false);
  const [backupImportSelection, setBackupImportSelection] =
    useState<WormholeBackupImportSelection | null>(null);
  const [backupImportPassword, setBackupImportPassword] = useState('');
  const [backupImportBusy, setBackupImportBusy] = useState(false);
  const [backupImportError, setBackupImportError] = useState('');
  const [backupImportResult, setBackupImportResult] = useState<WormholeBackupImportResult | null>(
    null,
  );
  const [backupSectionError, setBackupSectionError] = useState('');
  const backupAuthGateRef = useRef(authGate);
  backupAuthGateRef.current = authGate;

  useEffect(() => {
    if (settingsUpdatesRequest > 0) setActiveTab('updates');
  }, [settingsUpdatesRequest]);

  useEffect(() => {
    if (authGate === 'unlocked') return;
    setSecretDialog(null);
    pendingSecretAction.current = null;
    setBackupExportOpen(false);
    setBackupExportPassword('');
    setBackupExportConfirmation('');
    setBackupImportOpen(false);
    setBackupImportPassword('');
    setBackupImportSelection(null);
    setBackupSectionError('');
    window.wormhole?.clearBackupImportSelection();
  }, [authGate]);

  useEffect(() => {
    if (!authState) return;
    setAuthMethod(authState.mode);
    setHelloFallback(authState.fallback);
    setIdleTimeout(authState.idleTimeoutMinutes);
  }, [authState]);

  useEffect(() => {
    if (authGate !== 'unlocked' || !window.wormhole) {
      setMcpState(null);
      setMcpToken('');
      setMcpTokenRevealed(false);
      return;
    }
    let active = true;
    void window.wormhole
      .mcpStatus()
      .then((status) => {
        if (!active) return;
        setMcpState(status);
        setMcpPort(String(status.port));
        setMcpError('');
      })
      .catch((error) => {
        if (!active) return;
        setMcpError(errorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [authGate]);

  useEffect(() => {
    if (authGate !== 'unlocked' || !window.wormhole) return;
    let active = true;
    void window.wormhole
      .readAppSettings()
      .then((settings) => {
        if (active) setPromptBeforeTunnelConnect(settings.promptBeforeTunnelConnect);
      })
      .catch(() => {
        // The switch keeps its default (true) when the setting cannot be read.
      });
    return () => {
      active = false;
    };
  }, [authGate]);

  useEffect(() => {
    if (authGate !== 'unlocked' || !window.wormhole) return;
    let active = true;
    void window.wormhole
      .readLogsInfo()
      .then((info) => {
        if (!active) return;
        setLogsInfo(info);
        setRetentionDays(String(info.logRetentionDays));
        setLogLevelState(info.logLevel);
        setLogsError('');
      })
      .catch((error) => {
        if (active) setLogsError(logsErrorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [authGate]);

  function handlePromptBeforeTunnelConnectChange(enabled: boolean) {
    setPromptBeforeTunnelConnect(enabled);
    if (!window.wormhole) return;
    void window.wormhole.setPromptBeforeTunnelConnect(enabled).catch(() => {
      // A failed save leaves the local switch state; the next settings open re-syncs it.
    });
  }

  useEffect(() => {
    if (!authState || authState.mode !== 'windowsHello' || !window.wormhole) {
      helloStatusMode.current = null;
      return;
    }
    if (helloStatusMode.current === authState.mode) return;
    helloStatusMode.current = authState.mode;
    let active = true;
    void window.wormhole
      .checkWindowsHello()
      .then((windowsHello) => {
        if (active) onAuthStateChange({ ...authState, windowsHello });
      })
      .catch(() => {
        // The manual refresh action exposes failures without interrupting settings changes.
      });
    return () => {
      active = false;
    };
  }, [authState, onAuthStateChange]);

  function clearSecurityStatus() {
    setSecurityError('');
    setSecurityMessage('');
  }

  function errorMessage(error: unknown): string {
    if (error instanceof Error && /^(PIN|Password) (must|can)/.test(error.message)) {
      return error.message;
    }
    return "Wormhole couldn't save this change. Try again.";
  }

  function logsErrorMessage(error: unknown): string {
    if (error instanceof Error && error.message) return error.message;
    return "Wormhole couldn't complete this action. Try again.";
  }

  async function persistAuthSettings(
    mode: WormholeAuthMode,
    fallback: WormholeAuthFallback,
    timeout: number | null,
  ): Promise<WormholeAuthState> {
    if (!window.wormhole) throw new Error("Wormhole isn't ready. Try again.");
    const nextState = await window.wormhole.updateAuthSettings({
      mode,
      fallback,
      idleTimeoutMinutes: timeout,
    });
    onAuthStateChange(nextState);
    return nextState;
  }

  function openSecretDialog(method: WormholeAuthFallback, afterSecret?: () => Promise<void>) {
    pendingSecretAction.current = afterSecret ?? null;
    setSecurityError('');
    setSecretDialog(method);
  }

  function closeSecretDialog(open: boolean) {
    if (open || securityBusy) return;
    pendingSecretAction.current = null;
    setSecretDialog(null);
  }

  async function saveAuthSecret(secret: string) {
    if (!secretDialog || !window.wormhole) return;

    setSecurityBusy(true);
    setSecurityError('');
    setSecurityMessage('');
    try {
      const nextState = await window.wormhole.setAuthSecret({ method: secretDialog, secret });
      onAuthStateChange(nextState);
      setSecretDialog(null);
      const afterSecret = pendingSecretAction.current;
      pendingSecretAction.current = null;
      if (afterSecret) {
        await afterSecret();
      } else {
        setSecurityMessage(`${authSecretLabel(secretDialog)} saved.`);
      }
    } catch (error) {
      setSecurityError(errorMessage(error));
    } finally {
      setSecurityBusy(false);
    }
  }

  async function requireCurrentAuthentication(reason: string): Promise<boolean> {
    if (!authState?.configured) return true;
    const authenticated = await onRequestAuthentication(reason);
    if (!authenticated) {
      setSecurityError('Unlock canceled.');
    }
    return authenticated;
  }

  async function handleAuthMethodChange(value: string) {
    if (securityBusy || !authState) return;
    if (
      value !== 'disabled' &&
      value !== 'pin' &&
      value !== 'password' &&
      value !== 'windowsHello'
    ) {
      return;
    }

    const nextMode = value as WormholeAuthMode;
    const previousMode = authMethod;
    clearSecurityStatus();
    setSecurityBusy(true);
    try {
      if (!(await requireCurrentAuthentication('Unlock Wormhole to change how it locks.'))) {
        return;
      }

      let configuredFallback: WormholeAuthFallback = helloFallback;
      const requiredMethod: WormholeAuthFallback =
        nextMode === 'password' ? 'password' : nextMode === 'windowsHello' ? helloFallback : 'pin';
      if (nextMode === 'windowsHello' && !authStateHasSecret(authState, requiredMethod)) {
        const alternate: WormholeAuthFallback = requiredMethod === 'pin' ? 'password' : 'pin';
        if (authStateHasSecret(authState, alternate)) configuredFallback = alternate;
      }
      const secretMethodForMode = nextMode === 'windowsHello' ? configuredFallback : requiredMethod;
      if (nextMode !== 'disabled' && !authStateHasSecret(authState, secretMethodForMode)) {
        setSecurityBusy(false);
        openSecretDialog(secretMethodForMode, async () => {
          await persistAuthSettings(nextMode, configuredFallback, idleTimeout ?? 15);
          setSecurityMessage(`Unlock method set to ${authModeLabel(nextMode)}.`);
        });
        return;
      }

      await persistAuthSettings(
        nextMode,
        configuredFallback,
        nextMode === 'disabled' ? idleTimeout : (idleTimeout ?? 15),
      );
      setSecurityMessage(
        nextMode === 'disabled'
          ? 'App lock turned off.'
          : `Unlock method set to ${authModeLabel(nextMode)}.`,
      );
    } catch (error) {
      setAuthMethod(previousMode);
      setSecurityError(errorMessage(error));
    } finally {
      setSecurityBusy(false);
    }
  }

  async function handleFallbackChange(value: string) {
    if (securityBusy || !authState || (value !== 'pin' && value !== 'password')) return;
    const nextFallback = value as WormholeAuthFallback;
    if (nextFallback === helloFallback) return;

    clearSecurityStatus();
    setSecurityBusy(true);
    try {
      if (!(await requireCurrentAuthentication('Unlock Wormhole to change the backup method.')))
        return;
      if (!authStateHasSecret(authState, nextFallback)) {
        setSecurityBusy(false);
        openSecretDialog(nextFallback, async () => {
          await persistAuthSettings(authMethod, nextFallback, idleTimeout);
          setSecurityMessage(`Backup method set to ${authSecretLabel(nextFallback)}.`);
        });
        return;
      }

      await persistAuthSettings(authMethod, nextFallback, idleTimeout);
      setSecurityMessage(`Backup method set to ${authSecretLabel(nextFallback)}.`);
    } catch (error) {
      setSecurityError(errorMessage(error));
    } finally {
      setSecurityBusy(false);
    }
  }

  async function handleIdleTimeoutChange(value: string) {
    if (securityBusy || !authState) return;
    const nextTimeout = value === 'none' ? null : Number(value);
    if (nextTimeout !== null && ![1, 5, 15, 30, 60].includes(nextTimeout)) return;

    clearSecurityStatus();
    setSecurityBusy(true);
    try {
      if (!(await requireCurrentAuthentication('Unlock Wormhole to change auto-lock.'))) return;
      await persistAuthSettings(authMethod, helloFallback, nextTimeout);
      setSecurityMessage(
        nextTimeout === null ? 'Auto-lock turned off.' : `Auto-lock set to ${nextTimeout} minutes.`,
      );
    } catch (error) {
      setSecurityError(errorMessage(error));
    } finally {
      setSecurityBusy(false);
    }
  }

  async function handleSetSecret() {
    if (securityBusy || !authState || authMethod === 'disabled') return;
    clearSecurityStatus();
    const method = authMethod === 'windowsHello' ? helloFallback : authMethod;
    if (
      !(await requireCurrentAuthentication(
        `Unlock Wormhole to change your ${authSecretLabel(method)}.`,
      ))
    )
      return;
    openSecretDialog(method);
  }

  async function handleTestUnlock() {
    if (securityBusy || !authState) return;
    clearSecurityStatus();
    if (!authState.configured) {
      setSecurityMessage('App lock is off.');
      return;
    }
    if (authState.mode === 'windowsHello' && window.wormhole) {
      setSecurityBusy(true);
      try {
        const result = await window.wormhole.verifyWindowsHello();
        if (result.succeeded) setSecurityMessage('Windows Hello works.');
        else setSecurityError(result.message || 'Windows Hello was canceled.');
      } catch (error) {
        setSecurityError(errorMessage(error));
      } finally {
        setSecurityBusy(false);
      }
      return;
    }
    if (await onRequestAuthentication('Unlock Wormhole to test app lock.'))
      setSecurityMessage('App lock works.');
    else setSecurityError('Test canceled.');
  }

  async function handleRefreshWindowsHello() {
    if (securityBusy || !authState || !window.wormhole) return;
    clearSecurityStatus();
    setSecurityBusy(true);
    try {
      const windowsHello = await window.wormhole.checkWindowsHello();
      onAuthStateChange({ ...authState, windowsHello });
      setSecurityMessage(windowsHello.message);
    } catch (error) {
      setSecurityError(errorMessage(error));
    } finally {
      setSecurityBusy(false);
    }
  }

  async function handleMcpToggle(enabled: boolean) {
    if (mcpBusy || !window.wormhole) return;
    const port = Number(mcpPort);
    if (enabled && (!Number.isInteger(port) || port < 1 || port > 65535)) {
      setMcpError('MCP port must be an integer between 1 and 65535.');
      return;
    }
    setMcpBusy(true);
    setMcpError('');
    setMcpMessage('');
    try {
      const nextState = enabled
        ? await window.wormhole.startMcp(port)
        : await window.wormhole.stopMcp();
      setMcpState(nextState);
      setMcpPort(String(nextState.port));
      setMcpMessage(enabled ? 'MCP server started.' : 'MCP server stopped.');
    } catch (error) {
      setMcpError(errorMessage(error));
    } finally {
      setMcpBusy(false);
    }
  }

  async function commitMcpPort() {
    if (mcpBusy || mcpState?.running || !window.wormhole) return;
    const port = Number(mcpPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setMcpPort(String(mcpState?.port ?? 8765));
      setMcpError('MCP port must be an integer between 1 and 65535.');
      return;
    }
    if (port === mcpState?.port) return;
    setMcpBusy(true);
    setMcpError('');
    setMcpMessage('');
    try {
      const nextState = await window.wormhole.setMcpPort(port);
      setMcpState(nextState);
      setMcpPort(String(nextState.port));
      setMcpMessage('MCP port saved.');
    } catch (error) {
      setMcpPort(String(mcpState?.port ?? 8765));
      setMcpError(errorMessage(error));
    } finally {
      setMcpBusy(false);
    }
  }

  async function revealMcpToken() {
    if (mcpBusy || !window.wormhole) return;
    if (mcpTokenRevealed) {
      setMcpToken('');
      setMcpTokenRevealed(false);
      return;
    }
    setMcpBusy(true);
    setMcpError('');
    try {
      setMcpToken(await window.wormhole.getMcpToken());
      setMcpTokenRevealed(true);
    } catch (error) {
      setMcpError(errorMessage(error));
    } finally {
      setMcpBusy(false);
    }
  }

  async function copyMcpToken() {
    if (mcpBusy || !window.wormhole) return;
    setMcpBusy(true);
    setMcpError('');
    try {
      const token = mcpToken || (await window.wormhole.getMcpToken());
      await copyTextToClipboard(token);
      setMcpMessage('Bearer token copied.');
    } catch (error) {
      setMcpError(errorMessage(error));
    } finally {
      setMcpBusy(false);
    }
  }

  async function regenerateMcpToken() {
    if (mcpBusy || !window.wormhole) return;
    if (
      !window.confirm(
        'Regenerate the MCP token? Clients using the current token will stop working until you update them.',
      )
    ) {
      return;
    }
    setMcpBusy(true);
    setMcpError('');
    setMcpMessage('');
    try {
      setMcpToken(await window.wormhole.regenerateMcpToken());
      setMcpTokenRevealed(true);
      setMcpMessage('MCP token regenerated. Update connected clients.');
    } catch (error) {
      setMcpError(errorMessage(error));
    } finally {
      setMcpBusy(false);
    }
  }

  async function copyMcpEndpoint() {
    if (mcpBusy) return;
    setMcpError('');
    try {
      await copyTextToClipboard(mcpState?.endpoint ?? `http://127.0.0.1:${mcpPort}/mcp`);
      setMcpMessage('MCP endpoint copied.');
    } catch (error) {
      setMcpError(errorMessage(error));
    }
  }

  async function copyMcpConfig() {
    if (mcpBusy || !window.wormhole) return;
    setMcpBusy(true);
    setMcpError('');
    try {
      const token = await window.wormhole.getMcpToken();
      await copyTextToClipboard(buildMcpConfig(mcpClient, mcpEndpoint, token));
      setMcpMessage('MCP client configuration copied with the current bearer token.');
    } catch (error) {
      setMcpError(errorMessage(error));
    } finally {
      setMcpBusy(false);
    }
  }

  async function openCurrentLogFile() {
    if (logsOpenBusy || retentionBusy || !window.wormhole) return;
    setLogsOpenBusy(true);
    setLogsError('');
    try {
      await window.wormhole.openCurrentLogFile();
    } catch (error) {
      setLogsError(logsErrorMessage(error));
    } finally {
      setLogsOpenBusy(false);
    }
  }

  async function openLogsFolder() {
    if (logsOpenBusy || retentionBusy || !window.wormhole) return;
    setLogsOpenBusy(true);
    setLogsError('');
    try {
      await window.wormhole.openLogsFolder();
    } catch (error) {
      setLogsError(logsErrorMessage(error));
    } finally {
      setLogsOpenBusy(false);
    }
  }

  async function commitLogRetention() {
    if (retentionBusy || !window.wormhole) return;
    const saved = logsInfo?.logRetentionDays ?? 14;
    const days = Number(retentionDays);
    if (!Number.isInteger(days) || days < 1 || days > 365) {
      setRetentionDays(String(saved));
      setLogsError('Log retention must be a whole number between 1 and 365 days.');
      return;
    }
    if (days === saved) return;
    setRetentionBusy(true);
    setLogsError('');
    try {
      const result = await window.wormhole.setLogRetentionDays(days);
      setRetentionDays(String(result.logRetentionDays));
      setLogsInfo((current) =>
        current ? { ...current, logRetentionDays: result.logRetentionDays } : current,
      );
    } catch (error) {
      setRetentionDays(String(saved));
      setLogsError(logsErrorMessage(error));
    } finally {
      setRetentionBusy(false);
    }
  }

  async function commitLogLevel(next: string) {
    if (retentionBusy || !window.wormhole) return;
    const saved = logsInfo?.logLevel ?? 'info';
    if (next !== 'info' && next !== 'debug') return;
    if (next === saved) return;
    setRetentionBusy(true);
    setLogsError('');
    try {
      const result = await window.wormhole.setLogLevel(next);
      setLogLevelState(result.logLevel);
      setLogsInfo((current) => (current ? { ...current, logLevel: result.logLevel } : current));
    } catch (error) {
      setLogLevelState(saved);
      setLogsError(logsErrorMessage(error));
    } finally {
      setRetentionBusy(false);
    }
  }

  function backupErrorMessage(error: unknown): string {
    if (!(error instanceof Error) || !error.message) {
      return "Wormhole couldn't complete the backup operation.";
    }
    if (/password is incorrect|wrong password/i.test(error.message)) {
      return 'Wrong password, or the backup file is corrupted. Try again.';
    }
    return error.message.replace(/^Error invoking remote method '[^']+': (?:Error: )?/, '');
  }

  function closeBackupExport(open: boolean) {
    if (open) {
      setBackupExportOpen(true);
      return;
    }
    if (backupExportBusy) return;
    setBackupExportOpen(false);
    setBackupExportPassword('');
    setBackupExportConfirmation('');
    setBackupExportError('');
    setBackupExportResult(null);
  }

  async function exportWormholeBackup() {
    if (backupExportBusy || !window.wormhole) return;
    if (!backupExportPasswordsMatch(backupExportPassword, backupExportConfirmation)) {
      setBackupExportError('The password confirmation does not match.');
      return;
    }
    setBackupExportBusy(true);
    setBackupExportError('');
    setBackupExportResult(null);
    try {
      const result = await window.wormhole.exportBackup(backupExportPassword);
      if (!result) return;
      setBackupExportResult(result);
      setBackupExportPassword('');
      setBackupExportConfirmation('');
    } catch (error) {
      setBackupExportError(backupErrorMessage(error));
    } finally {
      setBackupExportBusy(false);
    }
  }

  async function chooseBackupForImport() {
    if (backupImportPickerBusy || !window.wormhole) return;
    setBackupImportPickerBusy(true);
    setBackupSectionError('');
    try {
      const selection = await window.wormhole.selectBackupForImport();
      if (!selection) return;
      setBackupImportSelection(selection);
      setBackupImportPassword('');
      setBackupImportError('');
      setBackupImportResult(null);
      setBackupImportOpen(true);
    } catch (error) {
      if (backupAuthGateRef.current === 'unlocked') {
        setBackupSectionError(backupErrorMessage(error));
      }
    } finally {
      setBackupImportPickerBusy(false);
    }
  }

  function closeBackupImport(open: boolean) {
    if (open) {
      setBackupImportOpen(true);
      return;
    }
    if (backupImportBusy) return;
    setBackupImportOpen(false);
    setBackupImportPassword('');
    setBackupImportError('');
    setBackupImportResult(null);
    setBackupImportSelection(null);
    window.wormhole?.clearBackupImportSelection();
  }

  async function importWormholeBackup() {
    if (backupImportBusy || !window.wormhole || !backupImportSelection) return;
    setBackupImportBusy(true);
    setBackupImportError('');
    try {
      const result = await window.wormhole.importBackup(backupImportPassword);
      setBackupImportResult(result);
      setBackupImportPassword('');
      try {
        onBackupImported(await window.wormhole.loadWorkspace());
      } catch {
        setBackupImportError(
          'Import completed, but the workspace could not refresh. Restart Wormhole to show the imported items.',
        );
      }
    } catch (error) {
      setBackupImportError(backupErrorMessage(error));
    } finally {
      setBackupImportBusy(false);
    }
  }

  const selectedSecretMethod: WormholeAuthFallback | null =
    authMethod === 'disabled' ? null : authMethod === 'windowsHello' ? helloFallback : authMethod;
  const selectedSecretExists = selectedSecretMethod
    ? authStateHasSecret(authState, selectedSecretMethod)
    : false;
  const mcpEnabled = mcpState?.enabled ?? false;
  const mcpRunning = mcpState?.running ?? false;
  const mcpEndpoint = mcpState?.endpoint ?? `http://127.0.0.1:${mcpPort || 8765}/mcp`;
  const mcpConfig = buildMcpConfig(
    mcpClient,
    mcpEndpoint,
    mcpTokenRevealed && mcpToken ? mcpToken : mcpTokenPlaceholder,
  );
  const mcpConfigDetails = mcpClientCopyDetails(mcpClient);
  const updateAvailable = Boolean(
    update.result?.isUpdateAvailable &&
    update.result.latestVersion &&
    update.result.latestVersion !== update.skippedUpdateVersion,
  );
  const backupExportPasswordConfirmed = backupExportPasswordsMatch(
    backupExportPassword,
    backupExportConfirmation,
  );

  return (
    <section className="flex h-full min-h-0 flex-col overflow-hidden p-6">
      <h2 className="shrink-0 text-xl font-semibold tracking-tight">Settings</h2>

      <Tabs className="mt-4 min-h-0 flex-1 gap-0" onValueChange={setActiveTab} value={activeTab}>
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
              onCheckedChange={handlePromptBeforeTunnelConnectChange}
            />
          </SettingsSection>
        </SettingsTabPanel>

        <SettingsTabPanel value="security">
          <SettingsSection
            description="Ask for a PIN, password, or Windows Hello when Wormhole opens or is left idle."
            title="App lock"
          >
            <div className="space-y-2 rounded-lg border border-border/70 bg-card/40 p-3">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs font-medium">App lock</p>
                <Badge variant={authState?.configured ? 'default' : 'secondary'}>
                  {authState?.configured ? 'Enabled' : 'Disabled'}
                </Badge>
              </div>
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                {authState?.isCorrupted
                  ? "Wormhole can't read the saved lock. Set a new PIN or password."
                  : authState?.configured
                    ? `Unlock with ${authModeLabel(authState.mode)}.`
                    : 'Wormhole opens without asking you to unlock it.'}
              </p>
            </div>
            <div className="grid max-w-64 gap-2">
              <Label htmlFor="settings-auth-method">How to unlock</Label>
              <Select
                disabled={!authState || securityBusy}
                onValueChange={(value) => void handleAuthMethodChange(value)}
                value={authMethod}
              >
                <SelectTrigger id="settings-auth-method" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="disabled">Disabled</SelectItem>
                  <SelectItem value="pin">PIN</SelectItem>
                  <SelectItem value="password">Password</SelectItem>
                  <SelectItem value="windowsHello">Windows Hello</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {authMethod === 'windowsHello' && authState ? (
              <div className="space-y-3 rounded-lg border border-border/70 bg-card/40 p-3">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-medium">Windows Hello</p>
                  <Badge variant={authState.windowsHello.available ? 'default' : 'secondary'}>
                    {authState.windowsHello.available ? 'Available' : 'Unavailable'}
                  </Badge>
                </div>
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  {authState.windowsHello.message}
                </p>
                <div className="grid max-w-64 gap-2">
                  <Label htmlFor="settings-hello-fallback">If Windows Hello doesn't work</Label>
                  <Select
                    disabled={securityBusy}
                    onValueChange={(value) => void handleFallbackChange(value)}
                    value={helloFallback}
                  >
                    <SelectTrigger id="settings-hello-fallback" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="pin">PIN</SelectItem>
                      <SelectItem value="password">Password</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button
                  disabled={securityBusy}
                  onClick={() => void handleRefreshWindowsHello()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  <RefreshCcw data-icon="inline-start" />
                  Check again
                </Button>
              </div>
            ) : null}

            <div className="grid max-w-64 gap-2">
              <Label htmlFor="settings-idle-timeout">Auto-lock after</Label>
              <Select
                disabled={!authState || securityBusy}
                onValueChange={(value) => void handleIdleTimeoutChange(value)}
                value={idleTimeout === null ? 'none' : String(idleTimeout)}
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
              <Button
                disabled={!authState || authMethod === 'disabled' || securityBusy}
                onClick={() => void handleSetSecret()}
                size="sm"
                type="button"
              >
                {selectedSecretExists
                  ? `Change ${authSecretLabel(selectedSecretMethod!)}`
                  : `Set ${authSecretLabel(selectedSecretMethod ?? 'pin')}`}
              </Button>
              <Button
                disabled={!authState || securityBusy}
                onClick={() => void handleTestUnlock()}
                size="sm"
                type="button"
                variant="outline"
              >
                Test app lock
              </Button>
            </div>
            {securityError ? <p className="text-[11px] text-destructive">{securityError}</p> : null}
            {securityMessage ? (
              <p className="text-[11px] text-emerald-400">{securityMessage}</p>
            ) : null}
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
              <p className="text-[11px] text-muted-foreground">Bitwarden CLI is not connected.</p>
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
                No browser extension is installed.
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
            <p className="text-xs font-medium">
              Wormhole {update.currentVersion || '…'}
              {update.currentVersion ? ' · Electron build' : ''}
            </p>
            <p className="text-[11px] text-muted-foreground">
              {formatLastUpdateCheck(update.lastUpdateCheck)}
            </p>
            <SettingsSwitch
              checked={update.autoCheckForUpdates}
              description="Check for a newer Wormhole build when the app starts."
              label="Automatically check for updates on startup"
              onCheckedChange={onSetAutoCheckForUpdates}
            />
            {update.status ? (
              <p className="text-[11px] text-muted-foreground">{update.status}</p>
            ) : null}
            {update.downloadProgress !== null ? (
              <div className="max-w-sm">
                <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary transition-[width]"
                    style={{ width: `${Math.round(update.downloadProgress * 100)}%` }}
                  />
                </div>
              </div>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button disabled={update.busy} onClick={onCheckForUpdates} size="sm">
                Check now
              </Button>
              <Button
                disabled={update.busy || !updateAvailable}
                onClick={onInstallUpdate}
                size="sm"
              >
                Install update
              </Button>
              <Button
                disabled={!updateAvailable}
                onClick={onOpenReleaseNotes}
                size="sm"
                variant="outline"
              >
                View release notes
              </Button>
              {updateAvailable ? (
                <Button disabled={update.busy} onClick={onDismissUpdate} size="sm" variant="ghost">
                  Not now
                </Button>
              ) : null}
            </div>
            <Card className="border-border/70 bg-card/40 p-4 shadow-none">
              <p className="text-xs font-semibold">Release notes</p>
              {updateAvailable ? (
                <div className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                  <ReleaseNotesMarkdown markdown={update.result?.releaseNotes ?? ''} />
                </div>
              ) : (
                <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                  {update.result?.checkFailed
                    ? "Couldn't reach the update server. Try again later."
                    : update.result?.latestVersion
                      ? "You're on the latest version."
                      : 'Update information will appear here after the native update service reports a new release.'}
                </p>
              )}
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
                value={
                  logsInfo?.currentLogFilePath ??
                  '%LOCALAPPDATA%\\Wormhole\\logs\\wormhole-YYYYMMDD.log'
                }
              />
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                disabled={logsOpenBusy || retentionBusy}
                onClick={() => void openCurrentLogFile()}
                size="sm"
                type="button"
              >
                Open today&apos;s log
              </Button>
              <Button
                disabled={logsOpenBusy || retentionBusy}
                onClick={() => void openLogsFolder()}
                size="sm"
                type="button"
                variant="outline"
              >
                Open log folder
              </Button>
            </div>
          </SettingsSection>

          <SettingsSection title="Log level">
            <div className="grid max-w-52 gap-2">
              <Label htmlFor="settings-log-level">Detail level</Label>
              <Select
                disabled={retentionBusy}
                onValueChange={(value) => void commitLogLevel(value)}
                value={logLevel}
              >
                <SelectTrigger id="settings-log-level" size="sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="info">Info</SelectItem>
                  <SelectItem value="debug">Debug</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <p className="text-[11px] leading-relaxed text-muted-foreground">
              Info logs high-level events (boot, connections, tunnels, errors). Debug adds verbose
              per-operation detail for diagnosing failures. Changes apply immediately.
            </p>
            {logsError ? <p className="text-[11px] text-destructive">{logsError}</p> : null}
          </SettingsSection>

          <SettingsSection title="Rotation">
            <div className="grid max-w-52 gap-2">
              <Label htmlFor="settings-retention">Retain daily log files</Label>
              <Input
                disabled={retentionBusy}
                id="settings-retention"
                max="365"
                min="1"
                onBlur={() => void commitLogRetention()}
                onChange={(event) => setRetentionDays(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    event.preventDefault();
                    void commitLogRetention();
                  }
                }}
                type="number"
                value={retentionDays}
              />
            </div>
            <p className="text-[11px] leading-relaxed text-muted-foreground">
              Logs rotate daily. Retention changes are saved now and apply after restarting
              Wormhole.
            </p>
            {logsError ? <p className="text-[11px] text-destructive">{logsError}</p> : null}
          </SettingsSection>
        </SettingsTabPanel>

        <SettingsTabPanel value="backup">
          <SettingsSection title="Backup &amp; Restore">
            <p className="max-w-2xl text-xs leading-relaxed text-muted-foreground">
              Export your connections, credentials, SSH keys, and VPN tunnels to a JSON file, or
              restore a backup from another installation. Existing metadata and readable secrets are
              kept; missing or unreadable secrets can be repaired from the backup.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                disabled={backupImportPickerBusy}
                onClick={() => {
                  setBackupSectionError('');
                  setBackupExportError('');
                  setBackupExportResult(null);
                  setBackupExportOpen(true);
                }}
                size="sm"
                type="button"
              >
                <Download data-icon="inline-start" />
                Export backup…
              </Button>
              <Button
                disabled={backupImportPickerBusy}
                onClick={() => void chooseBackupForImport()}
                size="sm"
                type="button"
                variant="outline"
              >
                {backupImportPickerBusy ? (
                  <LoaderCircle className="animate-spin" data-icon="inline-start" />
                ) : (
                  <Upload data-icon="inline-start" />
                )}
                Import backup…
              </Button>
            </div>
            <p className="max-w-2xl text-[11px] leading-relaxed text-muted-foreground">
              Backups use the same schema as Wormhole for WinUI3. Add a password to encrypt every
              connection name and secret; plaintext exports contain readable credentials.
            </p>
            {backupSectionError ? (
              <p className="text-[11px] text-destructive">{backupSectionError}</p>
            ) : null}
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
              onCheckedChange={(checked) => void handleMcpToggle(checked)}
            />
            <div className="grid max-w-52 gap-2">
              <Label htmlFor="settings-mcp-port">Port</Label>
              <Input
                disabled={mcpBusy || mcpRunning}
                id="settings-mcp-port"
                onBlur={() => void commitMcpPort()}
                onChange={(event) => setMcpPort(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    event.preventDefault();
                    void commitMcpPort();
                  }
                }}
                max="65535"
                min="1"
                type="number"
                value={mcpPort}
              />
            </div>
            <p className="text-[11px] text-muted-foreground">
              {mcpRunning
                ? `Running — connect an MCP client to ${mcpEndpoint}`
                : mcpEnabled
                  ? 'MCP server is enabled and will start when the native backend is available.'
                  : 'Stopped'}
            </p>
            <div className="grid gap-2">
              <Label htmlFor="settings-mcp-endpoint">Endpoint</Label>
              <div className="flex gap-2">
                <Input
                  className="min-w-0"
                  id="settings-mcp-endpoint"
                  readOnly
                  value={mcpEndpoint}
                />
                <Button
                  className="shrink-0"
                  disabled={mcpBusy}
                  onClick={() => void copyMcpEndpoint()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
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
                  type={mcpTokenRevealed ? 'text' : 'password'}
                  value={mcpTokenRevealed ? mcpToken : ''}
                />
                <Button
                  disabled={mcpBusy}
                  onClick={() => void revealMcpToken()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  {mcpTokenRevealed ? 'Hide' : 'Reveal'}
                </Button>
                <Button
                  disabled={mcpBusy}
                  onClick={() => void copyMcpToken()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  Copy
                </Button>
                <Button
                  disabled={mcpBusy}
                  onClick={() => void regenerateMcpToken()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  Regenerate
                </Button>
              </div>
            </div>
            <div className="grid max-w-60 gap-2">
              <Label htmlFor="settings-mcp-client">Client</Label>
              <Select onValueChange={(value) => setMcpClient(value as McpClient)} value={mcpClient}>
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
              {mcpConfigDetails.caption}
            </p>
            <p className="text-[11px] leading-relaxed text-muted-foreground">
              Reveal the token first to view it here, or use Copy config to copy a ready-to-paste
              configuration with the current token.
            </p>
            <div className="grid gap-2">
              <Label htmlFor="settings-mcp-config">{mcpConfigDetails.label}</Label>
              <Textarea
                className="min-h-48 resize-none font-mono text-[11px]"
                id="settings-mcp-config"
                readOnly
                value={mcpConfig}
              />
              <Button
                className="w-fit"
                disabled={mcpBusy}
                onClick={() => void copyMcpConfig()}
                size="sm"
                type="button"
                variant="outline"
              >
                Copy config
              </Button>
            </div>
            {mcpError ? <p className="text-[11px] text-destructive">{mcpError}</p> : null}
            {mcpMessage ? <p className="text-[11px] text-emerald-400">{mcpMessage}</p> : null}
          </SettingsSection>
        </SettingsTabPanel>
      </Tabs>
      <Dialog onOpenChange={closeBackupExport} open={backupExportOpen}>
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Export backup</DialogTitle>
            <DialogDescription>
              Save all connection metadata and locally stored secrets in the WinUI-compatible
              Wormhole backup format.
            </DialogDescription>
          </DialogHeader>
          {backupExportResult ? (
            <div className="grid gap-4">
              <div className="flex gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
                <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-400" />
                <div className="grid gap-1">
                  <p className="text-xs font-medium">Backup exported</p>
                  <p className="text-[11px] leading-relaxed text-muted-foreground">
                    {backupExportResult.fileName} contains {backupExportResult.nodeCount} nodes,{' '}
                    {backupExportResult.credentialCount} credentials,{' '}
                    {backupExportResult.tunnelCount} tunnels, {backupExportResult.passwordCount}{' '}
                    password{backupExportResult.passwordCount === 1 ? '' : 's'},{' '}
                    {backupExportResult.privateKeyCount} private key
                    {backupExportResult.privateKeyCount === 1 ? '' : 's'}, and{' '}
                    {backupExportResult.tunnelPayloadCount} tunnel payload
                    {backupExportResult.tunnelPayloadCount === 1 ? '' : 's'}. The file is{' '}
                    {backupExportResult.encrypted ? 'encrypted' : 'plaintext'}.
                  </p>
                </div>
              </div>
              <DialogFooter>
                <Button onClick={() => closeBackupExport(false)} size="sm" type="button">
                  Close
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <form
              className="grid gap-4"
              onSubmit={(event) => {
                event.preventDefault();
                void exportWormholeBackup();
              }}
            >
              <div className="grid gap-2">
                <Label htmlFor="backup-export-password">Encryption password (optional)</Label>
                <Input
                  autoComplete="new-password"
                  autoFocus
                  disabled={backupExportBusy}
                  id="backup-export-password"
                  onChange={(event) => {
                    const password = event.target.value;
                    setBackupExportPassword(password);
                    if (password.length === 0) setBackupExportConfirmation('');
                  }}
                  placeholder="Leave blank for a plaintext backup"
                  type="password"
                  value={backupExportPassword}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="backup-export-confirmation">Confirm password</Label>
                <Input
                  autoComplete="new-password"
                  disabled={backupExportBusy || backupExportPassword.length === 0}
                  id="backup-export-confirmation"
                  onChange={(event) => setBackupExportConfirmation(event.target.value)}
                  type="password"
                  value={backupExportConfirmation}
                />
              </div>
              {backupExportPassword.length === 0 ? (
                <div className="flex gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
                  <AlertCircle className="mt-0.5 size-4 shrink-0 text-amber-400" />
                  <p className="text-[11px] leading-relaxed text-muted-foreground">
                    Without a password, connection names, passwords, private keys, and VPN payloads
                    are readable in the JSON file.
                  </p>
                </div>
              ) : !backupExportPasswordConfirmed ? (
                <p className="text-[11px] text-destructive">The passwords do not match.</p>
              ) : null}
              {backupExportError ? (
                <p className="text-[11px] text-destructive">{backupExportError}</p>
              ) : null}
              <DialogFooter>
                <Button
                  disabled={backupExportBusy}
                  onClick={() => closeBackupExport(false)}
                  size="sm"
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button
                  disabled={backupExportBusy || !backupExportPasswordConfirmed}
                  size="sm"
                  type="submit"
                >
                  {backupExportBusy ? (
                    <LoaderCircle className="animate-spin" data-icon="inline-start" />
                  ) : (
                    <Download data-icon="inline-start" />
                  )}
                  {backupExportBusy ? 'Exporting…' : 'Choose destination…'}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
      <Dialog onOpenChange={closeBackupImport} open={backupImportOpen}>
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Import backup</DialogTitle>
            <DialogDescription>
              Merge a Wormhole backup into this workspace. Existing metadata and readable secrets
              are preserved; missing or unreadable secrets can be repaired.
            </DialogDescription>
          </DialogHeader>
          {backupImportSelection ? (
            <div className="grid gap-4">
              <div className="rounded-lg border border-border/70 bg-muted/30 p-3">
                <p className="truncate text-xs font-medium">{backupImportSelection.fileName}</p>
                <p className="mt-1 text-[11px] text-muted-foreground">
                  Schema v{backupImportSelection.schemaVersion}
                  {backupImportSelection.exportedAt
                    ? ` · Exported ${new Date(backupImportSelection.exportedAt).toLocaleString()}`
                    : ''}
                  {' · '}
                  {backupImportSelection.encrypted ? 'Encrypted' : 'Plaintext'}
                </p>
              </div>
              {backupImportResult ? (
                <div className="grid gap-3">
                  <div className="flex gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
                    <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-400" />
                    <div className="grid gap-1">
                      <p className="text-xs font-medium">Import complete</p>
                      <p className="text-[11px] leading-relaxed text-muted-foreground">
                        {backupImportResult.nodesImported} nodes imported (
                        {backupImportResult.nodesSkipped} skipped),{' '}
                        {backupImportResult.credentialsImported} credentials imported (
                        {backupImportResult.credentialsSkipped} skipped), and{' '}
                        {backupImportResult.tunnelsImported} tunnels imported (
                        {backupImportResult.tunnelsSkipped} skipped). Restored{' '}
                        {backupImportResult.passwordsImported} password
                        {backupImportResult.passwordsImported === 1 ? '' : 's'},{' '}
                        {backupImportResult.privateKeysImported} private key
                        {backupImportResult.privateKeysImported === 1 ? '' : 's'}, and{' '}
                        {backupImportResult.tunnelPayloadsImported} tunnel payload
                        {backupImportResult.tunnelPayloadsImported === 1 ? '' : 's'}.
                      </p>
                    </div>
                  </div>
                  {backupImportResult.warnings.length > 0 ? (
                    <div className="grid gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
                      <p className="text-[11px] font-medium text-amber-300">
                        {backupImportResult.warnings.length} import warning
                        {backupImportResult.warnings.length === 1 ? '' : 's'}
                      </p>
                      <ul className="grid list-disc gap-1 pl-4 text-[10px] leading-relaxed text-muted-foreground">
                        {backupImportResult.warnings.slice(0, 5).map((warning, index) => (
                          <li key={`${index}:${warning}`}>{warning}</li>
                        ))}
                      </ul>
                      {backupImportResult.warnings.length > 5 ? (
                        <p className="text-[10px] text-muted-foreground">
                          +{backupImportResult.warnings.length - 5} more. See the Wormhole log for
                          the full list.
                        </p>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              ) : (
                <form
                  className="grid gap-4"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void importWormholeBackup();
                  }}
                >
                  {backupImportSelection.encrypted ? (
                    <div className="grid gap-2">
                      <Label htmlFor="backup-import-password">Backup password</Label>
                      <Input
                        autoComplete="current-password"
                        autoFocus
                        disabled={backupImportBusy}
                        id="backup-import-password"
                        onChange={(event) => setBackupImportPassword(event.target.value)}
                        type="password"
                        value={backupImportPassword}
                      />
                      <p className="text-[10px] leading-relaxed text-muted-foreground">
                        Enter the password used when this backup was exported.
                      </p>
                    </div>
                  ) : (
                    <div className="flex gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
                      <AlertCircle className="mt-0.5 size-4 shrink-0 text-amber-400" />
                      <p className="text-[11px] leading-relaxed text-muted-foreground">
                        This backup is plaintext. Its contents will still be restored into the
                        platform-protected Wormhole stores.
                      </p>
                    </div>
                  )}
                  <DialogFooter>
                    <Button
                      disabled={backupImportBusy}
                      onClick={() => closeBackupImport(false)}
                      size="sm"
                      type="button"
                      variant="ghost"
                    >
                      Cancel
                    </Button>
                    <Button
                      disabled={
                        backupImportBusy ||
                        (backupImportSelection.encrypted && backupImportPassword.length === 0)
                      }
                      size="sm"
                      type="submit"
                    >
                      {backupImportBusy ? (
                        <LoaderCircle className="animate-spin" data-icon="inline-start" />
                      ) : (
                        <Upload data-icon="inline-start" />
                      )}
                      {backupImportBusy ? 'Importing…' : 'Import backup'}
                    </Button>
                  </DialogFooter>
                </form>
              )}
              {backupImportError ? (
                <p className="text-[11px] text-destructive">{backupImportError}</p>
              ) : null}
              {backupImportResult ? (
                <DialogFooter>
                  <Button onClick={() => closeBackupImport(false)} size="sm" type="button">
                    Close
                  </Button>
                </DialogFooter>
              ) : null}
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
      <AuthSecretDialog
        busy={securityBusy}
        error={securityError}
        method={secretDialog ?? 'pin'}
        onOpenChange={closeSecretDialog}
        onSubmit={saveAuthSecret}
        open={secretDialog !== null}
      />
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
          <h2 className="text-xl font-semibold tracking-tight">{details.title}</h2>
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
