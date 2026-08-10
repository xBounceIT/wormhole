import {
  lazy,
  memo,
  Suspense,
  useCallback,
  useDeferredValue,
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
import { backupExportPasswordsMatch } from './backup-state';
import wormholeIcon from '../Assets/Wormhole.png';
import bitwardenIcon from '../Assets/Bitwarden/bitwarden-icon.png';
import {
  credentialCanUseProtocol,
  effectiveSshAutoSudoMode,
  mergeCredential,
  sshAutoSudoAvailable,
  type CredentialKind,
} from './credential-state';
import {
  createLogLevelSaveState,
  drainLogLevelChanges,
  isLogLevel,
  type LogLevel,
} from './log-level-settings';
import {
  bitwardenCliIsLoggedIn,
  bitwardenCliServerRegionCode,
  formatBitwardenCurrentServerLabel,
  formatBitwardenLoginStatus,
  formatBitwardenSyncResult,
  formatBitwardenVaultStatus,
} from './bitwarden-cli-view';
import { writeClipboardText } from './clipboard';
import { buildMcpConfig, type McpClient } from './mcp-config';
import {
  hasNewerReleaseWithoutInstaller,
  isUpdateInstallable,
  shouldOfferUpdate,
} from './update-state';
import {
  normalizeTerminalPasteText,
  shouldAutoCopyTerminalSelection,
  shouldUseTerminalClipboardShortcut,
} from './terminal-clipboard';
import { failedSshReconnectState, reconnectingSshState } from './ssh-reconnect-state';
import {
  canSplitSession,
  createSessionLayout,
  focusSessionPane,
  moveSession,
  reconcileSessionLayout,
  restoreSessionFullView,
  selectSession,
  sessionPaneRects,
  sessionPanes,
  sessionSplitDividers,
  setSessionSplitRatio,
  splitSession,
  type SessionLayoutEdge,
  type SessionLayoutState,
  type SessionPane,
  type SessionPaneRect,
  type SessionSplitDivider,
} from './session-layout';
import {
  filterListSearchIndex,
  listSearchResultsArePending,
  normalizeListSearch,
} from './list-search';
import {
  parentLocalSftpPath,
  parentSftpPath,
  isLocalSftpPathRoot,
  isInvalidLocalSftpDropDestination,
  isSftpTransferTerminal,
  isValidSftpNameInput,
  joinLocalSftpPath,
  shouldApplySftpClosed,
  shouldApplySftpError,
  shouldApplySftpFailure,
  shouldApplySftpReady,
  shouldFinishSftpClose,
  shouldRefreshSftpPane,
  nextSftpOperationRefreshRequests,
  nextSftpSelection,
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
  Database,
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
  Maximize2,
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
  TriangleAlert,
  X,
  XCircle,
  Zap,
} from 'lucide-react';
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
  canonicalizeConnectionTreeNodeIds,
  isEditableConnectionTreeShortcutTarget,
  resolveConnectionTreeShortcut,
  resolveVisibleConnectionTreeSelection,
} from './tree-shortcuts';
import {
  quickConnectStartsImmediately,
  quickConnectTunnelId,
  type QuickConnectProtocol,
} from './quick-connect-state';
import { KeyedRetryQueue } from './keyed-retry-queue';
import {
  isBitwardenUnlockError,
  requiresRdpCredentialPrompt,
  requiresSshKeyPassphrasePrompt,
  sshCredentialPromptTarget,
} from './runtime-credential-errors';
import { RdpSurface } from './components/RdpSurface';
import { ConnectionStepper } from './components/ConnectionStepper';
import { SearchableCombobox, type SearchableComboboxOption } from './components/SearchableCombobox';
import { VirtualCardGrid } from './components/VirtualCardGrid';
import { applyTheme, getSystemTheme, isTheme, type ResolvedTheme, type Theme } from './theme';
import {
  applyRdpBackendEvent,
  applyRdpSystemClientOpenFailure,
  type RdpUiStatus,
} from './rdp-state';
import { formatSftpDate, formatSftpSize } from './sftp-format';
import { hasSftpDragPayload, sftpDragDataType } from './sftp-dnd';
import { cn } from '@/lib/utils';
import { WebSessionAttemptTracker } from '../electron/web-session-attempt';
import {
  canDisconnectRemoteDesktopSession,
  canOpenRdpSystemClient,
  connectedTabCloseMessage,
  disconnectedRemoteDesktopState,
  isSessionActive,
  nextSelectedSessionId,
  reconnectingVncState,
  sessionRuntimeRetryKeys,
  SessionCloseGate,
  SessionResourceReleaseGate,
  shouldConfirmConnectedTabClose,
} from './session-lifecycle';
import {
  createDebouncedSidebarWriter,
  maxSidebarWidth,
  minSidebarWidth,
  normalizeSidebarWidth,
} from './sidebar-settings';
import {
  appendTunnelTestLog,
  isTunnelTestCancellation,
  isTunnelTestNotice,
  missingTunnelFields,
  normalizeTunnelEditorSettings,
  parseTunnelProbeTarget,
  tunnelTestPhaseLabel,
  tunnelModeFor,
  tunnelValueFor,
  updateTunnelEditorSetting,
  userFacingTunnelError,
  watchguardEditorSettingsFromDetails,
  watchguardUsesSso,
  type TunnelMode,
} from './tunnel-state';

const MRemoteImportDialog = lazy(() =>
  import('./components/MRemoteImportDialog').then((module) => ({
    default: module.MRemoteImportDialog,
  })),
);
const VncSurface = lazy(() =>
  import('./components/VncSurface').then((module) => ({
    default: module.VncSurface,
  })),
);
const WebSurface = lazy(() =>
  import('./components/WebSurface').then((module) => ({
    default: module.WebSurface,
  })),
);

type Protocol = QuickConnectProtocol;
type CredentialProtocol = Extract<Protocol, 'ssh' | 'rdp' | 'vnc'>;
type AutoSudoMode = 'inherit' | 'on' | 'off';
type CredentialSelection = 'inherit' | 'none' | string;
type FolderForm = {
  name: string;
  sshAutoSudo: AutoSudoMode;
  tunnel: TunnelMode;
  credential: CredentialSelection;
};

function blankFolderForm(): FolderForm {
  return {
    name: '',
    sshAutoSudo: 'inherit',
    tunnel: 'inherit',
    credential: 'inherit',
  };
}
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

const defaultRdpSettings: WormholeWorkspaceRdpSettings = {
  domain: '',
  screenSize: 'fitToWindow',
  fullScreen: false,
  colorDepth: 32,
  useAllMonitors: false,
  audioMode: 0,
  audioCaptureMode: 0,
  keyboardHookMode: 2,
  redirectClipboard: true,
  redirectPrinters: false,
  redirectSmartCards: false,
  redirectPorts: false,
  redirectDevices: false,
  redirectDrives: '',
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
  gatewayUsageMethod: 0,
  gatewayHostname: '',
  gatewayCredentialId: '',
  gatewayBypassLocal: true,
  gatewayUseSameCreds: false,
  useExternalClient: false,
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
  username?: string;
  hasInlineCredential?: boolean;
  rdp?: WormholeWorkspaceRdpSettings;
  serialBaudRate?: number;
  serialDataBits?: number;
  serialStopBits?: number;
  serialParity?: number;
  serialFlowControl?: number;
  httpIgnoreCertErrors?: boolean;
  sshAutoSudo?: boolean | null;
  tunnelEnabled?: boolean | null;
  tunnelConfigId?: string;
  credentialMode?: number;
  credentialId?: string;
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
      ? {
          ...node,
          children: insertIntoTreeFolder(node.children, folderId, children),
        }
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
  credentialId?: string;
  sshAutoSudo?: boolean;
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
  rdpExternal?: boolean;
  rdpProfile?: WormholeRdpProfile;
  rdpSystemClientSupported?: boolean;
  vncConnectionGeneration?: number;
  webTargetNodeId?: string;
  webIgnoreCertErrors?: boolean;
  webUrl?: string;
  webCanGoBack?: boolean;
  webCanGoForward?: boolean;
  webIsLoading?: boolean;
  bitwardenPopupUrl?: string;
};

type RdpCredentials = {
  username: string;
  domain: string;
  password: string;
};

type SshCredentials = {
  username: string;
  password: string;
};

type SshStartRequest = {
  sessionId: string;
  nodeId?: string;
  host?: string;
  port?: number;
  username?: string;
  password?: string;
  credentialId?: string;
  autoSudo?: boolean;
  tunnelConfigId?: string;
  manualCredentials?: boolean;
  keyPassphrase?: string;
  manualKeyPassphrase?: boolean;
  frontendSessionId?: string;
};

type CredentialRecord = {
  id: string;
  name: string;
  protocol: Protocol;
  kind: CredentialKind;
  username: string;
  domain?: string;
  provider: 'Local' | 'Bitwarden';
  canEdit: boolean;
  canDelete: boolean;
  bitwardenItemId?: string;
  bitwardenItemName?: string;
  privateKeyFileName?: string;
  isVirtualBitwarden?: boolean;
};

type CredentialOptionGroups = Record<CredentialProtocol, CredentialRecord[]>;

const manualCredentialSelectionValue = '__manual__';

function workspaceCredentialOptions(workspace: WormholeWorkspaceSnapshot): CredentialOptionGroups {
  return {
    ssh: (workspace.credentialOptions.ssh as CredentialRecord[]).filter((credential) =>
      credentialCanUseProtocol(credential.kind, 'ssh'),
    ),
    rdp: (workspace.credentialOptions.rdp as CredentialRecord[]).filter((credential) =>
      credentialCanUseProtocol(credential.kind, 'rdp'),
    ),
    vnc: (workspace.credentialOptions.vnc as CredentialRecord[]).filter((credential) =>
      credentialCanUseProtocol(credential.kind, 'vnc'),
    ),
  };
}

function isCredentialProtocol(protocol: Protocol): protocol is CredentialProtocol {
  return protocol === 'ssh' || protocol === 'rdp' || protocol === 'vnc';
}

function mergeCredentialOption(
  groups: CredentialOptionGroups,
  credential: CredentialRecord,
): CredentialOptionGroups {
  const next = {
    ssh: groups.ssh.filter((candidate) => candidate.id !== credential.id),
    rdp: groups.rdp.filter((candidate) => candidate.id !== credential.id),
    vnc: groups.vnc.filter((candidate) => candidate.id !== credential.id),
  };
  if (
    !isCredentialProtocol(credential.protocol) ||
    !credentialCanUseProtocol(credential.kind, credential.protocol)
  ) {
    return next;
  }
  next[credential.protocol] = mergeCredential(
    next[credential.protocol].filter(
      (candidate) =>
        !(
          candidate.isVirtualBitwarden &&
          credential.bitwardenItemId &&
          candidate.bitwardenItemId === credential.bitwardenItemId
        ),
    ),
    credential,
  );
  return next;
}

type CredentialDialogState =
  | { kind: 'credentials'; result: WormholeWorkspaceCredentialReveal }
  | { kind: 'error'; message: string };
type CredentialCopyField = 'username' | 'secret';

function CredentialProviderIcon({
  provider,
  kind,
}: {
  provider: CredentialRecord['provider'];
  kind: CredentialRecord['kind'];
}) {
  const isBitwarden = provider === 'Bitwarden';
  const label = isBitwarden
    ? 'Stored in Bitwarden'
    : kind === 'sshKey'
      ? "Stored in Wormhole's encrypted local key storage"
      : "Stored in Wormhole's local credential database";

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          aria-label={label}
          className="inline-flex size-7 shrink-0 items-center justify-center rounded-md border border-border/70 bg-background shadow-xs outline-none transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring/50"
          role="img"
          tabIndex={0}
        >
          {isBitwarden ? (
            <img alt="" className="size-4 rounded-[3px]" draggable={false} src={bitwardenIcon} />
          ) : (
            <Database aria-hidden="true" className="size-4 text-muted-foreground" />
          )}
        </span>
      </TooltipTrigger>
      <TooltipContent side="bottom">{label}</TooltipContent>
    </Tooltip>
  );
}

type CredentialDraft = {
  name: string;
  protocol: 'ssh' | 'rdp' | 'vnc';
  kind: Extract<CredentialKind, 'password' | 'sshKey'>;
  username: string;
  domain: string;
  password: string;
  passphrase: string;
  clearPassphrase: boolean;
  privateKeySelectionId: string;
  privateKeyFileName: string;
  provider: 'Local' | 'Bitwarden';
  bitwardenItemId: string;
  bitwardenItemName: string;
};

function emptyCredentialDraft(): CredentialDraft {
  return {
    name: '',
    protocol: 'ssh',
    kind: 'password',
    username: '',
    domain: '',
    password: '',
    passphrase: '',
    clearPassphrase: false,
    privateKeySelectionId: '',
    privateKeyFileName: '',
    provider: 'Local',
    bitwardenItemId: '',
    bitwardenItemName: '',
  };
}

function credentialSelectionFor(node: Pick<TreeNode, 'credentialMode' | 'credentialId'>) {
  if (node.credentialMode === 1) return 'none';
  if ((node.credentialMode === 2 || node.credentialMode == null) && node.credentialId) {
    return node.credentialId;
  }
  return 'inherit';
}

function credentialSettingsFor(selection: CredentialSelection): {
  mode: 0 | 1 | 2;
  credentialId: string;
} {
  if (selection === 'inherit') return { mode: 0, credentialId: '' };
  if (selection === 'none') return { mode: 1, credentialId: '' };
  return { mode: 2, credentialId: selection };
}

function backendErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function formatLocalDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
}

function formatBitwardenExtensionStatus(state: WormholeBitwardenExtensionState): string {
  if (!state.enabled) return 'Disabled';
  if (!state.installed) {
    return 'Not installed. Wormhole will install the official Bitwarden browser extension automatically.';
  }
  const sourceLabel =
    state.source === 'ManualZip'
      ? 'manual ZIP, pinned'
      : state.source === 'ManualFolder'
        ? 'manual folder, pinned'
        : 'official release, auto-update enabled';
  const parts = [
    `Installed ${state.installed.version} (${sourceLabel}). HTTPS tabs will load the Bitwarden extension.`,
  ];
  if (state.lastUpdateCheckUtc) {
    parts.push(`Last update check: ${formatLocalDateTime(state.lastUpdateCheckUtc)}.`);
  }
  if (state.lastUpdateStatus) parts.push(state.lastUpdateStatus);
  if (state.availableVersion) parts.push(`Available version: ${state.availableVersion}.`);
  if (state.lastUpdateError) parts.push(`Last update error: ${state.lastUpdateError}.`);
  return parts.join(' ');
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

function measuredRdpSurfaceBounds(sessionId: string): WormholeRdpSurfaceRect | undefined {
  const surface = [...document.querySelectorAll<HTMLElement>('[data-rdp-session-id]')].find(
    (candidate) => candidate.dataset.rdpSessionId === sessionId,
  );
  if (!surface) return undefined;
  const rect = surface.getBoundingClientRect();
  if (rect.width < 1 || rect.height < 1) return undefined;
  return { x: rect.left, y: rect.top, width: rect.width, height: rect.height };
}

async function waitForRdpSurfaceBounds(
  sessionId: string,
): Promise<WormholeRdpSurfaceRect | undefined> {
  const measured = measuredRdpSurfaceBounds(sessionId);
  if (measured) return measured;
  await new Promise<void>((resolve) => window.requestAnimationFrame(() => resolve()));
  return measuredRdpSurfaceBounds(sessionId);
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
    // React Doctor mistakes this fresh local buffer for React state. It is copied above and never
    // aliases the previous frame.
    // react-doctor-disable-next-line react-doctor/no-side-effect-in-state-updater-function
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
  return {
    ssh: 'SSH',
    rdp: 'RDP',
    http: 'HTTP',
    https: 'HTTPS',
    vnc: 'VNC',
    serial: 'Serial',
  }[protocol];
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
  scope: 'connection' | 'folder' | 'quick';
}) {
  const isFolder = scope === 'folder';
  const isQuick = scope === 'quick';
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
          {isQuick ? null : <SelectItem value="inherit">{inheritLabel}</SelectItem>}
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
              <Copy />
              Duplicate connection
            </ContextMenuItem>
            <ContextMenuSeparator />
          </>
        ) : null}
        <ContextMenuItem onSelect={onEdit}>
          <Pencil />
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
  onRestoreFullView,
  onDisconnect,
  onDuplicate,
  onOpenSystemRdp,
  onClose,
  onFileTransfer,
}: {
  session: Session;
  children: ReactNode;
  onReconnect: () => void;
  onRestoreFullView?: () => void;
  onDisconnect: () => void;
  onDuplicate: () => void;
  onOpenSystemRdp: () => void;
  onClose: () => void;
  onFileTransfer: () => void;
}) {
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
      <ContextMenuContent className="w-64">
        <ContextMenuItem onSelect={onDuplicate}>
          <Copy />
          Duplicate
        </ContextMenuItem>
        <ContextMenuItem onSelect={onReconnect}>
          <RefreshCcw />
          Reconnect
        </ContextMenuItem>
        {onRestoreFullView ? (
          <ContextMenuItem onSelect={onRestoreFullView}>
            <Maximize2 />
            Restore full view
          </ContextMenuItem>
        ) : null}
        {canDisconnectRemoteDesktopSession(session) ? (
          <ContextMenuItem onSelect={onDisconnect}>
            <Power />
            Disconnect
          </ContextMenuItem>
        ) : null}
        {canOpenRdpSystemClient(session) ? (
          <ContextMenuItem onSelect={onOpenSystemRdp}>
            <Monitor />
            Open in System Remote Desktop
          </ContextMenuItem>
        ) : null}
        {session.canTransfer === true && session.status === 'connected' ? (
          <ContextMenuItem onSelect={onFileTransfer}>
            <FolderOpen />
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

const nodeTooltipDelayMs = 300;

function NodeTooltip({ node, children }: { node: TreeNode; children: ReactNode }) {
  const host = node.host;
  const anchorRef = useRef<HTMLDivElement>(null);
  const openTimer = useRef<number | undefined>(undefined);
  const clearOpenTimer = useCallback(() => {
    if (openTimer.current !== undefined) window.clearTimeout(openTimer.current);
    openTimer.current = undefined;
  }, []);

  useEffect(
    () => () => {
      clearOpenTimer();
      void window.wormhole?.hideTreeTooltip();
    },
    [clearOpenTimer],
  );
  if (!host) return children;

  const scheduleOpen = () => {
    clearOpenTimer();
    openTimer.current = window.setTimeout(() => {
      openTimer.current = undefined;
      const anchor = anchorRef.current;
      if (!anchor) return;
      const bounds = anchor.getBoundingClientRect();
      const context = document.createElement('canvas').getContext('2d');
      if (context) context.font = getComputedStyle(anchor).font;
      const textWidth = context?.measureText(host).width ?? host.length * 7;
      void window.wormhole?.showTreeTooltip({
        text: host,
        anchor: {
          x: bounds.x,
          y: bounds.y,
          width: bounds.width,
          height: bounds.height,
        },
        width: Math.min(328, Math.max(48, Math.ceil(textWidth) + 29)),
      });
    }, nodeTooltipDelayMs);
  };
  const close = () => {
    clearOpenTimer();
    void window.wormhole?.hideTreeTooltip();
  };

  return (
    <div
      ref={anchorRef}
      onBlurCapture={close}
      onFocusCapture={scheduleOpen}
      onPointerEnter={scheduleOpen}
      onPointerLeave={close}
    >
      {children}
    </div>
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
  const activeHelloRequest = useRef<string | null>(null);
  const helloInFlight = useRef<string | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const onResultRef = useRef(onResult);
  const method: WormholeAuthFallback =
    state.mode === 'password' || (state.mode === 'windowsHello' && state.fallback === 'password')
      ? 'password'
      : 'pin';
  const isHelloMode = state.mode === 'windowsHello';
  const fallbackName = method === 'pin' ? 'Wormhole PIN' : 'Wormhole password';
  const helloRequestKey = `${request.kind}\0${request.reason}\0${request.autoWindowsHello}\0${isHelloMode}\0${method}`;

  useLayoutEffect(() => {
    onResultRef.current = onResult;
  }, [onResult]);

  const tryWindowsHello = useCallback(
    (requestKey = helloRequestKey) => {
      if (helloInFlight.current === requestKey || !window.wormhole) return;

      const api = window.wormhole;
      const isCurrent = () => activeHelloRequest.current === requestKey;
      helloInFlight.current = requestKey;
      setHelloBusy(true);
      setStatus('Waiting for Windows Hello…');
      return api
        .checkWindowsHello()
        .then((availability) => {
          if (!isCurrent()) return;
          if (!availability.available) {
            setStatus(`${availability.message} You can use your ${fallbackName} instead.`);
            return;
          }
          return api.verifyWindowsHello().then((result) => {
            if (!isCurrent()) return;
            if (result.succeeded) {
              onResultRef.current(true);
              return;
            }
            setStatus(
              result.message || `Windows Hello didn't recognize you. Use your ${fallbackName}.`,
            );
          });
        })
        .catch(() => {
          if (isCurrent()) {
            setStatus(`Windows Hello isn't available right now. Use your ${fallbackName}.`);
          }
        })
        .finally(() => {
          if (helloInFlight.current === requestKey) helloInFlight.current = null;
          if (isCurrent()) setHelloBusy(false);
        });
    },
    [fallbackName, helloRequestKey],
  );

  useEffect(() => {
    activeHelloRequest.current = helloRequestKey;
    setSecret('');
    setStatus('');
    if (request.autoWindowsHello && isHelloMode) {
      void tryWindowsHello(helloRequestKey);
    }
    return () => {
      if (activeHelloRequest.current === helloRequestKey) activeHelloRequest.current = null;
    };
  }, [helloRequestKey, request.autoWindowsHello, isHelloMode, tryWindowsHello]);

  useLayoutEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    dialog.showModal();
    return () => dialog.close();
  }, []);

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
    <dialog
      ref={dialogRef}
      aria-describedby="auth-prompt-description"
      aria-labelledby="auth-prompt-title"
      className="fixed inset-0 z-[100] m-0 h-auto max-h-none w-auto max-w-none border-0 bg-background/85 p-5 backdrop-blur-md open:flex open:items-center open:justify-center"
      onCancel={(event) => {
        event.preventDefault();
        if (request.kind === 'confirmation') onResult(false);
      }}
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
    </dialog>
  );
}

type WormholeAppProps = {
  initialAuthState: WormholeAuthState;
  initialWorkspace: WormholeWorkspaceSnapshot;
  initialSettings: WormholeAppSettings;
};

const connectionTreeShortcutPortaledWidgetSelector = [
  '[data-slot="context-menu-content"][data-state="open"]',
  '[data-slot="context-menu-sub-content"][data-state="open"]',
  '[data-slot="dropdown-menu-content"][data-state="open"]',
  '[data-slot="dropdown-menu-sub-content"][data-state="open"]',
  '[data-slot="popover-content"][data-state="open"]',
  '[data-slot="select-content"][data-state="open"]',
].join(', ');

function useLazyRef<T>(initializer: () => T): { current: T } {
  const ref = useRef<T | null>(null);
  // This is React's documented lazy-ref initialization pattern: the same object is retained after
  // the first render and the initializer is not observable outside this component.
  // react-doctor-disable-next-line react-doctor/no-ref-current-in-render
  if (ref.current === null) ref.current = initializer();
  return ref as { current: T };
}

function getTreeDropPlacement(event: DragEvent<HTMLDivElement>, node: TreeNode): DropPlacement {
  const bounds = event.currentTarget.getBoundingClientRect();
  const position = (event.clientY - bounds.top) / Math.max(bounds.height, 1);

  if (node.kind === 'folder' && position > 0.25 && position < 0.75) return 'inside';
  return position < 0.5 ? 'before' : 'after';
}

function savedSerialNodeId(nodeId: string | undefined): string | undefined {
  return nodeId && !nodeId.startsWith('connection-') ? nodeId : undefined;
}

function defaultRdpProfile(session: Session): WormholeRdpProfile {
  if (session.nodeId) {
    // Go reloads the complete saved/inherited profile and its protected credentials from this
    // identity. Renderer values are intentionally limited to safe routing metadata.
    return {
      nodeId: session.nodeId,
      name: session.title,
      host: session.host,
      port: session.port,
    };
  }
  return {
    ...session.rdpProfile,
    nodeId: session.nodeId,
    name: session.title,
    host: session.host,
    port: session.port,
    screenSize: session.rdpProfile?.screenSize ?? 'Full connection content',
    colorDepth: session.rdpProfile?.colorDepth ?? 32,
    redirectClipboard: session.rdpProfile?.redirectClipboard ?? true,
    connectionSpeed: session.rdpProfile?.connectionSpeed ?? 7,
    desktopBackground: session.rdpProfile?.desktopBackground ?? true,
    fontSmoothing: session.rdpProfile?.fontSmoothing ?? true,
    desktopComposition: session.rdpProfile?.desktopComposition ?? true,
    windowDrag: session.rdpProfile?.windowDrag ?? true,
    menuAnimation: session.rdpProfile?.menuAnimation ?? true,
    visualStyles: session.rdpProfile?.visualStyles ?? true,
    bitmapCaching: session.rdpProfile?.bitmapCaching ?? true,
    autoReconnect: session.rdpProfile?.autoReconnect ?? true,
    serverAuthentication: session.rdpProfile?.serverAuthentication ?? 2,
    gatewayBypassLocal: session.rdpProfile?.gatewayBypassLocal ?? true,
    tunnelConfigId: session.tunnelConfigId,
    tunnelEnabled: session.tunnelConfigId ? true : undefined,
  };
}

function authSettingsErrorMessage(error: unknown): string {
  if (error instanceof Error && /^(PIN|Password) (must|can)/.test(error.message)) {
    return error.message;
  }
  return "Wormhole couldn't save this change. Try again.";
}

function backupOperationErrorMessage(error: unknown): string {
  if (!(error instanceof Error) || !error.message) {
    return "Wormhole couldn't complete the backup operation.";
  }
  if (/password is incorrect|wrong password/i.test(error.message)) {
    return 'Wrong password, or the backup file is corrupted. Try again.';
  }
  return error.message.replace(/^Error invoking remote method '[^']+': (?:Error: )?/, '');
}

// App owns independent, long-lived desktop domains (workspace, auth, sessions, tunnels, and
// updates). Folding those state machines into one reducer would couple unrelated transitions, and
// splitting the coordinator would duplicate the native lifecycle boundary across components.
// react-doctor-disable-next-line react-doctor/no-giant-component, react-doctor/prefer-useReducer
function App({ initialAuthState, initialWorkspace, initialSettings }: WormholeAppProps) {
  const [theme, setTheme] = useState<Theme>(initialSettings.theme);
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(getSystemTheme);
  const [tree, setTree] = useState<TreeNode[]>(initialWorkspace.tree);
  const treeRef = useRef(tree);
  useLayoutEffect(() => {
    treeRef.current = tree;
  }, [tree]);
  const [credentials, setCredentials] = useState<CredentialRecord[]>(initialWorkspace.credentials);
  const [credentialOptions, setCredentialOptions] = useState<CredentialOptionGroups>(() =>
    workspaceCredentialOptions(initialWorkspace),
  );
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
  const lastActivityAt = useLazyRef(Date.now);
  const quickConnectSubmitInFlight = useRef(false);
  const sshCredentialSubmitInFlight = useRef(false);
  const webSessionAttempts = useLazyRef(() => new WebSessionAttemptTracker());
  const webSessionOpenInFlight = useRef(new Map<string, number>());
  const rdpSavedCredentialAttempts = useRef(new Set<string>());
  const [runtimeBitwardenRetries] = useState(() => new KeyedRetryQueue<string>());
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
  const sessionsRef = useRef(sessions);
  useLayoutEffect(() => {
    sessionsRef.current = sessions;
  }, [sessions]);
  const [selectedSessionId, setSelectedSessionId] = useState('');
  const [rdpCredentialPrompt, setRdpCredentialPrompt] = useState<string | null>(null);
  const [rdpCredentialForm, setRdpCredentialForm] = useState<RdpCredentials>({
    username: '',
    domain: '',
    password: '',
  });
  const [rdpCredentialSelection, setRdpCredentialSelection] = useState(
    manualCredentialSelectionValue,
  );
  const [rdpCredentialSave, setRdpCredentialSave] = useState(false);
  const [sshCredentialPrompt, setSshCredentialPrompt] = useState<{
    kind: 'saved' | 'quick';
    backendSessionId?: string;
    nodeId?: string;
    sessionId?: string;
  } | null>(null);
  const [sshCredentialForm, setSshCredentialForm] = useState<SshCredentials>({
    username: '',
    password: '',
  });
  const [sshCredentialSelection, setSshCredentialSelection] = useState(
    manualCredentialSelectionValue,
  );
  const [sshCredentialSave, setSshCredentialSave] = useState(false);
  const [sshCredentialPromptBusy, setSshCredentialPromptBusy] = useState(false);
  const [rdpCredentialPromptBusy, setRdpCredentialPromptBusy] = useState(false);
  const [sshKeyPassphrasePrompt, setSshKeyPassphrasePrompt] = useState<SshStartRequest | null>(
    null,
  );
  const [sshKeyPassphrase, setSshKeyPassphrase] = useState('');
  const [bitwardenUnlockPrompt, setBitwardenUnlockPrompt] = useState<{
    reason: string;
  } | null>(null);
  const [bitwardenUnlockPassword, setBitwardenUnlockPassword] = useState('');
  const [bitwardenUnlockBusy, setBitwardenUnlockBusy] = useState(false);
  const [bitwardenUnlockError, setBitwardenUnlockError] = useState('');
  const [mremoteImportOpen, setMremoteImportOpen] = useState(false);
  const [newConnectionOpen, setNewConnectionOpen] = useState(false);
  const [connectionEditorMode, setConnectionEditorMode] = useState<'saved' | 'quick'>('saved');
  const [editingConnectionId, setEditingConnectionId] = useState<string | null>(null);
  const [folderDetailsOpen, setFolderDetailsOpen] = useState(false);
  const editingFolderId = useRef<string | null>(null);
  const editingFolderGeneration = useRef(0);
  const [folderDetailsForm, setFolderDetailsForm] = useState<FolderForm>(blankFolderForm);
  const [editorError, setEditorError] = useState('');
  const [editorBusy, setEditorBusy] = useState(false);
  const [credentialDialog, setCredentialDialog] = useState<CredentialDialogState | null>(null);
  const [copiedCredentialField, setCopiedCredentialField] = useState<CredentialCopyField | null>(
    null,
  );
  const credentialRevealBusy = useRef(false);
  const credentialRevealRequest = useRef(0);
  const copiedCredentialTimer = useRef<number | undefined>(undefined);
  const [pendingDeleteNodes, setPendingDeleteNodes] = useState<TreeNode[]>([]);
  const [deleteNodeBusy, setDeleteNodeBusy] = useState(false);
  const [deleteNodeError, setDeleteNodeError] = useState('');
  const [newConnectionForm, setNewConnectionForm] = useState({
    name: '',
    host: '',
    port: '',
    username: '',
    inlinePassword: '',
    protocol: 'ssh' as Protocol,
    folder: '',
    sshAutoSudo: 'inherit' as AutoSudoMode,
    httpIgnoreCertErrors: false,
    tunnel: 'inherit' as TunnelMode,
    useSavedCredentials: true,
    credential: 'inherit' as CredentialSelection,
    serial: { ...defaultSerialSettings },
    rdp: { ...defaultRdpSettings },
  });
  const [rdpExternalClientRequired, setRdpExternalClientRequired] = useState(false);
  const rdpExternalClientRequirementRequest = useRef(0);
  const [newFolderOpen, setNewFolderOpen] = useState(false);
  const [newFolderForm, setNewFolderForm] = useState<FolderForm>(blankFolderForm);
  const newFolderParentId = useRef<string | null>(null);
  const newFolderGeneration = useRef(0);
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
  const [autoCopyOnSelect, setAutoCopyOnSelect] = useState(initialSettings.autoCopyOnSelect);
  const [confirmOnTabClose, setConfirmOnTabClose] = useState(initialSettings.confirmOnTabClose);
  const [pendingSessionClose, setPendingSessionClose] = useState<{
    id: string;
    preferredNextSessionId?: string;
  } | null>(null);
  const [sessionCloseBusy, setSessionCloseBusy] = useState(false);
  const [pendingWindowClose, setPendingWindowClose] = useState<{
    activeSessionCount: number;
    action: 'window' | 'quit';
    resolve: (confirmed: boolean) => void;
  } | null>(null);
  const [windowCloseBusy, setWindowCloseBusy] = useState(false);
  const sidebarWidth = normalizeSidebarWidth(initialSettings.sidebarWidth);
  const sidebarWriter = useMemo(
    () =>
      createDebouncedSidebarWriter(
        (width) => window.wormhole?.setSidebarWidth(width).then(() => undefined),
        { initialWidth: initialSettings.sidebarWidth },
      ),
    [initialSettings.sidebarWidth],
  );
  const sessionCloseGate = useLazyRef(() => new SessionCloseGate());
  const sessionDisconnectGate = useLazyRef(() => new SessionCloseGate());
  const sessionResourceReleaseGate = useLazyRef(() => new SessionResourceReleaseGate());
  const rdpSessionAttempts = useLazyRef(() => new WebSessionAttemptTracker());
  const rdpCapabilityAttempts = useLazyRef(() => new WebSessionAttemptTracker());
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

  useEffect(() => () => sidebarWriter.cancel(), [sidebarWriter]);
  useEffect(() => {
    const requestId = ++rdpExternalClientRequirementRequest.current;
    if (!newConnectionOpen || newConnectionForm.protocol !== 'rdp' || !window.wormhole) {
      setRdpExternalClientRequired(false);
      return;
    }
    const credentialId =
      newConnectionForm.useSavedCredentials &&
      newConnectionForm.credential !== 'inherit' &&
      newConnectionForm.credential !== 'none'
        ? newConnectionForm.credential
        : undefined;
    const inheritedFromNodeId =
      newConnectionForm.useSavedCredentials &&
      newConnectionForm.credential === 'inherit' &&
      newConnectionForm.folder
        ? newConnectionForm.folder
        : undefined;
    const timer = window.setTimeout(() => {
      void window.wormhole
        ?.rdpExternalClientRequirement({
          username: newConnectionForm.username,
          domain: newConnectionForm.rdp.domain,
          credentialId,
          inheritedFromNodeId,
        })
        .then((result) => {
          if (rdpExternalClientRequirementRequest.current === requestId) {
            setRdpExternalClientRequired(result.required);
          }
        })
        .catch(() => {
          if (rdpExternalClientRequirementRequest.current === requestId) {
            setRdpExternalClientRequired(false);
          }
        });
    }, 200);
    return () => window.clearTimeout(timer);
  }, [
    newConnectionForm.credential,
    newConnectionForm.folder,
    newConnectionForm.protocol,
    newConnectionForm.rdp.domain,
    newConnectionForm.useSavedCredentials,
    newConnectionForm.username,
    newConnectionOpen,
  ]);
  const activeSessionCount = useMemo(() => sessions.filter(isSessionActive).length, [sessions]);
  useEffect(() => {
    window.wormhole?.reportActiveSessionCount(activeSessionCount);
  }, [activeSessionCount]);
  const folders = useMemo(() => collectFolders(tree), [tree]);
  const folderSelectionOptions = useMemo<SearchableComboboxOption[]>(
    () => [
      { value: rootFolderSelectionValue, label: 'Root' },
      ...folders.map((folder) => ({ value: folder.id, label: folder.name })),
    ],
    [folders],
  );
  const connectionCredentialSelectionOptions = useMemo<SearchableComboboxOption[]>(() => {
    const options = isCredentialProtocol(newConnectionForm.protocol)
      ? credentialOptions[newConnectionForm.protocol]
      : [];
    return [
      { value: 'inherit', label: 'Inherit from folder' },
      { value: 'none', label: 'No saved credential' },
      ...options.map((credential) => ({
        value: credential.id,
        label: `${credential.name} · ${credential.provider}`,
      })),
    ];
  }, [credentialOptions, newConnectionForm.protocol]);
  const selectedConnectionCredential = useMemo(() => {
    const selection = newConnectionForm.credential;
    if (selection === 'inherit' || selection === 'none') return undefined;
    return credentials.find((credential) => credential.id === selection);
  }, [credentials, newConnectionForm.credential]);
  const canConfigureConnectionSshAutoSudo =
    newConnectionForm.protocol === 'ssh' &&
    sshAutoSudoAvailable(newConnectionForm.useSavedCredentials, selectedConnectionCredential?.kind);
  const folderCredentialOptions = useMemo(() => {
    const byID = new Map<string, CredentialRecord>();
    for (const protocol of ['ssh', 'rdp', 'vnc'] as const) {
      for (const credential of credentialOptions[protocol]) byID.set(credential.id, credential);
    }
    return [...byID.values()].sort((left, right) => left.name.localeCompare(right.name));
  }, [credentialOptions]);
  const folderCredentialSelectionOptions = useMemo<SearchableComboboxOption[]>(
    () => [
      { value: 'inherit', label: 'Inherit from parent folder' },
      { value: 'none', label: 'No saved credential' },
      ...folderCredentialOptions.map((credential) => ({
        value: credential.id,
        label: `${credential.name} · ${protocolLabel(credential.protocol)} · ${credential.provider}`,
      })),
    ],
    [folderCredentialOptions],
  );
  const runtimeCredentialSelectionOptions = useMemo<
    Record<'ssh' | 'rdp', SearchableComboboxOption[]>
  >(
    () => ({
      ssh: [
        { value: manualCredentialSelectionValue, label: 'Enter manually' },
        ...credentialOptions.ssh.map((credential) => ({
          value: credential.id,
          label: credential.name,
        })),
      ],
      rdp: [
        { value: manualCredentialSelectionValue, label: 'Enter manually' },
        ...credentialOptions.rdp.map((credential) => ({
          value: credential.id,
          label: credential.name,
        })),
      ],
    }),
    [credentialOptions],
  );
  const selectedSession =
    sessions.find((session) => session.id === selectedSessionId) ?? sessions[0];
  const resolvedTheme = theme === 'system' ? systemTheme : theme;

  useLayoutEffect(() => {
    applyTheme(resolvedTheme);
  }, [resolvedTheme]);

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
    updateResult && shouldOfferUpdate(updateResult, skippedUpdateVersion),
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
            : hasNewerReleaseWithoutInstaller(result)
              ? `Wormhole ${result.latestVersion} is available, but no verified installer is published for this platform.`
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

  function handleAutoCopyOnSelectChange(enabled: boolean) {
    setAutoCopyOnSelect(enabled);
    void window.wormhole?.setAutoCopyOnSelect(enabled).catch(() => {
      // Keep the responsive local value; the next launch re-syncs the persisted setting.
    });
  }

  function handleThemeChange(nextTheme: Theme) {
    setTheme(nextTheme);
    void window.wormhole?.setTheme(nextTheme).catch(() => {
      // Keep the responsive local value; the next launch re-syncs the persisted setting.
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
      const platform = window.wormhole.platform;
      setUpdateStatus(platform === 'linux' ? 'Opening download location…' : 'Launching installer…');
      const installation = await window.wormhole.installUpdate(installerPath);
      if (installation.appWillQuit) return;
      setUpdateStatus(
        platform === 'darwin'
          ? 'Installer opened. Drag Wormhole to Applications to finish the update.'
          : 'AppImage downloaded. Replace your current AppImage with the verified download.',
      );
      setUpdateBusy(false);
      setUpdateDownloadProgress(null);
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
    window.addEventListener('touchstart', markActivity, { passive: true });
    return () => {
      window.removeEventListener('keydown', markActivity);
      window.removeEventListener('pointerdown', markActivity);
      window.removeEventListener('touchstart', markActivity);
    };
  }, [lastActivityAt]);

  useEffect(() => {
    const unsubscribe = window.wormhole?.onSshEvent((event) => {
      if (event.type === 'sftp.transfer') {
        const terminalBatch =
          event.transferState === 'batch-failed' ||
          event.transferState === 'batch-completed' ||
          event.transferState === 'batch-cancelled';
        if (terminalBatch) {
          clearSftpCancelRequestsForTransfer(sftpCancelRequests.current, event.transferId);
        } else if (event.itemId) {
          const itemKey = sftpTransferItemKey(event.transferId, event.itemId);
          if (sftpCancelRequests.current.has(itemKey)) {
            if (
              event.transferState === 'completed' ||
              event.transferState === 'failed' ||
              event.transferState === 'cancelled'
            ) {
              sftpCancelRequests.current.delete(itemKey);
            }
            return;
          }
        }
      }
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
          if (event.type === 'reconnecting') {
            return { ...session, ...reconnectingSshState(event) };
          }
          if (event.type === 'reconnect-failed') {
            return { ...session, ...failedSshReconnectState(event) };
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
            const knownOperationIds = {
              ...(session.sftp.knownOperationIds ?? {}),
            };
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
              const knownTransferIds = {
                ...(session.sftp.knownTransferIds ?? {}),
              };
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
                  ? {
                      expected: event.hostKeyExpected,
                      received: event.hostKeyReceived,
                    }
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
        if (Math.max(systemIdle.seconds, localIdle) >= (timeoutMinutes ?? 0) * 60) {
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
  }, [authGate, authState, lastActivityAt]);

  useEffect(() => {
    if (authGate === 'unlocked') return;
    credentialRevealRequest.current += 1;
    if (copiedCredentialTimer.current !== undefined) {
      window.clearTimeout(copiedCredentialTimer.current);
      copiedCredentialTimer.current = undefined;
    }
    sftpRequestIds.current.clear();
    sftpCancelRequests.current.clear();
    setMremoteImportOpen(false);
    window.wormhole?.clearMRemoteImport();
    setSshCredentialPrompt(null);
    setNewConnectionForm((form) => ({ ...form, inlinePassword: '' }));
    setNewConnectionOpen(false);
    setFolderDetailsOpen(false);
    setNewFolderOpen(false);
    setEditingConnectionId(null);
    editingFolderId.current = null;
    editingFolderGeneration.current += 1;
    setSshCredentialPrompt(null);
    setSshCredentialForm({ username: '', password: '' });
    setSshKeyPassphrasePrompt(null);
    setSshKeyPassphrase('');
    setRdpCredentialPrompt(null);
    setRdpCredentialForm({ username: '', domain: '', password: '' });
    rdpSavedCredentialAttempts.current.clear();
    runtimeBitwardenRetries.clear();
    setBitwardenUnlockPrompt(null);
    setBitwardenUnlockPassword('');
    setBitwardenUnlockError('');
    newFolderParentId.current = null;
    newFolderGeneration.current += 1;
    setEditorError('');
    setCredentialDialog(null);
    setCopiedCredentialField(null);
    setPendingDeleteNodes([]);
    setDeleteNodeError('');
    setSessions((current) => {
      if (!current.some((session) => session.sftp)) return current;
      return current.map((session) => ({ ...session, sftp: undefined }));
    });
    setMcpApprovals([]);
  }, [authGate, runtimeBitwardenRetries]);

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
      const savedCredentialFailure =
        rdpSavedCredentialAttempts.current.has(event.sessionId) && event.credentialFailure === true;
      if (savedCredentialFailure) {
        rdpSavedCredentialAttempts.current.delete(event.sessionId);
        setRdpCredentialForm({ username: '', domain: '', password: '' });
        setRdpCredentialSelection(manualCredentialSelectionValue);
        setRdpCredentialSave(false);
        setRdpCredentialPrompt(event.sessionId);
      }
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
              webIsLoading: false,
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
            webIsLoading: event.isLoading,
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
  }, [webSessionAttempts]);

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
      const target = event.target instanceof Element ? event.target : null;
      const editableTarget = target?.closest<HTMLElement>(
        'input, textarea, select, [contenteditable]:not([contenteditable="false"])',
      );
      const action = resolveConnectionTreeShortcut(event, {
        unlocked: authGate === 'unlocked',
        dialogOpen: Boolean(document.querySelector('[role="dialog"], [role="alertdialog"]')),
        editableTarget: isEditableConnectionTreeShortcutTarget({
          tagName: editableTarget?.tagName,
          isContentEditable:
            editableTarget?.isContentEditable ||
            (target instanceof HTMLElement && target.isContentEditable),
        }),
        portaledWidgetOpen: Boolean(
          document.querySelector(connectionTreeShortcutPortaledWidgetSelector),
        ),
        withinTree: Boolean(target?.closest('[data-connection-tree-shortcut-scope]')),
        deleteBusy: deleteNodeBusy,
        tree,
        visibleTree,
        selectedNodeId,
        selectedNodeIds: [...selectedTreeNodeIds],
      });
      if (!action) return;

      event.preventDefault();
      if (action.kind === 'quick-connect') {
        openQuickConnect();
      } else if (action.kind === 'new-folder') {
        openNewFolder(action.parentFolderId);
      } else if (action.kind === 'new-connection') {
        openNewConnection(action.parentFolderId);
      } else if (action.kind === 'delete') {
        openDeleteNodes(action.nodeIds);
      } else {
        const node = findTreeNode(tree, action.nodeId);
        if (!node) return;
        if (action.kind === 'edit') openEditNode(node);
        else openConnection(node);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  });

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
    const next = new Set(selectedTreeNodeIds);
    if (checked) next.add(id);
    else next.delete(id);
    setSelectedTreeNodeIds(next);
    setSelectedNodeId(checked ? id : ([...next].at(-1) ?? ''));
  }

  function updateTreeSearchText(value: string) {
    setSearchText(value);
    setSelectedTreeNodeIds(new Set());
    setSelectedNodeId('');
  }

  function getDraggedNodeIds(node: TreeNode): string[] {
    if (!selectedTreeNodeIds.has(node.id)) return [node.id];

    const selectedNodes: TreeNode[] = [];
    for (const id of selectedTreeNodeIds) {
      const selected = findTreeNode(tree, id);
      if (selected) selectedNodes.push(selected);
    }

    const topLevelIds: string[] = [];
    for (const selected of selectedNodes) {
      const nested = selectedNodes.some(
        (ancestor) => ancestor.id !== selected.id && containsTreeNode(ancestor, selected.id),
      );
      if (!nested) topLevelIds.push(selected.id);
    }
    return topLevelIds;
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

  function startSshSession(request: SshStartRequest) {
    const api = window.wormhole;
    if (!api) {
      setSessions((current) =>
        current.map((session) =>
          session.backendSessionId === request.sessionId
            ? {
                ...session,
                status: 'failed',
                error: 'The SSH service is unavailable.',
              }
            : session,
        ),
      );
      return;
    }

    const { frontendSessionId, ...nativeRequest } = request;
    void api
      .openSshSession({
        ...nativeRequest,
        columns: 80,
        rows: 24,
      })
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        if (requiresSshKeyPassphrasePrompt(message) && !request.manualKeyPassphrase) {
          setSshKeyPassphrase('');
          setSshKeyPassphrasePrompt(request);
        } else if (isBitwardenUnlockError(message)) {
          requestRuntimeBitwardenUnlock(`ssh:${request.sessionId}`, message, () =>
            startSshSession(request),
          );
        } else {
          const promptTarget = sshCredentialPromptTarget(request, message);
          if (promptTarget === 'saved' && request.nodeId) {
            setSshCredentialForm({ username: '', password: '' });
            setSshCredentialSelection(manualCredentialSelectionValue);
            setSshCredentialSave(false);
            setSshCredentialPrompt({
              kind: 'saved',
              backendSessionId: request.sessionId,
              nodeId: request.nodeId,
            });
          } else if (promptTarget === 'quick') {
            const sessionId =
              frontendSessionId ??
              sessionsRef.current.find(
                (candidate) => candidate.backendSessionId === request.sessionId,
              )?.id;
            if (sessionId) {
              setSshCredentialForm({ username: '', password: '' });
              setSshCredentialSelection(manualCredentialSelectionValue);
              setSshCredentialSave(false);
              setSshCredentialPrompt({ kind: 'quick', sessionId });
            }
          }
        }
        setSessions((current) =>
          current.map((session) =>
            session.backendSessionId === request.sessionId
              ? {
                  ...session,
                  status: 'failed',
                  error: message,
                }
              : session,
          ),
        );
      });
  }

  function submitSshKeyPassphrase(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const request = sshKeyPassphrasePrompt;
    if (!request || !sshKeyPassphrase) return;
    const passphrase = sshKeyPassphrase;
    setSshKeyPassphrasePrompt(null);
    setSshKeyPassphrase('');
    setSessions((current) =>
      current.map((session) =>
        session.backendSessionId === request.sessionId
          ? { ...session, status: 'connecting', error: undefined }
          : session,
      ),
    );
    startSshSession({
      ...request,
      keyPassphrase: passphrase,
      manualKeyPassphrase: true,
    });
  }

  async function submitSshCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const prompt = sshCredentialPrompt;
    if (!prompt || sshCredentialPromptBusy) return;
    const selectedCredentialID =
      sshCredentialSelection === manualCredentialSelectionValue ? '' : sshCredentialSelection;
    if (!selectedCredentialID && !sshCredentialForm.username.trim()) return;
    const credentials = {
      username: sshCredentialForm.username.trim(),
      password: sshCredentialForm.password,
    };
    setSshCredentialPromptBusy(true);
    try {
      if (prompt.kind === 'saved' && prompt.nodeId && sshCredentialSave) {
        await saveRuntimeConnectionCredential(
          prompt.nodeId,
          'ssh',
          selectedCredentialID,
          credentials,
        );
      }
      setSshCredentialPrompt(null);
      setSshCredentialForm({ username: '', password: '' });
      if (prompt.kind === 'quick' && prompt.sessionId) {
        sshCredentialSubmitInFlight.current = true;
        startQuickSshSession(prompt.sessionId, credentials, selectedCredentialID || undefined);
        return;
      }
      if (!prompt.backendSessionId || !prompt.nodeId) return;
      setSessions((current) =>
        current.map((session) =>
          session.backendSessionId === prompt.backendSessionId
            ? { ...session, status: 'connecting', error: undefined }
            : session,
        ),
      );
      startSshSession({
        sessionId: prompt.backendSessionId,
        nodeId: prompt.nodeId,
        credentialId: !sshCredentialSave && selectedCredentialID ? selectedCredentialID : undefined,
        manualCredentials: !sshCredentialSave && !selectedCredentialID,
        username: !sshCredentialSave && !selectedCredentialID ? credentials.username : undefined,
        password: !sshCredentialSave && !selectedCredentialID ? credentials.password : undefined,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Could not save SSH credentials.';
      setSessions((current) =>
        current.map((session) =>
          session.backendSessionId === prompt.backendSessionId
            ? { ...session, status: 'failed', error: message }
            : session,
        ),
      );
    } finally {
      setSshCredentialPromptBusy(false);
    }
  }

  function requestRuntimeBitwardenUnlock(key: string, reason: string, retry: () => void) {
    const isFirst = runtimeBitwardenRetries.upsert(key, retry);
    if (isFirst) {
      setBitwardenUnlockPassword('');
      setBitwardenUnlockError('');
    }
    setBitwardenUnlockPrompt((current) => current ?? { reason });
  }

  function dismissRuntimeBitwardenUnlock() {
    runtimeBitwardenRetries.clear();
    setBitwardenUnlockPrompt(null);
    setBitwardenUnlockPassword('');
    setBitwardenUnlockError('');
  }

  async function submitRuntimeBitwardenUnlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const prompt = bitwardenUnlockPrompt;
    if (!prompt || !window.wormhole || bitwardenUnlockBusy) return;
    setBitwardenUnlockBusy(true);
    setBitwardenUnlockError('');
    const masterPassword = bitwardenUnlockPassword;
    setBitwardenUnlockPassword('');
    try {
      await window.wormhole.unlockBitwardenCli(masterPassword);
      try {
        await refreshWorkspaceCredentials();
      } catch {
        // The vault session is already valid. A transient catalog refresh failure must not keep
        // live connections blocked; the next workspace refresh will reconcile the visible list.
      }
      const retries = runtimeBitwardenRetries.drain();
      setBitwardenUnlockPrompt(null);
      for (const retry of retries) retry();
    } catch (error: unknown) {
      setBitwardenUnlockError(
        error instanceof Error ? error.message : 'Bitwarden could not unlock the vault.',
      );
    } finally {
      setBitwardenUnlockBusy(false);
    }
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
            ? {
                ...session,
                status: 'failed',
                error: 'The serial service is unavailable.',
              }
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

  function startWebSession(session: Session) {
    if (webSessionOpenInFlight.current.has(session.id)) return;
    const generation = webSessionAttempts.current.begin(session.id);
    webSessionOpenInFlight.current.set(session.id, generation);
    const api = window.wormhole;
    if (!api) {
      webSessionOpenInFlight.current.delete(session.id);
      setSessions((current) =>
        webSessionAttempts.current.isCurrent(session.id, generation)
          ? current.map((candidate) =>
              candidate.id === session.id
                ? {
                    ...candidate,
                    status: 'failed',
                    error: 'The web session service is unavailable.',
                  }
                : candidate,
            )
          : current,
      );
      return;
    }

    const request = session.webTargetNodeId
      ? {
          sessionId: session.id,
          attempt: generation,
          nodeId: session.webTargetNodeId,
        }
      : {
          sessionId: session.id,
          attempt: generation,
          address: session.host,
          port: session.port,
          protocol: session.protocol as 'http' | 'https',
          ignoreCertErrors: session.webIgnoreCertErrors === true,
          tunnelConfigId: session.tunnelConfigId,
        };

    void api
      .openWebSession(request)
      .then(
        (target) => {
          setSessions((current) =>
            webSessionAttempts.current.isCurrent(session.id, generation)
              ? current.map((candidate) =>
                  candidate.id === session.id
                    ? {
                        ...candidate,
                        webUrl: target.url,
                        webIgnoreCertErrors: target.ignoreCertErrors,
                        bitwardenPopupUrl: target.bitwarden?.popupUrl,
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
      )
      .finally(() => {
        if (webSessionOpenInFlight.current.get(session.id) === generation) {
          webSessionOpenInFlight.current.delete(session.id);
        }
      });
  }

  async function closeWebSession(sessionId: string): Promise<void> {
    webSessionOpenInFlight.current.delete(sessionId);
    webSessionAttempts.current.cancel(sessionId);
    await window.wormhole?.closeWebSession(sessionId);
  }

  async function requestRdpCredentials(sessionId: string) {
    const session = sessionsRef.current.find((candidate) => candidate.id === sessionId);
    if (!session || session.protocol !== 'rdp') return;
    setSelectedSessionId(sessionId);
    setActivePage('sessions');
    if (session.nodeId || session.credentialId) {
      startRdpSession(sessionId, { username: '', domain: '', password: '' }, false);
      return;
    }
    setRdpCredentialForm({ username: '', domain: '', password: '' });
    setRdpCredentialSelection(manualCredentialSelectionValue);
    setRdpCredentialSave(false);
    setRdpCredentialPrompt(sessionId);
  }

  function startRdpSession(
    sessionId: string,
    credentials: RdpCredentials,
    manualCredentials: boolean,
    credentialIdOverride?: string,
  ) {
    const session = sessionsRef.current.find((candidate) => candidate.id === sessionId);
    if (!session || session.protocol !== 'rdp') return;
    const attempt = rdpSessionAttempts.current.begin(sessionId);

    const normalizedCredentials = {
      username: credentials.username.trim(),
      domain: credentials.domain.trim(),
      password: credentials.password,
    };
    if (manualCredentials) {
      rdpSavedCredentialAttempts.current.delete(sessionId);
    } else {
      rdpSavedCredentialAttempts.current.add(sessionId);
    }
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === sessionId
          ? {
              ...candidate,
              rdpStatus: 'starting',
              rdpError: undefined,
              tunnelProgress: null,
              rdpProfile: defaultRdpProfile(candidate),
            }
          : candidate,
      ),
    );

    const wormhole = window.wormhole;
    if (!wormhole) {
      setSessions((current) =>
        current.map((candidate) =>
          candidate.id === sessionId
            ? {
                ...candidate,
                rdpStatus: 'failed',
                rdpError: 'The RDP service is unavailable.',
              }
            : candidate,
        ),
      );
      return;
    }

    void waitForRdpSurfaceBounds(sessionId)
      .then((bounds) => {
        // Opening a saved connection creates and starts its tab in one event. Wait one frame for
        // that tab's real layout so the native host never centers prompts or initializes the
        // remote desktop from the backend's 1x1 startup placeholder.
        if (
          !rdpSessionAttempts.current.isCurrent(sessionId, attempt) ||
          !sessionsRef.current.some(
            (candidate) => candidate.id === sessionId && candidate.protocol === 'rdp',
          )
        ) {
          return;
        }
        return wormhole.startRdpSession({
          sessionId,
          profile: {
            ...defaultRdpProfile(session),
            credentialId: !session.nodeId
              ? (credentialIdOverride ?? session.rdpProfile?.credentialId)
              : undefined,
            credentialIdOverride:
              session.nodeId && credentialIdOverride ? credentialIdOverride : undefined,
            username: manualCredentials ? normalizedCredentials.username || undefined : undefined,
            domain: manualCredentials ? normalizedCredentials.domain || undefined : undefined,
            password: manualCredentials ? normalizedCredentials.password || undefined : undefined,
          },
          bounds,
          manualCredentials,
        });
      })
      .catch((error: unknown) => {
        if (!rdpSessionAttempts.current.isCurrent(sessionId, attempt)) return;
        const message = error instanceof Error ? error.message : 'The RDP service could not start.';
        if (isBitwardenUnlockError(message)) {
          requestRuntimeBitwardenUnlock(`rdp:${sessionId}`, message, () =>
            manualCredentials
              ? requestRdpCredentials(sessionId)
              : startRdpSession(sessionId, normalizedCredentials, false, credentialIdOverride),
          );
        } else if (!manualCredentials && requiresRdpCredentialPrompt(message)) {
          rdpSavedCredentialAttempts.current.delete(sessionId);
          setRdpCredentialForm({ username: '', domain: '', password: '' });
          setRdpCredentialSelection(manualCredentialSelectionValue);
          setRdpCredentialSave(false);
          setRdpCredentialPrompt(sessionId);
        }
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
    void (async () => {
      const source = sessionsRef.current.find((session) => session.id === sessionId);
      if (!source || source.protocol !== 'rdp') return;
      if (canDisconnectRemoteDesktopSession(source)) {
        if (!(await disconnectRemoteDesktopSession(sessionId))) return;
      }
      await requestRdpCredentials(sessionId);
    })();
  }

  const refreshRdpSystemClientCapability = useCallback(
    (sessionId: string, nodeId: string | undefined) => {
      if (!nodeId) return;
      const attempt = rdpCapabilityAttempts.current.begin(sessionId);
      setSessions((current) =>
        current.map((session) =>
          session.id === sessionId && session.protocol === 'rdp' && session.nodeId === nodeId
            ? { ...session, rdpSystemClientSupported: false }
            : session,
        ),
      );
      const api = window.wormhole;
      if (!api) return;
      void api
        .getRdpSystemClientCapability({ nodeId })
        .then((capability) => {
          if (!rdpCapabilityAttempts.current.isCurrent(sessionId, attempt)) return;
          setSessions((current) =>
            current.map((session) =>
              session.id === sessionId && session.protocol === 'rdp' && session.nodeId === nodeId
                ? { ...session, rdpSystemClientSupported: capability.supported }
                : session,
            ),
          );
        })
        .catch(() => {
          if (!rdpCapabilityAttempts.current.isCurrent(sessionId, attempt)) return;
          setSessions((current) =>
            current.map((session) =>
              session.id === sessionId && session.protocol === 'rdp'
                ? { ...session, rdpSystemClientSupported: false }
                : session,
            ),
          );
        });
    },
    [rdpCapabilityAttempts],
  );

  useLayoutEffect(() => {
    for (const session of sessionsRef.current) {
      if (session.protocol === 'rdp' && session.nodeId) {
        refreshRdpSystemClientCapability(session.id, session.nodeId);
      }
    }
  }, [refreshRdpSystemClientCapability, tree]);

  async function disconnectRemoteDesktopSession(sessionId: string): Promise<boolean> {
    const source = sessionsRef.current.find((session) => session.id === sessionId);
    if (!source || !canDisconnectRemoteDesktopSession(source)) return false;
    if (source.protocol === 'rdp') rdpSessionAttempts.current.cancel(sessionId);

    let disconnected = false;
    const ran = await sessionDisconnectGate.current.run(sessionId, async () => {
      try {
        const api = window.wormhole;
        if (!api) throw new Error('The remote desktop service is unavailable.');
        if (source.protocol === 'rdp') {
          await api.commandRdpSession({ sessionId, operation: 'disconnect' });
          rdpSavedCredentialAttempts.current.delete(sessionId);
          if (rdpCredentialPrompt === sessionId) setRdpCredentialPrompt(null);
        } else {
          const response = await api.sendVncCommand({
            action: 'vnc.disconnect',
            sessionId,
          });
          if (!response.ok) {
            throw new Error(response.error || 'The VNC disconnect request could not be completed.');
          }
        }
        for (const key of sessionRuntimeRetryKeys(source)) {
          runtimeBitwardenRetries.remove(key);
        }
        setSessions((current) =>
          current.map((session) =>
            session.id === sessionId
              ? {
                  ...session,
                  ...disconnectedRemoteDesktopState(session),
                  error: undefined,
                  rdpError: undefined,
                  tunnelProgress: null,
                }
              : session,
          ),
        );
        disconnected = true;
      } catch (error) {
        const message =
          error instanceof Error ? error.message : 'The session could not disconnect.';
        setSessions((current) =>
          current.map((session) =>
            session.id === sessionId
              ? session.protocol === 'rdp'
                ? { ...session, rdpStatus: 'failed', rdpError: message }
                : { ...session, error: message }
              : session,
          ),
        );
      }
    });
    return ran && disconnected;
  }

  async function openRdpInSystemClient(sessionId: string) {
    const source = sessionsRef.current.find((session) => session.id === sessionId);
    if (!source?.nodeId || !canOpenRdpSystemClient(source)) return;
    const api = window.wormhole;
    if (!api) return;
    const attempt = rdpSessionAttempts.current.begin(sessionId);
    rdpSavedCredentialAttempts.current.delete(sessionId);
    if (rdpCredentialPrompt === sessionId) setRdpCredentialPrompt(null);
    try {
      const result = await api.openRdpInSystemClient({
        sessionId,
        nodeId: source.nodeId,
      });
      if (!rdpSessionAttempts.current.isCurrent(sessionId, attempt) || result.ok) return;
      setSessions((current) =>
        current.map((session) =>
          session.id === sessionId
            ? applyRdpSystemClientOpenFailure(session, result.error, result.lifecycleCommitted)
            : session,
        ),
      );
      refreshRdpSystemClientCapability(sessionId, source.nodeId);
    } catch (error) {
      if (!rdpSessionAttempts.current.isCurrent(sessionId, attempt)) return;
      const message =
        error instanceof Error ? error.message : 'System Remote Desktop could not start.';
      setSessions((current) =>
        current.map((session) =>
          session.id === sessionId
            ? applyRdpSystemClientOpenFailure(session, message, false)
            : session,
        ),
      );
      refreshRdpSystemClientCapability(sessionId, source.nodeId);
    }
  }

  async function submitRdpCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!rdpCredentialPrompt || rdpCredentialPromptBusy) return;
    const sessionId = rdpCredentialPrompt;
    const credentials = rdpCredentialForm;
    const source = sessionsRef.current.find((session) => session.id === sessionId);
    const selectedCredentialID =
      rdpCredentialSelection === manualCredentialSelectionValue ? '' : rdpCredentialSelection;
    if (!selectedCredentialID && !credentials.username.trim()) return;
    setRdpCredentialPromptBusy(true);
    try {
      if (source?.nodeId && rdpCredentialSave) {
        await saveRuntimeConnectionCredential(
          source.nodeId,
          'rdp',
          selectedCredentialID,
          credentials,
        );
      }
      setRdpCredentialPrompt(null);
      setRdpCredentialForm({ username: '', domain: '', password: '' });
      if (source && canDisconnectRemoteDesktopSession(source)) {
        if (!(await disconnectRemoteDesktopSession(sessionId))) return;
      }
      startRdpSession(
        sessionId,
        credentials,
        !rdpCredentialSave && !selectedCredentialID,
        !rdpCredentialSave ? selectedCredentialID || undefined : undefined,
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Could not save RDP credentials.';
      setSessions((current) =>
        current.map((session) =>
          session.id === sessionId
            ? { ...session, rdpStatus: 'failed', rdpError: message }
            : session,
        ),
      );
    } finally {
      setRdpCredentialPromptBusy(false);
    }
  }

  function requestSshCredentials(sessionId: string) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session || session.protocol !== 'ssh' || session.nodeId) return;
    sshCredentialSubmitInFlight.current = false;
    setSshCredentialForm({ username: '', password: '' });
    setSshCredentialSelection(manualCredentialSelectionValue);
    setSshCredentialSave(false);
    setSshCredentialPrompt({ kind: 'quick', sessionId });
    setSelectedSessionId(sessionId);
    setActivePage('sessions');
  }

  function startQuickSshSession(
    sessionId: string,
    credentials: SshCredentials,
    credentialId?: string,
  ) {
    const session = sessions.find((candidate) => candidate.id === sessionId);
    if (!session || session.protocol !== 'ssh' || session.nodeId) return;

    const backendSessionId = newSessionToken();
    const username = credentials.username.trim();
    setSessions((current) =>
      current.map((candidate) =>
        candidate.id === sessionId
          ? {
              ...candidate,
              backendSessionId,
              status: 'connecting',
              terminalFrame: undefined,
              sftp: undefined,
              error: undefined,
              hostKeyMismatch: undefined,
              tunnelProgress: null,
            }
          : candidate,
      ),
    );
    startSshSession({
      sessionId: backendSessionId,
      host: session.host,
      port: session.port,
      credentialId,
      username: credentialId ? undefined : username,
      password: credentialId ? undefined : credentials.password,
      tunnelConfigId: session.tunnelConfigId,
    });
  }

  function openConnection(node: TreeNode) {
    if (node.kind !== 'connection' || !node.protocol) return;

    const sessionId = `session-${node.id}`;
    if (webSessionOpenInFlight.current.has(sessionId)) {
      setSelectedSessionId(sessionId);
      setActivePage('sessions');
      return;
    }

    const existing = sessions.find((session) => session.id === sessionId);
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
      id: sessionId,
      title: node.name,
      protocol: node.protocol,
      host: node.host ?? '',
      nodeId: node.id,
      port: node.port,
      canTransfer: node.protocol === 'ssh',
      backendSessionId,
      status:
        node.protocol === 'ssh' ||
        node.protocol === 'vnc' ||
        node.protocol === 'serial' ||
        node.protocol === 'http' ||
        node.protocol === 'https'
          ? 'connecting'
          : 'placeholder',
      serialSettings,
      rdpStatus: node.protocol === 'rdp' ? 'idle' : undefined,
      rdpSystemClientSupported: node.protocol === 'rdp' ? false : undefined,
      vncConnectionGeneration: node.protocol === 'vnc' ? 0 : undefined,
      webTargetNodeId:
        (node.protocol === 'http' || node.protocol === 'https') && node.persisted
          ? node.id
          : undefined,
      webIgnoreCertErrors: node.protocol === 'https' && node.httpIgnoreCertErrors === true,
    };

    sessionResourceReleaseGate.current.reset(session.id);
    setSessions((current) => [...current, session]);
    setSelectedSessionId(session.id);
    setActivePage('sessions');
    if (backendSessionId && session.protocol === 'ssh') {
      startSshSession({ sessionId: backendSessionId, nodeId: node.id });
    }
    if (backendSessionId && session.protocol === 'serial') {
      startSerialSession(
        backendSessionId,
        savedSerialNodeId(node.id),
        session.host,
        serialSettings ?? defaultSerialSettings,
      );
    }
    if (session.protocol === 'rdp') {
      refreshRdpSystemClientCapability(session.id, session.nodeId);
      window.setTimeout(() => void requestRdpCredentials(session.id), 0);
    }
    if (session.protocol === 'http' || session.protocol === 'https') startWebSession(session);
  }

  async function releaseSessionResources(closing: Session): Promise<void> {
    await sessionResourceReleaseGate.current.release(closing.id, async () => {
      const releases: Promise<unknown>[] = [];
      if (closing.protocol === 'rdp') {
        rdpSessionAttempts.current.cancel(closing.id);
        releases.push(
          window.wormhole
            ?.commandRdpSession({
              sessionId: closing.id,
              operation: 'disconnect',
            })
            .catch(() => undefined) ?? Promise.resolve(),
        );
      } else if (closing.protocol === 'http' || closing.protocol === 'https') {
        releases.push(closeWebSession(closing.id).catch(() => undefined));
      } else if (closing.protocol === 'vnc') {
        releases.push(
          window.wormhole
            ?.sendVncCommand({
              action: 'vnc.disconnect',
              sessionId: closing.id,
            })
            .catch(() => undefined) ?? Promise.resolve(),
        );
      }
      if (closing.backendSessionId) {
        const release =
          closing.protocol === 'serial'
            ? window.wormhole?.closeSerialSession(closing.backendSessionId)
            : window.wormhole?.closeSshSession(closing.backendSessionId);
        if (release) releases.push(release.catch(() => undefined));
      }
      await Promise.allSettled(releases);
    });
  }

  function handleConfirmOnTabCloseChange(enabled: boolean) {
    setConfirmOnTabClose(enabled);
    void window.wormhole?.setConfirmOnTabClose(enabled).catch(() => undefined);
  }

  async function performSessionClose(id: string, preferredNextSessionId?: string) {
    const closing = sessions.find((session) => session.id === id);
    if (!closing) return;
    await sessionCloseGate.current.run(id, async () => {
      for (const key of sessionRuntimeRetryKeys(closing)) {
        runtimeBitwardenRetries.remove(key);
      }
      if (runtimeBitwardenRetries.isEmpty && bitwardenUnlockPrompt) {
        dismissRuntimeBitwardenUnlock();
      }
      rdpSavedCredentialAttempts.current.delete(id);
      if (rdpCredentialPrompt === id) setRdpCredentialPrompt(null);
      if (sshCredentialPrompt?.backendSessionId === closing.backendSessionId) {
        setSshCredentialPrompt(null);
        setSshCredentialForm({ username: '', password: '' });
      }
      if (sshKeyPassphrasePrompt?.sessionId === closing.backendSessionId) {
        setSshKeyPassphrasePrompt(null);
        setSshKeyPassphrase('');
      }
      await releaseSessionResources(closing);
      setSessions((current) => current.filter((session) => session.id !== id));
      sftpRequestIds.current.delete(id);
      clearSftpCancelRequestsForBrowser(sftpCancelRequests.current, closing.sftp);

      const closingSessionIds = sessionCloseGate.current.activeSessionIds();
      setSelectedSessionId((current) => {
        if (!closingSessionIds.has(current)) return current;
        if (
          preferredNextSessionId &&
          !closingSessionIds.has(preferredNextSessionId) &&
          sessions.some((session) => session.id === preferredNextSessionId)
        ) {
          return preferredNextSessionId;
        }
        return nextSelectedSessionId(sessions, current, (sessionId) =>
          closingSessionIds.has(sessionId),
        );
      });
      setSshCredentialPrompt((current) =>
        current?.sessionId === id || current?.backendSessionId === id ? null : current,
      );
    });
  }

  async function closeSession(id: string, preferredNextSessionId?: string) {
    const closing = sessions.find((session) => session.id === id);
    if (!closing) return;
    if (shouldConfirmConnectedTabClose(confirmOnTabClose, [closing])) {
      setPendingSessionClose((current) => current ?? { id, preferredNextSessionId });
      return;
    }
    await performSessionClose(id, preferredNextSessionId);
  }

  async function confirmSessionClose() {
    const pending = pendingSessionClose;
    if (!pending || sessionCloseBusy) return;
    setSessionCloseBusy(true);
    try {
      await performSessionClose(pending.id, pending.preferredNextSessionId);
      setPendingSessionClose(null);
    } finally {
      setSessionCloseBusy(false);
    }
  }

  async function closeSessionsForNodeIds(nodeIds: ReadonlySet<string>) {
    const closing = sessionsRef.current.filter(
      (session) => session.nodeId && nodeIds.has(session.nodeId),
    );
    if (closing.length === 0) return;
    const closingIds = new Set(closing.map((session) => session.id));
    for (const session of closing) {
      for (const key of sessionRuntimeRetryKeys(session)) {
        runtimeBitwardenRetries.remove(key);
      }
      rdpSavedCredentialAttempts.current.delete(session.id);
    }
    if (runtimeBitwardenRetries.isEmpty && bitwardenUnlockPrompt) {
      dismissRuntimeBitwardenUnlock();
    }
    await Promise.allSettled(closing.map(releaseSessionResources));
    for (const session of closing) {
      sftpRequestIds.current.delete(session.id);
      clearSftpCancelRequestsForBrowser(sftpCancelRequests.current, session.sftp);
    }

    const currentSessions = sessionsRef.current;
    setSessions((current) => current.filter((session) => !closingIds.has(session.id)));
    setSelectedSessionId((current) => {
      if (!closingIds.has(current)) return current;
      return nextSelectedSessionId(currentSessions, current, (sessionId) =>
        closingIds.has(sessionId),
      );
    });
    setRdpCredentialPrompt((current) => (current && closingIds.has(current) ? null : current));
    setSshCredentialPrompt((current) =>
      current &&
      ((current.sessionId && closingIds.has(current.sessionId)) ||
        (current.backendSessionId && closingIds.has(current.backendSessionId)))
        ? null
        : current,
    );
    setRoutePrompts((current) => current.filter((prompt) => !closingIds.has(prompt.sessionId)));
  }

  const releaseSessionResourcesRef = useRef(releaseSessionResources);
  useLayoutEffect(() => {
    releaseSessionResourcesRef.current = releaseSessionResources;
  });
  useEffect(() => {
    return window.wormhole?.onWindowCloseRequested(async () => {
      await sidebarWriter.flush().catch(() => undefined);
      await Promise.allSettled(
        sessionsRef.current.map((session) => releaseSessionResourcesRef.current(session)),
      );
      setSessions([]);
      setSelectedSessionId('');
    });
  }, [sidebarWriter]);

  useEffect(() => {
    return window.wormhole?.onWindowCloseConfirmationRequested(
      (request) =>
        new Promise<boolean>((resolve) => {
          setPendingWindowClose((current) => {
            if (current) {
              resolve(false);
              return current;
            }
            return { ...request, resolve };
          });
        }),
    );
  }, []);

  function cancelWindowClose() {
    if (!pendingWindowClose || windowCloseBusy) return;
    pendingWindowClose.resolve(false);
    setPendingWindowClose(null);
  }

  function confirmWindowClose() {
    if (!pendingWindowClose || windowCloseBusy) return;
    setWindowCloseBusy(true);
    pendingWindowClose.resolve(true);
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
    if (source.protocol === 'vnc') {
      setSessions((current) =>
        current.map((session) =>
          session.id === id
            ? {
                ...session,
                ...reconnectingVncState(session),
                error: undefined,
                tunnelProgress: null,
              }
            : session,
        ),
      );
    }
    if (source.protocol === 'http' || source.protocol === 'https') {
      const restarted: Session = {
        ...source,
        status: 'connecting',
        error: undefined,
        webCanGoBack: false,
        webCanGoForward: false,
        webIsLoading: false,
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
      startSshSession({ sessionId: backendSessionId, nodeId: source.nodeId });
    } else if (source.protocol === 'ssh' && source.credentialId) {
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
                tunnelProgress: null,
              }
            : session,
        ),
      );
      startSshSession({
        sessionId: backendSessionId,
        host: source.host,
        port: source.port,
        credentialId: source.credentialId,
        autoSudo: source.sshAutoSudo,
        tunnelConfigId: source.tunnelConfigId,
        frontendSessionId: source.id,
      });
    } else if (source.protocol === 'ssh') {
      setSessions((current) =>
        current.map((session) =>
          session.id === id
            ? {
                ...session,
                backendSessionId: undefined,
                status: 'placeholder',
                terminalFrame: undefined,
                sftp: undefined,
                error: undefined,
                hostKeyMismatch: undefined,
                tunnelProgress: null,
              }
            : session,
        ),
      );
      requestSshCredentials(id);
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
    if (source.protocol === 'rdp') {
      retryRdpSession(id);
    }
  }

  function duplicateSession(id: string) {
    const source = sessions.find((session) => session.id === id);
    if (!source) return;

    const duplicate: Session = {
      ...source,
      id: `session-duplicate-${newSessionToken()}`,
      title: `${source.title} (copy)`,
      backendSessionId:
        (source.protocol === 'ssh' && (source.nodeId || source.credentialId)) ||
        source.protocol === 'serial'
          ? newSessionToken()
          : undefined,
      status:
        source.protocol === 'ssh' && !source.nodeId && !source.credentialId
          ? 'placeholder'
          : source.protocol === 'ssh' || source.protocol === 'serial'
            ? 'connecting'
            : 'placeholder',
      terminalFrame: undefined,
      sftp: undefined,
      error: undefined,
      hostKeyMismatch: undefined,
      rdpStatus: source.protocol === 'rdp' ? 'idle' : source.rdpStatus,
      rdpExternal: source.protocol === 'rdp' ? false : source.rdpExternal,
      rdpError: undefined,
      vncConnectionGeneration: source.protocol === 'vnc' ? 0 : source.vncConnectionGeneration,
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
      startSshSession({
        sessionId: duplicate.backendSessionId,
        nodeId: duplicate.nodeId,
      });
    }
    if (duplicate.backendSessionId && duplicate.credentialId && duplicate.protocol === 'ssh') {
      startSshSession({
        sessionId: duplicate.backendSessionId,
        host: duplicate.host,
        port: duplicate.port,
        credentialId: duplicate.credentialId,
        autoSudo: duplicate.sshAutoSudo,
        tunnelConfigId: duplicate.tunnelConfigId,
        frontendSessionId: duplicate.id,
      });
    }
    if (duplicate.protocol === 'ssh' && !duplicate.nodeId && !duplicate.credentialId) {
      sshCredentialSubmitInFlight.current = false;
      setSshCredentialForm({ username: '', password: '' });
      setSshCredentialPrompt({ kind: 'quick', sessionId: duplicate.id });
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
      setRdpCredentialForm({ username: '', domain: '', password: '' });
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
      setSftpFailure(id, requestId, 'The SFTP service is unavailable.');
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
          ? {
              ...candidate,
              sftp: { ...candidate.sftp, status: 'closing', error: undefined },
            }
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
      setSftpFailure(sessionId, requestId, 'The SFTP service is unavailable.');
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
        setSftpFailure(id, requestId, 'The SFTP service is unavailable.');
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
                    error: 'The SFTP service is unavailable.',
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
          const knownOperationIds = {
            ...(candidate.sftp.knownOperationIds ?? {}),
          };
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
                  error: 'The SFTP service is unavailable.',
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
              error: 'The SFTP service is unavailable.',
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
            const knownOperationIds = {
              ...(candidate.sftp.knownOperationIds ?? {}),
            };
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
              sftp: {
                ...candidate.sftp,
                knownOperationIds,
                status: 'failed',
                error: message,
              },
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
          const knownTransferIds = {
            ...(candidate.sftp.knownTransferIds ?? {}),
          };
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
              transferError: 'The SFTP service is unavailable.',
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
            const knownTransferIds = {
              ...(candidate.sftp.knownTransferIds ?? {}),
            };
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
                  transferError: 'The SFTP service is unavailable.',
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
              transferError: 'The SFTP service is unavailable.',
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

  useLayoutEffect(() => {
    sftpRefreshHandlers.current = {
      local: requestLocalSftpDirectory,
      remote: requestSftpDirectory,
    };
  });

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
      if (!window.wormhole) throw new Error('The SSH service is unavailable.');
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
    quickConnectSubmitInFlight.current = false;
    setEditingConnectionId(null);
    setConnectionEditorMode('quick');
    setEditorError('');
    setNewConnectionForm({
      name: '',
      host: '',
      port: '',
      username: '',
      inlinePassword: '',
      protocol: 'ssh',
      folder: '',
      sshAutoSudo: 'off',
      tunnel: 'off',
      useSavedCredentials: true,
      credential: 'none',
      httpIgnoreCertErrors: false,
      serial: { ...defaultSerialSettings },
      rdp: { ...defaultRdpSettings },
    });
    setNewConnectionOpen(true);
  }

  function applyWorkspaceSnapshot(workspace: WormholeWorkspaceSnapshot) {
    const nextTree = workspace.tree as TreeNode[];
    setTree(nextTree);
    setCredentials(workspace.credentials as CredentialRecord[]);
    setCredentialOptions(workspaceCredentialOptions(workspace));
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
    setConnectionEditorMode('saved');
    setEditorError('');
    setNewConnectionForm({
      name: '',
      host: '',
      port: '',
      username: '',
      inlinePassword: '',
      protocol: 'ssh',
      folder: folderId ?? '',
      sshAutoSudo: 'inherit',
      httpIgnoreCertErrors: false,
      tunnel: 'inherit',
      useSavedCredentials: true,
      credential: 'inherit',
      serial: { ...defaultSerialSettings },
      rdp: { ...defaultRdpSettings },
    });
    setNewConnectionOpen(true);
  }

  async function showConnectionCredentials(node: TreeNode) {
    const api = window.wormhole;
    if (node.kind !== 'connection' || !api || credentialRevealBusy.current) return;

    const requestId = ++credentialRevealRequest.current;
    credentialRevealBusy.current = true;
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
      credentialRevealBusy.current = false;
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

  function openDeleteNodes(nodeIds: readonly string[]) {
    if (deleteNodeBusy) return;
    const canonicalIds = canonicalizeConnectionTreeNodeIds(tree, nodeIds);
    const nodes = canonicalIds
      .map((nodeId) => findTreeNode(tree, nodeId))
      .filter((node): node is TreeNode => Boolean(node));
    if (nodes.length === 0) return;

    setDeleteNodeError('');
    setPendingDeleteNodes(nodes);
  }

  function openDeleteNode(node: TreeNode) {
    const selectedIds = resolveVisibleConnectionTreeSelection(
      visibleTree,
      node.id,
      selectedTreeNodeIds.has(node.id) ? [...selectedTreeNodeIds] : [],
    );
    openDeleteNodes(selectedIds);
  }

  async function confirmDeleteNodes() {
    const nodes = pendingDeleteNodes;
    if (nodes.length === 0 || deleteNodeBusy) return;

    setDeleteNodeBusy(true);
    setDeleteNodeError('');
    try {
      const requestedNodeIds = nodes.map((node) => node.id);
      const currentTree = treeRef.current;
      const currentNodes = canonicalizeConnectionTreeNodeIds(currentTree, requestedNodeIds)
        .map((nodeId) => findTreeNode(currentTree, nodeId))
        .filter((node): node is TreeNode => Boolean(node));
      if (currentNodes.length !== requestedNodeIds.length) {
        throw new Error('The selected workspace nodes are no longer available.');
      }
      const deletedNodeIds = new Set(currentNodes.flatMap(collectTreeNodeIds));
      const persistedNodeIds = canonicalizeConnectionTreeNodeIds(
        currentTree,
        [...deletedNodeIds].filter((nodeId) => findTreeNode(currentTree, nodeId)?.persisted),
      );
      const reconcileDeletedNodes = async () => {
        const latestTree = treeRef.current;
        const latestDeletedNodeIds = new Set(deletedNodeIds);
        for (const nodeId of requestedNodeIds) {
          const latestNode = findTreeNode(latestTree, nodeId);
          if (latestNode) {
            for (const descendantID of collectTreeNodeIds(latestNode)) {
              latestDeletedNodeIds.add(descendantID);
            }
          }
        }
        await closeSessionsForNodeIds(latestDeletedNodeIds);
        const treeAfterSessionClose = treeRef.current;
        applyDeletedTreeState(
          extractTreeNodes(treeAfterSessionClose, new Set(requestedNodeIds)).nodes,
        );
      };
      if (persistedNodeIds.length > 0) {
        const api = window.wormhole;
        if (!api) throw new Error('The workspace service is unavailable.');
        const result = await api.deleteWorkspaceNodes({
          nodeIds: persistedNodeIds,
        });
        if (!result.deleted) throw new Error('The workspace nodes were not deleted.');
        await reconcileDeletedNodes();
        setPendingDeleteNodes([]);
        try {
          applyWorkspaceSnapshot(await api.loadWorkspace());
        } catch {
          // The delete is already committed. The local tree has been updated above, so a
          // transient refresh failure must not leave a deleted node visible or invite a retry.
        }
      } else {
        await reconcileDeletedNodes();
        setPendingDeleteNodes([]);
      }
    } catch (error: unknown) {
      setDeleteNodeError(error instanceof Error ? error.message : 'Could not delete the nodes.');
    } finally {
      setDeleteNodeBusy(false);
    }
  }

  function duplicateConnection(node: TreeNode) {
    if (node.kind !== 'connection') return;
    const api = window.wormhole;
    if (node.persisted) {
      if (!api) {
        setEditorError('The workspace service is unavailable.');
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
      port: node.port === undefined ? '' : String(node.port),
      username: node.username ?? '',
      inlinePassword: '',
      protocol: node.protocol,
      folder: findParentFolderId(tree, node.id) ?? '',
      sshAutoSudo: autoSudoModeFor(node.sshAutoSudo),
      httpIgnoreCertErrors: node.httpIgnoreCertErrors === true,
      tunnel: tunnelModeFor(node),
      useSavedCredentials: !node.hasInlineCredential,
      credential: credentialSelectionFor(node),
      serial: serialSettingsFromNode(node),
      rdp: { ...defaultRdpSettings, ...(node.rdp ?? {}) },
    });
    setNewConnectionOpen(true);
  }

  function openEditFolder(node: TreeNode) {
    if (node.kind !== 'folder') return;

    setSelectedNodeId(node.id);
    editingFolderGeneration.current += 1;
    editingFolderId.current = node.id;
    setEditorError('');
    setFolderDetailsForm({
      name: node.name,
      sshAutoSudo: autoSudoModeFor(node.sshAutoSudo),
      tunnel: tunnelModeFor(node),
      credential: credentialSelectionFor(node),
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

  async function reloadWorkspaceAfterNodeWrite(): Promise<void> {
    if (!window.wormhole) throw new Error('The workspace service is unavailable.');
    const workspace = await window.wormhole.loadWorkspace();
    setTree(workspace.tree as TreeNode[]);
    setCredentials(workspace.credentials as CredentialRecord[]);
    setCredentialOptions(workspaceCredentialOptions(workspace));
    setTunnels(workspace.tunnels as TunnelRecord[]);
  }

  async function saveRuntimeConnectionCredential(
    nodeId: string,
    protocol: 'ssh' | 'rdp',
    selectedCredentialId: string,
    credentials: { username: string; domain?: string; password: string },
  ): Promise<void> {
    const api = window.wormhole;
    if (!api) throw new Error('The workspace service is unavailable.');
    const result = selectedCredentialId
      ? await api.updateWorkspaceNodeCredential({
          nodeId,
          mode: 2,
          credentialId: selectedCredentialId,
        })
      : await api.updateWorkspaceNodeInlineCredential({
          nodeId,
          protocol,
          username: credentials.username.trim(),
          domain: protocol === 'rdp' ? credentials.domain?.trim() || '' : '',
          password: credentials.password,
        });
    if (!result.updated) throw new Error('The workspace did not save the connection credential.');
    try {
      await reloadWorkspaceAfterNodeWrite();
    } catch {
      // The Go transaction is already committed. A catalog refresh must not turn a successful
      // credential save into a duplicate write or prevent this connection attempt.
    }
  }

  function openNewFolder(parentFolderId?: string | null) {
    setNewFolderForm(blankFolderForm());
    newFolderGeneration.current += 1;
    newFolderParentId.current = parentFolderId ?? null;
    setEditorError('');
    setNewFolderOpen(true);
  }

  function submitQuickConnect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (quickConnectSubmitInFlight.current) return;
    quickConnectSubmitInFlight.current = true;
    const name = newConnectionForm.name.trim() || newConnectionForm.host.trim() || 'New connection';
    const host = newConnectionForm.host.trim() || 'localhost';
    const portText = newConnectionForm.port.trim();
    const port = portText ? Number(portText) : undefined;
    if (
      portText &&
      (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535)
    ) {
      setEditorError('Port must be a whole number between 1 and 65535.');
      quickConnectSubmitInFlight.current = false;
      return;
    }
    const credentialId =
      newConnectionForm.useSavedCredentials &&
      newConnectionForm.credential !== 'inherit' &&
      newConnectionForm.credential !== 'none'
        ? newConnectionForm.credential
        : undefined;
    const quickAutoSudo =
      effectiveSshAutoSudoMode(
        newConnectionForm.protocol,
        canConfigureConnectionSshAutoSudo,
        newConnectionForm.sshAutoSudo,
        'off',
      ) === 'on';
    if (
      newConnectionForm.protocol === 'ssh' &&
      !credentialId &&
      !newConnectionForm.useSavedCredentials &&
      !newConnectionForm.username.trim()
    ) {
      setEditorError('Enter a username for this SSH connection.');
      quickConnectSubmitInFlight.current = false;
      return;
    }
    const id = `session-quick-${newSessionToken()}`;
    const startsImmediately = quickConnectStartsImmediately(
      newConnectionForm.protocol,
      newConnectionForm.useSavedCredentials,
      credentialId,
    );
    const backendSessionId =
      (newConnectionForm.protocol === 'ssh' && startsImmediately) ||
      newConnectionForm.protocol === 'serial'
        ? newSessionToken()
        : undefined;
    const tunnelConfigId = quickConnectTunnelId(
      newConnectionForm.protocol,
      newConnectionForm.tunnel,
    );
    const session: Session = {
      id,
      title: name,
      protocol: newConnectionForm.protocol,
      host,
      port,
      credentialId,
      sshAutoSudo: quickAutoSudo,
      tunnelConfigId,
      canTransfer: newConnectionForm.protocol === 'ssh',
      backendSessionId,
      status: startsImmediately ? 'connecting' : 'placeholder',
      serialSettings:
        newConnectionForm.protocol === 'serial' ? { ...newConnectionForm.serial } : undefined,
      rdpStatus: newConnectionForm.protocol === 'rdp' ? 'idle' : undefined,
      rdpSystemClientSupported: newConnectionForm.protocol === 'rdp' ? false : undefined,
      vncConnectionGeneration: newConnectionForm.protocol === 'vnc' ? 0 : undefined,
      rdpProfile:
        newConnectionForm.protocol === 'rdp'
          ? {
              ...newConnectionForm.rdp,
              credentialId,
              gatewayCredentialId: newConnectionForm.rdp.gatewayCredentialId || undefined,
              name,
              host,
              port,
              tunnelConfigId,
              tunnelEnabled: tunnelConfigId ? true : undefined,
            }
          : undefined,
      webIgnoreCertErrors:
        newConnectionForm.protocol === 'https' && newConnectionForm.httpIgnoreCertErrors,
    };
    setSessions((current) => [...current, session]);
    setSelectedSessionId(id);
    setActivePage('sessions');
    setNewConnectionForm((form) => ({ ...form, inlinePassword: '' }));
    setNewConnectionOpen(false);
    if (newConnectionForm.protocol === 'ssh') {
      if (backendSessionId && credentialId) {
        startSshSession({
          sessionId: backendSessionId,
          host,
          port,
          credentialId,
          autoSudo: quickAutoSudo,
          tunnelConfigId,
          frontendSessionId: id,
        });
      } else if (backendSessionId && !newConnectionForm.useSavedCredentials) {
        startSshSession({
          sessionId: backendSessionId,
          host,
          port,
          username: newConnectionForm.username,
          password: newConnectionForm.inlinePassword,
          autoSudo: quickAutoSudo,
          tunnelConfigId,
        });
      } else {
        sshCredentialSubmitInFlight.current = false;
        setSshCredentialForm({ username: '', password: '' });
        setSshCredentialPrompt({ kind: 'quick', sessionId: id });
      }
    }
    if (backendSessionId && newConnectionForm.protocol === 'serial') {
      startSerialSession(backendSessionId, undefined, host, newConnectionForm.serial);
    }
    if (newConnectionForm.protocol === 'rdp') {
      const manual = !newConnectionForm.useSavedCredentials;
      const credentials = {
        username: newConnectionForm.username,
        domain: newConnectionForm.rdp.domain,
        password: newConnectionForm.inlinePassword,
      };
      window.setTimeout(() => startRdpSession(id, credentials, manual), 0);
    }
    if (newConnectionForm.protocol === 'http' || newConnectionForm.protocol === 'https') {
      startWebSession(session);
    }
  }
  async function submitNewConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (editorBusy) return;
    const name = newConnectionForm.name.trim();
    const host = newConnectionForm.host.trim();
    const portText = newConnectionForm.port.trim();
    const port = portText === '' ? 0 : Number(portText);
    const editingId = editingConnectionId;
    if (
      newConnectionForm.protocol !== 'serial' &&
      portText !== '' &&
      (!Number.isInteger(port) || port < 1 || port > 65535)
    ) {
      setEditorError('Port must be a whole number between 1 and 65535.');
      return;
    }
    setEditorBusy(true);
    setEditorError('');

    try {
      const editingNode = editingId ? findTreeNode(tree, editingId) : undefined;
      const connectionAutoSudo = effectiveSshAutoSudoMode(
        newConnectionForm.protocol,
        canConfigureConnectionSshAutoSudo,
        newConnectionForm.sshAutoSudo,
        editingNode ? autoSudoModeFor(editingNode.sshAutoSudo) : 'inherit',
      );
      const connectionTunnel =
        newConnectionForm.protocol === 'serial' ? 'off' : newConnectionForm.tunnel;
      const connectionCredential: CredentialSelection =
        newConnectionForm.protocol === 'ssh' ||
        newConnectionForm.protocol === 'rdp' ||
        newConnectionForm.protocol === 'vnc'
          ? newConnectionForm.credential
          : 'none';
      if (!window.wormhole) throw new Error('The workspace service is unavailable.');
      const tunnel = tunnelValueFor(connectionTunnel);
      const credential = credentialSettingsFor(connectionCredential);
      const usingInlinePassword =
        !newConnectionForm.useSavedCredentials &&
        (newConnectionForm.protocol === 'ssh' || newConnectionForm.protocol === 'rdp');
      const inlinePasswordAction: 'preserve' | 'set' | 'clear' | null = usingInlinePassword
        ? newConnectionForm.inlinePassword
          ? 'set'
          : editingNode?.hasInlineCredential
            ? 'preserve'
            : null
        : 'clear';
      if (!inlinePasswordAction) {
        throw new Error('Enter a password for this connection.');
      }
      const nodeWrite = {
        parentId: newConnectionForm.folder,
        name,
        kind: 'connection' as const,
        protocol: newConnectionForm.protocol,
        host,
        port: newConnectionForm.protocol === 'serial' ? 0 : port,
        username:
          !newConnectionForm.useSavedCredentials &&
          (newConnectionForm.protocol === 'ssh' || newConnectionForm.protocol === 'rdp')
            ? newConnectionForm.username
            : '',
        inlinePasswordAction,
        inlinePassword: inlinePasswordAction === 'set' ? newConnectionForm.inlinePassword : '',
        sshAutoSudo: autoSudoValueFor(connectionAutoSudo),
        httpIgnoreCertErrors:
          newConnectionForm.protocol === 'https' ? newConnectionForm.httpIgnoreCertErrors : null,
        tunnelEnabled: tunnel.tunnelEnabled,
        tunnelConfigId: tunnel.tunnelConfigId,
        credentialMode: newConnectionForm.useSavedCredentials ? credential.mode : 1,
        credentialId: newConnectionForm.useSavedCredentials ? credential.credentialId : '',
        serialBaudRate: newConnectionForm.serial.baudRate,
        serialDataBits: newConnectionForm.serial.dataBits,
        serialStopBits: newConnectionForm.serial.stopBits,
        serialParity: newConnectionForm.serial.parity,
        serialFlowControl: newConnectionForm.serial.flowControl,
        rdp: newConnectionForm.protocol === 'rdp' ? newConnectionForm.rdp : undefined,
      };
      if (editingId) {
        const result = await window.wormhole.updateWorkspaceNode({
          id: editingId,
          ...nodeWrite,
        });
        if (!result.updated) throw new Error('The workspace did not save the connection.');
        const editedSessionId = `session-${editingId}`;
        const editedSession = sessions.find((session) => session.id === editedSessionId);
        if (editedSession) {
          for (const key of sessionRuntimeRetryKeys(editedSession)) {
            runtimeBitwardenRetries.remove(key);
          }
          rdpSavedCredentialAttempts.current.delete(editedSession.id);
          if (rdpCredentialPrompt === editedSession.id) setRdpCredentialPrompt(null);
          if (sshCredentialPrompt?.backendSessionId === editedSession.backendSessionId) {
            setSshCredentialPrompt(null);
            setSshCredentialForm({ username: '', password: '' });
          }
          if (sshKeyPassphrasePrompt?.sessionId === editedSession.backendSessionId) {
            setSshKeyPassphrasePrompt(null);
            setSshKeyPassphrase('');
          }
          if (runtimeBitwardenRetries.isEmpty && bitwardenUnlockPrompt) {
            dismissRuntimeBitwardenUnlock();
          }
          await releaseSessionResources(editedSession);
          sessionResourceReleaseGate.current.reset(editedSession.id);
        }
        clearSftpCancelRequestsForBrowser(sftpCancelRequests.current, editedSession?.sftp);
        const backendSessionId =
          editedSession &&
          (newConnectionForm.protocol === 'ssh' || newConnectionForm.protocol === 'serial')
            ? newSessionToken()
            : undefined;
        await reloadWorkspaceAfterNodeWrite();
        setSessions((current) =>
          current.map((session) =>
            session.id === editedSessionId
              ? {
                  ...session,
                  title: name,
                  host,
                  port: port || undefined,
                  protocol: newConnectionForm.protocol,
                  canTransfer: newConnectionForm.protocol === 'ssh',
                  nodeId: editingId,
                  backendSessionId,
                  status:
                    newConnectionForm.protocol === 'ssh' ||
                    newConnectionForm.protocol === 'vnc' ||
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
                  rdpStatus: newConnectionForm.protocol === 'rdp' ? 'idle' : undefined,
                  rdpBackend: undefined,
                  rdpError: undefined,
                  rdpExternal: undefined,
                  rdpProfile: undefined,
                  rdpSystemClientSupported:
                    newConnectionForm.protocol === 'rdp' ? false : undefined,
                  vncConnectionGeneration:
                    newConnectionForm.protocol === 'vnc'
                      ? (session.vncConnectionGeneration ?? 0) + 1
                      : undefined,
                  tunnelProgress: null,
                  webTargetNodeId:
                    newConnectionForm.protocol === 'http' || newConnectionForm.protocol === 'https'
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
          startSshSession({ sessionId: backendSessionId, nodeId: editingId });
        }
        if (backendSessionId && newConnectionForm.protocol === 'serial') {
          startSerialSession(
            backendSessionId,
            savedSerialNodeId(editingId),
            host,
            newConnectionForm.serial,
          );
        }
        if (editedSession && newConnectionForm.protocol === 'rdp') {
          refreshRdpSystemClientCapability(editedSessionId, editingId);
          window.setTimeout(() => void requestRdpCredentials(editedSessionId), 0);
        }
        if (
          editedSession &&
          (newConnectionForm.protocol === 'http' || newConnectionForm.protocol === 'https')
        ) {
          startWebSession({
            ...editedSession,
            title: name,
            host,
            port: port || undefined,
            protocol: newConnectionForm.protocol,
            status: 'connecting',
            webTargetNodeId: editingId,
            webIgnoreCertErrors:
              newConnectionForm.protocol === 'https'
                ? newConnectionForm.httpIgnoreCertErrors
                : undefined,
          });
        }
      } else {
        const result = await window.wormhole.createWorkspaceNode(nodeWrite);
        await reloadWorkspaceAfterNodeWrite();
        setSelectedNodeId(result.nodeId);
      }

      if (newConnectionForm.folder) {
        setExpanded((current) => new Set(current).add(newConnectionForm.folder));
      }
      setEditingConnectionId(null);
      setNewConnectionForm((form) => ({ ...form, inlinePassword: '' }));
      setNewConnectionOpen(false);
    } catch (error: unknown) {
      setEditorError(error instanceof Error ? error.message : 'Could not save the connection.');
    } finally {
      setEditorBusy(false);
    }
  }

  async function submitFolderDetails(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const folderId = editingFolderId.current;
    if (editorBusy || !folderId) return;
    const dialogGeneration = editingFolderGeneration.current;
    const name = folderDetailsForm.name.trim();
    if (!name) return;

    setEditorBusy(true);
    setEditorError('');
    try {
      const folder = findTreeNode(tree, folderId);
      if (!folder) return;
      if (!window.wormhole) throw new Error('The workspace service is unavailable.');
      const tunnel = tunnelValueFor(folderDetailsForm.tunnel);
      const credential = credentialSettingsFor(folderDetailsForm.credential);
      const result = await window.wormhole.updateWorkspaceNode({
        id: folderId,
        parentId: findParentFolderId(tree, folderId) ?? '',
        name,
        kind: 'folder',
        protocol: '',
        host: '',
        port: 0,
        username: '',
        inlinePasswordAction: 'clear',
        inlinePassword: '',
        sshAutoSudo: autoSudoValueFor(folderDetailsForm.sshAutoSudo),
        httpIgnoreCertErrors: null,
        tunnelEnabled: tunnel.tunnelEnabled,
        tunnelConfigId: tunnel.tunnelConfigId,
        credentialMode: credential.mode,
        credentialId: credential.credentialId,
        serialBaudRate: 0,
        serialDataBits: 0,
        serialStopBits: 0,
        serialParity: 0,
        serialFlowControl: 0,
      });
      if (!result.updated) throw new Error('The workspace did not save the folder.');
      await reloadWorkspaceAfterNodeWrite();
      if (editingFolderGeneration.current === dialogGeneration) {
        setFolderDetailsOpen(false);
        editingFolderId.current = null;
      }
    } catch (error: unknown) {
      if (editingFolderGeneration.current === dialogGeneration) {
        setEditorError(error instanceof Error ? error.message : 'Could not save the folder.');
      }
    } finally {
      setEditorBusy(false);
    }
  }

  async function submitNewFolder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (editorBusy) return;
    const parentFolderId = newFolderParentId.current;
    const dialogGeneration = newFolderGeneration.current;
    const name = newFolderForm.name.trim();
    if (!name) return;
    setEditorBusy(true);
    setEditorError('');
    try {
      if (!window.wormhole) throw new Error('The workspace service is unavailable.');
      const tunnel = tunnelValueFor(newFolderForm.tunnel);
      const credential = credentialSettingsFor(newFolderForm.credential);
      const result = await window.wormhole.createWorkspaceNode({
        parentId: parentFolderId ?? '',
        name,
        kind: 'folder',
        protocol: '',
        host: '',
        port: 0,
        username: '',
        inlinePasswordAction: 'clear',
        inlinePassword: '',
        sshAutoSudo: autoSudoValueFor(newFolderForm.sshAutoSudo),
        httpIgnoreCertErrors: null,
        tunnelEnabled: tunnel.tunnelEnabled,
        tunnelConfigId: tunnel.tunnelConfigId,
        credentialMode: credential.mode,
        credentialId: credential.credentialId,
        serialBaudRate: 0,
        serialDataBits: 0,
        serialStopBits: 0,
        serialParity: 0,
        serialFlowControl: 0,
      });
      await reloadWorkspaceAfterNodeWrite();
      setExpanded(
        (current) =>
          new Set([...current, result.nodeId, ...(parentFolderId ? [parentFolderId] : [])]),
      );
      if (newFolderGeneration.current === dialogGeneration) {
        setSelectedNodeId(result.nodeId);
        newFolderParentId.current = null;
        setNewFolderOpen(false);
      }
    } catch (error: unknown) {
      if (newFolderGeneration.current === dialogGeneration) {
        setEditorError(error instanceof Error ? error.message : 'Could not create the folder.');
      }
    } finally {
      setEditorBusy(false);
    }
  }

  const draggedNodeIdSet = useMemo(() => new Set(draggedNodeIds), [draggedNodeIds]);
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
      const isDragging = draggedNodeIdSet.has(node.id);
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
          aria-keyshortcuts={isFolder ? 'F2 Delete' : 'F2 Delete Enter'}
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
          onFocus={() => setSelectedNodeId(node.id)}
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
    if (!window.wormhole) throw new Error('The credential service is unavailable.');
    const credential = (await window.wormhole.createCredential(draft)) as CredentialRecord;
    setCredentials((current) => mergeCredential(current, credential));
    setCredentialOptions((current) => mergeCredentialOption(current, credential));
    void refreshWorkspaceCredentials().catch(() => {
      // The new option is already visible; a later workspace refresh can reconcile vault aliases.
    });
  }

  async function updateCredential(id: string, draft: CredentialDraft): Promise<void> {
    if (!window.wormhole) throw new Error('The credential service is unavailable.');
    const credential = (await window.wormhole.updateCredential({
      ...draft,
      id,
    })) as CredentialRecord;
    setCredentials((current) => mergeCredential(current, credential));
    setCredentialOptions((current) => mergeCredentialOption(current, credential));
    void refreshWorkspaceCredentials().catch(() => {
      // The edited option is already visible; a later workspace refresh can reconcile vault aliases.
    });
  }

  async function deleteSavedCredential(id: string): Promise<void> {
    if (!window.wormhole) throw new Error('The credential service is unavailable.');
    const result = await window.wormhole.deleteCredential({ id });
    if (!result.deleted) throw new Error(result.error ?? 'The credential was not deleted.');
    setCredentials((current) => current.filter((credential) => credential.id !== id));
    setCredentialOptions((current) => ({
      ssh: current.ssh.filter((credential) => credential.id !== id),
      rdp: current.rdp.filter((credential) => credential.id !== id),
      vnc: current.vnc.filter((credential) => credential.id !== id),
    }));
    void refreshWorkspaceCredentials().catch(() => {
      // The deletion succeeded; the next workspace refresh will restore any virtual vault option.
    });
  }

  async function refreshWorkspaceCredentials(): Promise<void> {
    if (!window.wormhole) return;
    const workspace = await window.wormhole.loadWorkspace();
    setCredentials(workspace.credentials);
    setCredentialOptions(workspaceCredentialOptions(workspace));
  }

  const currentPage = navItems.find((item) => item.id === activePage)!;
  const visibleAuthPrompt =
    authPrompt ??
    (authGate === 'locked' && authState?.configured
      ? { kind: 'lock' as const, reason: lockReason, autoWindowsHello: true }
      : null);
  const credentialResult =
    credentialDialog?.kind === 'credentials' ? credentialDialog.result : null;
  const pendingDeleteNode = pendingDeleteNodes[0];
  const deleteNodeDescendantCount = pendingDeleteNodes.reduce(
    (count, node) => count + collectTreeNodeIds(node).length - 1,
    0,
  );

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
          ) : credentialDialog?.kind === 'error' ? (
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
          ) : null}
        </DialogContent>
      </Dialog>
      <Dialog
        onOpenChange={(open) => {
          if (!open && !deleteNodeBusy) {
            setPendingDeleteNodes([]);
            setDeleteNodeError('');
          }
        }}
        open={pendingDeleteNodes.length > 0}
      >
        <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {pendingDeleteNodes.length > 1
                ? `Delete ${pendingDeleteNodes.length} items`
                : `Delete ${pendingDeleteNode?.kind === 'folder' ? 'folder' : 'connection'}`}
            </DialogTitle>
            <DialogDescription>
              {pendingDeleteNodes.length > 1
                ? deleteNodeDescendantCount > 0
                  ? `Delete ${pendingDeleteNodes.length} selected items and their ${deleteNodeDescendantCount} nested ${deleteNodeDescendantCount === 1 ? 'item' : 'items'}? This cannot be undone.`
                  : `Delete ${pendingDeleteNodes.length} selected items? This cannot be undone.`
                : deleteNodeDescendantCount > 0
                  ? `Delete “${pendingDeleteNode?.name ?? 'this item'}” and its ${deleteNodeDescendantCount} nested ${deleteNodeDescendantCount === 1 ? 'item' : 'items'}? This cannot be undone.`
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
                setPendingDeleteNodes([]);
                setDeleteNodeError('');
              }}
              type="button"
              variant="ghost"
            >
              Cancel
            </Button>
            <Button
              disabled={deleteNodeBusy}
              onClick={() => void confirmDeleteNodes()}
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
        <DialogContent className="max-h-[88vh] overflow-y-auto border-border/70 bg-card text-card-foreground sm:max-w-xl">
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
          <ResizablePanel
            className="min-h-0"
            defaultSize={`${sidebarWidth}px`}
            groupResizeBehavior="preserve-pixel-size"
            maxSize={`${maxSidebarWidth}px`}
            minSize={`${minSidebarWidth}px`}
            onResize={(size, _id, previous) => {
              if (previous) sidebarWriter.schedule(size.inPixels);
            }}
          >
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
                          <DropdownMenuItem onClick={() => setMremoteImportOpen(true)}>
                            <Upload />
                            Import from mRemoteNG
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                      <IconButton
                        aria-keyshortcuts="Control+Shift+N Meta+Shift+N"
                        label="New folder"
                        onClick={() => openNewFolder(null)}
                      >
                        <FolderPlus />
                      </IconButton>
                      <IconButton
                        aria-keyshortcuts="Control+N Meta+N"
                        label="New connection"
                        onClick={() => openNewConnection(null)}
                      >
                        <Plus />
                      </IconButton>
                    </div>
                  </div>
                  <Button
                    aria-keyshortcuts="Control+K Meta+K"
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
                      onChange={(event) => updateTreeSearchText(event.target.value)}
                      placeholder="Search connections"
                      value={searchText}
                    />
                    {searchText ? (
                      <IconButton
                        label="Clear search"
                        className="absolute right-1 top-1/2 size-7 -translate-y-1/2 text-muted-foreground"
                        onClick={() => updateTreeSearchText('')}
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
                      <div
                        className="flex min-h-0 flex-1 flex-col"
                        data-connection-tree-shortcut-scope=""
                      >
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
                  autoCopyOnSelect={autoCopyOnSelect}
                  bitwardenUnlockPending={bitwardenUnlockPrompt !== null}
                  onBitwardenUnlockRequired={(sessionId, reason, retry) =>
                    requestRuntimeBitwardenUnlock(`vnc:${sessionId}`, reason, retry)
                  }
                  onCloseSession={closeSession}
                  onConnectRdp={requestRdpCredentials}
                  onDisconnectSession={disconnectRemoteDesktopSession}
                  onDuplicateSession={duplicateSession}
                  onCloseSftpBrowser={closeSftpBrowser}
                  onOpenFileTransfer={openFileTransfer}
                  onOpenQuickConnect={openQuickConnect}
                  onOpenSystemRdp={openRdpInSystemClient}
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
                  onVncStatusChange={(sessionId, status) =>
                    setSessions((current) =>
                      current.map((session) =>
                        session.id === sessionId ? { ...session, status } : session,
                      ),
                    )
                  }
                  isAuthorized={authGate === 'unlocked'}
                  isWebSurfaceVisible={
                    !newConnectionOpen &&
                    !folderDetailsOpen &&
                    !newFolderOpen &&
                    !authPrompt &&
                    !rdpCredentialPrompt &&
                    !sshCredentialPrompt &&
                    !sshKeyPassphrasePrompt &&
                    !pendingSessionClose
                  }
                  selectedSession={selectedSession}
                  sessions={sessions}
                />
              ) : activePage === 'settings' ? (
                <SettingsPage
                  autoCopyOnSelect={autoCopyOnSelect}
                  confirmOnTabClose={confirmOnTabClose}
                  authGate={authGate}
                  authState={authState}
                  onAuthStateChange={setAuthState}
                  onAutoCopyOnSelectChange={handleAutoCopyOnSelectChange}
                  onConfirmOnTabCloseChange={handleConfirmOnTabCloseChange}
                  onBackupImported={(workspace) => {
                    setTree(workspace.tree);
                    setCredentials(workspace.credentials);
                    setCredentialOptions(workspaceCredentialOptions(workspace));
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
                  onThemeChange={handleThemeChange}
                  onCheckForUpdates={() => void handleCheckForUpdates()}
                  onDismissUpdate={handleDismissUpdate}
                  onInstallUpdate={() => void handleInstallUpdate()}
                  onOpenReleaseNotes={handleOpenReleaseNotes}
                  onSetAutoCheckForUpdates={handleSetAutoCheckForUpdates}
                  settingsUpdatesRequest={settingsUpdatesRequest}
                  onWorkspaceCredentialsChanged={refreshWorkspaceCredentials}
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
                  isAuthorized={authGate === 'unlocked'}
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

        {mremoteImportOpen ? (
          <Suspense fallback={null}>
            <MRemoteImportDialog
              onImported={applyWorkspaceSnapshot}
              onOpenChange={setMremoteImportOpen}
              open
            />
          </Suspense>
        ) : null}

        <Dialog
          onOpenChange={(open) => {
            if (!open) cancelWindowClose();
          }}
          open={pendingWindowClose !== null}
        >
          <DialogContent
            aria-describedby="wormhole-close-description"
            className="overflow-hidden border-border/70 bg-card p-0 text-card-foreground sm:max-w-md"
            onEscapeKeyDown={(event) => {
              if (windowCloseBusy) event.preventDefault();
            }}
            onInteractOutside={(event) => event.preventDefault()}
            role="alertdialog"
            showCloseButton={false}
          >
            <DialogHeader className="gap-4 p-5 pb-4">
              <div className="flex items-start gap-3">
                <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-destructive/10 text-destructive ring-1 ring-destructive/15">
                  <TriangleAlert className="size-5" />
                </div>
                <div className="grid min-w-0 flex-1 gap-2 pt-0.5">
                  <div className="flex items-center justify-between gap-3">
                    <DialogTitle>
                      {pendingWindowClose?.action === 'quit' ? 'Quit Wormhole?' : 'Close Wormhole?'}
                    </DialogTitle>
                    <Badge className="shrink-0 font-mono" variant="destructive">
                      {pendingWindowClose?.activeSessionCount} active
                    </Badge>
                  </div>
                  <DialogDescription id="wormhole-close-description">
                    {pendingWindowClose?.activeSessionCount === 1
                      ? '1 session is still active. Closing Wormhole will terminate it.'
                      : `${pendingWindowClose?.activeSessionCount ?? 0} sessions are still active. Closing Wormhole will terminate them.`}
                  </DialogDescription>
                </div>
              </div>
            </DialogHeader>
            <div className="mx-5 rounded-lg border border-border/70 bg-muted/40 px-3 py-2.5 text-xs text-muted-foreground">
              Terminal processes and remote connections in these sessions will be disconnected.
            </div>
            <DialogFooter className="m-0">
              <Button
                disabled={windowCloseBusy}
                onClick={cancelWindowClose}
                type="button"
                variant="outline"
              >
                Cancel
              </Button>
              <Button
                disabled={windowCloseBusy}
                onClick={confirmWindowClose}
                type="button"
                variant="destructive"
              >
                {windowCloseBusy ? <LoaderCircle className="animate-spin" /> : <Power />}
                {windowCloseBusy ? 'Terminating sessions…' : 'Close and terminate sessions'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            if (!open) {
              setSshKeyPassphrasePrompt(null);
              setSshKeyPassphrase('');
            }
          }}
          open={sshKeyPassphrasePrompt !== null}
        >
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
            <DialogHeader>
              <DialogTitle>SSH key passphrase</DialogTitle>
              <DialogDescription>
                This private key is encrypted. Enter its passphrase for this connection attempt.
              </DialogDescription>
            </DialogHeader>
            <form className="grid gap-4" onSubmit={submitSshKeyPassphrase}>
              <div className="grid gap-2">
                <Label htmlFor="ssh-key-passphrase">Passphrase</Label>
                <Input
                  autoFocus
                  autoComplete="off"
                  id="ssh-key-passphrase"
                  onChange={(event) => setSshKeyPassphrase(event.target.value)}
                  required
                  type="password"
                  value={sshKeyPassphrase}
                />
              </div>
              <DialogFooter>
                <Button
                  onClick={() => {
                    setSshKeyPassphrasePrompt(null);
                    setSshKeyPassphrase('');
                  }}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button disabled={!sshKeyPassphrase} type="submit">
                  <Power data-icon="inline-start" />
                  Connect
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            if (!open && !sessionCloseBusy) setPendingSessionClose(null);
          }}
          open={pendingSessionClose !== null}
        >
          <DialogContent
            aria-describedby="active-connection-close-description"
            className="border-border/70 bg-card text-card-foreground sm:max-w-md"
            role="alertdialog"
            showCloseButton={false}
          >
            <DialogHeader className="gap-3">
              <div className="flex size-9 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
                <AlertCircle className="size-5" />
              </div>
              <div className="grid gap-2">
                <DialogTitle>Disconnect active connection?</DialogTitle>
                <DialogDescription id="active-connection-close-description">
                  {connectedTabCloseMessage(1)}
                </DialogDescription>
              </div>
            </DialogHeader>
            <DialogFooter>
              <Button
                disabled={sessionCloseBusy}
                onClick={() => setPendingSessionClose(null)}
                type="button"
                variant="outline"
              >
                Cancel
              </Button>
              <Button
                disabled={sessionCloseBusy}
                onClick={() => void confirmSessionClose()}
                type="button"
                variant="destructive"
              >
                {sessionCloseBusy ? <LoaderCircle className="animate-spin" /> : null}
                {sessionCloseBusy ? 'Disconnecting…' : 'Close and disconnect'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            setNewConnectionOpen(open);
            if (!open) {
              setNewConnectionForm((form) => ({ ...form, inlinePassword: '' }));
              setEditingConnectionId(null);
              setConnectionEditorMode('saved');
              setEditorError('');
            }
          }}
          open={newConnectionOpen}
        >
          <DialogContent className="flex h-[min(36rem,calc(100vh-2rem))] max-h-[calc(100vh-2rem)] flex-col overflow-hidden border-border/70 bg-card text-card-foreground sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>
                {connectionEditorMode === 'quick'
                  ? 'Quick Connect'
                  : editingConnectionId
                    ? 'Edit connection'
                    : 'New connection'}
              </DialogTitle>
              <DialogDescription>
                {connectionEditorMode === 'quick'
                  ? 'Start a temporary session without adding it to your connection tree.'
                  : editingConnectionId
                    ? 'Update the connection settings used by this tree item.'
                    : 'Save a connection to the tree for reuse later.'}
              </DialogDescription>
            </DialogHeader>
            <form
              className="flex min-h-0 flex-1 flex-col gap-4"
              onSubmit={connectionEditorMode === 'quick' ? submitQuickConnect : submitNewConnection}
            >
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
                      <Label htmlFor="connection-name">
                        {connectionEditorMode === 'quick'
                          ? 'Session name (optional)'
                          : 'Connection name'}
                      </Label>
                      <Input
                        autoFocus
                        id="connection-name"
                        onChange={(event) =>
                          setNewConnectionForm((form) => ({
                            ...form,
                            name: event.target.value,
                          }))
                        }
                        placeholder={
                          connectionEditorMode === 'quick'
                            ? 'Defaults to target'
                            : 'e.g. production gateway'
                        }
                        required={connectionEditorMode === 'saved'}
                        value={newConnectionForm.name}
                      />
                    </div>

                    <div
                      className={cn(
                        'grid gap-3',
                        newConnectionForm.protocol === 'serial'
                          ? 'sm:grid-cols-[120px_minmax(0,1fr)]'
                          : 'sm:grid-cols-[120px_minmax(0,1fr)_110px]',
                      )}
                    >
                      <div className="grid gap-2">
                        <Label htmlFor="connection-protocol">Protocol</Label>
                        <Select
                          onValueChange={(protocol: Protocol) =>
                            setNewConnectionForm((form) => ({
                              ...form,
                              protocol,
                              port: protocol === form.protocol ? form.port : '',
                              credential:
                                protocol === form.protocol
                                  ? form.credential
                                  : connectionEditorMode === 'quick'
                                    ? 'none'
                                    : 'inherit',
                            }))
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
                              : 'hostname or IP address'
                          }
                          required
                          value={newConnectionForm.host}
                        />
                      </div>
                      {newConnectionForm.protocol !== 'serial' ? (
                        <div className="grid gap-2">
                          <Label htmlFor="connection-port">Port</Label>
                          <Input
                            id="connection-port"
                            inputMode="numeric"
                            max={65535}
                            min={1}
                            onChange={(event) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                port: event.target.value,
                              }))
                            }
                            placeholder="Default"
                            type="number"
                            value={newConnectionForm.port}
                          />
                        </div>
                      ) : null}
                    </div>

                    {newConnectionForm.protocol !== 'serial' ? (
                      <p className="text-[11px] leading-relaxed text-muted-foreground">
                        Leave the port blank to use the protocol default.
                      </p>
                    ) : null}

                    {connectionEditorMode === 'saved' ? (
                      <div className="grid max-w-[280px] gap-2">
                        <Label htmlFor="connection-folder">Folder</Label>
                        <SearchableCombobox
                          id="connection-folder"
                          emptyMessage="No folders found."
                          onValueChange={(folder) =>
                            setNewConnectionForm((form) => ({
                              ...form,
                              folder: folder === rootFolderSelectionValue ? '' : folder,
                            }))
                          }
                          options={folderSelectionOptions}
                          placeholder="Root"
                          searchPlaceholder="Search folders…"
                          value={newConnectionForm.folder || rootFolderSelectionValue}
                        />
                      </div>
                    ) : null}

                    {newConnectionForm.protocol === 'ssh' ||
                    newConnectionForm.protocol === 'rdp' ||
                    newConnectionForm.protocol === 'vnc' ? (
                      <div className="grid gap-4">
                        <label className="flex items-center gap-2 text-xs">
                          <Checkbox
                            checked={newConnectionForm.useSavedCredentials}
                            onCheckedChange={(checked) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                useSavedCredentials: checked === true,
                              }))
                            }
                          />
                          <span>Use saved credentials</span>
                        </label>

                        {newConnectionForm.useSavedCredentials ? (
                          <div className="grid max-w-[280px] gap-2">
                            <Label htmlFor="connection-credential">Saved credentials</Label>
                            <SearchableCombobox
                              id="connection-credential"
                              emptyMessage="No credentials found."
                              onValueChange={(credential) =>
                                setNewConnectionForm((form) => ({
                                  ...form,
                                  credential,
                                }))
                              }
                              options={
                                connectionEditorMode === 'quick'
                                  ? connectionCredentialSelectionOptions.filter(
                                      (option) => option.value !== 'inherit',
                                    )
                                  : connectionCredentialSelectionOptions
                              }
                              placeholder="Select a credential"
                              searchPlaceholder="Search credentials…"
                              value={newConnectionForm.credential}
                            />
                          </div>
                        ) : null}
                      </div>
                    ) : null}

                    {!newConnectionForm.useSavedCredentials &&
                    (newConnectionForm.protocol === 'ssh' ||
                      newConnectionForm.protocol === 'rdp') ? (
                      <div className="grid gap-4 sm:grid-cols-2">
                        <div className="grid gap-2">
                          <Label htmlFor="connection-username">Username</Label>
                          <Input
                            id="connection-username"
                            onChange={(event) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                username: event.target.value,
                              }))
                            }
                            placeholder="(optional)"
                            value={newConnectionForm.username}
                          />
                        </div>
                        <div className="grid gap-2">
                          <Label htmlFor="connection-inline-password">Password</Label>
                          <Input
                            autoComplete="new-password"
                            id="connection-inline-password"
                            onChange={(event) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                inlinePassword: event.target.value,
                              }))
                            }
                            placeholder={
                              editingConnectionId ? 'Leave blank to keep stored password' : ''
                            }
                            type="password"
                            value={newConnectionForm.inlinePassword}
                          />
                        </div>
                      </div>
                    ) : null}

                    {canConfigureConnectionSshAutoSudo ? (
                      <AutoSudoField
                        id="connection-auto-sudo"
                        mode={newConnectionForm.sshAutoSudo}
                        onChange={(sshAutoSudo) =>
                          setNewConnectionForm((form) => ({
                            ...form,
                            sshAutoSudo,
                          }))
                        }
                        scope={connectionEditorMode === 'quick' ? 'quick' : 'connection'}
                      />
                    ) : null}

                    <TunnelRouteField
                      disabled={newConnectionForm.protocol === 'serial'}
                      id="connection-tunnel-route"
                      mode={
                        newConnectionForm.protocol === 'serial' ? 'off' : newConnectionForm.tunnel
                      }
                      onChange={(tunnel) => setNewConnectionForm((form) => ({ ...form, tunnel }))}
                      scope={connectionEditorMode === 'quick' ? 'quick' : 'connection'}
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
                              serial: {
                                ...form.serial,
                                dataBits: Number(value),
                              },
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
                              serial: {
                                ...form.serial,
                                stopBits: Number(value),
                              },
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
                              serial: {
                                ...form.serial,
                                flowControl: Number(value),
                              },
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
                          <Select
                            onValueChange={(value) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  fullScreen: value === 'full',
                                  screenSize:
                                    value === 'custom'
                                      ? /^\d+x\d+$/i.test(form.rdp.screenSize)
                                        ? form.rdp.screenSize
                                        : '1280x800'
                                      : 'fitToWindow',
                                },
                              }))
                            }
                            value={
                              newConnectionForm.rdp.fullScreen
                                ? 'full'
                                : /^\d+x\d+$/i.test(newConnectionForm.rdp.screenSize)
                                  ? 'custom'
                                  : 'fit'
                            }
                          >
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
                          <Select
                            onValueChange={(value) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: { ...form.rdp, colorDepth: Number(value) },
                              }))
                            }
                            value={String(newConnectionForm.rdp.colorDepth)}
                          >
                            <SelectTrigger id="rdp-color-depth">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="32">32-bit</SelectItem>
                              <SelectItem value="24">24-bit</SelectItem>
                              <SelectItem value="16">16-bit</SelectItem>
                              <SelectItem value="15">15-bit</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        {!newConnectionForm.rdp.fullScreen &&
                        /^\d+x\d+$/i.test(newConnectionForm.rdp.screenSize) ? (
                          <div className="grid gap-2 sm:col-span-2 sm:max-w-[260px]">
                            <Label htmlFor="rdp-custom-size">Custom desktop size</Label>
                            <Input
                              id="rdp-custom-size"
                              onChange={(event) =>
                                setNewConnectionForm((form) => ({
                                  ...form,
                                  rdp: {
                                    ...form.rdp,
                                    screenSize: event.target.value,
                                  },
                                }))
                              }
                              placeholder="1280x800"
                              value={newConnectionForm.rdp.screenSize}
                            />
                          </div>
                        ) : null}
                        <label className="flex items-center gap-2 text-xs sm:col-span-2">
                          <Checkbox
                            checked={newConnectionForm.rdp.useAllMonitors}
                            onCheckedChange={(checked) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  useAllMonitors: checked === true,
                                },
                              }))
                            }
                          />
                          <span>Use all my monitors</span>
                        </label>
                        <div className="grid gap-2 sm:col-span-2 sm:max-w-[320px]">
                          <Label htmlFor="rdp-domain">Domain override</Label>
                          <Input
                            id="rdp-domain"
                            onChange={(event) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  domain: event.target.value,
                                },
                              }))
                            }
                            value={newConnectionForm.rdp.domain}
                          />
                        </div>
                      </div>
                    </TabsContent>
                    <TabsContent
                      className="min-h-0 flex-1 overflow-y-auto px-1 py-4"
                      value="resources"
                    >
                      <div className="grid gap-4">
                        <div className="grid gap-2 sm:max-w-[320px]">
                          <Label htmlFor="rdp-audio-playback">Remote audio playback</Label>
                          <Select
                            onValueChange={(value) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: { ...form.rdp, audioMode: Number(value) },
                              }))
                            }
                            value={String(newConnectionForm.rdp.audioMode)}
                          >
                            <SelectTrigger id="rdp-audio-playback">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="0">Play on this device</SelectItem>
                              <SelectItem value="2">Play on remote device</SelectItem>
                              <SelectItem value="1">Do not play</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="grid gap-2 sm:max-w-[320px]">
                          <Label htmlFor="rdp-audio-capture">Remote audio recording</Label>
                          <Select
                            onValueChange={(value) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  audioCaptureMode: Number(value),
                                },
                              }))
                            }
                            value={String(newConnectionForm.rdp.audioCaptureMode)}
                          >
                            <SelectTrigger id="rdp-audio-capture">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="0">Do not record</SelectItem>
                              <SelectItem value="1">Record from this device</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="grid gap-2 sm:max-w-[320px]">
                          <Label htmlFor="rdp-keyboard">Apply Windows key combinations</Label>
                          <Select
                            onValueChange={(value) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  keyboardHookMode: Number(value),
                                },
                              }))
                            }
                            value={String(newConnectionForm.rdp.keyboardHookMode)}
                          >
                            <SelectTrigger id="rdp-keyboard">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="0">On this computer</SelectItem>
                              <SelectItem value="1">On the remote computer</SelectItem>
                              <SelectItem value="2">Remote only in full screen</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="grid gap-2 sm:grid-cols-2">
                          {(
                            [
                              ['redirectClipboard', 'Clipboard'],
                              ['redirectPrinters', 'Printers'],
                              ['redirectSmartCards', 'Smart cards'],
                              ['redirectPorts', 'Serial / parallel ports'],
                              ['redirectDevices', 'Supported Plug and Play devices'],
                            ] as const
                          ).map(([key, label]) => (
                            <label className="flex items-center gap-2 text-xs" key={label}>
                              <Checkbox
                                checked={newConnectionForm.rdp[key]}
                                onCheckedChange={(checked) =>
                                  setNewConnectionForm((form) => ({
                                    ...form,
                                    rdp: {
                                      ...form.rdp,
                                      [key]: checked === true,
                                    },
                                  }))
                                }
                              />
                              <span>{label}</span>
                            </label>
                          ))}
                        </div>
                        <div className="grid gap-2 sm:max-w-[420px]">
                          <Label htmlFor="rdp-drives">Drive redirection</Label>
                          <Select
                            onValueChange={(value) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  redirectDrives:
                                    value === 'custom' ? 'C' : value === 'all' ? 'all' : '',
                                },
                              }))
                            }
                            value={
                              newConnectionForm.rdp.redirectDrives === ''
                                ? 'none'
                                : newConnectionForm.rdp.redirectDrives.toLowerCase() === 'all'
                                  ? 'all'
                                  : 'custom'
                            }
                          >
                            <SelectTrigger id="rdp-drives">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="none">Do not redirect drives</SelectItem>
                              <SelectItem value="all">All drives</SelectItem>
                              <SelectItem value="custom">Selected drive letters</SelectItem>
                            </SelectContent>
                          </Select>
                          {newConnectionForm.rdp.redirectDrives &&
                          newConnectionForm.rdp.redirectDrives !== 'all' ? (
                            <Input
                              onChange={(event) =>
                                setNewConnectionForm((form) => ({
                                  ...form,
                                  rdp: {
                                    ...form.rdp,
                                    redirectDrives: event.target.value,
                                  },
                                }))
                              }
                              placeholder="C,D"
                              value={newConnectionForm.rdp.redirectDrives}
                            />
                          ) : null}
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
                          <Select
                            onValueChange={(value) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  connectionSpeed: Number(value),
                                },
                              }))
                            }
                            value={String(newConnectionForm.rdp.connectionSpeed)}
                          >
                            <SelectTrigger id="rdp-connection-speed">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="1">Modem</SelectItem>
                              <SelectItem value="2">Low-speed broadband</SelectItem>
                              <SelectItem value="3">Satellite</SelectItem>
                              <SelectItem value="4">High-speed broadband</SelectItem>
                              <SelectItem value="5">WAN</SelectItem>
                              <SelectItem value="6">LAN</SelectItem>
                              <SelectItem value="7">Auto detect</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="grid gap-2 sm:grid-cols-2">
                          {(
                            [
                              ['desktopBackground', 'Desktop background'],
                              ['fontSmoothing', 'Font smoothing'],
                              ['desktopComposition', 'Desktop composition'],
                              ['windowDrag', 'Show window contents while dragging'],
                              ['menuAnimation', 'Menu and window animation'],
                              ['visualStyles', 'Visual styles'],
                              ['bitmapCaching', 'Persistent bitmap caching'],
                            ] as const
                          ).map(([key, label]) => (
                            <label className="flex items-center gap-2 text-xs" key={label}>
                              <Checkbox
                                checked={newConnectionForm.rdp[key]}
                                onCheckedChange={(checked) =>
                                  setNewConnectionForm((form) => ({
                                    ...form,
                                    rdp: {
                                      ...form.rdp,
                                      [key]: checked === true,
                                    },
                                  }))
                                }
                              />
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
                          <Select
                            onValueChange={(value) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  serverAuthentication: Number(value),
                                },
                              }))
                            }
                            value={String(newConnectionForm.rdp.serverAuthentication)}
                          >
                            <SelectTrigger id="rdp-authentication">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="2">Warn if authentication fails</SelectItem>
                              <SelectItem value="0">Connect and do not warn</SelectItem>
                              <SelectItem value="1">Never connect</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="grid gap-2 sm:max-w-[320px]">
                          <Label htmlFor="rdp-gateway-mode">Remote Desktop Gateway</Label>
                          <Select
                            onValueChange={(value) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  gatewayUsageMethod: Number(value),
                                },
                              }))
                            }
                            value={String(newConnectionForm.rdp.gatewayUsageMethod)}
                          >
                            <SelectTrigger id="rdp-gateway-mode">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="0">Do not use a gateway</SelectItem>
                              <SelectItem value="1">Always use this gateway</SelectItem>
                              <SelectItem value="2">Detect automatically</SelectItem>
                              <SelectItem value="3">Use system default</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        {newConnectionForm.rdp.gatewayUsageMethod !== 0 ? (
                          <div className="grid gap-4 sm:grid-cols-2">
                            <div className="grid gap-2">
                              <Label htmlFor="rdp-gateway-host">Gateway hostname</Label>
                              <Input
                                id="rdp-gateway-host"
                                onChange={(event) =>
                                  setNewConnectionForm((form) => ({
                                    ...form,
                                    rdp: {
                                      ...form.rdp,
                                      gatewayHostname: event.target.value,
                                    },
                                  }))
                                }
                                value={newConnectionForm.rdp.gatewayHostname}
                              />
                            </div>
                            <div className="grid gap-2">
                              <Label htmlFor="rdp-gateway-credential">Gateway credential</Label>
                              <SearchableCombobox
                                id="rdp-gateway-credential"
                                emptyMessage="No RDP credentials found."
                                onValueChange={(credentialId) =>
                                  setNewConnectionForm((form) => ({
                                    ...form,
                                    rdp: {
                                      ...form.rdp,
                                      gatewayCredentialId:
                                        credentialId === 'none' ? '' : credentialId,
                                    },
                                  }))
                                }
                                options={[
                                  {
                                    value: 'none',
                                    label: 'No saved gateway credential',
                                  },
                                  ...credentialOptions.rdp.map((credential) => ({
                                    value: credential.id,
                                    label: `${credential.name} · ${credential.provider}`,
                                  })),
                                ]}
                                placeholder="No saved gateway credential"
                                searchPlaceholder="Search RDP credentials…"
                                value={newConnectionForm.rdp.gatewayCredentialId || 'none'}
                              />
                            </div>
                            {(
                              [
                                ['gatewayBypassLocal', 'Bypass gateway for local addresses'],
                                [
                                  'gatewayUseSameCreds',
                                  'Use the connection credentials for the gateway',
                                ],
                              ] as const
                            ).map(([key, label]) => (
                              <label className="flex items-center gap-2 text-xs" key={key}>
                                <Checkbox
                                  checked={newConnectionForm.rdp[key]}
                                  onCheckedChange={(checked) =>
                                    setNewConnectionForm((form) => ({
                                      ...form,
                                      rdp: {
                                        ...form.rdp,
                                        [key]: checked === true,
                                      },
                                    }))
                                  }
                                />
                                <span>{label}</span>
                              </label>
                            ))}
                          </div>
                        ) : null}
                        {window.wormhole?.platform === 'win32' ? (
                          <>
                            <label className="flex items-center gap-2 text-xs">
                              <Checkbox
                                checked={
                                  rdpExternalClientRequired ||
                                  newConnectionForm.rdp.useExternalClient
                                }
                                disabled={rdpExternalClientRequired}
                                onCheckedChange={(checked) =>
                                  setNewConnectionForm((form) => ({
                                    ...form,
                                    rdp: {
                                      ...form.rdp,
                                      useExternalClient: checked === true,
                                    },
                                  }))
                                }
                              />
                              <span>Open with system Remote Desktop (mstsc.exe)</span>
                            </label>
                            {rdpExternalClientRequired ? (
                              <p className="text-[11px] leading-relaxed text-muted-foreground">
                                Azure AD credentials require the system Remote Desktop client.
                                Wormhole enforces this route to avoid the embedded Windows host
                                failure.
                              </p>
                            ) : null}
                          </>
                        ) : null}
                        <label className="flex items-center gap-2 text-xs">
                          <Checkbox
                            checked={newConnectionForm.rdp.autoReconnect}
                            onCheckedChange={(checked) =>
                              setNewConnectionForm((form) => ({
                                ...form,
                                rdp: {
                                  ...form.rdp,
                                  autoReconnect: checked === true,
                                },
                              }))
                            }
                          />
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
                    setNewConnectionForm((form) => ({
                      ...form,
                      inlinePassword: '',
                    }));
                    setNewConnectionOpen(false);
                    setEditingConnectionId(null);
                    setConnectionEditorMode('saved');
                  }}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button disabled={editorBusy} type="submit">
                  {connectionEditorMode === 'quick' ? (
                    <Power data-icon="inline-start" />
                  ) : editingConnectionId ? (
                    <Check data-icon="inline-start" />
                  ) : (
                    <Plus data-icon="inline-start" />
                  )}
                  {connectionEditorMode === 'quick'
                    ? 'Connect'
                    : editorBusy
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
              editingFolderGeneration.current += 1;
              editingFolderId.current = null;
              setEditorError('');
            }
          }}
          open={folderDetailsOpen}
        >
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-xl">
            <DialogHeader>
              <DialogTitle>Folder details</DialogTitle>
              <DialogDescription>
                Set defaults inherited by connections inside this folder.
              </DialogDescription>
            </DialogHeader>
            <form className="grid gap-4" onSubmit={submitFolderDetails}>
              <div className="grid gap-2">
                <Label htmlFor="folder-details-name">Folder name</Label>
                <Input
                  autoFocus
                  id="folder-details-name"
                  onChange={(event) =>
                    setFolderDetailsForm((form) => ({
                      ...form,
                      name: event.target.value,
                    }))
                  }
                  required
                  value={folderDetailsForm.name}
                />
              </div>
              <div className="grid max-w-[280px] gap-2">
                <Label htmlFor="folder-credential">Credential</Label>
                <SearchableCombobox
                  id="folder-credential"
                  emptyMessage="No credentials found."
                  onValueChange={(credential) =>
                    setFolderDetailsForm((form) => ({ ...form, credential }))
                  }
                  options={folderCredentialSelectionOptions}
                  placeholder="Select a credential"
                  searchPlaceholder="Search credentials…"
                  value={folderDetailsForm.credential}
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
            if (!open && !bitwardenUnlockBusy) {
              dismissRuntimeBitwardenUnlock();
            }
          }}
          open={bitwardenUnlockPrompt !== null}
        >
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Unlock Bitwarden</DialogTitle>
              <DialogDescription>
                This connection uses a Bitwarden login. Unlock the vault to continue.
              </DialogDescription>
            </DialogHeader>
            <form className="grid gap-4" onSubmit={submitRuntimeBitwardenUnlock}>
              <div className="grid gap-2">
                <Label htmlFor="runtime-bitwarden-password">Master password</Label>
                <Input
                  autoFocus
                  autoComplete="current-password"
                  id="runtime-bitwarden-password"
                  onChange={(event) => setBitwardenUnlockPassword(event.target.value)}
                  type="password"
                  value={bitwardenUnlockPassword}
                />
              </div>
              {bitwardenUnlockError ? (
                <p className="text-[11px] text-destructive" role="alert">
                  {bitwardenUnlockError}
                </p>
              ) : null}
              <DialogFooter>
                <Button
                  disabled={bitwardenUnlockBusy}
                  onClick={dismissRuntimeBitwardenUnlock}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button disabled={bitwardenUnlockBusy || !bitwardenUnlockPassword} type="submit">
                  <KeyRound data-icon="inline-start" />
                  {bitwardenUnlockBusy ? 'Unlocking…' : 'Unlock and connect'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            if (!open && !sshCredentialPromptBusy) {
              setSshCredentialPrompt(null);
              setSshCredentialForm({ username: '', password: '' });
              setSshCredentialSelection(manualCredentialSelectionValue);
              setSshCredentialSave(false);
            }
          }}
          open={sshCredentialPrompt !== null}
        >
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
            <DialogHeader>
              <DialogTitle>SSH credentials</DialogTitle>
              <DialogDescription>
                Choose another saved credential or enter account credentials for this connection.
              </DialogDescription>
            </DialogHeader>
            <form className="grid gap-4" onSubmit={submitSshCredentials}>
              <div className="grid gap-2">
                <Label htmlFor="ssh-runtime-credential">Credential</Label>
                <SearchableCombobox
                  id="ssh-runtime-credential"
                  emptyMessage="No SSH credentials found."
                  onValueChange={setSshCredentialSelection}
                  options={runtimeCredentialSelectionOptions.ssh}
                  placeholder="Select a credential"
                  searchPlaceholder="Search SSH credentials…"
                  value={sshCredentialSelection}
                />
              </div>
              {sshCredentialSelection === manualCredentialSelectionValue ? (
                <>
                  <div className="grid gap-2">
                    <Label htmlFor="ssh-username">Username</Label>
                    <Input
                      autoFocus
                      autoComplete="username"
                      id="ssh-username"
                      onChange={(event) =>
                        setSshCredentialForm((form) => ({
                          ...form,
                          username: event.target.value,
                        }))
                      }
                      required
                      value={sshCredentialForm.username}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="ssh-password">Password</Label>
                    <Input
                      autoComplete="current-password"
                      id="ssh-password"
                      onChange={(event) =>
                        setSshCredentialForm((form) => ({
                          ...form,
                          password: event.target.value,
                        }))
                      }
                      required={sshCredentialSave}
                      type="password"
                      value={sshCredentialForm.password}
                    />
                  </div>
                </>
              ) : null}
              {sshCredentialPrompt?.kind === 'saved' ? (
                <label className="flex items-center gap-2 text-xs">
                  <Checkbox
                    checked={sshCredentialSave}
                    onCheckedChange={(checked) => setSshCredentialSave(checked === true)}
                  />
                  Save to this connection
                </label>
              ) : null}
              <DialogFooter>
                <Button
                  disabled={sshCredentialPromptBusy}
                  onClick={() => {
                    setSshCredentialPrompt(null);
                    setSshCredentialForm({ username: '', password: '' });
                  }}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button
                  disabled={
                    sshCredentialPromptBusy ||
                    (sshCredentialSelection === manualCredentialSelectionValue &&
                      (!sshCredentialForm.username.trim() ||
                        (sshCredentialSave && !sshCredentialForm.password)))
                  }
                  type="submit"
                >
                  <Power data-icon="inline-start" />
                  {sshCredentialPromptBusy ? 'Connecting…' : 'Connect'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            if (!open && !rdpCredentialPromptBusy) {
              setRdpCredentialPrompt(null);
              setRdpCredentialForm({ username: '', domain: '', password: '' });
              setRdpCredentialSelection(manualCredentialSelectionValue);
              setRdpCredentialSave(false);
            }
          }}
          open={rdpCredentialPrompt !== null}
        >
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
            <DialogHeader>
              <DialogTitle>RDP credentials</DialogTitle>
              <DialogDescription>
                Choose a saved credential or enter account credentials for this connection.
              </DialogDescription>
            </DialogHeader>
            <form className="grid gap-4" onSubmit={submitRdpCredentials}>
              <div className="grid gap-2">
                <Label htmlFor="rdp-runtime-credential">Credential</Label>
                <SearchableCombobox
                  id="rdp-runtime-credential"
                  emptyMessage="No RDP credentials found."
                  onValueChange={setRdpCredentialSelection}
                  options={runtimeCredentialSelectionOptions.rdp}
                  placeholder="Select a credential"
                  searchPlaceholder="Search RDP credentials…"
                  value={rdpCredentialSelection}
                />
              </div>
              {rdpCredentialSelection === manualCredentialSelectionValue ? (
                <>
                  <div className="grid gap-2">
                    <Label htmlFor="rdp-username">Username</Label>
                    <Input
                      autoFocus
                      id="rdp-username"
                      onChange={(event) =>
                        setRdpCredentialForm((form) => ({
                          ...form,
                          username: event.target.value,
                        }))
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
                        setRdpCredentialForm((form) => ({
                          ...form,
                          domain: event.target.value,
                        }))
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
                        setRdpCredentialForm((form) => ({
                          ...form,
                          password: event.target.value,
                        }))
                      }
                      required={rdpCredentialSave}
                      type="password"
                      value={rdpCredentialForm.password}
                    />
                  </div>
                </>
              ) : null}
              {sessionsRef.current.find((session) => session.id === rdpCredentialPrompt)?.nodeId ? (
                <label className="flex items-center gap-2 text-xs">
                  <Checkbox
                    checked={rdpCredentialSave}
                    onCheckedChange={(checked) => setRdpCredentialSave(checked === true)}
                  />
                  Save to this connection
                </label>
              ) : null}
              <DialogFooter>
                <Button
                  disabled={rdpCredentialPromptBusy}
                  onClick={() => {
                    setRdpCredentialPrompt(null);
                    setRdpCredentialForm({
                      username: '',
                      domain: '',
                      password: '',
                    });
                  }}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button
                  disabled={
                    rdpCredentialPromptBusy ||
                    (rdpCredentialSelection === manualCredentialSelectionValue &&
                      (!rdpCredentialForm.username.trim() ||
                        (rdpCredentialSave && !rdpCredentialForm.password)))
                  }
                  type="submit"
                >
                  <Power data-icon="inline-start" />
                  {rdpCredentialPromptBusy ? 'Connecting…' : 'Connect'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        <Dialog
          onOpenChange={(open) => {
            setNewFolderOpen(open);
            if (!open) {
              newFolderGeneration.current += 1;
              newFolderParentId.current = null;
            }
          }}
          open={newFolderOpen}
        >
          <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-xl">
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
                  onChange={(event) =>
                    setNewFolderForm((form) => ({
                      ...form,
                      name: event.target.value,
                    }))
                  }
                  placeholder="e.g. Staging"
                  required
                  value={newFolderForm.name}
                />
              </div>
              <div className="grid max-w-[280px] gap-2">
                <Label htmlFor="new-folder-credential">Credential</Label>
                <SearchableCombobox
                  id="new-folder-credential"
                  emptyMessage="No credentials found."
                  onValueChange={(credential) =>
                    setNewFolderForm((form) => ({ ...form, credential }))
                  }
                  options={folderCredentialSelectionOptions}
                  placeholder="Select a credential"
                  searchPlaceholder="Search credentials…"
                  value={newFolderForm.credential}
                />
              </div>
              <AutoSudoField
                id="new-folder-auto-sudo"
                mode={newFolderForm.sshAutoSudo}
                onChange={(sshAutoSudo) => setNewFolderForm((form) => ({ ...form, sshAutoSudo }))}
                scope="folder"
              />
              <TunnelRouteField
                id="new-folder-tunnel-route"
                mode={newFolderForm.tunnel}
                onChange={(tunnel) => setNewFolderForm((form) => ({ ...form, tunnel }))}
                scope="folder"
                tunnels={tunnels}
              />
              {editorError ? <p className="text-[11px] text-destructive">{editorError}</p> : null}
              <DialogFooter>
                <Button
                  disabled={editorBusy}
                  onClick={() => setNewFolderOpen(false)}
                  type="button"
                  variant="ghost"
                >
                  Cancel
                </Button>
                <Button disabled={editorBusy} type="submit">
                  <FolderPlus data-icon="inline-start" />
                  {editorBusy ? 'Creating…' : 'Create folder'}
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
      runs.push({
        text: cell.character || ' ',
        foreground,
        background,
        cursor,
        cellCount: 1,
      });
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

function terminalSelectionText(surface: HTMLElement): string {
  const selection = window.getSelection();
  if (
    !selection ||
    selection.isCollapsed ||
    !selection.anchorNode ||
    !selection.focusNode ||
    !surface.contains(selection.anchorNode) ||
    !surface.contains(selection.focusNode)
  ) {
    return '';
  }
  return selection.toString();
}

function SshTerminalSurface({
  session,
  isActive,
  autoCopyOnSelect,
  onInput,
  onReconnect,
  onTrustHostKey,
  isSerial = false,
}: {
  session: Session;
  isActive: boolean;
  autoCopyOnSelect: boolean;
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
        if (
          shouldUseTerminalClipboardShortcut(
            event,
            Boolean(terminalSelectionText(event.currentTarget)),
          )
        ) {
          return;
        }
        const data = terminalKeyData(event, session.terminalFrame?.applicationCursor ?? false);
        if (data === undefined) return;
        event.preventDefault();
        onInput(session.id, data);
      }}
      onPaste={(event) => {
        const text = event.clipboardData.getData('text');
        if (!text) return;
        event.preventDefault();
        onInput(session.id, normalizeTerminalPasteText(text));
      }}
      onMouseUp={(event) => {
        if (!shouldAutoCopyTerminalSelection(autoCopyOnSelect, event.button)) return;
        const text = terminalSelectionText(event.currentTarget);
        if (text) void copyTextToClipboard(text).catch(() => undefined);
      }}
      onContextMenu={(event) => {
        if (isSerial || !session.backendSessionId) return;
        event.preventDefault();
        void window.wormhole?.pasteClipboardToSsh(session.backendSessionId).catch(() => undefined);
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
    // This helper intentionally mutates its Set argument; it is not a React state updater.
    // react-doctor-disable-next-line react-doctor/no-side-effect-in-state-updater-function
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
  const dataItems = Array.from(data.items);
  const items = Array.from(data.files).reduce<SftpTransferItem[]>((result, file) => {
    const candidate = file as File & { path?: string };
    const transferItem = dataItems.find((item) => item.getAsFile()?.name === file.name) as
      | (DataTransferItem & {
          webkitGetAsEntry?: () => { isDirectory?: boolean } | null;
        })
      | undefined;
    const fileSystemEntry = transferItem?.webkitGetAsEntry?.();
    const item = {
      sourcePath: candidate.path || file.name,
      name: file.name,
      isDirectory: fileSystemEntry?.isDirectory === true,
      size: file.size,
    } satisfies SftpTransferItem;
    if (item.sourcePath.length > 0) result.push(item);
    return result;
  }, []);
  return items.length > 0 ? { sourcePane: 'local', items, external: true } : undefined;
}

// Virtualization, selection, drag/drop, and keyboard navigation share one pane coordinate system;
// keeping them together prevents subtly different path and selection semantics.
// react-doctor-disable-next-line react-doctor/no-giant-component
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
        if (event.key === 'Enter') {
          event.preventDefault();
          onDecision('skip', applyToAll);
        } else if (event.key === 'Escape') {
          event.preventDefault();
          onCancel();
        }
      }}
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
    </dialog>
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

// The pane tree and its drag, split, focus, and native-surface routing are one layout state machine.
// react-doctor-disable-next-line react-doctor/no-giant-component
function SessionsPage({
  autoCopyOnSelect,
  bitwardenUnlockPending,
  isAuthorized,
  isWebSurfaceVisible,
  sessions,
  selectedSession,
  onBitwardenUnlockRequired,
  onCloseSession,
  onConnectRdp,
  onOpenSystemRdp,
  onDisconnectSession,
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
  onVncStatusChange,
}: {
  autoCopyOnSelect: boolean;
  bitwardenUnlockPending: boolean;
  isAuthorized: boolean;
  isWebSurfaceVisible: boolean;
  sessions: Session[];
  selectedSession?: Session;
  onBitwardenUnlockRequired: (sessionId: string, reason: string, retry: () => void) => void;
  onCloseSession: (id: string, preferredNextSessionId?: string) => void;
  onConnectRdp: (id: string) => void;
  onOpenSystemRdp: (id: string) => void;
  onDisconnectSession: (id: string) => void;
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
  onVncStatusChange: (sessionId: string, status: Session['status']) => void;
}) {
  const [bitwardenOpenSessionId, setBitwardenOpenSessionId] = useState('');
  useEffect(() => {
    return window.wormhole?.onBitwardenPopupState((state) => {
      setBitwardenOpenSessionId(state.open ? state.sessionId : '');
    });
  }, []);
  const [layout, setLayout] = useState<SessionLayoutState>(() =>
    createSessionLayout(
      sessions.map((session) => session.id),
      selectedSession?.id,
    ),
  );
  const [draggedSessionId, setDraggedSessionId] = useState('');
  const [resizingSplitId, setResizingSplitId] = useState('');
  const [dropPreview, setDropPreview] = useState<{
    paneId: string;
    edge?: SessionLayoutEdge;
    tabIndex?: number;
  } | null>(null);
  const sessionIdsKey = JSON.stringify(sessions.map((session) => session.id));
  const sessionIds = useMemo(() => JSON.parse(sessionIdsKey) as string[], [sessionIdsKey]);
  const currentLayout = useMemo(
    () => reconcileSessionLayout(layout, sessionIds, selectedSession?.id),
    [layout, selectedSession?.id, sessionIds],
  );

  // The session catalog is owned by App and may change after native lifecycle events. Persist the
  // reconciled tree so removed tab identities and drag state cannot revive if an ID is reopened.
  // react-doctor-disable-next-line react-hooks-js/set-state-in-effect
  useEffect(() => {
    setLayout((current) => reconcileSessionLayout(current, sessionIds, selectedSession?.id)); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    if (draggedSessionId && !sessionIds.includes(draggedSessionId)) {
      setDraggedSessionId(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
      setDropPreview(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    }
  }, [draggedSessionId, selectedSession?.id, sessionIds]);

  const dragIsValid = !draggedSessionId || sessionIds.includes(draggedSessionId);
  const activeDraggedSessionId = dragIsValid ? draggedSessionId : '';
  const activeDropPreview = dragIsValid ? dropPreview : null;

  function updateLayout(updater: (current: SessionLayoutState) => SessionLayoutState) {
    setLayout((current) =>
      updater(reconcileSessionLayout(current, sessionIds, selectedSession?.id)),
    );
  }

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

  const panes = sessionPanes(currentLayout.root);
  const rects = sessionPaneRects(currentLayout.root);
  const dividers = sessionSplitDividers(currentLayout.root);
  const rectByPane = new Map(rects.map((rect) => [rect.paneId, rect]));
  const sessionById = new Map(sessions.map((session) => [session.id, session]));
  const paneBySessionId = new Map(
    panes.flatMap((pane) => pane.tabs.map((sessionId) => [sessionId, pane] as const)),
  );

  function activateSession(paneId: string, sessionId: string) {
    updateLayout((current) => selectSession(current, paneId, sessionId));
    onSelectSession(sessionId);
  }

  function closePaneSession(pane: SessionPane, sessionId: string) {
    const index = pane.tabs.indexOf(sessionId);
    const preferredNextSessionId =
      pane.tabs[index + 1] ??
      pane.tabs[index - 1] ??
      panes.find((candidate) => candidate.id !== pane.id)?.activeSessionId;
    onCloseSession(sessionId, preferredNextSessionId);
  }

  function finishDrop(sessionId: string) {
    if (!sessionIds.includes(sessionId) || !activeDropPreview) {
      setDraggedSessionId('');
      setDropPreview(null);
      return;
    }
    updateLayout((current) =>
      activeDropPreview.edge
        ? splitSession(current, activeDropPreview.paneId, activeDropPreview.edge, sessionId)
        : moveSession(current, activeDropPreview.paneId, sessionId, activeDropPreview.tabIndex),
    );
    onSelectSession(sessionId);
    setDraggedSessionId('');
    setDropPreview(null);
  }

  function restoreFullView(sessionId: string) {
    updateLayout((current) => restoreSessionFullView(current, sessionId));
    onSelectSession(sessionId);
  }

  function updateDropPreview(event: DragEvent<HTMLElement>) {
    const sessionId = activeDraggedSessionId || event.dataTransfer.getData('text/wormhole-session');
    if (!sessionId) return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const x = ((event.clientX - bounds.left) / bounds.width) * 100;
    const y = ((event.clientY - bounds.top) / bounds.height) * 100;
    const rect = rects.find(
      (candidate) =>
        x >= candidate.x &&
        x <= candidate.x + candidate.width &&
        y >= candidate.y &&
        y <= candidate.y + candidate.height,
    );
    if (!rect) return;
    event.preventDefault();
    const headerHeight = (36 / bounds.height) * 100;
    if (y <= rect.y + headerHeight) {
      const tab = (event.target as HTMLElement).closest<HTMLElement>('[data-session-tab-index]');
      setDropPreview({
        paneId: rect.paneId,
        tabIndex: tab ? Number(tab.dataset.sessionTabIndex) : undefined,
      });
      return;
    }
    if (!canSplitSession(currentLayout, rect.paneId, sessionId)) {
      event.dataTransfer.dropEffect = 'none';
      setDropPreview(null);
      return;
    }
    const localX = (x - rect.x) / rect.width;
    const localY = (y - rect.y) / rect.height;
    const distances: Array<[SessionLayoutEdge, number]> = [
      ['left', localX],
      ['right', 1 - localX],
      ['top', localY],
      ['bottom', 1 - localY],
    ];
    distances.sort((left, right) => left[1] - right[1]);
    setDropPreview({ paneId: rect.paneId, edge: distances[0][0] });
  }

  function keyboardMove(
    event: ReactKeyboardEvent<HTMLButtonElement>,
    pane: SessionPane,
    sessionId: string,
  ) {
    const edgeByKey: Partial<Record<string, SessionLayoutEdge>> = {
      ArrowLeft: 'left',
      ArrowRight: 'right',
      ArrowUp: 'top',
      ArrowDown: 'bottom',
    };
    if (event.altKey && event.shiftKey && edgeByKey[event.key]) {
      event.preventDefault();
      const edge = edgeByKey[event.key]!;
      updateLayout((current) => splitSession(current, pane.id, edge, sessionId));
      onSelectSession(sessionId);
      return;
    }
    if (!event.altKey && (event.key === 'ArrowLeft' || event.key === 'ArrowRight')) {
      event.preventDefault();
      const offset = event.key === 'ArrowLeft' ? -1 : 1;
      const index = pane.tabs.indexOf(sessionId);
      const next = pane.tabs[(index + offset + pane.tabs.length) % pane.tabs.length];
      activateSession(pane.id, next);
      document.querySelector<HTMLElement>(`[data-session-tab-id="${CSS.escape(next)}"]`)?.focus();
    }
  }

  return (
    <section
      aria-label="Session pane workspace"
      className="relative h-full min-h-0 min-w-0 overflow-hidden bg-background"
      onDragLeave={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDropPreview(null);
      }}
      onDragOver={updateDropPreview}
      onDrop={(event) => {
        event.preventDefault();
        finishDrop(activeDraggedSessionId || event.dataTransfer.getData('text/wormhole-session'));
      }}
    >
      {panes.map((pane) => {
        const rect = rectByPane.get(pane.id)!;
        return (
          <SessionPaneChrome
            dropTarget={activeDropPreview?.paneId === pane.id && !activeDropPreview.edge}
            key={pane.id}
            onActivate={() => updateLayout((current) => focusSessionPane(current, pane.id))}
            rect={rect}
          >
            {pane.tabs.map((sessionId, tabIndex) => {
              const session = sessionById.get(sessionId);
              if (!session) return null;
              const active = sessionId === pane.activeSessionId;
              return (
                <SessionTabContextMenu
                  key={session.id}
                  onClose={() => closePaneSession(pane, session.id)}
                  onDisconnect={() => onDisconnectSession(session.id)}
                  onDuplicate={() => onDuplicateSession(session.id)}
                  onFileTransfer={() => onOpenFileTransfer(session.id)}
                  onOpenSystemRdp={() => onOpenSystemRdp(session.id)}
                  onReconnect={() => onReconnectSession(session.id)}
                  onRestoreFullView={
                    panes.length > 1 ? () => restoreFullView(session.id) : undefined
                  }
                  session={session}
                >
                  <div
                    className={`relative flex h-9 min-w-[8rem] max-w-[15rem] flex-1 border-r border-border/60 ${active ? 'bg-card text-foreground' : 'text-muted-foreground hover:bg-muted/25'}`}
                    data-session-tab-index={tabIndex}
                  >
                    <button
                      aria-label={`${session.title}. Drag to a pane edge to split.`}
                      aria-selected={active}
                      className="min-w-0 flex-1 cursor-grab truncate px-3 pr-12 text-left !text-xs font-medium outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
                      data-session-tab-id={session.id}
                      draggable
                      onAuxClick={(event) => {
                        if (event.button === 1) closePaneSession(pane, session.id);
                      }}
                      onClick={() => activateSession(pane.id, session.id)}
                      onDragEnd={() => {
                        setDraggedSessionId('');
                        setDropPreview(null);
                      }}
                      onDragStart={(event) => {
                        event.dataTransfer.effectAllowed = 'move';
                        event.dataTransfer.setData('text/wormhole-session', session.id);
                        setDraggedSessionId(session.id);
                        activateSession(pane.id, session.id);
                      }}
                      onFocus={() => activateSession(pane.id, session.id)}
                      onKeyDown={(event) => keyboardMove(event, pane, session.id)}
                      onDoubleClick={() => {
                        if (panes.length > 1) restoreFullView(session.id);
                      }}
                      role="tab"
                      tabIndex={active ? 0 : -1}
                      title="Drag to another tab bar to move, or to a pane edge to split. Alt+Shift+Arrow also splits."
                      type="button"
                    >
                      {session.title}
                    </button>
                    <div className="absolute right-1 top-1/2 flex -translate-y-1/2 items-center">
                      {session.canTransfer && session.status === 'connected' ? (
                        <IconButton
                          label={`Open SFTP browser for ${session.title}`}
                          onClick={() => onOpenFileTransfer(session.id)}
                        >
                          <ArrowRightLeft />
                        </IconButton>
                      ) : null}
                      <IconButton
                        className="text-muted-foreground hover:bg-transparent hover:text-foreground"
                        label={`Close ${session.title}`}
                        onClick={() => closePaneSession(pane, session.id)}
                      >
                        <X />
                      </IconButton>
                    </div>
                  </div>
                </SessionTabContextMenu>
              );
            })}
          </SessionPaneChrome>
        );
      })}

      {sessions.map((session) => {
        const pane = paneBySessionId.get(session.id);
        const rect = pane ? rectByPane.get(pane.id) : undefined;
        const active = Boolean(pane && rect && pane.activeSessionId === session.id);
        return (
          <div
            aria-hidden={!active}
            className="absolute min-h-0 min-w-0 overflow-hidden"
            key={session.id}
            onPointerDownCapture={() => {
              if (pane) activateSession(pane.id, session.id);
            }}
            style={sessionSurfaceStyle(rect, active)}
          >
            <SessionSurface
              autoCopyOnSelect={autoCopyOnSelect}
              bitwardenOpen={bitwardenOpenSessionId === session.id}
              bitwardenUnlockPending={bitwardenUnlockPending}
              isActive={active}
              isAuthorized={isAuthorized}
              isWebSurfaceVisible={isWebSurfaceVisible}
              nativeSurfaceActive={
                active && isWebSurfaceVisible && !activeDraggedSessionId && !resizingSplitId
              }
              onBitwardenUnlockRequired={onBitwardenUnlockRequired}
              onCloseSftpBrowser={onCloseSftpBrowser}
              onConnectRdp={onConnectRdp}
              onOpenSystemRdp={onOpenSystemRdp}
              onReconnectSession={onReconnectSession}
              onRetryRdp={onRetryRdp}
              onSerialInput={onSerialInput}
              onSftpConflict={onSftpConflict}
              onSftpLocalNavigate={onSftpLocalNavigate}
              onSftpNavigate={onSftpNavigate}
              onSftpOperation={onSftpOperation}
              onSftpRefresh={onSftpRefresh}
              onSftpTransfer={onSftpTransfer}
              onSftpTransferCancel={onSftpTransferCancel}
              onSftpTransferErrorClear={onSftpTransferErrorClear}
              onSftpTransferRemove={onSftpTransferRemove}
              onSshInput={onSshInput}
              onTrustSshHostKey={onTrustSshHostKey}
              onVncStatusChange={onVncStatusChange}
              session={session}
            />
          </div>
        );
      })}

      {dividers.map((divider) => (
        <SessionSplitHandle
          divider={divider}
          key={divider.splitId}
          onResizeEnd={() => setResizingSplitId('')}
          onResizeStart={() => setResizingSplitId(divider.splitId)}
          onRatioChange={(ratio) =>
            updateLayout((current) => setSessionSplitRatio(current, divider.splitId, ratio))
          }
        />
      ))}

      {activeDropPreview?.edge ? (
        <SessionDropPreview
          edge={activeDropPreview.edge}
          rect={rectByPane.get(activeDropPreview.paneId)}
        />
      ) : null}
      <p aria-live="polite" className="sr-only">
        {activeDropPreview?.edge
          ? `Drop to split ${activeDropPreview.edge}`
          : activeDropPreview
            ? 'Drop to move this tab into the pane'
            : ''}
      </p>
    </section>
  );
}

function SessionSplitHandle({
  divider,
  onRatioChange,
  onResizeEnd,
  onResizeStart,
}: {
  divider: SessionSplitDivider;
  onRatioChange: (ratio: number) => void;
  onResizeEnd: () => void;
  onResizeStart: () => void;
}) {
  const horizontal = divider.orientation === 'horizontal';
  const style: CSSProperties = horizontal
    ? {
        left: `calc(${divider.x + divider.width * divider.ratio}% - 3px)`,
        top: `${divider.y}%`,
        width: '6px',
        height: `${divider.height}%`,
      }
    : {
        left: `${divider.x}%`,
        top: `calc(${divider.y + divider.height * divider.ratio}% - 3px)`,
        width: `${divider.width}%`,
        height: '6px',
      };

  function updateFromPointer(event: React.PointerEvent<HTMLDivElement>) {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
    const bounds = event.currentTarget.parentElement?.getBoundingClientRect();
    if (!bounds || bounds.width < 1 || bounds.height < 1) return;
    const position = horizontal
      ? ((event.clientX - bounds.left) / bounds.width) * 100
      : ((event.clientY - bounds.top) / bounds.height) * 100;
    const origin = horizontal ? divider.x : divider.y;
    const size = horizontal ? divider.width : divider.height;
    onRatioChange((position - origin) / size);
  }

  return (
    <div
      aria-label={`Resize ${horizontal ? 'left and right' : 'top and bottom'} session panes`}
      aria-orientation={horizontal ? 'vertical' : 'horizontal'}
      aria-valuemax={85}
      aria-valuemin={15}
      aria-valuenow={Math.round(divider.ratio * 100)}
      className={`absolute z-30 touch-none bg-transparent outline-none after:absolute after:bg-border hover:after:bg-primary focus-visible:after:bg-primary ${horizontal ? 'cursor-col-resize after:inset-y-0 after:left-[2px] after:w-px' : 'cursor-row-resize after:inset-x-0 after:top-[2px] after:h-px'}`}
      onKeyDown={(event) => {
        const decrease = horizontal ? event.key === 'ArrowLeft' : event.key === 'ArrowUp';
        const increase = horizontal ? event.key === 'ArrowRight' : event.key === 'ArrowDown';
        if (!decrease && !increase) return;
        event.preventDefault();
        onRatioChange(divider.ratio + (decrease ? -0.05 : 0.05));
      }}
      onPointerDown={(event) => {
        onResizeStart();
        event.currentTarget.setPointerCapture(event.pointerId);
        updateFromPointer(event);
      }}
      onPointerCancel={onResizeEnd}
      onPointerUp={(event) => {
        if (event.currentTarget.hasPointerCapture(event.pointerId)) {
          event.currentTarget.releasePointerCapture(event.pointerId);
        }
        onResizeEnd();
      }}
      onPointerMove={updateFromPointer}
      role="separator"
      style={style}
      tabIndex={0}
    />
  );
}

function sessionSurfaceStyle(rect: SessionPaneRect | undefined, active: boolean): CSSProperties {
  if (!rect) {
    return {
      left: 0,
      top: 0,
      width: 1,
      height: 1,
      visibility: 'hidden',
      pointerEvents: 'none',
    };
  }
  return {
    left: `calc(${rect.x}% + 3px)`,
    top: `calc(${rect.y}% + 39px)`,
    width: `calc(${rect.width}% - 6px)`,
    height: `calc(${rect.height}% - 42px)`,
    visibility: active ? 'visible' : 'hidden',
    pointerEvents: active ? 'auto' : 'none',
    zIndex: active ? 10 : 0,
  };
}

function SessionPaneChrome({
  children,
  dropTarget,
  onActivate,
  rect,
}: {
  children: ReactNode;
  dropTarget: boolean;
  onActivate: () => void;
  rect: SessionPaneRect;
}) {
  return (
    <div
      aria-label={`Session pane ${rect.paneId}`}
      className="pointer-events-none absolute border border-border"
      role="group"
      style={{
        left: `${rect.x}%`,
        top: `${rect.y}%`,
        width: `${rect.width}%`,
        height: `${rect.height}%`,
      }}
    >
      <div
        aria-label="Pane tabs"
        className={`pointer-events-auto relative z-30 flex h-9 min-w-0 items-stretch overflow-x-auto overflow-y-hidden border-b border-border ${dropTarget ? 'bg-primary/20 ring-2 ring-inset ring-primary' : 'bg-card/55'}`}
        onFocusCapture={onActivate}
        onPointerDown={onActivate}
        role="tablist"
      >
        {children}
      </div>
    </div>
  );
}

function SessionDropPreview({
  edge,
  rect,
}: {
  edge: SessionLayoutEdge;
  rect: SessionPaneRect | undefined;
}) {
  if (!rect) return null;
  const style: CSSProperties = {
    left: `${rect.x + (edge === 'right' ? rect.width / 2 : 0)}%`,
    top: `${rect.y + (edge === 'bottom' ? rect.height / 2 : 0)}%`,
    width: `${edge === 'left' || edge === 'right' ? rect.width / 2 : rect.width}%`,
    height: `${edge === 'top' || edge === 'bottom' ? rect.height / 2 : rect.height}%`,
  };
  return (
    <div
      className="pointer-events-none absolute z-40 grid place-items-center border-2 border-primary bg-primary/20 text-xs font-semibold uppercase tracking-wider text-primary"
      style={style}
    >
      Split {edge}
    </div>
  );
}

function SessionSurfaceFallback({ protocol }: { protocol: Protocol }) {
  return (
    <div className="grid h-full place-items-center text-xs text-muted-foreground" role="status">
      Loading {protocolLabel(protocol)} session…
    </div>
  );
}

function SessionSurface({
  autoCopyOnSelect,
  bitwardenOpen,
  bitwardenUnlockPending,
  isActive,
  isAuthorized,
  isWebSurfaceVisible,
  nativeSurfaceActive,
  onBitwardenUnlockRequired,
  onCloseSftpBrowser,
  onConnectRdp,
  onOpenSystemRdp,
  onReconnectSession,
  onRetryRdp,
  onSerialInput,
  onSftpConflict,
  onSftpLocalNavigate,
  onSftpNavigate,
  onSftpOperation,
  onSftpRefresh,
  onSftpTransfer,
  onSftpTransferCancel,
  onSftpTransferErrorClear,
  onSftpTransferRemove,
  onSshInput,
  onTrustSshHostKey,
  onVncStatusChange,
  session,
}: {
  autoCopyOnSelect: boolean;
  bitwardenOpen: boolean;
  bitwardenUnlockPending: boolean;
  isActive: boolean;
  isAuthorized: boolean;
  isWebSurfaceVisible: boolean;
  nativeSurfaceActive: boolean;
  session: Session;
  onBitwardenUnlockRequired: (sessionId: string, reason: string, retry: () => void) => void;
  onCloseSftpBrowser: (id: string) => void;
  onConnectRdp: (id: string) => void;
  onOpenSystemRdp: (id: string) => void;
  onReconnectSession: (id: string) => void;
  onRetryRdp: (id: string) => void;
  onSerialInput: (sessionId: string, value: string) => void;
  onSftpConflict: (
    sessionId: string,
    transferId: string,
    itemId: string,
    decision: 'overwrite' | 'skip',
    applyToAll: boolean,
  ) => void;
  onSftpLocalNavigate: (sessionId: string, path: string) => void;
  onSftpNavigate: (sessionId: string, path: string) => void;
  onSftpOperation: (
    sessionId: string,
    pane: SftpPaneKind,
    operation: SftpOperation,
    path: string,
    destinationPath?: string,
  ) => void;
  onSftpRefresh: (id: string) => void;
  onSftpTransfer: (
    sessionId: string,
    direction: SftpTransferDirection,
    destinationPath: string,
    items: SftpTransferItem[],
  ) => void;
  onSftpTransferCancel: (sessionId: string, transferId: string, itemId: string) => void;
  onSftpTransferErrorClear: (sessionId: string) => void;
  onSftpTransferRemove: (sessionId: string, transferId: string, itemId: string) => void;
  onSshInput: (sessionId: string, value: string) => void;
  onTrustSshHostKey: (sessionId: string, mismatch: NonNullable<Session['hostKeyMismatch']>) => void;
  onVncStatusChange: (sessionId: string, status: Session['status']) => void;
}) {
  if (session.protocol === 'ssh') {
    return (
      <>
        <SshTerminalSurface
          autoCopyOnSelect={autoCopyOnSelect}
          isActive={isActive}
          onInput={onSshInput}
          onReconnect={onReconnectSession}
          onTrustHostKey={onTrustSshHostKey}
          session={session}
        />
        {session.sftp && isActive ? (
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
    );
  }
  if (session.protocol === 'serial') {
    return (
      <SshTerminalSurface
        autoCopyOnSelect={autoCopyOnSelect}
        isActive={isActive}
        isSerial
        onInput={onSerialInput}
        onReconnect={onReconnectSession}
        session={session}
      />
    );
  }
  if (session.protocol === 'rdp') {
    return (
      <RdpSurface
        canOpenSystemClient={canOpenRdpSystemClient(session)}
        error={session.rdpError}
        external={session.rdpExternal}
        isActive={nativeSurfaceActive}
        isAuthorized={isAuthorized}
        onConnect={() => onConnectRdp(session.id)}
        onOpenSystemClient={() => onOpenSystemRdp(session.id)}
        onRetry={() => onRetryRdp(session.id)}
        sessionId={session.id}
        status={session.rdpStatus ?? 'idle'}
        tunnelProgress={session.tunnelProgress}
      />
    );
  }
  if (session.protocol === 'vnc') {
    return (
      <Suspense fallback={<SessionSurfaceFallback protocol="vnc" />}>
        <VncSurface
          bitwardenUnlockPending={bitwardenUnlockPending}
          connectionGeneration={session.vncConnectionGeneration ?? 0}
          disconnected={session.status === 'closed'}
          isAuthorized={isAuthorized}
          onBitwardenUnlockRequired={(reason, retry) =>
            onBitwardenUnlockRequired(session.id, reason, retry)
          }
          onReconnect={() => onReconnectSession(session.id)}
          onStatusChange={(status) =>
            status === 'idle'
              ? undefined
              : onVncStatusChange(session.id, status === 'disconnected' ? 'closed' : status)
          }
          session={{
            id: session.id,
            nodeId: session.nodeId,
            credentialId: session.credentialId,
            host: session.host,
            port: session.port,
            tunnelConfigId: session.tunnelConfigId,
            tunnelProgress: session.tunnelProgress,
          }}
        />
      </Suspense>
    );
  }
  if (session.protocol === 'http' || session.protocol === 'https') {
    return (
      <Suspense fallback={<SessionSurfaceFallback protocol={session.protocol} />}>
        <WebSurface
          bitwardenOpen={bitwardenOpen}
          isActive={nativeSurfaceActive}
          isAuthorized={isAuthorized && isWebSurfaceVisible}
          onReconnect={onReconnectSession}
          session={session}
        />
      </Suspense>
    );
  }
  return (
    <div aria-label="Connection canvas" className="grid h-full place-items-center p-8 text-center">
      <div>
        <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">
          {protocolLabel(session.protocol)}
        </p>
        <p className="mt-2 text-sm font-medium">Unsupported protocol surface</p>
        <p className="mt-1 text-xs text-muted-foreground">
          {session.host || 'inherited target'}:{session.port ?? 'default'}
        </p>
      </div>
    </div>
  );
}

// Credential editing and Bitwarden lookup deliberately share one authorization boundary so every
// close, lock, and failed lookup scrubs the same renderer-held secret state.
// react-doctor-disable-next-line react-doctor/no-giant-component, react-doctor/prefer-useReducer
function CredentialsPage({
  initialCredentials,
  isAuthorized,
  onCreate,
  onUpdate,
  onDelete,
}: {
  initialCredentials: CredentialRecord[];
  isAuthorized: boolean;
  onCreate: (draft: CredentialDraft) => Promise<void>;
  onUpdate: (id: string, draft: CredentialDraft) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  // react-doctor-disable-next-line react-doctor/prefer-useReducer
}) {
  const [searchText, setSearchText] = useState('');
  const [selectedCredentials, setSelectedCredentials] = useState<Set<string>>(() => new Set());
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingCredential, setEditingCredential] = useState<CredentialRecord | null>(null);
  const [credentialForm, setCredentialForm] = useState<CredentialDraft>(emptyCredentialDraft);
  const [pendingDeletion, setPendingDeletion] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [operationError, setOperationError] = useState('');
  const [bitwardenQuery, setBitwardenQuery] = useState('');
  const [bitwardenItems, setBitwardenItems] = useState<WormholeBitwardenLoginItem[]>([]);
  const [bitwardenUnlockPassword, setBitwardenUnlockPassword] = useState('');
  const [bitwardenSearchStatus, setBitwardenSearchStatus] = useState('');
  const [bitwardenSearching, setBitwardenSearching] = useState(false);
  const [privateKeySelecting, setPrivateKeySelecting] = useState(false);
  const bitwardenSearchAttempts = useLazyRef(() => new WebSessionAttemptTracker());

  // App lock is an external security boundary. Scrub every renderer-held secret without
  // remounting this page, because a remount would orphan credential mutations already in flight.
  // react-doctor-disable-next-line react-hooks-js/set-state-in-effect, react-doctor/no-adjust-state-on-prop-change
  useEffect(() => {
    if (isAuthorized) return;
    setEditorOpen(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setEditingCredential(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setCredentialForm(emptyCredentialDraft()); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setPendingDeletion([]); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setOperationError(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenQuery(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenItems([]); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenUnlockPassword(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenSearchStatus(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenSearching(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setPrivateKeySelecting(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    bitwardenSearchAttempts.current.cancel('credential-search');
  }, [bitwardenSearchAttempts, isAuthorized]);

  const credentials = initialCredentials;
  const deferredSearchText = useDeferredValue(searchText);
  const normalizedCredentialSearch = normalizeListSearch(deferredSearchText);
  const credentialSearchResultsPending = listSearchResultsArePending(
    searchText,
    deferredSearchText,
  );
  const credentialSearchActive = normalizedCredentialSearch.length > 0;
  const credentialSearchIndex = useMemo(
    () =>
      credentialSearchActive
        ? credentials.map((credential) => ({
            item: credential,
            text: [
              credential.name,
              credential.username,
              credential.domain,
              credential.provider,
              credential.kind === 'sshKey' ? 'SSH key' : 'Password',
              credential.privateKeyFileName,
            ]
              .filter(Boolean)
              .join('\u0000')
              .toLowerCase(),
          }))
        : [],
    [credentialSearchActive, credentials],
  );

  const filteredCredentials = useMemo(
    () => filterListSearchIndex(credentials, credentialSearchIndex, normalizedCredentialSearch),
    [credentialSearchIndex, credentials, normalizedCredentialSearch],
  );

  const credentialById = useMemo(
    () => new Map(credentials.map((credential) => [credential.id, credential])),
    [credentials],
  );
  const validSelectedCredentials = useMemo(
    () => new Set([...selectedCredentials].filter((id) => credentialById.has(id))),
    [credentialById, selectedCredentials],
  );

  const allVisibleSelected =
    filteredCredentials.length > 0 &&
    filteredCredentials.every((credential) => validSelectedCredentials.has(credential.id));
  const deletableSelectedCredentials = [...validSelectedCredentials].filter(
    (id) => credentialById.get(id)?.canDelete,
  );

  const deletingCredentials = pendingDeletion
    .map((id) => credentialById.get(id))
    .filter((credential): credential is CredentialRecord => Boolean(credential));

  function toggleCredential(id: string, checked: boolean) {
    setSelectedCredentials((current) => {
      const next = new Set(current);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function openNewCredential() {
    setEditingCredential(null);
    setCredentialForm(emptyCredentialDraft());
    setOperationError('');
    resetBitwardenSearch();
    setEditorOpen(true);
  }

  function openEditCredential(credential: CredentialRecord) {
    if (!credential.canEdit) return;
    const protocol = credential.protocol as CredentialDraft['protocol'];
    setEditingCredential(credential);
    setCredentialForm({
      name: credential.name,
      protocol,
      kind: credential.kind === 'sshKey' ? 'sshKey' : 'password',
      username: credential.username === 'No username' ? '' : credential.username,
      domain: credential.domain ?? '',
      // The renderer never reads saved secrets. Leaving this blank preserves a local secret.
      password: '',
      passphrase: '',
      clearPassphrase: false,
      privateKeySelectionId: '',
      privateKeyFileName: credential.privateKeyFileName ?? '',
      provider: credential.provider,
      bitwardenItemId: credential.bitwardenItemId ?? '',
      bitwardenItemName: credential.bitwardenItemName ?? '',
    });
    setOperationError('');
    resetBitwardenSearch();
    setEditorOpen(true);
  }

  function closeCredentialEditor() {
    discardPrivateKeySelection(credentialForm.privateKeySelectionId);
    setEditorOpen(false);
    setEditingCredential(null);
    setCredentialForm(emptyCredentialDraft());
    setOperationError('');
    resetBitwardenSearch();
  }

  function discardPrivateKeySelection(selectionId: string) {
    if (!selectionId) return;
    void window.wormhole?.discardSshPrivateKeySelection({ selectionId }).catch(() => undefined);
  }

  async function selectPrivateKey() {
    if (privateKeySelecting || !window.wormhole) return;
    setPrivateKeySelecting(true);
    setOperationError('');
    try {
      const selected = await window.wormhole.selectSshPrivateKey();
      if (!selected) return;
      discardPrivateKeySelection(credentialForm.privateKeySelectionId);
      setCredentialForm((form) => ({
        ...form,
        clearPassphrase: false,
        privateKeySelectionId: selected.selectionId,
        privateKeyFileName: selected.fileName,
      }));
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : 'Could not select the SSH key.');
    } finally {
      setPrivateKeySelecting(false);
    }
  }

  function resetBitwardenSearch() {
    bitwardenSearchAttempts.current.cancel('credential-search');
    setBitwardenQuery('');
    setBitwardenItems([]);
    setBitwardenUnlockPassword('');
    setBitwardenSearchStatus('');
    setBitwardenSearching(false);
  }

  async function searchBitwarden() {
    if (bitwardenSearching || !window.wormhole) return;
    const generation = bitwardenSearchAttempts.current.begin('credential-search');
    const masterPassword = bitwardenUnlockPassword;
    // Treat an unlock value like every other renderer-held secret: consume it before the first
    // native await so errors, editor closure, and stale responses cannot keep it in React state.
    setBitwardenUnlockPassword('');
    setBitwardenSearching(true);
    setBitwardenSearchStatus('Searching Bitwarden…');
    setOperationError('');
    try {
      let response: { items: WormholeBitwardenLoginItem[] };
      try {
        response = await window.wormhole.searchBitwardenItems(bitwardenQuery);
      } catch (error) {
        if (!bitwardenSearchAttempts.current.isCurrent('credential-search', generation)) return;
        if (!masterPassword || !isBitwardenUnlockError(backendErrorMessage(error))) {
          throw error;
        }
        await window.wormhole.unlockBitwardenCli(masterPassword);
        if (!bitwardenSearchAttempts.current.isCurrent('credential-search', generation)) return;
        response = await window.wormhole.searchBitwardenItems(bitwardenQuery);
      }
      if (!bitwardenSearchAttempts.current.isCurrent('credential-search', generation)) return;
      setBitwardenItems(response.items);
      setBitwardenSearchStatus(
        response.items.length === 0
          ? 'No Bitwarden login items matched.'
          : `Found ${response.items.length} login item(s).`,
      );
      if (response.items.length === 1) selectBitwardenItem(response.items[0]);
    } catch (error) {
      if (!bitwardenSearchAttempts.current.isCurrent('credential-search', generation)) return;
      const message = backendErrorMessage(error);
      const needsLogin = /log in|login|unauth/i.test(message);
      const locked = isBitwardenUnlockError(message);
      setBitwardenSearchStatus(
        needsLogin
          ? 'Bitwarden CLI is not logged in. Log in from Settings first.'
          : locked
            ? 'The vault is locked. Enter the master password and search again.'
            : message,
      );
    } finally {
      if (bitwardenSearchAttempts.current.isCurrent('credential-search', generation)) {
        setBitwardenSearching(false);
      }
    }
  }

  function selectBitwardenItem(item: WormholeBitwardenLoginItem) {
    setCredentialForm((form) => ({
      ...form,
      name: form.name || item.name,
      username: form.protocol === 'vnc' ? '' : form.username || item.username || '',
      bitwardenItemId: item.id,
      bitwardenItemName: item.name,
    }));
  }

  async function submitCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const draft: CredentialDraft = {
      name: credentialForm.name.trim(),
      protocol: credentialForm.kind === 'sshKey' ? 'ssh' : credentialForm.protocol,
      kind: credentialForm.kind,
      username:
        credentialForm.kind === 'password' && credentialForm.protocol === 'vnc'
          ? ''
          : credentialForm.username.trim(),
      domain:
        credentialForm.kind === 'password' && credentialForm.protocol === 'rdp'
          ? credentialForm.domain.trim()
          : '',
      password: credentialForm.kind === 'password' ? credentialForm.password : '',
      passphrase: credentialForm.kind === 'sshKey' ? credentialForm.passphrase : '',
      clearPassphrase: credentialForm.kind === 'sshKey' ? credentialForm.clearPassphrase : false,
      privateKeySelectionId:
        credentialForm.kind === 'sshKey' ? credentialForm.privateKeySelectionId : '',
      privateKeyFileName: credentialForm.kind === 'sshKey' ? credentialForm.privateKeyFileName : '',
      provider: credentialForm.kind === 'sshKey' ? 'Local' : credentialForm.provider,
      bitwardenItemId:
        credentialForm.kind === 'password' && credentialForm.provider === 'Bitwarden'
          ? credentialForm.bitwardenItemId.trim()
          : '',
      bitwardenItemName:
        credentialForm.kind === 'password' && credentialForm.provider === 'Bitwarden'
          ? credentialForm.bitwardenItemName.trim()
          : '',
    };
    const localPasswordRequired =
      draft.kind === 'password' &&
      draft.provider === 'Local' &&
      (!editingCredential || editingCredential.provider !== 'Local');
    if (
      !draft.name ||
      (draft.kind === 'sshKey'
        ? !editingCredential && !draft.privateKeySelectionId
        : draft.provider === 'Local'
          ? localPasswordRequired && !draft.password
          : !draft.bitwardenItemId)
    ) {
      setOperationError(
        draft.kind === 'sshKey'
          ? 'Enter a name and select an SSH private key.'
          : draft.provider === 'Local'
            ? 'Enter a name and password.'
            : 'Enter a name and select a Bitwarden login item.',
      );
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
    const ids = pendingDeletion.filter((id) => credentialById.get(id)?.canDelete);
    if (ids.length === 0) {
      setPendingDeletion([]);
      return;
    }
    setBusy(true);
    setOperationError('');
    const failures: string[] = [];
    try {
      // Credential deletion reloads the authoritative Go workspace after each write. Keep those
      // mutations ordered so a slower earlier reload cannot overwrite a later result.
      for (const id of ids) {
        try {
          // react-doctor-disable-next-line react-doctor/async-await-in-loop
          await onDelete(id);
        } catch (error) {
          const name = credentialById.get(id)?.name ?? 'Credential';
          const message =
            error instanceof Error ? error.message : 'Could not delete the credential.';
          failures.push(`${name}: ${message}`);
        }
      }
      setSelectedCredentials(new Set());
      setPendingDeletion([]);
      if (failures.length > 0) setOperationError(failures.join(' '));
    } finally {
      setBusy(false);
    }
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
            disabled={credentialSearchResultsPending}
            onClick={() =>
              setSelectedCredentials(
                allVisibleSelected
                  ? new Set()
                  : new Set(filteredCredentials.map((credential) => credential.id)),
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

        {validSelectedCredentials.size > 0 ? (
          <div className="mt-3 flex shrink-0 flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-muted/30 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-foreground/80">
              <Check className="size-3.5" />
              <span>{validSelectedCredentials.size} credential(s) selected</span>
            </div>
            <div className="flex gap-2">
              <Button
                className="!text-xs"
                onClick={() => setSelectedCredentials(new Set())}
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
                    ? 'Add a password or SSH key credential to reuse across your connections.'
                    : 'Try a different name, username, domain, or provider.'}
                </p>
              </div>
            </div>
          ) : (
            <VirtualCardGrid
              ariaLabel="Credentials"
              bottomPadding={20}
              className="mt-4 h-full"
              endPadding={8}
              gap={16}
              getKey={(credential) => credential.id}
              items={filteredCredentials}
              minimumColumnWidth={280}
              renderItem={(credential) => (
                <Card className="h-full transition-colors hover:bg-muted/50">
                  <CardHeader>
                    <CardTitle className="min-w-0 truncate text-sm">{credential.name}</CardTitle>
                    <CardAction>
                      <Badge className="shrink-0" variant="secondary">
                        {credential.isVirtualBitwarden ? 'ANY' : protocolLabel(credential.protocol)}
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
                      <Badge variant="outline">
                        {credential.kind === 'sshKey' ? 'SSH key' : 'Password'}
                      </Badge>
                      <CredentialProviderIcon
                        kind={credential.kind}
                        provider={credential.provider}
                      />
                    </div>
                  </CardContent>
                  <CardFooter className="justify-between gap-2">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Checkbox
                          aria-label={`Select ${credential.name}`}
                          checked={validSelectedCredentials.has(credential.id)}
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
              )}
              resetKey={normalizedCredentialSearch}
              rowHeight={176}
            />
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
              {credentialForm.kind === 'sshKey'
                ? editingCredential
                  ? 'Update this SSH key profile or select a replacement private key. Key material never enters the renderer.'
                  : 'Import an SSH private key into protected local storage.'
                : credentialForm.provider === 'Bitwarden'
                  ? 'Link this profile to a Bitwarden login. Wormhole stores only the item reference.'
                  : editingCredential
                    ? 'Leave the password blank to keep the current one. Saved passwords are never returned to the renderer.'
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
                  setCredentialForm((form) => ({
                    ...form,
                    name: event.target.value,
                  }))
                }
                placeholder="Production SSH"
                required
                value={credentialForm.name}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="credential-protocol">Protocol</Label>
              <Select
                disabled={credentialForm.kind === 'sshKey'}
                onValueChange={(value) => {
                  if (value !== 'ssh') {
                    discardPrivateKeySelection(credentialForm.privateKeySelectionId);
                  }
                  setCredentialForm((form) => ({
                    ...form,
                    protocol: value as CredentialDraft['protocol'],
                    kind: value === 'ssh' ? form.kind : 'password',
                    passphrase: value === 'ssh' ? form.passphrase : '',
                    clearPassphrase: value === 'ssh' ? form.clearPassphrase : false,
                    privateKeySelectionId: value === 'ssh' ? form.privateKeySelectionId : '',
                    privateKeyFileName: value === 'ssh' ? form.privateKeyFileName : '',
                  }));
                }}
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
            {credentialForm.protocol === 'ssh' ? (
              <div className="grid gap-2">
                <Label htmlFor="credential-kind">Authentication</Label>
                <Select
                  disabled={Boolean(editingCredential)}
                  onValueChange={(value) => {
                    const kind = value as CredentialDraft['kind'];
                    if (kind === 'password') {
                      discardPrivateKeySelection(credentialForm.privateKeySelectionId);
                    }
                    setCredentialForm((form) => ({
                      ...form,
                      kind,
                      provider: kind === 'sshKey' ? 'Local' : form.provider,
                      password: kind === 'sshKey' ? '' : form.password,
                      passphrase: kind === 'password' ? '' : form.passphrase,
                      clearPassphrase: kind === 'password' ? false : form.clearPassphrase,
                      privateKeySelectionId: kind === 'password' ? '' : form.privateKeySelectionId,
                      privateKeyFileName: kind === 'password' ? '' : form.privateKeyFileName,
                      bitwardenItemId: kind === 'sshKey' ? '' : form.bitwardenItemId,
                      bitwardenItemName: kind === 'sshKey' ? '' : form.bitwardenItemName,
                    }));
                  }}
                  value={credentialForm.kind}
                >
                  <SelectTrigger id="credential-kind">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="password">Password</SelectItem>
                    <SelectItem value="sshKey">SSH private key</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            ) : null}
            {credentialForm.kind === 'password' ? (
              <div className="grid gap-2">
                <Label htmlFor="credential-provider">Credential vault</Label>
                <Select
                  onValueChange={(value) =>
                    setCredentialForm((form) => ({
                      ...form,
                      provider: value as CredentialDraft['provider'],
                      password: value === 'Bitwarden' ? '' : form.password,
                    }))
                  }
                  value={credentialForm.provider}
                >
                  <SelectTrigger id="credential-provider">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Local">Local password</SelectItem>
                    <SelectItem value="Bitwarden">Bitwarden item</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            ) : (
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                The private key is copied into Wormhole's encrypted local storage. The source file
                is not used after import.
              </p>
            )}
            {credentialForm.protocol !== 'vnc' ? (
              <div className="grid gap-2">
                <Label htmlFor="credential-username">Username</Label>
                <Input
                  autoComplete="username"
                  id="credential-username"
                  maxLength={512}
                  onChange={(event) =>
                    setCredentialForm((form) => ({
                      ...form,
                      username: event.target.value,
                    }))
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
                    setCredentialForm((form) => ({
                      ...form,
                      domain: event.target.value,
                    }))
                  }
                  placeholder="CORP"
                  required
                  value={credentialForm.domain}
                />
              </div>
            ) : null}
            {credentialForm.kind === 'sshKey' ? (
              <div className="grid gap-4 rounded-lg border border-border/70 bg-muted/20 p-3">
                <div className="grid gap-2">
                  <Label>Private key file</Label>
                  <div className="flex min-w-0 items-center justify-between gap-3 rounded-md border border-input bg-background px-3 py-2">
                    <span className="min-w-0 truncate text-xs text-foreground/80">
                      {credentialForm.privateKeyFileName || 'No private key selected'}
                    </span>
                    <Button
                      disabled={privateKeySelecting}
                      onClick={() => void selectPrivateKey()}
                      size="sm"
                      type="button"
                      variant="outline"
                    >
                      <Upload data-icon="inline-start" />
                      {privateKeySelecting
                        ? 'Selecting…'
                        : editingCredential
                          ? 'Replace…'
                          : 'Select…'}
                    </Button>
                  </div>
                  <p className="text-[11px] leading-relaxed text-muted-foreground">
                    OpenSSH and PEM private keys up to 1 MB are supported.
                  </p>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="credential-key-passphrase">
                    {editingCredential && !credentialForm.privateKeySelectionId
                      ? 'Replacement passphrase (leave blank to keep current)'
                      : 'Key passphrase (optional)'}
                  </Label>
                  <Input
                    autoComplete="off"
                    disabled={credentialForm.clearPassphrase}
                    id="credential-key-passphrase"
                    maxLength={4096}
                    onChange={(event) =>
                      setCredentialForm((form) => ({
                        ...form,
                        passphrase: event.target.value,
                        clearPassphrase: false,
                      }))
                    }
                    type="password"
                    value={credentialForm.passphrase}
                  />
                  {editingCredential && !credentialForm.privateKeySelectionId ? (
                    <label className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Checkbox
                        checked={credentialForm.clearPassphrase}
                        onCheckedChange={(checked) =>
                          setCredentialForm((form) => ({
                            ...form,
                            passphrase: checked === true ? '' : form.passphrase,
                            clearPassphrase: checked === true,
                          }))
                        }
                      />
                      Forget the saved passphrase and ask when connecting
                    </label>
                  ) : null}
                  <p className="text-[11px] leading-relaxed text-muted-foreground">
                    If an encrypted key is saved without a passphrase, Wormhole asks for it when
                    connecting.
                  </p>
                </div>
              </div>
            ) : credentialForm.provider === 'Local' ? (
              <div className="grid gap-2">
                <Label htmlFor="credential-password">
                  {editingCredential?.provider === 'Local'
                    ? 'Replacement password (leave blank to keep current)'
                    : 'Password'}
                </Label>
                <Input
                  autoComplete="new-password"
                  id="credential-password"
                  maxLength={4096}
                  onChange={(event) =>
                    setCredentialForm((form) => ({
                      ...form,
                      password: event.target.value,
                    }))
                  }
                  required={!editingCredential || editingCredential.provider !== 'Local'}
                  type="password"
                  value={credentialForm.password}
                />
              </div>
            ) : (
              <div className="grid gap-3 rounded-lg border border-border/70 bg-muted/20 p-3">
                <div className="grid gap-2 sm:grid-cols-[1fr_auto] sm:items-end">
                  <div className="grid gap-2">
                    <Label htmlFor="credential-bitwarden-search">Search Bitwarden</Label>
                    <Input
                      id="credential-bitwarden-search"
                      maxLength={2048}
                      onChange={(event) => setBitwardenQuery(event.target.value)}
                      placeholder="Item name, URI, or username"
                      value={bitwardenQuery}
                    />
                  </div>
                  <Button
                    disabled={bitwardenSearching}
                    onClick={() => void searchBitwarden()}
                    type="button"
                    variant="outline"
                  >
                    {bitwardenSearching ? 'Searching…' : 'Search'}
                  </Button>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="credential-bitwarden-unlock">Bitwarden master password</Label>
                  <Input
                    autoComplete="current-password"
                    id="credential-bitwarden-unlock"
                    maxLength={4096}
                    onChange={(event) => setBitwardenUnlockPassword(event.target.value)}
                    placeholder="Required only when the vault is locked"
                    type="password"
                    value={bitwardenUnlockPassword}
                  />
                </div>
                {bitwardenItems.length > 0 ? (
                  <div className="grid gap-2">
                    <Label htmlFor="credential-bitwarden-item">Login item</Label>
                    <Select
                      onValueChange={(value) => {
                        const item = bitwardenItems.find((candidate) => candidate.id === value);
                        if (item) selectBitwardenItem(item);
                      }}
                      value={credentialForm.bitwardenItemId || undefined}
                    >
                      <SelectTrigger id="credential-bitwarden-item">
                        <SelectValue placeholder="Select a login item" />
                      </SelectTrigger>
                      <SelectContent>
                        {bitwardenItems.map((item) => (
                          <SelectItem key={item.id} value={item.id}>
                            {item.username ? `${item.name} — ${item.username}` : item.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                ) : null}
                <div className="grid gap-2">
                  <Label htmlFor="credential-bitwarden-item-id">Item ID</Label>
                  <Input
                    id="credential-bitwarden-item-id"
                    maxLength={512}
                    onChange={(event) =>
                      setCredentialForm((form) => ({
                        ...form,
                        bitwardenItemId: event.target.value,
                      }))
                    }
                    placeholder="Bitwarden item id"
                    required
                    value={credentialForm.bitwardenItemId}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="credential-bitwarden-item-name">Item name</Label>
                  <Input
                    id="credential-bitwarden-item-name"
                    maxLength={1024}
                    onChange={(event) =>
                      setCredentialForm((form) => ({
                        ...form,
                        bitwardenItemName: event.target.value,
                      }))
                    }
                    placeholder="Display name"
                    value={credentialForm.bitwardenItemName}
                  />
                </div>
                {bitwardenSearchStatus ? (
                  <p className="text-[11px] text-muted-foreground">{bitwardenSearchStatus}</p>
                ) : null}
              </div>
            )}
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
  fullWidth?: boolean;
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
  scope: 'connection' | 'folder' | 'quick';
  tunnels: TunnelRecord[];
  disabled?: boolean;
}) {
  const isFolder = scope === 'folder';
  const isQuick = scope === 'quick';
  const options = useMemo<SearchableComboboxOption[]>(
    () => [
      ...(isQuick
        ? []
        : [
            {
              value: 'inherit',
              label: isFolder ? 'Inherit from parent' : 'Inherit from folder',
            },
          ]),
      { value: 'off', label: 'No VPN tunnel' },
      ...tunnels.map((tunnel) => ({
        value: tunnel.id,
        label: `${tunnel.name} · ${tunnel.kind}`,
      })),
    ],
    [isFolder, isQuick, tunnels],
  );
  const description = isQuick
    ? 'The selected VPN tunnel starts before this temporary connection.'
    : mode === 'off'
      ? 'Always connect directly for this item and its descendants that inherit the route.'
      : mode === 'inherit'
        ? isFolder
          ? 'Follows the VPN route configured by the parent folder.'
          : 'Follows the VPN route configured by the containing folder.'
        : 'Wormhole establishes this VPN route before connecting.';
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{isFolder ? 'VPN route default' : 'VPN route'}</Label>
      <SearchableCombobox
        className="sm:max-w-[280px]"
        disabled={disabled}
        emptyMessage="No VPN routes found."
        id={id}
        onValueChange={(value) => onChange(value as TunnelMode)}
        options={options}
        placeholder="Select a VPN route"
        searchPlaceholder="Search VPN routes…"
        value={mode}
      />
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
        {
          key: 'Mtu',
          label: 'MTU (optional)',
          section: 'Interface',
          type: 'number',
        },
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
        {
          key: 'Password',
          label: 'Password',
          section: 'Authentication',
          type: 'password',
        },
      ];
    case 2:
      return [
        {
          key: 'Host',
          label: 'Host',
          section: 'Gateway',
          placeholder: 'vpn.example.com',
        },
        {
          key: 'Port',
          label: 'Port',
          section: 'Gateway',
          type: 'number',
          placeholder: '443',
        },
        { key: 'Username', label: 'Username', section: 'Credentials' },
        {
          key: 'Password',
          label: 'Password',
          section: 'Credentials',
          type: 'password',
        },
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
          key: 'Server',
          label: 'Server',
          section: 'Gateway',
          placeholder: 'firebox.example.com',
        },
        {
          key: 'Port',
          label: 'Port',
          section: 'Gateway',
          type: 'number',
          placeholder: '443',
        },
        {
          key: 'TrustServerCertificate',
          label: 'Ignore certificate errors',
          section: 'Gateway',
          type: 'checkbox',
          fullWidth: true,
          hint: 'Skip certificate validation for the WatchGuard portal and embedded SAML sign-in. Use only for a gateway you trust.',
        },
        {
          key: 'AuthMode',
          label: 'Authentication mode',
          section: 'Authentication',
          type: 'select',
          options: [
            { value: 1, label: 'Username and password' },
            { value: 2, label: 'SAML' },
          ],
          fullWidth: true,
        },
        { key: 'Username', label: 'Username', section: 'Authentication' },
        {
          key: 'Password',
          label: 'Password',
          section: 'Authentication',
          type: 'password',
        },
        {
          key: 'Domain',
          label: 'Authentication domain override',
          section: 'Advanced',
          placeholder: 'auto-detect',
        },
        {
          key: 'CaPem',
          label: 'CA certificate (PEM)',
          section: 'Advanced',
          type: 'textarea',
        },
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
        {
          key: 'Server',
          label: 'Server',
          section: 'Gateway',
          placeholder: 'rpv.example.com',
        },
        {
          key: 'Port',
          label: 'Port',
          section: 'Gateway',
          type: 'number',
          placeholder: '443',
        },
        {
          key: 'Description',
          label: 'Description (optional)',
          section: 'Gateway',
        },
        {
          key: 'UseOtp',
          label: 'Use an OTP',
          section: 'Authentication',
          type: 'checkbox',
          fullWidth: true,
        },
        { key: 'Username', label: 'Username', section: 'Authentication' },
        {
          key: 'Password',
          label: 'Password',
          section: 'Authentication',
          type: 'password',
        },
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
        {
          key: 'Host',
          label: 'Host',
          section: 'Gateway',
          placeholder: 'vpn.example.com',
        },
        {
          key: 'Port',
          label: 'Port',
          section: 'Gateway',
          type: 'number',
          placeholder: '443',
        },
        {
          key: 'Group',
          label: 'Group / connection profile (optional)',
          section: 'Gateway',
          placeholder: 'leave blank for the gateway default',
        },
        { key: 'Username', label: 'Username', section: 'Credentials' },
        {
          key: 'Password',
          label: 'Password',
          section: 'Credentials',
          type: 'password',
        },
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
        AuthMode: 1,
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
  const settings =
    details.kind === 3
      ? watchguardEditorSettingsFromDetails(tunnelDefaultSettings(details.kind), details.settings)
      : { ...tunnelDefaultSettings(details.kind), ...details.settings };
  return {
    id: details.id,
    name: details.name,
    kind: details.kind,
    settings,
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
    <div
      className={cn(
        'grid gap-2',
        (field.type === 'textarea' || field.fullWidth) && 'col-span-full',
      )}
    >
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
  contentClassName,
}: {
  title?: string;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
}) {
  return (
    <section className={cn('grid gap-3', className)}>
      {title ? (
        <h4 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
          {title}
        </h4>
      ) : null}
      <div className={cn('grid gap-4', contentClassName ?? 'md:grid-cols-2')}>{children}</div>
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

// Provider-specific tunnel fields are schema-driven branches of one editor transaction; separate
// components would duplicate validation and secret-clearing behavior.
// react-doctor-disable-next-line react-doctor/no-giant-component
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
  const [advancedOpen, setAdvancedOpen] = useState(
    () =>
      initial.kind === 3 &&
      ['Domain', 'CaPem', 'ClientCertPem', 'ClientKeyPem'].some(
        (key) =>
          typeof initial.settings[key] === 'string' && (initial.settings[key] as string).trim(),
      ),
  );

  const missing = useMemo(() => missingTunnelFields(value), [value]);
  const canSave = missing.length === 0;
  const fields = tunnelEditorFields(value.kind);
  const rows = (
    section: string,
    options?: {
      disabled?: (field: TunnelField) => boolean;
      hidden?: (field: TunnelField) => boolean;
    },
  ) =>
    fields.flatMap((field) =>
      field.section === section && !options?.hidden?.(field)
        ? [
            <TunnelFieldRow
              disabled={options?.disabled?.(field)}
              field={field}
              key={field.key}
              onChange={setSetting}
              value={value.settings}
            />,
          ]
        : [],
    );
  const useFortinetSso = value.settings.UseSingleSignOn === true;
  const useFortinetExternalBrowser = useFortinetSso && value.settings.UseExternalBrowser === true;
  const useWatchguardSso = value.kind === 3 && watchguardUsesSso(value.settings);

  function setSetting(key: string, next: unknown) {
    setValue((current) => ({
      ...current,
      settings: updateTunnelEditorSetting(current.kind, current.settings, key, next),
    }));
  }

  async function runTunnelImport<T>(
    action: () => Promise<T | null>,
    fallback: string,
  ): Promise<T | null> {
    const api = window.wormhole;
    if (!api) {
      setError('The VPN service is unavailable.');
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
      setError('The VPN service is unavailable.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const settings = normalizeTunnelEditorSettings(value.kind, value.settings);
      const saved = value.id
        ? await api.updateTunnel({
            id: value.id,
            name: value.name,
            kind: value.kind,
            settings,
          })
        : await api.createTunnel({
            name: value.name,
            kind: value.kind,
            settings,
          });
      onSaved({
        id: saved.id,
        name: saved.name,
        kind: tunnelKindLabel(saved.kind),
      });
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
            Tunnel credentials stay in encrypted storage and never enter the connection tree.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto pr-3"
          id="tunnel-editor-form"
          onSubmit={submit}
        >
          <div className="grid gap-3 md:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="tunnel-name">Name</Label>
              <Input
                id="tunnel-name"
                onChange={(event) =>
                  setValue((current) => ({
                    ...current,
                    name: event.target.value,
                  }))
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
                Microsoft Entra tokens are cached separately in protected storage.
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
                filled from the imported configuration.
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
                        ? useFortinetExternalBrowser &&
                          !(typeof value.settings.Realm === 'string' && value.settings.Realm.trim())
                        : useFortinetSso,
                  })}
                </TunnelSection>
                <div className="grid gap-2 rounded-lg border border-border/70 bg-muted/20 px-3 py-2">
                  {rows('Single sign-on', {
                    disabled: (field) => field.key === 'UseExternalBrowser' && !useFortinetSso,
                    hidden: (field) =>
                      field.key === 'SamlRedirectPort' && !useFortinetExternalBrowser,
                  })}
                  <p className="text-[11px] leading-relaxed text-muted-foreground">
                    The embedded option uses a dedicated browser profile. External-browser
                    authentication requires the callback port configured on the FortiGate.
                  </p>
                </div>
                <TunnelAdvanced label="Advanced" onOpenChange={setAdvancedOpen} open={advancedOpen}>
                  {rows('Advanced', {
                    disabled: (field) => field.key === 'TotpSecret' && useFortinetSso,
                  })}
                </TunnelAdvanced>
              </>
            ) : null}
            {value.kind === 3 ? (
              <>
                <TunnelSection
                  contentClassName="grid-cols-[minmax(0,1fr)_7rem] sm:grid-cols-[minmax(0,1fr)_8rem]"
                  title="Gateway"
                >
                  {rows('Gateway')}
                </TunnelSection>
                <TunnelSection title="Authentication">
                  {rows('Authentication', {
                    hidden: (field) =>
                      useWatchguardSso && (field.key === 'Username' || field.key === 'Password'),
                  })}
                </TunnelSection>
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
                <TunnelSection title="Authentication">{rows('Authentication')}</TunnelSection>
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
                <TunnelAdvanced label="Advanced" onOpenChange={setAdvancedOpen} open={advancedOpen}>
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
                    generated automatically) or a static secondary password. SAML single sign-on and
                    client-certificate authentication are not supported.
                  </p>
                  {rows('Two-factor & advanced')}
                </TunnelAdvanced>
              </>
            ) : null}
          </div>
        </form>
        {error ? (
          <p
            className="max-h-20 shrink-0 overflow-y-auto text-[11px] text-destructive"
            role="alert"
          >
            {error}
          </p>
        ) : null}
        <DialogFooter>
          <Button disabled={busy} onClick={() => onOpenChange(false)} type="button" variant="ghost">
            Cancel
          </Button>
          <Button disabled={busy || !canSave} form="tunnel-editor-form" type="submit">
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
      </DialogContent>
    </Dialog>
  );
}

// Tunnel CRUD, test progress, and editor lifecycle form one backend-owned workflow. Their local
// states transition independently, so combining them in a reducer would obscure those boundaries.
// react-doctor-disable-next-line react-doctor/no-giant-component, react-doctor/prefer-useReducer
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
  // react-doctor-disable-next-line react-doctor/prefer-useReducer
}) {
  const [searchText, setSearchText] = useState('');
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorValue, setEditorValue] = useState<TunnelEditorValue>(blankTunnelEditor);
  const [actionError, setActionError] = useState('');
  const [testState, setTestState] = useState<{
    tunnel: TunnelRecord;
    status: 'idle' | 'connecting' | 'cancelling' | 'connected' | 'notice' | 'cancelled' | 'failed';
    targetProbed?: boolean;
    error?: string;
    progress?: string;
    log: string[];
  } | null>(null);
  const [testTargetHost, setTestTargetHost] = useState('');
  const [testTargetPort, setTestTargetPort] = useState('');
  const [testInputError, setTestInputError] = useState('');
  const testAttemptRef = useRef(0);
  const deferredSearchText = useDeferredValue(searchText);
  const normalizedTunnelSearch = normalizeListSearch(deferredSearchText);
  const tunnelSearchActive = normalizedTunnelSearch.length > 0;
  const tunnelSearchIndex = useMemo(
    () =>
      tunnelSearchActive
        ? tunnels.map((tunnel) => ({
            item: tunnel,
            text: `${tunnel.name}\u0000${tunnel.kind}`.toLowerCase(),
          }))
        : [],
    [tunnelSearchActive, tunnels],
  );
  const filteredTunnels = useMemo(
    () => filterListSearchIndex(tunnels, tunnelSearchIndex, normalizedTunnelSearch),
    [normalizedTunnelSearch, tunnelSearchIndex, tunnels],
  );

  useEffect(() => {
    return window.wormhole?.onTunnelTestProgress((event) => {
      if (event.attempt !== testAttemptRef.current) return;
      setTestState((current) =>
        current
          ? {
              ...current,
              progress: tunnelTestPhaseLabel(event.phase, event.detail),
              log: appendTunnelTestLog(current.log, event.detail),
            }
          : current,
      );
    });
  }, []);

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
      setActionError('The VPN service is unavailable.');
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

  function openTunnelTest(tunnel: TunnelRecord) {
    if (testState) return;
    setActionError('');
    setTestTargetHost('');
    setTestTargetPort('');
    setTestInputError('');
    setTestState({ tunnel, status: 'idle', log: [] });
  }

  async function runTunnelTest() {
    const api = window.wormhole;
    if (
      !api ||
      !testState ||
      testState.status === 'connecting' ||
      testState.status === 'cancelling'
    ) {
      if (!api) setActionError('The VPN service is unavailable.');
      return;
    }
    const parsedTarget = parseTunnelProbeTarget(testTargetHost, testTargetPort);
    if (parsedTarget.error) {
      setTestInputError(parsedTarget.error);
      return;
    }
    setActionError('');
    setTestInputError('');
    const attempt = ++testAttemptRef.current;
    const tunnel = testState.tunnel;
    setTestState({
      tunnel,
      status: 'connecting',
      targetProbed: Boolean(parsedTarget.target),
      log: [],
    });
    try {
      const result = await api.testTunnel({
        id: tunnel.id,
        attempt,
        ...(parsedTarget.target
          ? {
              targetHost: parsedTarget.target.host,
              targetPort: parsedTarget.target.port,
            }
          : {}),
      });
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

  async function cancelTunnelTestRun() {
    if (testState?.status !== 'connecting') return;
    const attempt = testAttemptRef.current;
    setTestState((current) =>
      current ? { ...current, status: 'cancelling', error: undefined } : current,
    );
    try {
      await window.wormhole?.cancelTunnelTest();
      if (attempt !== testAttemptRef.current) return;
      setTestState((current) =>
        current ? { ...current, status: 'cancelled', error: undefined } : current,
      );
    } catch (error) {
      if (attempt !== testAttemptRef.current) return;
      setTestState((current) =>
        current
          ? {
              ...current,
              status: 'failed',
              error: userFacingTunnelError(error) || 'Could not cancel the VPN tunnel test.',
            }
          : current,
      );
    }
  }

  function closeTunnelTest() {
    if (testState?.status === 'connecting') {
      void cancelTunnelTestRun();
      return;
    }
    if (testState?.status === 'cancelling') return;
    ++testAttemptRef.current;
    setTestState(null);
    setTestInputError('');
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
                  ? 'Add a VPN tunnel to route a connection through a secure path.'
                  : 'Try a different tunnel name or provider.'}
              </p>
            </div>
          </div>
        ) : (
          <VirtualCardGrid
            ariaLabel="VPN tunnels"
            bottomPadding={16}
            className="mt-3 h-full"
            endPadding={8}
            gap={12}
            getKey={(tunnel) => tunnel.id}
            items={filteredTunnels}
            minimumColumnWidth={260}
            renderItem={(tunnel) => (
              <Card className="h-full max-w-[260px] transition-colors hover:bg-muted/50" size="sm">
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
                    <span className="truncate">Managed VPN tunnel</span>
                  </CardDescription>
                </CardHeader>
                <CardFooter className="mt-auto justify-end gap-0.5">
                  <IconButton label={`Test ${tunnel.name}`} onClick={() => openTunnelTest(tunnel)}>
                    <FlaskConical />
                  </IconButton>
                  <IconButton label={`Edit ${tunnel.name}`} onClick={() => void editTunnel(tunnel)}>
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
            )}
            resetKey={normalizedTunnelSearch}
            rowHeight={140}
          />
        )}
      </div>
      {editorOpen ? (
        <TunnelEditorDialog
          initial={editorValue}
          key={editorValue.id ?? `new:${editorValue.kind}`}
          onOpenChange={setTunnelEditorOpen}
          onSaved={(tunnel) => (editorValue.id ? onTunnelUpdated(tunnel) : onTunnelCreated(tunnel))}
          open
        />
      ) : null}
      <Dialog
        onOpenChange={(open) => {
          if (!open) closeTunnelTest();
        }}
        open={testState !== null}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Test VPN tunnel</DialogTitle>
            <DialogDescription>{testState?.tunnel.name}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-[1fr_8rem]">
            <div className="grid gap-2">
              <Label htmlFor="tunnel-test-target-host">Target host (optional)</Label>
              <Input
                disabled={testState?.status === 'connecting' || testState?.status === 'cancelling'}
                id="tunnel-test-target-host"
                onChange={(event) => {
                  setTestTargetHost(event.target.value);
                  setTestInputError('');
                }}
                placeholder="server.internal"
                value={testTargetHost}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="tunnel-test-target-port">Port</Label>
              <Input
                disabled={testState?.status === 'connecting' || testState?.status === 'cancelling'}
                id="tunnel-test-target-port"
                inputMode="numeric"
                onChange={(event) => {
                  setTestTargetPort(event.target.value);
                  setTestInputError('');
                }}
                placeholder="22"
                value={testTargetPort}
              />
            </div>
          </div>
          {testInputError ? <p className="text-xs text-destructive">{testInputError}</p> : null}
          <div className="flex min-h-24 items-center gap-3 rounded-lg border border-border/70 bg-muted/20 px-4 py-3">
            {testState?.status === 'idle' ? (
              <>
                <Info className="size-5 shrink-0 text-muted-foreground" />
                <p className="text-sm">Ready to start a temporary VPN tunnel.</p>
              </>
            ) : testState?.status === 'connecting' ? (
              <>
                <LoaderCircle className="size-5 shrink-0 animate-spin text-muted-foreground" />
                <p className="text-sm">{testState.progress ?? 'Connecting to the VPN gateway…'}</p>
              </>
            ) : testState?.status === 'cancelling' ? (
              <>
                <LoaderCircle className="size-5 shrink-0 animate-spin text-muted-foreground" />
                <p className="text-sm">Stopping the VPN tunnel test…</p>
              </>
            ) : testState?.status === 'connected' ? (
              <>
                <CheckCircle2 className="size-5 shrink-0 text-emerald-500" />
                <p className="text-sm">
                  {testState.targetProbed
                    ? 'VPN tunnel connected and the target is reachable.'
                    : 'VPN tunnel connected successfully.'}
                </p>
              </>
            ) : testState?.status === 'cancelled' ? (
              <>
                <Info className="size-5 shrink-0 text-muted-foreground" />
                <div className="min-w-0 space-y-1">
                  <p className="text-sm font-medium">Test cancelled.</p>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    The temporary tunnel was stopped and released.
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
          {testState && testState.log.length > 0 ? (
            <div className="grid gap-2">
              <Label>Diagnostic log</Label>
              <ScrollArea className="h-32 rounded-md border border-border/70 bg-background/50">
                <ol
                  aria-live="polite"
                  className="grid gap-1 p-3 font-mono text-[10px] text-muted-foreground"
                >
                  {testState.log.map((entry, index) => (
                    <li key={`${index}:${entry}`}>{entry}</li>
                  ))}
                </ol>
              </ScrollArea>
            </div>
          ) : null}
          <DialogFooter>
            {testState?.status === 'connecting' ? (
              <Button
                onClick={() => void cancelTunnelTestRun()}
                type="button"
                variant="destructive"
              >
                Cancel test
              </Button>
            ) : testState?.status === 'cancelling' ? (
              <Button disabled type="button" variant="outline">
                <LoaderCircle className="animate-spin" />
                Cancelling…
              </Button>
            ) : (
              <>
                <Button onClick={closeTunnelTest} type="button" variant="ghost">
                  Close
                </Button>
                <Button onClick={() => void runTunnelTest()} type="button">
                  Start test
                </Button>
              </>
            )}
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
  disabled,
  onCheckedChange,
}: {
  label: string;
  description?: string;
  checked: boolean;
  disabled?: boolean;
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
      <Switch
        aria-label={label}
        checked={checked}
        disabled={disabled}
        onCheckedChange={onCheckedChange}
      />
    </div>
  );
}

function SettingsTabPanel({
  value,
  children,
  forceMount,
}: {
  value: string;
  children: ReactNode;
  forceMount?: true;
}) {
  return (
    <TabsContent
      className="min-h-0 flex-1 overflow-hidden data-[state=inactive]:hidden"
      forceMount={forceMount}
      value={value}
    >
      <ScrollArea className="h-full">
        <div className="max-w-[720px] space-y-7 px-1 py-5 pb-12">{children}</div>
      </ScrollArea>
    </TabsContent>
  );
}

function logsErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  return "Wormhole couldn't complete this action. Try again.";
}

function LogLevelSetting({
  initialValue,
  loaded,
  onSaved,
}: {
  initialValue: LogLevel;
  loaded: boolean;
  onSaved: (level: LogLevel) => void;
}) {
  const [logLevel, setLogLevel] = useState<LogLevel>(initialValue);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const saveState = useLazyRef(() => createLogLevelSaveState(initialValue));

  useEffect(() => {
    if (!loaded || busyRef.current) return;
    saveState.current.desired = initialValue;
    saveState.current.persisted = initialValue;
    setLogLevel(initialValue);
  }, [initialValue, loaded, saveState]);

  async function persistDesiredLogLevel() {
    const api = window.wormhole;
    if (busyRef.current || !api) return;
    busyRef.current = true;
    setBusy(true);
    try {
      await drainLogLevelChanges(
        saveState.current,
        async (target) => (await api.setLogLevel(target)).logLevel,
        onSaved,
      );
      setLogLevel(saveState.current.persisted);
    } catch (error) {
      saveState.current.desired = saveState.current.persisted;
      setLogLevel(saveState.current.persisted);
      setError(logsErrorMessage(error));
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }

  function commitLogLevel(next: string) {
    if (!loaded || !isLogLevel(next) || next === saveState.current.desired) return;
    saveState.current.desired = next;
    setLogLevel(next);
    if (error) setError('');
    void persistDesiredLogLevel();
  }

  return (
    <SettingsSection title="Log level">
      <div className="grid max-w-52 gap-2">
        <Label htmlFor="settings-log-level">Detail level</Label>
        <Select disabled={!loaded} onValueChange={commitLogLevel} value={logLevel}>
          <SelectTrigger aria-busy={busy} id="settings-log-level" size="sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="info">Info</SelectItem>
            <SelectItem value="debug">Debug</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <p className="text-[11px] leading-relaxed text-muted-foreground">
        {logLevel === 'debug'
          ? 'Debug adds verbose per-operation detail for diagnosing failures.'
          : 'Info logs high-level events (boot, connections, tunnels, errors).'}{' '}
        Changes apply immediately.
      </p>
      {error ? <p className="text-[11px] text-destructive">{error}</p> : null}
    </SettingsSection>
  );
}

function BitwardenCliDialog({
  currentServerRegion,
  defaultServerRegion,
  loginBusy,
  mode,
  onClose,
  onLogin,
  onUnlock,
}: {
  currentServerRegion: 'US' | 'EU' | null;
  defaultServerRegion: 'UnitedStates' | 'Europe' | 'Current';
  loginBusy: boolean;
  mode: 'login' | 'unlock' | null;
  onClose: () => void;
  onLogin: (
    email: string,
    masterPassword: string,
    authenticatorCode: string | undefined,
    serverRegion: 'UnitedStates' | 'Europe' | 'Current',
  ) => void;
  onUnlock: (masterPassword: string) => void;
}) {
  const [email, setEmail] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [authenticatorCode, setAuthenticatorCode] = useState('');
  const [serverRegion, setServerRegion] = useState(defaultServerRegion);

  function reset() {
    setEmail('');
    setMasterPassword('');
    setAuthenticatorCode('');
    setServerRegion(defaultServerRegion);
  }

  const isLogin = mode === 'login';
  return (
    <Dialog
      onOpenChange={(open) => {
        if (!open) {
          reset();
          onClose();
        }
      }}
      open={mode !== null}
    >
      <DialogContent className="border-border/70 bg-card text-card-foreground sm:max-w-md">
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (isLogin) {
              onLogin(email, masterPassword, authenticatorCode || undefined, serverRegion);
              setAuthenticatorCode('');
            } else {
              onUnlock(masterPassword);
            }
            // Match WinUI's secret prompts: hand the value to the native boundary, then remove it
            // from renderer state even when the CLI rejects the attempt.
            setMasterPassword('');
          }}
        >
          <DialogHeader>
            <DialogTitle>{isLogin ? 'Log in to Bitwarden' : 'Unlock Bitwarden vault'}</DialogTitle>
            <DialogDescription>
              {isLogin
                ? 'Enter your Bitwarden account credentials to connect this vault.'
                : 'Enter your master password to unlock the vault.'}
            </DialogDescription>
          </DialogHeader>
          {isLogin ? (
            <div className="space-y-3">
              <div className="grid gap-2">
                <Label>Server region</Label>
                <Select
                  disabled={loginBusy}
                  onValueChange={(value) =>
                    setServerRegion(value as 'UnitedStates' | 'Europe' | 'Current')
                  }
                  value={serverRegion}
                >
                  <SelectTrigger className="w-full">
                    <SelectValue>
                      {serverRegion === 'Current'
                        ? formatBitwardenCurrentServerLabel(currentServerRegion)
                        : undefined}
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Current">
                      {formatBitwardenCurrentServerLabel(currentServerRegion)}
                    </SelectItem>
                    <SelectItem value="UnitedStates">
                      United States (vault.bitwarden.com)
                    </SelectItem>
                    <SelectItem value="Europe">Europe (vault.bitwarden.eu)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="bw-login-email">Email</Label>
                <Input
                  autoComplete="username"
                  autoFocus
                  id="bw-login-email"
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@example.com"
                  required
                  spellCheck={false}
                  type="email"
                  value={email}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="bw-login-password">Master password</Label>
                <Input
                  autoComplete="current-password"
                  id="bw-login-password"
                  onChange={(event) => setMasterPassword(event.target.value)}
                  required
                  type="password"
                  value={masterPassword}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="bw-login-2fa">
                  Two-step login code <span className="text-muted-foreground">(optional)</span>
                </Label>
                <Input
                  autoComplete="one-time-code"
                  id="bw-login-2fa"
                  onChange={(event) => setAuthenticatorCode(event.target.value)}
                  placeholder="000000"
                  spellCheck={false}
                  type="text"
                  value={authenticatorCode}
                />
              </div>
            </div>
          ) : (
            <div className="grid gap-2">
              <Label htmlFor="bw-unlock-password">Master password</Label>
              <Input
                autoComplete="current-password"
                autoFocus
                id="bw-unlock-password"
                onChange={(event) => setMasterPassword(event.target.value)}
                required
                type="password"
                value={masterPassword}
              />
            </div>
          )}
          <DialogFooter>
            <Button
              disabled={loginBusy}
              onClick={() => {
                reset();
                onClose();
              }}
              type="button"
              variant="ghost"
            >
              Cancel
            </Button>
            <Button
              disabled={loginBusy || !masterPassword || (isLogin && !email.trim())}
              type="submit"
            >
              {loginBusy ? 'Working…' : isLogin ? 'Log in' : 'Unlock'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

type BitwardenOperationDialogState = {
  status: 'working' | 'success' | 'warning' | 'error';
  message: string;
};

function BitwardenOperationDialog({
  description,
  state,
  title,
  onClose,
}: {
  description: string;
  state: BitwardenOperationDialogState | null;
  title: string;
  onClose: () => void;
}) {
  const working = state?.status === 'working';
  return (
    <Dialog
      onOpenChange={(open) => {
        if (!open && !working) onClose();
      }}
      open={state !== null}
    >
      <DialogContent
        className="border-border/70 bg-card text-card-foreground sm:max-w-sm"
        onEscapeKeyDown={(event) => {
          if (working) event.preventDefault();
        }}
        onPointerDownOutside={(event) => {
          if (working) event.preventDefault();
        }}
        showCloseButton={!working}
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <div className="flex items-start gap-3 rounded-lg border border-border/70 bg-background/40 p-3">
          {state?.status === 'working' ? (
            <LoaderCircle className="mt-0.5 size-4 shrink-0 animate-spin text-muted-foreground" />
          ) : state?.status === 'success' ? (
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-500" />
          ) : state?.status === 'warning' ? (
            <AlertCircle className="mt-0.5 size-4 shrink-0 text-amber-500" />
          ) : (
            <AlertCircle className="mt-0.5 size-4 shrink-0 text-destructive" />
          )}
          <p className="text-xs leading-relaxed">
            {state?.message ?? 'Preparing Bitwarden operation…'}
          </p>
        </div>
        <DialogFooter>
          <Button disabled={working} onClick={onClose} type="button">
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

const mcpTokenPlaceholder = '<bearer-token — click Reveal or Copy config>';

function mcpClientCopyDetails(client: McpClient): {
  label: string;
  caption: string;
} {
  switch (client) {
    case 'claude-desktop':
      return {
        label: 'Claude Desktop config (claude_desktop_config.json)',
        caption: 'Use this configuration to connect Claude Desktop to Wormhole.',
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
  const asyncWrite = navigator.clipboard?.writeText.bind(navigator.clipboard);
  await writeClipboardText(value, asyncWrite, () => {
    const activeElement =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const selection = document.getSelection();
    const ranges = selection
      ? Array.from({ length: selection.rangeCount }, (_, index) =>
          selection.getRangeAt(index).cloneRange(),
        )
      : [];
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    try {
      textarea.select();
      return document.execCommand('copy');
    } finally {
      textarea.remove();
      activeElement?.focus({ preventScroll: true });
      if (selection && ranges.length > 0) {
        selection.removeAllRanges();
        for (const range of ranges) selection.addRange(range);
      }
    }
  });
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
  const nodes: ReactNode[] = [];
  let searchFrom = 0;
  for (const part of text.split(markdownInlinePattern)) {
    if (!part) continue;
    const sourceOffset = text.indexOf(part, searchFrom);
    searchFrom = sourceOffset + part.length;
    const key = `${keyPrefix}:${sourceOffset}`;
    if (part.startsWith('`') && part.endsWith('`') && part.length >= 2) {
      nodes.push(<code key={key}>{part.slice(1, -1)}</code>);
      continue;
    }
    if (part.startsWith('**') && part.endsWith('**') && part.length >= 4) {
      nodes.push(<strong key={key}>{part.slice(2, -2)}</strong>);
      continue;
    }
    if (part.startsWith('*') && part.endsWith('*') && part.length >= 2) {
      nodes.push(<em key={key}>{part.slice(1, -1)}</em>);
      continue;
    }
    const link = part.match(/^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/);
    if (link) {
      const url = link[2];
      nodes.push(
        <button
          className="text-foreground underline decoration-border underline-offset-2 hover:text-foreground/80"
          key={key}
          onClick={() => {
            void window.wormhole?.openExternal(url).catch(() => {
              // Opening the release page is a convenience; a failure is not actionable here.
            });
          }}
          type="button"
        >
          {link[1]}
        </button>,
      );
      continue;
    }
    nodes.push(<span key={key}>{part}</span>);
  }
  return nodes;
}

// ReleaseNotesMarkdown is a deliberately small markdown renderer for GitHub release bodies:
// headings, bullet/numbered lists, fenced code blocks, paragraphs, and inline
// bold/italic/code/links. It never injects raw HTML.
function ReleaseNotesMarkdown({ markdown }: { markdown: string }) {
  return useMemo(() => {
    const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
    const blocks: ReactNode[] = [];
    let sourceOffset = 0;
    let listType: 'ul' | 'ol' | null = null;
    let listStartOffset = 0;
    let listItems: Array<{ sourceOffset: number; text: string }> = [];
    let paragraph: string[] = [];
    let paragraphStartOffset = 0;
    let codeLines: string[] | null = null;
    let codeStartOffset = 0;

    const flushParagraph = () => {
      if (paragraph.length === 0) return;
      const text = paragraph.join(' ').trim();
      paragraph = [];
      if (!text) return;
      const key = `paragraph:${paragraphStartOffset}`;
      blocks.push(<p key={key}>{renderMarkdownInline(text, key)}</p>);
    };
    const flushList = () => {
      if (!listType) return;
      const items = listItems;
      const type = listType;
      listType = null;
      listItems = [];
      blocks.push(
        type === 'ol' ? (
          <ol className="list-decimal space-y-0.5 pl-4" key={`list:${listStartOffset}`}>
            {items.map((item) => (
              <li key={`item:${item.sourceOffset}`}>
                {renderMarkdownInline(item.text, `item:${item.sourceOffset}`)}
              </li>
            ))}
          </ol>
        ) : (
          <ul className="list-disc space-y-0.5 pl-4" key={`list:${listStartOffset}`}>
            {items.map((item) => (
              <li key={`item:${item.sourceOffset}`}>
                {renderMarkdownInline(item.text, `item:${item.sourceOffset}`)}
              </li>
            ))}
          </ul>
        ),
      );
    };

    for (const line of lines) {
      const lineOffset = sourceOffset;
      sourceOffset += line.length + 1;
      if (codeLines) {
        if (line.trim().startsWith('```')) {
          blocks.push(
            <pre
              className="overflow-x-auto rounded-md bg-muted/70 p-3 font-mono text-[10px] leading-relaxed"
              key={`code:${codeStartOffset}`}
            >
              {codeLines.join('\n')}
            </pre>,
          );
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
        codeStartOffset = lineOffset;
        continue;
      }
      const heading = line.match(/^(#{1,6})\s+(.+)$/);
      if (heading) {
        flushParagraph();
        flushList();
        const key = `heading:${lineOffset}`;
        blocks.push(
          <p className="text-xs font-semibold text-foreground" key={key}>
            {renderMarkdownInline(heading[2], key)}
          </p>,
        );
        continue;
      }
      const unordered = line.match(/^[-*]\s+(.+)$/);
      const ordered = line.match(/^\d+\.\s+(.+)$/);
      if (unordered || ordered) {
        flushParagraph();
        const type: 'ul' | 'ol' = ordered ? 'ol' : 'ul';
        if (listType !== type) {
          flushList();
          listStartOffset = lineOffset;
        }
        listType = type;
        listItems.push({
          sourceOffset: lineOffset,
          text: (unordered ?? ordered)![1],
        });
        continue;
      }
      if (line.trim() === '') {
        flushParagraph();
        flushList();
        continue;
      }
      flushList();
      if (paragraph.length === 0) paragraphStartOffset = lineOffset;
      paragraph.push(line);
    }
    flushParagraph();
    flushList();
    if (codeLines) {
      blocks.push(
        <pre
          className="overflow-x-auto rounded-md bg-muted/70 p-3 font-mono text-[10px] leading-relaxed"
          key={`code:${codeStartOffset}`}
        >
          {codeLines.join('\n')}
        </pre>,
      );
    }
    return blocks.length > 0 ? blocks : <p>No release notes were provided.</p>;
  }, [markdown]);
}

// Settings hosts independent native services whose state must not share reducer transitions; the
// long component is an explicit composition root for those isolated settings sections.
// react-doctor-disable-next-line react-doctor/no-giant-component, react-doctor/prefer-useReducer
function SettingsPage({
  autoCopyOnSelect,
  confirmOnTabClose,
  theme,
  onThemeChange,
  authGate,
  authState,
  onAuthStateChange,
  onAutoCopyOnSelectChange,
  onConfirmOnTabCloseChange,
  onBackupImported,
  onRequestAuthentication,
  onCheckForUpdates,
  onDismissUpdate,
  onInstallUpdate,
  onOpenReleaseNotes,
  onSetAutoCheckForUpdates,
  settingsUpdatesRequest,
  update,
  onWorkspaceCredentialsChanged,
}: {
  autoCopyOnSelect: boolean;
  confirmOnTabClose: boolean;
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
  authGate: 'loading' | 'locked' | 'unlocked' | 'error';
  authState: WormholeAuthState | null;
  onAuthStateChange: (state: WormholeAuthState) => void;
  onAutoCopyOnSelectChange: (enabled: boolean) => void;
  onConfirmOnTabCloseChange: (enabled: boolean) => void;
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
  onWorkspaceCredentialsChanged: () => Promise<void>;
  // react-doctor-disable-next-line react-doctor/prefer-useReducer
}) {
  const [activeTabSelection, setActiveTabSelection] = useState({
    request: settingsUpdatesRequest,
    value: settingsUpdatesRequest > 0 ? 'updates' : 'general',
  });
  const activeTab =
    activeTabSelection.request === settingsUpdatesRequest ? activeTabSelection.value : 'updates';
  const [promptBeforeTunnelConnect, setPromptBeforeTunnelConnect] = useState(true);
  const authMethod = authState?.mode ?? 'disabled';
  const helloFallback = authState?.fallback ?? 'pin';
  const idleTimeout = authState?.idleTimeoutMinutes ?? 15;
  const [securityBusy, setSecurityBusy] = useState(false);
  const [securityError, setSecurityError] = useState('');
  const [securityMessage, setSecurityMessage] = useState('');
  const [secretDialog, setSecretDialog] = useState<WormholeAuthFallback | null>(null);
  const pendingSecretAction = useRef<(() => Promise<void>) | null>(null);
  const helloStatusMode = useRef<WormholeAuthMode | null>(null);
  const [bitwardenEnabled, setBitwardenEnabled] = useState(false);
  const [bitwardenPath, setBitwardenPath] = useState('bw');
  const [bitwardenServerRegion, setBitwardenServerRegion] = useState<
    'UnitedStates' | 'Europe' | 'Current'
  >('UnitedStates');
  const bitwardenSavedConfig = useRef<{
    path: string;
    serverRegion: 'UnitedStates' | 'Europe' | 'Current';
  }>({ path: 'bw', serverRegion: 'UnitedStates' });
  const bitwardenConfigSaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [bitwardenCliStatus, setBitwardenCliStatus] = useState<WormholeBitwardenCliStatus | null>(
    null,
  );
  const [bitwardenInstalledVersion, setBitwardenInstalledVersion] = useState('');
  const [bitwardenInstallError, setBitwardenInstallError] = useState('');
  const [bitwardenLastSyncStatus, setBitwardenLastSyncStatus] = useState('');
  const [bitwardenAvailableCount, setBitwardenAvailableCount] = useState<number | null>(null);
  const [bitwardenBusy, setBitwardenBusy] = useState(false);
  const [bitwardenInstallBusy, setBitwardenInstallBusy] = useState(false);
  const [bitwardenError, setBitwardenError] = useState('');
  const [bitwardenCliDialog, setBitwardenCliDialog] = useState<'login' | 'unlock' | null>(null);
  const [bitwardenSyncDialog, setBitwardenSyncDialog] =
    useState<BitwardenOperationDialogState | null>(null);
  const [bitwardenCliUpdateDialog, setBitwardenCliUpdateDialog] =
    useState<BitwardenOperationDialogState | null>(null);
  const [browserExtensionEnabled, setBrowserExtensionEnabled] = useState(false);
  const [browserExtensionStatus, setBrowserExtensionStatus] = useState('Disabled');
  const [browserExtensionBusy, setBrowserExtensionBusy] = useState(false);
  const [browserExtensionUpdateBusy, setBrowserExtensionUpdateBusy] = useState(false);
  const [browserExtensionError, setBrowserExtensionError] = useState('');
  const [bitwardenExtensionUpdateDialog, setBitwardenExtensionUpdateDialog] =
    useState<BitwardenOperationDialogState | null>(null);
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
  const savedLogLevel = useRef<LogLevel>('info');
  const [logsActionError, setLogsActionError] = useState('');
  const [retentionError, setRetentionError] = useState('');
  const [backupExportOpen, setBackupExportOpen] = useState(false);
  const [backupExportPassword, setBackupExportPassword] = useState('');
  const [backupExportConfirmation, setBackupExportConfirmation] = useState('');
  const [backupExportBusy, setBackupExportBusy] = useState(false);
  const [backupExportCancelling, setBackupExportCancelling] = useState(false);
  const [backupExportProgress, setBackupExportProgress] =
    useState<WormholeOperationProgress | null>(null);
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
  const [backupImportCancelling, setBackupImportCancelling] = useState(false);
  const [backupImportProgress, setBackupImportProgress] =
    useState<WormholeOperationProgress | null>(null);
  const [backupImportError, setBackupImportError] = useState('');
  const [backupImportResult, setBackupImportResult] = useState<WormholeBackupImportResult | null>(
    null,
  );
  const [backupSectionError, setBackupSectionError] = useState('');
  const authGateRef = useRef(authGate);
  useLayoutEffect(() => {
    authGateRef.current = authGate;
  }, [authGate]);

  useEffect(() => {
    return window.wormhole?.onOperationProgress((event) => {
      if (event.kind === 'backup-export') setBackupExportProgress(event);
      if (event.kind === 'backup-import') setBackupImportProgress(event);
    });
  }, []);

  useEffect(
    () => () => {
      window.wormhole?.clearBackupImportSelection();
    },
    [],
  );

  useEffect(
    () => () => {
      if (bitwardenConfigSaveTimer.current !== null) {
        clearTimeout(bitwardenConfigSaveTimer.current);
      }
    },
    [],
  );

  // App lock is an external security boundary. Scrub renderer-held secrets while retaining the
  // Settings instance so native backup and Bitwarden operations keep their progress/cancel state.
  // react-doctor-disable-next-line react-hooks-js/set-state-in-effect, react-doctor/no-adjust-state-on-prop-change
  useEffect(() => {
    if (authGate === 'unlocked') return;
    setSecretDialog(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenCliDialog(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenSyncDialog(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenCliUpdateDialog(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenExtensionUpdateDialog(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    pendingSecretAction.current = null;
    setBackupExportOpen(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBackupExportPassword(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBackupExportConfirmation(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBackupImportOpen(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBackupImportPassword(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBackupImportSelection(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBackupSectionError(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setMcpState(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setMcpToken(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setMcpTokenRevealed(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    window.wormhole?.clearBackupImportSelection();
  }, [authGate]);

  useEffect(() => {
    if (authGate !== 'unlocked' || !window.wormhole) return;
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
        setMcpError(authSettingsErrorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [authGate]);

  useEffect(() => {
    if (authGate !== 'unlocked' || !window.wormhole) return;
    let active = true;
    void (async () => {
      const [settingsResult, extensionResult, cliResult] = await Promise.allSettled([
        window.wormhole!.readAppSettings(),
        window.wormhole!.readBitwardenExtension(),
        window.wormhole!.readBitwardenCli(),
      ]);
      if (!active) return;

      if (settingsResult.status === 'fulfilled') {
        setPromptBeforeTunnelConnect(settingsResult.value.promptBeforeTunnelConnect);
      }
      if (extensionResult.status === 'fulfilled') {
        applyBitwardenExtensionState(extensionResult.value);
      } else {
        const message = backendErrorMessage(extensionResult.reason);
        setBrowserExtensionError(message);
        setBrowserExtensionStatus(message);
      }
      if (cliResult.status === 'rejected') {
        setBitwardenError(backendErrorMessage(cliResult.reason));
        return;
      }

      const cliState = cliResult.value;
      applyBitwardenCliState(cliState);
      if (!cliState.enabled || !cliState.installed) {
        setBitwardenCliStatus(null);
        return;
      }
      try {
        const cliStatus = await window.wormhole!.refreshBitwardenCliStatus();
        if (active) setBitwardenCliStatus(cliStatus);
      } catch (error: unknown) {
        if (active) setBitwardenError(backendErrorMessage(error));
      }
    })();
    return () => {
      active = false;
    };
  }, [authGate]);

  useEffect(() => {
    if (authGate !== 'unlocked' || !window.wormhole) {
      setLogsInfo(null);
      return;
    }
    let active = true;
    void window.wormhole
      .readLogsInfo()
      .then((info) => {
        if (!active) return;
        if (isLogLevel(info.logLevel)) savedLogLevel.current = info.logLevel;
        setLogsInfo(info);
        setRetentionDays(String(info.logRetentionDays));
        setLogsActionError('');
      })
      .catch((error) => {
        if (active) setLogsActionError(logsErrorMessage(error));
      });
    return () => {
      active = false;
    };
  }, [authGate]);

  function applyBitwardenExtensionState(state: WormholeBitwardenExtensionState) {
    setBrowserExtensionEnabled(state.enabled);
    setBrowserExtensionStatus(formatBitwardenExtensionStatus(state));
    setBrowserExtensionError(state.lastUpdateError || '');
  }

  function applyBitwardenCliState(state: WormholeBitwardenCliState) {
    const path = state.path || 'bw';
    setBitwardenEnabled(state.enabled);
    setBitwardenPath(path);
    setBitwardenServerRegion(state.serverRegion);
    bitwardenSavedConfig.current = { path, serverRegion: state.serverRegion };
    setBitwardenInstalledVersion(state.installed?.version || '');
    setBitwardenInstallError(state.installError || '');
    setBitwardenLastSyncStatus(state.lastSyncStatus || '');
    setBitwardenAvailableCount(state.availableCount);
  }

  async function reloadBitwardenCliStatus(state?: WormholeBitwardenCliState) {
    if (!window.wormhole) return;
    const freshState = state ?? (await window.wormhole.readBitwardenCli());
    applyBitwardenCliState(freshState);
    setBitwardenCliStatus(null);
    setBitwardenCliStatus(
      freshState.enabled && freshState.installed
        ? await window.wormhole.refreshBitwardenCliStatus()
        : null,
    );
  }

  async function refreshBitwardenCliStatus() {
    if (bitwardenBusy || !window.wormhole) return;
    setBitwardenBusy(true);
    setBitwardenError('');
    try {
      await reloadBitwardenCliStatus();
    } catch (error) {
      setBitwardenError(backendErrorMessage(error));
    } finally {
      setBitwardenBusy(false);
    }
  }

  async function runBitwardenCliInstall() {
    if (bitwardenBusy || !window.wormhole) return;
    setBitwardenBusy(true);
    setBitwardenInstallBusy(true);
    setBitwardenError('');
    setBitwardenCliUpdateDialog({
      status: 'working',
      message: 'Updating Bitwarden CLI…',
    });
    try {
      const state = await window.wormhole.installBitwardenCli();
      await reloadBitwardenCliStatus(state);
      setBitwardenCliUpdateDialog({
        status: 'success',
        message: state.installed?.version
          ? `Bitwarden CLI is up to date (version ${state.installed.version}).`
          : 'Bitwarden CLI updated successfully.',
      });
    } catch (error) {
      const message = backendErrorMessage(error);
      setBitwardenError(message);
      setBitwardenInstallError(message);
      setBitwardenCliUpdateDialog({ status: 'error', message });
    } finally {
      setBitwardenInstallBusy(false);
      setBitwardenBusy(false);
    }
  }

  async function handleBitwardenCliConfigSave(
    path: string,
    serverRegion: 'UnitedStates' | 'Europe' | 'Current',
  ) {
    if (bitwardenBusy || !window.wormhole) return;
    setBitwardenBusy(true);
    setBitwardenError('');
    try {
      const state = await window.wormhole.setBitwardenCliConfig({
        path,
        serverRegion: serverRegion === 'UnitedStates' ? 0 : serverRegion === 'Europe' ? 1 : 2,
      });
      await reloadBitwardenCliStatus(state);
    } catch (error) {
      setBitwardenPath(bitwardenSavedConfig.current.path);
      setBitwardenServerRegion(bitwardenSavedConfig.current.serverRegion);
      setBitwardenError(backendErrorMessage(error));
    } finally {
      setBitwardenBusy(false);
    }
  }

  function cancelScheduledBitwardenCliConfigSave() {
    if (bitwardenConfigSaveTimer.current !== null) {
      clearTimeout(bitwardenConfigSaveTimer.current);
      bitwardenConfigSaveTimer.current = null;
    }
  }

  function scheduleBitwardenCliConfigSave(
    path: string,
    serverRegion: 'UnitedStates' | 'Europe' | 'Current',
  ) {
    cancelScheduledBitwardenCliConfigSave();
    bitwardenConfigSaveTimer.current = setTimeout(() => {
      bitwardenConfigSaveTimer.current = null;
      void handleBitwardenCliConfigSave(path, serverRegion);
    }, 400);
  }

  async function handleBitwardenCliEnabledChange(enabled: boolean) {
    if (bitwardenBusy || !window.wormhole) return;
    setBitwardenBusy(true);
    setBitwardenEnabled(enabled);
    setBitwardenError('');
    let settingSaved = false;
    try {
      const state = await window.wormhole.setBitwardenCliEnabled(enabled);
      settingSaved = true;
      await reloadBitwardenCliStatus(state);
      await onWorkspaceCredentialsChanged();
    } catch (error) {
      if (!settingSaved) setBitwardenEnabled(!enabled);
      setBitwardenError(backendErrorMessage(error));
    } finally {
      setBitwardenBusy(false);
    }
  }

  async function handleBitwardenCliLogin(
    email: string,
    masterPassword: string,
    authenticatorCode?: string,
    serverRegion: 'UnitedStates' | 'Europe' | 'Current' = bitwardenServerRegion,
  ) {
    if (bitwardenBusy || !window.wormhole) return false;
    setBitwardenBusy(true);
    setBitwardenError('');
    try {
      try {
        await window.wormhole.loginBitwardenCli({
          email,
          masterPassword,
          authenticatorCode: authenticatorCode?.trim() || undefined,
          serverRegion: serverRegion === 'UnitedStates' ? 0 : serverRegion === 'Europe' ? 1 : 2,
        });
      } catch (error) {
        setBitwardenError(backendErrorMessage(error));
        return false;
      }

      // Authentication is complete at this point. Close the secret prompt before the potentially
      // slower initial vault sync so successful credentials never leave the dialog stuck on Working.
      setBitwardenCliDialog(null);
      let syncSucceeded = false;
      try {
        const result = await window.wormhole.syncBitwardenCli();
        setBitwardenLastSyncStatus(result.lastSyncStatus);
        setBitwardenAvailableCount(result.availableCount);
        syncSucceeded = true;
      } catch (error) {
        setBitwardenError(backendErrorMessage(error));
      }
      try {
        await reloadBitwardenCliStatus();
      } catch (error) {
        if (syncSucceeded) setBitwardenError(backendErrorMessage(error));
      }
      if (syncSucceeded) {
        try {
          await onWorkspaceCredentialsChanged();
        } catch (error) {
          setBitwardenError(backendErrorMessage(error));
        }
      }
      return true;
    } finally {
      setBitwardenBusy(false);
    }
  }

  async function handleBitwardenCliUnlock(masterPassword: string) {
    if (bitwardenBusy || !window.wormhole) return false;
    setBitwardenBusy(true);
    setBitwardenError('');
    try {
      await window.wormhole.unlockBitwardenCli(masterPassword);
      setBitwardenCliDialog(null);
      await reloadBitwardenCliStatus();
      await onWorkspaceCredentialsChanged();
      return true;
    } catch (error) {
      setBitwardenError(backendErrorMessage(error));
      return false;
    } finally {
      setBitwardenBusy(false);
    }
  }

  async function handleBitwardenCliSync() {
    if (bitwardenBusy || !window.wormhole) return;
    setBitwardenBusy(true);
    setBitwardenError('');
    setBitwardenSyncDialog({
      status: 'working',
      message: 'Syncing Bitwarden vault…',
    });
    try {
      const result = await window.wormhole.syncBitwardenCli();
      setBitwardenLastSyncStatus(result.lastSyncStatus);
      setBitwardenAvailableCount(result.availableCount);
      await reloadBitwardenCliStatus();
      await onWorkspaceCredentialsChanged();
      setBitwardenSyncDialog(formatBitwardenSyncResult(result));
    } catch (error) {
      const message = backendErrorMessage(error);
      setBitwardenError(message);
      setBitwardenSyncDialog({ status: 'error', message });
    } finally {
      setBitwardenBusy(false);
    }
  }

  async function handleBitwardenCliLogout() {
    if (bitwardenBusy || !window.wormhole) return;
    setBitwardenBusy(true);
    setBitwardenError('');
    try {
      await window.wormhole.logoutBitwardenCli();
      await reloadBitwardenCliStatus();
    } catch (error) {
      setBitwardenError(backendErrorMessage(error));
    } finally {
      setBitwardenBusy(false);
    }
  }

  async function handleBrowserExtensionEnabledChange(enabled: boolean) {
    if (browserExtensionBusy || !window.wormhole) return;
    setBrowserExtensionBusy(true);
    setBrowserExtensionError('');
    setBrowserExtensionEnabled(enabled);
    let settingSaved = false;
    try {
      let state = await window.wormhole.setBitwardenExtensionEnabled(enabled);
      settingSaved = true;
      applyBitwardenExtensionState(state);
      if (enabled && !state.installed) {
        setBrowserExtensionStatus('Installing Bitwarden browser extension...');
        state = await window.wormhole.ensureBitwardenExtension();
        applyBitwardenExtensionState(state);
      }
    } catch (error) {
      const message = backendErrorMessage(error);
      if (!settingSaved) setBrowserExtensionEnabled(!enabled);
      setBrowserExtensionError(message);
      setBrowserExtensionStatus(message);
    } finally {
      setBrowserExtensionBusy(false);
    }
  }

  async function runBitwardenExtensionUpdate() {
    if (browserExtensionBusy || !window.wormhole) return;
    setBrowserExtensionBusy(true);
    setBrowserExtensionUpdateBusy(true);
    setBrowserExtensionError('');
    setBrowserExtensionStatus('Updating Bitwarden browser extension...');
    setBitwardenExtensionUpdateDialog({
      status: 'working',
      message: 'Updating Bitwarden browser extension…',
    });
    try {
      const state = await window.wormhole.installBitwardenExtension();
      applyBitwardenExtensionState(state);
      setBitwardenExtensionUpdateDialog({
        status: 'success',
        message: state.installed?.version
          ? `Bitwarden browser extension is up to date (version ${state.installed.version}).`
          : 'Bitwarden browser extension updated successfully.',
      });
    } catch (error) {
      const message = backendErrorMessage(error);
      setBrowserExtensionError(message);
      setBrowserExtensionStatus(message);
      setBitwardenExtensionUpdateDialog({ status: 'error', message });
    } finally {
      setBrowserExtensionUpdateBusy(false);
      setBrowserExtensionBusy(false);
    }
  }

  async function importBitwardenExtensionZip() {
    if (browserExtensionBusy || !window.wormhole) return;
    setBrowserExtensionBusy(true);
    setBrowserExtensionError('');
    setBrowserExtensionStatus('Importing Bitwarden browser extension ZIP...');
    try {
      const state = await window.wormhole.importBitwardenExtensionZip();
      if (state) {
        applyBitwardenExtensionState(state);
      } else {
        const fresh = await window.wormhole.readBitwardenExtension();
        applyBitwardenExtensionState(fresh);
      }
    } catch (error) {
      const message = backendErrorMessage(error);
      setBrowserExtensionError(message);
      setBrowserExtensionStatus(message);
    } finally {
      setBrowserExtensionBusy(false);
    }
  }

  async function importBitwardenExtensionFolder() {
    if (browserExtensionBusy || !window.wormhole) return;
    setBrowserExtensionBusy(true);
    setBrowserExtensionError('');
    setBrowserExtensionStatus('Importing Bitwarden browser extension folder...');
    try {
      const state = await window.wormhole.importBitwardenExtensionFolder();
      if (state) {
        applyBitwardenExtensionState(state);
      } else {
        const fresh = await window.wormhole.readBitwardenExtension();
        applyBitwardenExtensionState(fresh);
      }
    } catch (error) {
      const message = backendErrorMessage(error);
      setBrowserExtensionError(message);
      setBrowserExtensionStatus(message);
    } finally {
      setBrowserExtensionBusy(false);
    }
  }

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
      const nextState = await window.wormhole.setAuthSecret({
        method: secretDialog,
        secret,
      });
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
      setSecurityError(authSettingsErrorMessage(error));
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
      setSecurityError(authSettingsErrorMessage(error));
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
      setSecurityError(authSettingsErrorMessage(error));
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
      setSecurityError(authSettingsErrorMessage(error));
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
        setSecurityError(authSettingsErrorMessage(error));
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
      setSecurityError(authSettingsErrorMessage(error));
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
      setMcpError(authSettingsErrorMessage(error));
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
      setMcpError(authSettingsErrorMessage(error));
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
      const token = await window.wormhole.getMcpToken();
      if (authGateRef.current !== 'unlocked') return;
      setMcpToken(token);
      setMcpTokenRevealed(true);
    } catch (error) {
      setMcpError(authSettingsErrorMessage(error));
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
      if (authGateRef.current !== 'unlocked') return;
      await copyTextToClipboard(token);
      setMcpMessage('Bearer token copied.');
    } catch (error) {
      setMcpError(authSettingsErrorMessage(error));
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
      const token = await window.wormhole.regenerateMcpToken();
      if (authGateRef.current !== 'unlocked') {
        setMcpMessage('MCP token regenerated. Reveal it again after unlocking.');
        return;
      }
      setMcpToken(token);
      setMcpTokenRevealed(true);
      setMcpMessage('MCP token regenerated. Update connected clients.');
    } catch (error) {
      setMcpError(authSettingsErrorMessage(error));
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
      setMcpError(authSettingsErrorMessage(error));
    }
  }

  async function copyMcpConfig() {
    if (mcpBusy || !window.wormhole) return;
    setMcpBusy(true);
    setMcpError('');
    try {
      const token = await window.wormhole.getMcpToken();
      if (authGateRef.current !== 'unlocked') return;
      await copyTextToClipboard(
        buildMcpConfig(mcpClient, mcpEndpoint, token, window.wormhole.platform),
      );
      setMcpMessage('MCP client configuration copied with the current bearer token.');
    } catch (error) {
      setMcpError(authSettingsErrorMessage(error));
    } finally {
      setMcpBusy(false);
    }
  }

  async function openCurrentLogFile() {
    if (logsOpenBusy || retentionBusy || !window.wormhole) return;
    setLogsOpenBusy(true);
    setLogsActionError('');
    try {
      await window.wormhole.openCurrentLogFile();
    } catch (error) {
      setLogsActionError(logsErrorMessage(error));
    } finally {
      setLogsOpenBusy(false);
    }
  }

  async function openLogsFolder() {
    if (logsOpenBusy || retentionBusy || !window.wormhole) return;
    setLogsOpenBusy(true);
    setLogsActionError('');
    try {
      await window.wormhole.openLogsFolder();
    } catch (error) {
      setLogsActionError(logsErrorMessage(error));
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
      setRetentionError('Log retention must be a whole number between 1 and 365 days.');
      return;
    }
    if (days === saved) {
      setRetentionError('');
      return;
    }
    setRetentionBusy(true);
    setRetentionError('');
    try {
      const result = await window.wormhole.setLogRetentionDays(days);
      setRetentionDays(String(result.logRetentionDays));
      setLogsInfo((current) =>
        current ? { ...current, logRetentionDays: result.logRetentionDays } : current,
      );
    } catch (error) {
      setRetentionDays(String(saved));
      setRetentionError(logsErrorMessage(error));
    } finally {
      setRetentionBusy(false);
    }
  }

  function closeBackupExport(open: boolean) {
    if (open) {
      setBackupExportOpen(true);
      return;
    }
    if (backupExportBusy) {
      void cancelBackupExport();
      return;
    }
    setBackupExportOpen(false);
    setBackupExportPassword('');
    setBackupExportConfirmation('');
    setBackupExportError('');
    setBackupExportResult(null);
    setBackupExportProgress(null);
  }

  async function cancelBackupExport() {
    if (!backupExportBusy || backupExportCancelling || !window.wormhole) return;
    setBackupExportCancelling(true);
    try {
      await window.wormhole.cancelBackupExport();
    } catch (error) {
      setBackupExportError(backupOperationErrorMessage(error));
    } finally {
      setBackupExportCancelling(false);
    }
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
    setBackupExportProgress(null);
    try {
      const result = await window.wormhole.exportBackup(backupExportPassword);
      if (!result) return;
      setBackupExportResult(result);
      setBackupExportPassword('');
      setBackupExportConfirmation('');
    } catch (error) {
      setBackupExportError(backupOperationErrorMessage(error));
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
      if (authGateRef.current === 'unlocked') {
        setBackupSectionError(backupOperationErrorMessage(error));
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
    if (backupImportBusy) {
      void cancelBackupImport();
      return;
    }
    setBackupImportOpen(false);
    setBackupImportPassword('');
    setBackupImportError('');
    setBackupImportResult(null);
    setBackupImportSelection(null);
    setBackupImportProgress(null);
    window.wormhole?.clearBackupImportSelection();
  }

  async function cancelBackupImport() {
    if (!backupImportBusy || backupImportCancelling || !window.wormhole) return;
    setBackupImportCancelling(true);
    try {
      await window.wormhole.cancelBackupImport();
    } catch (error) {
      setBackupImportError(backupOperationErrorMessage(error));
    } finally {
      setBackupImportCancelling(false);
    }
  }

  async function importWormholeBackup() {
    if (backupImportBusy || !window.wormhole || !backupImportSelection) return;
    setBackupImportBusy(true);
    setBackupImportError('');
    setBackupImportProgress(null);
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
      const message = backupOperationErrorMessage(error);
      setBackupImportError(
        /cancel/i.test(message)
          ? 'Import cancelled. Items committed before cancellation were kept; running the import again safely skips them.'
          : message,
      );
      if (/cancel/i.test(message)) {
        try {
          onBackupImported(await window.wormhole.loadWorkspace());
        } catch {
          // The cancellation result remains accurate even if the refreshed tree cannot be loaded.
        }
      }
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
    window.wormhole?.platform ?? '',
  );
  const mcpConfigDetails = mcpClientCopyDetails(mcpClient);
  const updateAvailable = Boolean(update.result && isUpdateInstallable(update.result));
  const updateDismissible = Boolean(
    update.result && shouldOfferUpdate(update.result, update.skippedUpdateVersion),
  );
  const newerReleaseWithoutInstaller = Boolean(
    update.result && hasNewerReleaseWithoutInstaller(update.result),
  );
  const backupExportPasswordConfirmed = backupExportPasswordsMatch(
    backupExportPassword,
    backupExportConfirmation,
  );
  const bitwardenLoggedIn = bitwardenCliIsLoggedIn(bitwardenCliStatus?.status);
  const currentBitwardenServerRegion = bitwardenCliServerRegionCode(bitwardenCliStatus?.serverUrl);

  return (
    <section className="flex h-full min-h-0 flex-col overflow-hidden p-6">
      <h2 className="shrink-0 text-xl font-semibold tracking-tight">Settings</h2>

      <Tabs
        className="mt-4 min-h-0 flex-1 gap-0"
        onValueChange={(value) => setActiveTabSelection({ request: settingsUpdatesRequest, value })}
        value={activeTab}
      >
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
              onCheckedChange={onConfirmOnTabCloseChange}
            />
          </SettingsSection>

          <SettingsSection title="Terminal">
            <SettingsSwitch
              checked={autoCopyOnSelect}
              description="Copy selected terminal text to the clipboard automatically."
              label="Auto-copy selection to clipboard"
              onCheckedChange={onAutoCopyOnSelectChange}
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
                  {window.wormhole?.platform === 'win32' ? (
                    <SelectItem value="windowsHello">Windows Hello</SelectItem>
                  ) : authMethod === 'windowsHello' ? (
                    <SelectItem disabled value="windowsHello">
                      Windows Hello (Windows only)
                    </SelectItem>
                  ) : null}
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
                description="Manage the Bitwarden vault used by SSH, RDP, and VNC credentials."
                disabled={bitwardenBusy}
                label="Enable Bitwarden Password Manager"
                onCheckedChange={(enabled) => void handleBitwardenCliEnabledChange(enabled)}
              />
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                Turning this on installs the official Bitwarden CLI automatically.
              </p>
              <div className="grid gap-2">
                <Label htmlFor="settings-bitwarden-path">Bitwarden CLI path</Label>
                <Input
                  disabled={bitwardenBusy}
                  id="settings-bitwarden-path"
                  onBlur={(event) => {
                    if (
                      event.relatedTarget instanceof Element &&
                      event.relatedTarget.closest('[data-slot="select-trigger"]')
                    ) {
                      return;
                    }
                    cancelScheduledBitwardenCliConfigSave();
                    void handleBitwardenCliConfigSave(
                      event.currentTarget.value,
                      bitwardenServerRegion,
                    );
                  }}
                  onChange={(event) => {
                    const path = event.target.value;
                    setBitwardenPath(path);
                    scheduleBitwardenCliConfigSave(path, bitwardenServerRegion);
                  }}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') event.currentTarget.blur();
                  }}
                  placeholder="bw"
                  spellCheck={false}
                  value={bitwardenPath}
                />
              </div>
              <div className="grid gap-2">
                <Label>Server region</Label>
                <Select
                  disabled={bitwardenBusy}
                  onValueChange={(value) => {
                    const serverRegion = value as 'UnitedStates' | 'Europe' | 'Current';
                    cancelScheduledBitwardenCliConfigSave();
                    setBitwardenServerRegion(serverRegion);
                    void handleBitwardenCliConfigSave(bitwardenPath, serverRegion);
                  }}
                  value={bitwardenServerRegion}
                >
                  <SelectTrigger className="w-full sm:max-w-[280px]">
                    <SelectValue>
                      {bitwardenServerRegion === 'Current'
                        ? formatBitwardenCurrentServerLabel(currentBitwardenServerRegion)
                        : undefined}
                    </SelectValue>
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="UnitedStates">bitwarden.com (US)</SelectItem>
                    <SelectItem value="Europe">bitwarden.eu (EU)</SelectItem>
                    <SelectItem value="Current">
                      {formatBitwardenCurrentServerLabel(currentBitwardenServerRegion)}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {bitwardenCliStatus ? (
                <div className="grid gap-1 text-[11px] leading-relaxed text-muted-foreground">
                  <p>
                    Status:{' '}
                    <span className="text-foreground">
                      {formatBitwardenLoginStatus(bitwardenCliStatus.status)}
                    </span>
                  </p>
                  <p>
                    Vault:{' '}
                    <span className="text-foreground">
                      {formatBitwardenVaultStatus(bitwardenCliStatus.status)}
                    </span>
                  </p>
                  {bitwardenCliStatus.userEmail ? (
                    <p>
                      Account:{' '}
                      <span className="text-foreground">{bitwardenCliStatus.userEmail}</span>
                    </p>
                  ) : null}
                  {bitwardenCliStatus.serverUrl ? (
                    <p>
                      Server:{' '}
                      <span className="text-foreground">{bitwardenCliStatus.serverUrl}</span>
                    </p>
                  ) : null}
                </div>
              ) : (
                <p className="text-[11px] text-muted-foreground">
                  No status available. Connect to Bitwarden to see your vault.
                </p>
              )}
              {bitwardenInstalledVersion ? (
                <p className="text-[11px] text-muted-foreground">
                  Installed bw CLI {bitwardenInstalledVersion}
                </p>
              ) : null}
              {bitwardenLastSyncStatus ? (
                <p className="text-[11px] text-muted-foreground">
                  {bitwardenLastSyncStatus}
                  {bitwardenAvailableCount !== null ? ` · ${bitwardenAvailableCount} logins` : ''}
                </p>
              ) : null}
              {bitwardenInstallError ? (
                <p className="text-[11px] text-destructive">{bitwardenInstallError}</p>
              ) : null}
              {bitwardenError ? (
                <p className="text-[11px] text-destructive">{bitwardenError}</p>
              ) : null}
              <div className="flex flex-wrap gap-2">
                <Button
                  disabled={bitwardenBusy}
                  onClick={() => void refreshBitwardenCliStatus()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  Refresh status
                </Button>
                <Button
                  disabled={bitwardenBusy}
                  onClick={() => void runBitwardenCliInstall()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  {bitwardenInstallBusy ? 'Working…' : 'Update CLI'}
                </Button>
                {bitwardenCliStatus?.status === 'Unauthenticated' ? (
                  <Button
                    disabled={bitwardenBusy || !bitwardenEnabled}
                    onClick={() => setBitwardenCliDialog('login')}
                    size="sm"
                    type="button"
                    variant="outline"
                  >
                    Log in
                  </Button>
                ) : null}
                {bitwardenCliStatus?.status === 'Locked' ? (
                  <Button
                    disabled={bitwardenBusy || !bitwardenEnabled}
                    onClick={() => setBitwardenCliDialog('unlock')}
                    size="sm"
                    type="button"
                    variant="outline"
                  >
                    Unlock
                  </Button>
                ) : null}
                {bitwardenLoggedIn ? (
                  <>
                    <Button
                      disabled={bitwardenBusy || !bitwardenEnabled}
                      onClick={() => void handleBitwardenCliSync()}
                      size="sm"
                      type="button"
                      variant="outline"
                    >
                      Sync
                    </Button>
                    <Button
                      disabled={bitwardenBusy || !bitwardenEnabled}
                      onClick={() => void handleBitwardenCliLogout()}
                      size="sm"
                      type="button"
                      variant="outline"
                    >
                      Log out
                    </Button>
                  </>
                ) : null}
              </div>
            </SettingsSection>

            <SettingsSection title="Browser extension">
              <SettingsSwitch
                checked={browserExtensionEnabled}
                description="Use the official Bitwarden extension inside HTTPS sessions."
                disabled={browserExtensionBusy}
                label="Enable Bitwarden in HTTPS windows"
                onCheckedChange={(enabled) => void handleBrowserExtensionEnabledChange(enabled)}
              />
              <p
                className={
                  browserExtensionError
                    ? 'text-[11px] leading-relaxed text-destructive'
                    : 'text-[11px] leading-relaxed text-muted-foreground'
                }
              >
                {browserExtensionStatus}
              </p>
              <p className="text-[11px] leading-relaxed text-muted-foreground">
                Turning this on installs the official extension automatically.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button
                  disabled={browserExtensionBusy}
                  onClick={() => void runBitwardenExtensionUpdate()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  {browserExtensionUpdateBusy ? 'Working…' : 'Update Extension'}
                </Button>
                <Button
                  disabled={browserExtensionBusy}
                  onClick={() => void importBitwardenExtensionZip()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  Import ZIP
                </Button>
                <Button
                  disabled={browserExtensionBusy}
                  onClick={() => void importBitwardenExtensionFolder()}
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  Use folder
                </Button>
              </div>
            </SettingsSection>
          </SettingsSection>
        </SettingsTabPanel>

        {bitwardenCliDialog ? (
          <BitwardenCliDialog
            currentServerRegion={currentBitwardenServerRegion}
            defaultServerRegion={bitwardenServerRegion}
            key={bitwardenCliDialog}
            loginBusy={bitwardenBusy}
            mode={bitwardenCliDialog}
            onClose={() => setBitwardenCliDialog(null)}
            onLogin={(email, masterPassword, authenticatorCode, serverRegion) =>
              void handleBitwardenCliLogin(email, masterPassword, authenticatorCode, serverRegion)
            }
            onUnlock={(masterPassword) => void handleBitwardenCliUnlock(masterPassword)}
          />
        ) : null}

        <BitwardenOperationDialog
          description="Refresh the Bitwarden credentials available to Wormhole."
          onClose={() => setBitwardenSyncDialog(null)}
          state={bitwardenSyncDialog}
          title="Sync Bitwarden vault"
        />

        <BitwardenOperationDialog
          description="Download and install the latest Bitwarden command-line client."
          onClose={() => setBitwardenCliUpdateDialog(null)}
          state={bitwardenCliUpdateDialog}
          title="Update Bitwarden CLI"
        />

        <BitwardenOperationDialog
          description="Download and install the latest official Bitwarden browser extension."
          onClose={() => setBitwardenExtensionUpdateDialog(null)}
          state={bitwardenExtensionUpdateDialog}
          title="Update Bitwarden extension"
        />

        <SettingsTabPanel value="updates">
          <SettingsSection title="Wormhole updates">
            <p className="text-xs font-medium">Wormhole {update.currentVersion || '…'}</p>
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
                    style={{
                      width: `${Math.round(update.downloadProgress * 100)}%`,
                    }}
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
                {window.wormhole?.platform === 'linux' ? 'Download AppImage' : 'Install update'}
              </Button>
              <Button
                disabled={!update.result?.releaseUrl}
                onClick={onOpenReleaseNotes}
                size="sm"
                variant="outline"
              >
                View release notes
              </Button>
              {updateDismissible ? (
                <Button disabled={update.busy} onClick={onDismissUpdate} size="sm" variant="ghost">
                  Not now
                </Button>
              ) : null}
            </div>
          </SettingsSection>

          <SettingsSection title="Release notes">
            <Card className="border-border/70 bg-card/40 p-4 shadow-none">
              {updateAvailable ? (
                <div className="text-[11px] leading-relaxed text-muted-foreground">
                  <ReleaseNotesMarkdown markdown={update.result?.releaseNotes ?? ''} />
                </div>
              ) : (
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  {update.result?.checkFailed
                    ? "Couldn't reach the update server. Try again later."
                    : newerReleaseWithoutInstaller
                      ? `Wormhole ${update.result?.latestVersion} is available, but no verified installer is published for this platform.`
                      : update.result?.latestVersion
                        ? "You're on the latest version."
                        : 'Update information will appear here when a new release is available.'}
                </p>
              )}
            </Card>
          </SettingsSection>
        </SettingsTabPanel>

        <SettingsTabPanel forceMount value="logs">
          <SettingsSection title="Current log">
            <div className="grid gap-2">
              <Label htmlFor="settings-log-file">Today&apos;s log file</Label>
              <Input
                id="settings-log-file"
                readOnly
                spellCheck={false}
                value={logsInfo?.currentLogFilePath ?? 'Loading the current log path…'}
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
            {logsActionError ? (
              <p className="text-[11px] text-destructive">{logsActionError}</p>
            ) : null}
          </SettingsSection>

          <LogLevelSetting
            initialValue={savedLogLevel.current}
            loaded={logsInfo !== null}
            onSaved={(level) => {
              savedLogLevel.current = level;
            }}
          />

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
            {retentionError ? (
              <p className="text-[11px] text-destructive">{retentionError}</p>
            ) : null}
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
              Add a password to encrypt every connection name and secret; plaintext exports contain
              readable credentials.
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
                  ? 'MCP server is enabled and will start when Wormhole is ready.'
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
              Save all connection metadata and locally stored secrets in the Wormhole backup format.
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
                    password
                    {backupExportResult.passwordCount === 1 ? '' : 's'},{' '}
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
              {backupExportBusy ? (
                <div aria-live="polite" className="grid gap-1.5">
                  <div className="flex justify-between text-[11px] text-muted-foreground">
                    <span>
                      {backupExportCancelling
                        ? 'Cancelling backup export…'
                        : (backupExportProgress?.detail ?? 'Preparing backup export…')}
                    </span>
                    <span>{backupExportProgress?.percent ?? 0}%</span>
                  </div>
                  <progress
                    aria-label="Backup export progress"
                    className="h-2 w-full"
                    max={100}
                    value={backupExportProgress?.percent ?? 0}
                  />
                </div>
              ) : null}
              {backupExportError ? (
                <p className="text-[11px] text-destructive">{backupExportError}</p>
              ) : null}
              <DialogFooter>
                <Button
                  disabled={backupExportCancelling}
                  onClick={() => closeBackupExport(false)}
                  size="sm"
                  type="button"
                  variant="ghost"
                >
                  {backupExportBusy
                    ? backupExportCancelling
                      ? 'Cancelling…'
                      : 'Cancel export'
                    : 'Cancel'}
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
                  {backupImportBusy ? (
                    <div aria-live="polite" className="grid gap-1.5">
                      <div className="flex justify-between text-[11px] text-muted-foreground">
                        <span>
                          {backupImportCancelling
                            ? 'Cancelling backup import…'
                            : (backupImportProgress?.detail ?? 'Preparing backup import…')}
                        </span>
                        <span>{backupImportProgress?.percent ?? 0}%</span>
                      </div>
                      <progress
                        aria-label="Backup import progress"
                        className="h-2 w-full"
                        max={100}
                        value={backupImportProgress?.percent ?? 0}
                      />
                    </div>
                  ) : null}
                  <DialogFooter>
                    <Button
                      disabled={backupImportCancelling}
                      onClick={() => closeBackupImport(false)}
                      size="sm"
                      type="button"
                      variant="ghost"
                    >
                      {backupImportBusy
                        ? backupImportCancelling
                          ? 'Cancelling…'
                          : 'Cancel import'
                        : 'Cancel'}
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
      {secretDialog ? (
        <AuthSecretDialog
          busy={securityBusy}
          error={securityError}
          key={secretDialog}
          method={secretDialog}
          onOpenChange={closeSecretDialog}
          onSubmit={saveAuthSecret}
          open
        />
      ) : null}
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
            <span className="text-[10px] text-muted-foreground">Available in Wormhole</span>
            <MoreHorizontal className="absolute bottom-4 right-4 size-4 text-muted-foreground" />
          </Card>
        ))}
      </div>
    </section>
  );
}

export default App;
