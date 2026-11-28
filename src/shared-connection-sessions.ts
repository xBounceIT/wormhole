import { applyRdpBackendEvent, type RdpBackendKind, type RdpUiStatus } from './rdp-state.ts';
import { isRdpSurfaceRectWithinNativeBounds } from '../electron/rdp-contract.ts';
import type { SharedCatalogNode } from '../electron/vault-shared-catalog.ts';
import type { TerminalActions, XtermSession } from './xterm-terminal.ts';
import { SharedSftpSession, type SharedFileAPI } from './shared-sftp-session.ts';
import {
  applySshTerminalFrame,
  encodeTerminalData,
  type RenderedTerminalFrame,
} from './native-terminal-frame.ts';
import {
  modeForProtocol,
  sharedConnectionMode,
  type SharedConnectionMode,
} from './shared-connection-mode.ts';

// Reconnects allocate a fresh session ID instead of reusing a browser attempt.
const webSessionAttempt = 1;

export type SharedSessionAPI = SharedFileAPI &
  Pick<
    NonNullable<Window['wormhole']>,
    | 'readSharedConnectionContext'
    | 'openSshSession'
    | 'closeSshSession'
    | 'sendSshInput'
    | 'resizeSshSession'
    | 'pasteClipboardToSsh'
    | 'prepareSftpEditClose'
    | 'onSshEvent'
    | 'onBackendEvent'
    | 'sendVncCommand'
    | 'openVaultRdpSession'
    | 'commandRdpSession'
    | 'onRdpEvent'
    | 'openWebSession'
    | 'closeWebSession'
    | 'onWebEvent'
    | 'openSerialSession'
    | 'sendSerialInput'
    | 'resizeSerialSession'
    | 'closeSerialSession'
    | 'onSerialEvent'
  >;
export type SharedTerminal = Pick<
  XtermSession,
  'attach' | 'detach' | 'configure' | 'receive' | 'fit' | 'focus' | 'dispose'
>;
export type SharedSessionView = {
  id: string;
  node: SharedCatalogNode;
  mode: SharedConnectionMode;
  status: 'opening' | 'connected' | 'failed' | 'closing';
  connection?: WormholeSshConnected;
  error?: string;
  closeBusy: boolean;
  closeConfirmed: boolean;
  sftp?: SharedSftpSession['state'];
  vncMount?: boolean;
  rdpMount?: boolean;
  rdpStatus?: RdpUiStatus;
  rdpBackend?: RdpBackendKind;
  rdpExternal?: boolean;
  webTarget?: WormholeWebTarget;
  webEvent?: Pick<WormholeWebEvent, 'url' | 'browser' | 'canGoBack' | 'canGoForward' | 'isLoading'>;
  serialPort?: string;
  serialFrame?: RenderedTerminalFrame;
  passwordRequired?: boolean;
};
type Member = SharedSessionView & {
  started: boolean;
  rdpBounds?: WormholeRdpSurfaceRect;
  requestedMode?: SharedConnectionMode;
  manualCredentials: boolean;
  surfaceReady?: () => void;
  surfaceGate?: Promise<void>;
  terminal?: SharedTerminal;
  files?: SharedSftpSession;
  opening?: Promise<void>;
  closing?: Promise<boolean>;
  forceClose?: () => void;
  forceRequested?: boolean;
  cleanupFailed?: boolean;
  failureCleanup?: Promise<void>;
};
export type SharedSessionsSnapshot = {
  sessions: SharedSessionView[];
  activeId?: string;
  error?: string;
  link?: string;
};

// Presentation/request lifetimes only. Go authorizes every open. Reconnects use
// new IDs and never use cached endpoints/credentials as connection authority.
export class SharedConnectionSessions {
  private members = new Map<string, Member>();
  private listeners = new Set<() => void>();
  private disposed = false;
  private activeId?: string;
  private error?: string;
  private link?: string;
  private snapshot: SharedSessionsSnapshot = { sessions: [] };
  private readonly subscriptions: (() => void)[] = [];
  private api: SharedSessionAPI;
  private terminal: (id: string) => SharedTerminal;
  private copy: (text: string) => Promise<void>;
  constructor(
    api: SharedSessionAPI,
    terminal: (id: string) => SharedTerminal,
    copy: (text: string) => Promise<void>,
  ) {
    this.api = api;
    this.terminal = terminal;
    this.copy = copy;
    try {
      this.subscriptions.push(api.onSshEvent((event) => this.receive(event)));
      this.subscriptions.push(api.onBackendEvent((event) => this.receiveVnc(event)));
      this.subscriptions.push(api.onRdpEvent((event) => this.receiveRdp(event)));
      this.subscriptions.push(api.onWebEvent((event) => this.receiveWeb(event)));
      this.subscriptions.push(api.onSerialEvent((event) => this.receiveSerial(event)));
    } catch (error) {
      this.removeSubscriptions();
      throw error;
    }
  }
  private removeSubscriptions(): void {
    for (const unsubscribe of this.subscriptions.splice(0).reverse()) {
      try {
        unsubscribe();
      } catch {
        /* The owning document is already gone. */
      }
    }
  }
  getSnapshot = (): SharedSessionsSnapshot => this.snapshot;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  private current(member: Member): boolean {
    return !this.disposed && this.members.get(member.id) === member;
  }
  private publish(): void {
    if (this.disposed) return;
    for (const member of this.members.values()) this.configure(member);
    this.snapshot = {
      sessions: [...this.members.values()].map(
        ({
          id,
          node,
          mode,
          status,
          connection,
          error,
          closeBusy,
          closeConfirmed,
          files,
          opening,
          vncMount,
          rdpMount,
          rdpStatus,
          rdpBackend,
          rdpExternal,
          webTarget,
          webEvent,
          serialPort,
          serialFrame,
          passwordRequired,
        }) => ({
          id,
          node,
          mode,
          status,
          connection,
          error,
          closeBusy,
          vncMount,
          rdpMount,
          rdpStatus,
          rdpBackend,
          rdpExternal,
          webTarget,
          webEvent,
          serialPort,
          serialFrame,
          passwordRequired,
          closeConfirmed: closeConfirmed && !opening,
          ...(files ? { sftp: files.state } : {}),
        }),
      ),
      activeId: this.activeId,
      error: this.error,
      link: this.link,
    };
    for (const listener of this.listeners) listener();
  }
  select(id: string): void {
    if (this.disposed || !this.members.has(id)) return;
    this.activeId = id;
    this.link = undefined;
    this.publish();
  }
  observeNodes(nodes: readonly SharedCatalogNode[]): void {
    if (this.disposed) return;
    for (const member of this.members.values()) {
      const node = nodes.find((node) => node.id === member.node.id);
      if (node && (!node.canUse || node.kind !== 1 || node.protocol !== member.node.protocol)) {
        member.node = { ...node };
        this.error = 'Access to a connection has changed.';
        void this.close(member.id, true);
      }
    }
  }
  open(
    node: SharedCatalogNode,
    mode = sharedConnectionMode(node),
    manualPassword = false,
  ): Promise<void> {
    if (this.disposed) return Promise.resolve();
    if (
      node.kind !== 1 ||
      !node.canUse ||
      (node.protocol !== null && !sharedConnectionMode(node)) ||
      (mode === 'terminal' && node.protocol !== null && node.protocol !== 0) ||
      (mode === 'serial' && node.protocol !== null && node.protocol !== 5) ||
      (mode === 'sftp' && node.protocol !== null && node.protocol !== 0 && node.protocol !== 7) ||
      (mode === 'vnc' && node.protocol !== null && node.protocol !== 6) ||
      (mode === 'rdp' && node.protocol !== null && node.protocol !== 1) ||
      (mode === 'web' && node.protocol !== null && modeForProtocol(node.protocol) !== 'web')
    ) {
      this.error = node.canUse
        ? 'This connection is not available yet.'
        : 'You can view this connection. Ask an administrator for access.';
      this.publish();
      return Promise.resolve();
    }
    const pending = [...this.members.values()].find(
      (member) =>
        member.node.id === node.id &&
        (member.requestedMode ?? 'auto') === (mode ?? 'auto') &&
        member.status === 'opening' &&
        member.manualCredentials === manualPassword &&
        !member.closeBusy,
    );
    if (pending) {
      this.select(pending.id);
      return pending.opening ?? Promise.resolve();
    }
    if (this.members.size >= 32) {
      this.error = 'Close a session before opening another.';
      this.publish();
      return Promise.resolve();
    }
    const member: Member = {
      id: crypto.randomUUID(),
      node: { ...node },
      mode: mode ?? 'terminal',
      requestedMode: mode,
      manualCredentials: manualPassword,
      status: 'opening',
      started: false,
      closeBusy: false,
      closeConfirmed: false,
    };
    this.members.set(member.id, member);
    this.activeId = member.id;
    this.error = this.link = undefined;
    const opening = Promise.resolve()
      .then(async () => {
        if (!this.current(member) || member.status !== 'opening' || member.closeBusy)
          return undefined;
        if (member.node.protocol === null) {
          const context = await this.api.readSharedConnectionContext(member.node.id);
          if (!this.current(member) || member.status !== 'opening' || member.closeBusy)
            return undefined;
          const resolvedMode = modeForProtocol(context.protocol);
          if (
            context.nodeId !== member.node.id ||
            !resolvedMode ||
            (mode && mode !== resolvedMode && (mode !== 'sftp' || resolvedMode !== 'terminal'))
          )
            throw Error('Unsupported inherited protocol.');
          member.mode = mode ?? resolvedMode;
        }
        if (!this.current(member) || member.status !== 'opening' || member.closeBusy)
          return undefined;
        if (manualPassword && member.mode !== 'vnc' && member.mode !== 'rdp')
          throw Error('Unsupported manual password.');
        if (member.mode === 'serial') {
          member.started = true;
          const response = await this.api
            .openSerialSession({
              sessionId: member.id,
              nodeId: member.node.id,
              columns: 80,
              rows: 24,
            })
            .catch((error: unknown) => {
              if (!this.current(member) || member.closeBusy) return undefined;
              throw error;
            });
          if (!response) return undefined;
          if (response.sessionId !== member.id) throw Error('Serial owner changed.');
          if (member.failureCleanup) {
            await member.failureCleanup;
            return undefined;
          }
          if (!this.current(member) || member.closeBusy) {
            await this.closeNative(member);
            return undefined;
          }
          member.serialPort = response.portName;
          member.status = 'connected';
          this.publish();
          return undefined;
        }
        if (member.mode === 'web') {
          member.started = true;
          const target = await this.api.openWebSession({
            sessionId: member.id,
            nodeId: member.node.id,
            attempt: webSessionAttempt,
          });
          if (member.failureCleanup) {
            await member.failureCleanup;
            return undefined;
          }
          if (!this.current(member) || member.status !== 'opening' || member.closeBusy) {
            await this.closeNative(member);
            return undefined;
          }
          member.webTarget = target;
          member.status = 'connected';
          this.publish();
          return undefined;
        }
        if (member.mode === 'rdp') {
          member.surfaceGate = new Promise<void>((resolve) => {
            member.surfaceReady = resolve;
          });
          member.rdpMount = true;
          member.rdpStatus = 'starting';
          this.publish();
          await member.surfaceGate;
          if (!this.current(member) || member.status !== 'opening' || member.closeBusy)
            return undefined;
          if (!member.rdpBounds) throw Error('RDP surface is unavailable.');
          member.started = true;
          const response = await this.api.openVaultRdpSession({
            sessionId: member.id,
            nodeId: member.node.id,
            bounds: { ...member.rdpBounds },
            ...(manualPassword ? { manualCredentials: true } : {}),
          });
          if (response.sessionId !== member.id) throw Error('RDP owner changed.');
          if (member.failureCleanup) {
            await member.failureCleanup;
            return undefined;
          }
          if (
            !this.current(member) ||
            member.closeBusy ||
            (member.status !== 'opening' && member.status !== 'connected')
          )
            await this.closeNative(member);
          return undefined;
        }
        if (member.mode === 'vnc') {
          member.surfaceGate = new Promise<void>((resolve) => {
            member.surfaceReady = resolve;
          });
          member.vncMount = true;
          this.publish();
          await member.surfaceGate;
          if (!this.current(member) || member.status !== 'opening' || member.closeBusy)
            return undefined;
          member.started = true;
          const response = await this.api.sendVncCommand({
            action: 'vnc.connect',
            sessionId: member.id,
            nodeId: member.node.id,
            ...(manualPassword ? { manualPassword: true } : {}),
          });
          if (!response.ok) {
            this.failSession(member, 'Could not connect. Check access and reconnect.');
            return undefined;
          }
          if (!this.current(member) || member.status !== 'opening' || member.closeBusy) {
            await this.closeNative(member);
            return undefined;
          }
          member.status = 'connected';
          this.publish();
          return undefined;
        }
        if (member.mode === 'terminal') member.terminal = this.terminal(member.id);
        this.publish();
        if (!this.current(member) || member.status !== 'opening' || member.closeBusy)
          return undefined;
        member.started = true;
        return this.api.openSshSession({
          sessionId: member.id,
          nodeId: member.node.id,
          mode: member.mode,
          columns: 80,
          rows: 24,
        });
      })
      .then(async (connection) => {
        if (!connection) return;
        if (!this.current(member) || member.status !== 'opening' || member.closeBusy) {
          await this.closeNative(member);
          return;
        }
        if (connection.sessionId !== member.id) throw Error('Connection owner changed.');
        member.connection = { ...connection };
        member.status = 'connected';
        if (member.mode === 'sftp') {
          member.files = new SharedSftpSession(member.id, this.api, () => this.publish());
          member.files.start();
        }
        this.publish();
      })
      .catch(async () => {
        if (
          this.current(member) &&
          (member.mode === 'rdp' || member.mode === 'web' || member.mode === 'serial') &&
          member.status === 'failed' &&
          member.failureCleanup
        ) {
          await member.failureCleanup;
          return;
        }
        if (this.current(member) && member.status === 'opening') {
          member.status = 'failed';
          if (member.mode === 'rdp') member.rdpStatus = 'failed';
          member.error = 'Could not connect. Check the connection or ask an administrator.';
          this.publish();
          if (!member.started) {
            member.closeConfirmed = true;
            this.publish();
            return;
          }
          try {
            await this.closeNative(member);
            if (this.current(member)) member.closeConfirmed = true;
          } catch {
            if (this.current(member))
              member.error = 'Could not confirm session closure. Retry closing this tab.';
          }
          this.publish();
        } else if (this.current(member)) {
          member.cleanupFailed = true;
          member.closeConfirmed = false;
          member.error = 'Could not confirm session closure. Retry closing this tab.';
          this.publish();
        }
      });
    const tracked = opening.finally(() => {
      if (this.current(member)) {
        member.opening = undefined;
        this.publish();
      }
    });
    member.opening = tracked;
    this.publish();
    return tracked;
  }
  reconnect(id: string, manualPassword?: boolean): Promise<void> {
    const member = this.members.get(id);
    manualPassword ??= member?.mode === 'rdp' && member.manualCredentials;
    if (
      !member ||
      !this.current(member) ||
      member.status !== 'failed' ||
      !member.closeConfirmed ||
      member.opening ||
      (manualPassword &&
        member.mode !== 'rdp' &&
        (member.mode !== 'vnc' || !member.passwordRequired))
    )
      return Promise.resolve();
    const { node, requestedMode } = member;
    this.remove(member);
    return this.open(node, requestedMode, manualPassword);
  }
  close(id: string, force = false): Promise<boolean> {
    const member = this.members.get(id);
    if (!member || !this.current(member)) return Promise.resolve(true);
    if (member.closing) {
      if (force) member.forceClose?.();
      return member.closing;
    }
    const forced = new Promise<boolean>((resolve) => {
      member.forceClose = () => {
        member.forceRequested = true;
        resolve(true);
      };
    });
    if (force) member.forceClose?.();
    member.cleanupFailed = false;
    member.closeBusy = true;
    member.surfaceReady?.();
    const closing = Promise.resolve()
      .then(async () => {
        if (!this.current(member)) return true;
        if (
          !member.forceRequested &&
          member.mode === 'sftp' &&
          member.status === 'connected' &&
          !(await Promise.race([
            Promise.resolve().then(() => this.api.prepareSftpEditClose(id)),
            forced,
          ])) &&
          !member.forceRequested
        )
          return false;
        if (!this.current(member)) return true;
        member.status = 'closing';
        this.publish();
        if (member.started) await this.closeNative(member);
        // Late admission replies perform their own cleanup. Reserve the tab until
        // that original operation settles as well as the native close receipt.
        await member.opening;
        if (member.cleanupFailed) throw Error('Session closure was not confirmed.');
        if (this.current(member)) this.remove(member);
        return true;
      })
      .catch(() => {
        if (this.current(member)) {
          member.status = 'failed';
          if (member.mode === 'rdp') member.rdpStatus = 'failed';
          member.cleanupFailed = true;
          member.closeConfirmed = false;
          member.error = 'Could not confirm session closure. Retry closing this tab.';
          this.publish();
        }
        return false;
      })
      .finally(() => {
        if (this.current(member)) {
          member.closeBusy = false;
          member.closing = undefined;
          member.forceClose = undefined;
          member.forceRequested = false;
          this.publish();
        }
      });
    member.closing = closing;
    this.publish();
    return closing;
  }
  readyVnc(id: string): void {
    const member = this.members.get(id);
    if (
      member &&
      this.current(member) &&
      member.mode === 'vnc' &&
      member.status === 'opening' &&
      !member.closeBusy
    )
      member.surfaceReady?.();
  }
  readyRdp(id: string, bounds: WormholeRdpSurfaceRect): void {
    const member = this.members.get(id);
    if (
      member &&
      this.current(member) &&
      member.mode === 'rdp' &&
      member.status === 'opening' &&
      !member.closeBusy &&
      isRdpSurfaceRectWithinNativeBounds(bounds)
    ) {
      member.rdpBounds = { ...bounds };
      member.surfaceReady?.();
    }
  }
  private async closeNative(member: Member): Promise<void> {
    if (member.mode === 'web') {
      await this.api.closeWebSession(member.id);
      return;
    }
    if (member.mode === 'serial') {
      await this.api.closeSerialSession(member.id);
      return;
    }
    if (member.mode === 'rdp') {
      const result = await this.api.commandRdpSession({
        sessionId: member.id,
        operation: 'disconnect',
      });
      if (result.sessionId !== member.id || result.type !== 'ack')
        throw Error('RDP closure was not confirmed.');
      return;
    }

    if (member.mode !== 'vnc') {
      await this.api.closeSshSession(member.id);
      return;
    }
    const result = await this.api.sendVncCommand({
      action: 'vnc.disconnect',
      sessionId: member.id,
    });
    if (!result.ok) throw Error('VNC closure was not confirmed.');
  }
  private remove(member: Member): void {
    member.files?.dispose();
    member.terminal?.dispose();
    this.members.delete(member.id);
    if (this.activeId === member.id) this.activeId = [...this.members.keys()].at(-1);
    this.link = undefined;
    this.publish();
  }
  attach(id: string, surface: HTMLElement): () => void {
    const member = this.members.get(id);
    if (!member || !this.current(member) || !member.terminal) return () => {};
    const terminal = member.terminal;
    terminal.attach(surface);
    terminal.fit();
    terminal.focus();
    return () => terminal.detach();
  }
  fit(id: string): void {
    const member = this.members.get(id);
    if (member && this.current(member)) member.terminal?.fit();
  }
  focus(id: string): void {
    const member = this.members.get(id);
    if (member && this.active(member)) member.terminal?.focus();
  }
  sendSerialInput = (id: string, data: string): void => {
    const member = this.members.get(id);
    if (member?.mode === 'serial' && this.active(member))
      void this.api.sendSerialInput(id, encodeTerminalData(data)).catch(() => {});
  };
  resizeSerial = async (id: string, columns: number, rows: number): Promise<void> => {
    const member = this.members.get(id);
    if (member?.mode === 'serial' && this.active(member))
      await this.api.resizeSerialSession(id, columns, rows);
  };
  private active(member: Member): boolean {
    return (
      this.current(member) &&
      this.activeId === member.id &&
      member.status === 'connected' &&
      !member.closeBusy
    );
  }
  private configure(member: Member): void {
    if (!member.terminal) return;
    const active =
      this.activeId === member.id && member.status === 'connected' && !member.closeBusy;
    const actions: TerminalActions = {
      active,
      autoCopy: false,
      input: (data, paste) => {
        if (
          !this.current(member) ||
          member.status === 'closing' ||
          member.status === 'failed' ||
          member.closeBusy
        )
          return;
        const bytes = new TextEncoder().encode(data);
        let binary = '';
        for (const byte of bytes) binary += String.fromCharCode(byte);
        void this.api.sendSshInput(member.id, btoa(binary), paste).catch(() => {});
      },
      resize: (columns, rows) => {
        if (this.active(member))
          void this.api.resizeSshSession(member.id, columns, rows).catch(() => {});
      },
      copy: (text) => {
        if (this.active(member)) void this.copy(text).catch(() => {});
      },
      paste: async () =>
        this.active(member) ? (await this.api.pasteClipboardToSsh(member.id)).pasted : false,
      openLink: (url) => {
        if (this.active(member) && !this.link) {
          this.link = url;
          this.publish();
        }
      },
    };
    member.terminal.configure(actions);
  }
  closeLink(): void {
    this.link = undefined;
    this.publish();
  }
  fileSession(id: string): SharedSftpSession | undefined {
    const member = this.members.get(id);
    return member && this.current(member) && member.status === 'connected'
      ? member.files
      : undefined;
  }
  private receive(event: WormholeSshEvent): void {
    const member = this.members.get(event.sessionId);
    if (!member || !this.current(member) || (member.mode !== 'terminal' && member.mode !== 'sftp'))
      return;
    if (event.type === 'terminal-output') {
      if (member.status !== 'failed' && member.status !== 'closing')
        member.terminal?.receive(event);
      return;
    }
    if (event.type === 'closed' || event.type === 'error' || event.type === 'reconnect-failed') {
      this.failSession(
        member,
        event.type === 'closed'
          ? 'Connection closed.'
          : 'Connection failed. Check access and reconnect.',
      );
      return;
    }
    member.files?.receive(event);
  }
  private receiveSerial(event: WormholeSerialEvent): void {
    const member = this.members.get(event.sessionId);
    if (
      !member ||
      !this.current(member) ||
      member.mode !== 'serial' ||
      !member.started ||
      member.closeBusy ||
      (member.status !== 'opening' && member.status !== 'connected')
    )
      return;
    if (event.type === 'closed' || event.type === 'error') {
      this.failSession(member, 'Serial connection closed. Check access and reconnect.');
      return;
    }
    if (event.type === 'connected') {
      member.serialPort = event.portName;
      member.status = 'connected';
    } else if (member.status === 'connected') {
      member.serialFrame = applySshTerminalFrame(member.serialFrame, event.frame);
    }
    this.publish();
  }
  private receiveRdp(event: WormholeRdpBackendEvent): void {
    const member = this.members.get(event.sessionId ?? '');
    if (
      !member ||
      !this.current(member) ||
      member.mode !== 'rdp' ||
      !member.started ||
      member.closeBusy ||
      member.status === 'failed' ||
      member.status === 'closing' ||
      ['frame', 'frameEnd', 'certificate', 'ack'].includes(event.type)
    )
      return;
    const next = applyRdpBackendEvent(
      {
        rdpStatus: member.rdpStatus,
        rdpError: member.error,
        rdpBackend: member.rdpBackend,
        rdpExternal: member.rdpExternal,
      },
      event,
    );
    member.rdpStatus = next.rdpStatus;
    member.rdpBackend = next.rdpBackend;
    member.rdpExternal = next.rdpExternal;
    member.error = next.rdpError;
    if (next.rdpStatus === 'failed' || next.rdpStatus === 'disconnected') {
      this.failSession(member, 'RDP connection closed. Check access and reconnect.');
      return;
    }
    if (next.rdpStatus === 'connected') member.status = 'connected';
    this.publish();
  }
  private receiveVnc(event: WormholeBackendEvent): void {
    if (
      event.type !== 'vnc.status' ||
      (event.status !== 'failed' && event.status !== 'disconnected')
    )
      return;
    const member = this.members.get(event.sessionId ?? '');
    if (member && this.current(member) && member.mode === 'vnc')
      this.failSession(
        member,
        'Connection closed. Check access and reconnect.',
        Boolean(event.passwordRequired),
      );
  }
  private receiveWeb(event: WormholeWebEvent): void {
    const member = this.members.get(event.sessionId);
    if (
      !member ||
      !this.current(member) ||
      member.mode !== 'web' ||
      !member.started ||
      member.closeBusy ||
      (member.status !== 'opening' && member.status !== 'connected') ||
      event.attempt !== webSessionAttempt ||
      event.type === 'focus-address'
    )
      return;
    if (event.type === 'failed') {
      this.failSession(member, 'Browser connection closed. Check access and reconnect.');
      return;
    }
    const { url, browser, canGoBack, canGoForward, isLoading } = event;
    member.webEvent = { url, browser, canGoBack, canGoForward, isLoading };
    this.publish();
  }
  private failSession(member: Member, message: string, passwordRequired = false): void {
    if (member.status === 'closing' || member.status === 'failed') return;
    member.status = 'failed';
    member.serialFrame = undefined;
    member.passwordRequired = passwordRequired;
    member.surfaceReady?.();
    member.files?.dispose();
    member.error = message;
    this.publish();
    member.failureCleanup = Promise.resolve()
      .then(() => this.closeNative(member))
      .then(() => {
        if (this.current(member) && !member.cleanupFailed) {
          member.closeConfirmed = true;
          this.publish();
        }
      })
      .catch(() => {});
  }
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.removeSubscriptions();
    for (const member of this.members.values()) {
      member.surfaceReady?.();
      member.files?.dispose();
      member.terminal?.dispose();
      if (member.started)
        void Promise.resolve()
          .then(() => this.closeNative(member))
          .catch(() => {});
    }
    this.members.clear();
    this.listeners.clear();
    this.activeId = this.link = this.error = undefined;
    this.snapshot = { sessions: [] };
  }
}
