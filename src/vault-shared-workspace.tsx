import { RdpSurface } from './components/RdpSurface';
import {
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  useId,
  useCallback,
  type ReactNode,
} from 'react';
import { createRoot } from 'react-dom/client';
import {
  SharedConnectionSessions,
  type SharedSessionAPI,
  type SharedSessionView,
} from './shared-connection-sessions';
import type { SharedConnectionMode } from './shared-connection-mode';
import { XtermSession } from './xterm-terminal';
import { copyTextToClipboard } from './clipboard';
import { VncSurface } from './components/VncSurface';
import { WebSurface } from './components/WebSurface';
import { SftpBrowserSurface } from './components/SftpBrowser';
import { TerminalLinkDialog } from './components/TerminalLinkDialog';
import { ContextMenuOverlayProvider } from './components/ui/context-menu';
import { TooltipProvider } from './components/ui/tooltip';
import type { SharedCatalogNode } from '../electron/vault-shared-catalog';
import { WorkspaceErrorBoundary } from './WorkspaceErrorBoundary';
import { NativeTerminalSurface } from './components/NativeTerminalSurface';
import { UpdateNotification } from './components/UpdateNotification';
import { VaultSecurityProfile, type VaultProfileAPI } from './VaultSecurityProfile';
import { installCheckedUpdate, shouldOfferUpdate, updateStatusMessage } from './update-state';
import './index.css';
import './vault-shared-workspace.css';

function TerminalSurface({ sessions, id }: { sessions: SharedConnectionSessions; id: string }) {
  const surface = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!surface.current) return;
    const detach = sessions.attach(id, surface.current);
    const observer = new ResizeObserver(() => sessions.fit(id));
    observer.observe(surface.current);
    return () => {
      observer.disconnect();
      detach();
    };
  }, [sessions, id]);
  return <div className="shared-terminal-surface" aria-label="Live SSH terminal" ref={surface} />;
}

function SharedVncSurface({
  sessions,
  session,
  active,
}: {
  sessions: SharedConnectionSessions;
  session: SharedSessionView;
  active: boolean;
}) {
  return (
    <div className="shared-vnc-surface" hidden={!active} inert={!active || session.closeBusy}>
      <VncSurface
        vault
        isAuthorized={active && session.status === 'connected' && !session.closeBusy}
        session={{
          id: session.id,
          nodeId: session.node.id,
          host: session.node.host ?? session.node.name,
          port: session.node.port ?? undefined,
        }}
        connectionGeneration={0}
        disconnected={false}
        bitwardenUnlockPending={false}
        onReconnect={() => void sessions.reconnect(session.id)}
        managed={{
          status: session.status,
          label: session.node.name,
          error: session.error,
          canReconnect: session.closeConfirmed && !session.closeBusy,
          active: active && session.status === 'connected' && !session.closeBusy,
          ready: () => sessions.readyVnc(session.id),
          passwordRequired: session.passwordRequired,
          manualReconnect: () => void sessions.reconnect(session.id, true),
        }}
      />
    </div>
  );
}

function SharedRdpSurface({
  sessions,
  session,
  active,
}: {
  sessions: SharedConnectionSessions;
  session: SharedSessionView;
  active: boolean;
}) {
  const ready = useCallback(
    (bounds: WormholeRdpSurfaceRect) => sessions.readyRdp(session.id, bounds),
    [sessions, session.id],
  );
  const reconnect = () => {
    if (session.closeConfirmed && !session.closeBusy) void sessions.reconnect(session.id);
  };
  return (
    <div
      className="shared-vnc-surface shared-rdp-surface"
      hidden={!active}
      inert={!active || session.closeBusy}
    >
      <RdpSurface
        sessionId={session.id}
        isActive={active}
        isAuthorized={!session.closeBusy}
        status={session.rdpStatus ?? 'starting'}
        backend={session.rdpBackend}
        external={session.rdpExternal}
        error={session.error}
        onReady={ready}
        onConnect={reconnect}
        onRetry={reconnect}
        onEnterCredentials={() => {
          if (session.closeConfirmed && !session.closeBusy)
            void sessions.reconnect(session.id, true);
        }}
        canOpenSystemClient={false}
      />
    </div>
  );
}

type SharedUpdateAPI = Pick<
  NonNullable<Window['wormhole']>,
  | 'updateStatus'
  | 'checkForUpdates'
  | 'downloadUpdate'
  | 'installUpdate'
  | 'onUpdateResult'
  | 'onUpdateProgress'
  | 'openExternal'
>;

type SharedProfileAPI = VaultProfileAPI &
  Pick<NonNullable<Window['wormhole']>, 'tightenSharedVaultProfile'>;

function SharedSecuritySettings({ api }: { api: SharedProfileAPI }) {
  const [open, setOpen] = useState(false);
  return (
    <details className="px-2 py-1 text-xs" onToggle={(event) => setOpen(event.currentTarget.open)}>
      <summary className="cursor-pointer">Security settings</summary>
      {open && (
        <div className="pt-2">
          <VaultSecurityProfile api={api} shared tighten={api.tightenSharedVaultProfile} />
        </div>
      )}
    </details>
  );
}

function SharedUpdateControls({ api }: { api: SharedUpdateAPI }) {
  const [result, setResult] = useState<WormholeUpdateCheckResult | null>(null);
  const [dismissed, setDismissed] = useState<string | null>(null);
  const [status, setStatus] = useState('');
  const [progress, setProgress] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  useEffect(() => {
    let active = true;
    let received = false;
    const release = api.onUpdateResult((value) => {
      received = true;
      setStatus('');
      setResult(value);
    });
    const unsubscribeProgress = api.onUpdateProgress(({ downloaded, total }) => {
      setProgress(total > 0 ? Math.min(1, downloaded / total) : null);
    });
    void api
      .updateStatus()
      .then(({ result }) => {
        if (active && !received) setResult(result);
      })
      .catch(() => undefined);
    return () => {
      active = false;
      release();
      unsubscribeProgress();
    };
  }, [api]);
  async function run(action: () => Promise<void>) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    try {
      await action();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Update failed.');
    } finally {
      running.current = false;
      setBusy(false);
      setProgress(null);
    }
  }
  const showNotice = result && shouldOfferUpdate(result, dismissed);
  const message = updateStatusMessage(status, result);
  return (
    <div className="flex flex-wrap items-center gap-2 px-2 py-1 text-xs">
      <button
        className="startup-button startup-button-secondary"
        type="button"
        disabled={busy}
        onClick={() =>
          void run(async () => {
            setStatus('Checking for updates…');
            setResult(await api.checkForUpdates());
            setStatus('');
          })
        }
      >
        {result?.updatePolicy === 'managed' ? 'Check managed updates' : 'Check for updates'}
      </button>
      {!showNotice && message ? <span role="status">{message}</span> : null}
      {showNotice ? (
        <UpdateNotification
          version={result.latestVersion}
          busy={busy}
          status={status}
          downloadProgress={progress}
          onDismiss={() => setDismissed(result.latestVersion)}
          onViewChanges={
            result.releaseUrl
              ? () => void api.openExternal(result.releaseUrl!).catch(() => undefined)
              : undefined
          }
          onUpdate={
            result.isUpdateAvailable
              ? () =>
                  void run(async () => {
                    setStatus('Downloading…');
                    const installation = await installCheckedUpdate(api, result, () =>
                      setStatus('Opening verified update…'),
                    );
                    if (!installation.appWillQuit) setStatus(installation.status);
                  })
              : undefined
          }
        />
      ) : null}
    </div>
  );
}

export function SharedSessionsView({
  sessions,
  controls,
}: {
  sessions: SharedConnectionSessions;
  controls?: ReactNode;
}) {
  const panelId = useId();
  const snapshot = useSyncExternalStore(sessions.subscribe, sessions.getSnapshot);
  const active = snapshot.sessions.find((session) => session.id === snapshot.activeId);
  const files = active ? sessions.fileSession(active.id) : undefined;
  return (
    <section className="shared-sessions" aria-label="Connection sessions">
      <div className="shared-session-tabs" role="tablist" aria-label="Open sessions">
        {snapshot.sessions.map((session) => (
          <div
            className="shared-session-tab"
            key={session.id}
            data-active={session.id === snapshot.activeId}
          >
            <button
              type="button"
              role="tab"
              id={`${panelId}-${session.id}`}
              tabIndex={session.id === snapshot.activeId ? 0 : -1}
              aria-selected={session.id === snapshot.activeId}
              aria-controls={panelId}
              onKeyDown={(event) => {
                const index = snapshot.sessions.findIndex((item) => item.id === session.id);
                const last = snapshot.sessions.length - 1;
                const next =
                  event.key === 'ArrowRight'
                    ? (index + 1) % (last + 1)
                    : event.key === 'ArrowLeft'
                      ? (index + last) % (last + 1)
                      : event.key === 'Home'
                        ? 0
                        : event.key === 'End'
                          ? last
                          : undefined;
                if (next === undefined) return;
                event.preventDefault();
                const id = snapshot.sessions[next].id;
                sessions.select(id);
                document.getElementById(`${panelId}-${id}`)?.focus();
              }}
              onClick={() => sessions.select(session.id)}
            >
              <span className="shared-session-indicator" data-status={session.status} />
              <span>{session.node.name}</span>
              <small>{sessionLabel[session.mode]}</small>
            </button>
            <button
              type="button"
              aria-label={`Close ${session.node.name}`}
              disabled={session.closeBusy}
              onClick={() => void sessions.close(session.id)}
            >
              ×
            </button>
          </div>
        ))}
      </div>
      {controls}
      {snapshot.error ? (
        <p className="shared-session-notice" role="status">
          {snapshot.error}
        </p>
      ) : null}
      <div
        className="shared-session-panel"
        id={panelId}
        role="tabpanel"
        aria-labelledby={active ? `${panelId}-${active.id}` : undefined}
        aria-label={active?.node.name ?? 'No active session'}
      >
        {!active ? (
          <div className="shared-session-empty">
            <strong>Your connections, in one workspace</strong>
            <p>Choose a connection from the catalog to open a terminal or transfer files.</p>
          </div>
        ) : (
          <>
            <div className="shared-session-route">
              <span>{active.mode === 'sftp' ? 'File transfer' : sessionLabel[active.mode]}</span>
              <code>
                {active.connection
                  ? `${active.connection.username}@${active.connection.host}:${active.connection.port}`
                  : (active.serialPort ?? active.node.name)}
              </code>
            </div>
            {active.mode === 'web' && active.status === 'connected' && active.webTarget ? (
              <WebSurface
                key={active.id}
                session={{
                  id: active.id,
                  status: 'connected',
                  protocol: active.webTarget.protocol,
                  host: active.webTarget.host,
                  port: active.webTarget.port,
                  webUrl: active.webEvent?.url ?? active.webTarget.url,
                  webBrowser: active.webEvent?.browser ?? active.webTarget.browser,
                  webCanGoBack: active.webEvent?.canGoBack,
                  webCanGoForward: active.webEvent?.canGoForward,
                  webIsLoading: active.webEvent?.isLoading,
                }}
                isActive
                isAuthorized={!active.closeBusy}
                bitwardenOpen={false}
                onReconnect={(id) => void sessions.reconnect(id)}
              />
            ) : active.mode === 'vnc' || active.mode === 'rdp' ? null : active.status ===
                'connected' && active.mode === 'terminal' ? (
              <TerminalSurface sessions={sessions} id={active.id} />
            ) : active.mode === 'serial' && active.status === 'connected' ? (
              <NativeTerminalSurface
                key={active.id}
                session={{
                  id: active.id,
                  backendSessionId: active.id,
                  status: active.status,
                  terminalFrame: active.serialFrame,
                }}
                isActive={!active.closeBusy}
                autoCopyOnSelect={false}
                onInput={sessions.sendSerialInput}
                onResize={sessions.resizeSerial}
                isSerial
              />
            ) : active.status === 'connected' && active.mode === 'sftp' && active.sftp && files ? (
              <div className="shared-file-surface">
                <SftpBrowserSurface
                  session={{
                    id: active.id,
                    title: active.node.name,
                    host: active.connection?.host ?? '',
                    protocol: 'sftp',
                    backendSessionId: active.id,
                    sftp: active.closeBusy ? { ...active.sftp, status: 'closing' } : active.sftp,
                  }}
                  onClose={() => void sessions.close(active.id)}
                  onNavigate={(path) => files.navigate('remote', path)}
                  onLocalNavigate={(path) => files.navigate('local', path)}
                  onRefresh={(pane) => files.navigate(pane, files.path(pane))}
                  onOperation={(pane, operation, path, destination) =>
                    files.operate(pane, operation, path, destination)
                  }
                  onTransfer={(direction, destination, items) =>
                    files.transfer(direction, destination, items)
                  }
                  onConflict={(transfer, item, decision, all) =>
                    files.decide(transfer, item, decision, all)
                  }
                  onTransferCancel={(transfer, item) => files.cancel(transfer, item)}
                  onTransferErrorClear={() => files.clearError()}
                  onTransferRemove={(transfer, item) => files.removeTransfer(transfer, item)}
                />
              </div>
            ) : (
              <div className="shared-session-empty" role="status">
                <strong>
                  {active.status === 'opening'
                    ? 'Connecting…'
                    : active.closeBusy || active.status === 'closing'
                      ? 'Closing…'
                      : 'Connection closed'}
                </strong>
                {active.error ? <p>{active.error}</p> : null}
                {active.status === 'failed' && active.closeConfirmed && !active.closeBusy ? (
                  <button
                    type="button"
                    className="startup-button"
                    onClick={() => void sessions.reconnect(active.id)}
                  >
                    Reconnect
                  </button>
                ) : null}
              </div>
            )}
          </>
        )}
        {snapshot.sessions
          .filter((session) => session.mode === 'rdp' && session.rdpMount)
          .map((session) => (
            <SharedRdpSurface
              key={session.id}
              sessions={sessions}
              session={session}
              active={session.id === snapshot.activeId}
            />
          ))}
        {snapshot.sessions
          .filter((session) => session.mode === 'vnc' && session.vncMount)
          .map((session) => (
            <SharedVncSurface
              key={session.id}
              sessions={sessions}
              session={session}
              active={session.id === snapshot.activeId}
            />
          ))}
      </div>
      {snapshot.link ? (
        <TerminalLinkDialog
          url={snapshot.link}
          onClose={() => sessions.closeLink()}
          onRestoreFocus={() => sessions.focus(snapshot.activeId ?? '')}
        />
      ) : null}
    </section>
  );
}

const sessionLabel: Record<SharedConnectionMode, string> = {
  terminal: 'SSH',
  serial: 'Serial',
  sftp: 'Files',
  rdp: 'RDP',
  vnc: 'VNC',
  web: 'Web',
};

export function mountSharedWorkspace(
  container: HTMLElement,
  api: SharedSessionAPI & SharedUpdateAPI & SharedProfileAPI,
  onFailure: () => void,
) {
  const sessions = new SharedConnectionSessions(
    api,
    (id) => new XtermSession(id),
    copyTextToClipboard,
  );
  const root = createRoot(container);
  root.render(
    <WorkspaceErrorBoundary
      onFailure={() => {
        sessions.dispose();
        // Error boundaries run during React's commit. Unmount after it completes.
        queueMicrotask(onFailure);
      }}
      onRetry={() => window.location.reload()}
    >
      <ContextMenuOverlayProvider>
        <TooltipProvider>
          <SharedSessionsView
            sessions={sessions}
            controls={
              <>
                <SharedSecuritySettings api={api} />
                <SharedUpdateControls api={api} />
              </>
            }
          />
        </TooltipProvider>
      </ContextMenuOverlayProvider>
    </WorkspaceErrorBoundary>,
  );
  return {
    connect: (node: SharedCatalogNode, mode?: SharedConnectionMode) => {
      void sessions.open(node, mode);
    },
    observeNodes: (nodes: readonly SharedCatalogNode[]) => sessions.observeNodes(nodes),
    dispose: () => {
      sessions.dispose();
      root.unmount();
    },
  };
}
