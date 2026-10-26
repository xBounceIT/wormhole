import { useEffect, useLayoutEffect, useRef, useState, type ReactNode, type Ref } from 'react';
import {
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  Globe,
  LoaderCircle,
  LockKeyhole,
  Plus,
  RefreshCcw,
  ShieldCheck,
  X,
} from 'lucide-react';
import bitwardenIcon from '../../Assets/Bitwarden/bitwarden-icon.png';
import { Button } from '@/components/ui/button';
import { ConnectionStepper, type TunnelProgress } from './ConnectionStepper';

type WebSessionSurface = {
  id: string;
  protocol: 'sftp' | 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
  host: string;
  port?: number;
  status: 'connecting' | 'connected' | 'failed' | 'closed' | 'placeholder';
  error?: string;
  tunnelProgress?: TunnelProgress | null;
  webUrl?: string;
  webCanGoBack?: boolean;
  webCanGoForward?: boolean;
  webIsLoading?: boolean;
  webBrowser?: WormholeWebBrowserState;
  bitwardenPopupUrl?: string;
};

type WebSurfaceProps = {
  session: WebSessionSurface;
  isActive: boolean;
  isAuthorized: boolean;
  isOccluded?: boolean;
  bitwardenOpen: boolean;
  onReconnect: (sessionId: string) => void;
};

export function WebSurface({
  session,
  isActive,
  isAuthorized,
  isOccluded = false,
  bitwardenOpen,
  onReconnect,
}: WebSurfaceProps) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const tabListRef = useRef<HTMLDivElement>(null);
  const bitwardenButtonRef = useRef<HTMLButtonElement>(null);
  const addressRef = useRef<HTMLInputElement>(null);
  const previewIdRef = useRef<string | undefined>(undefined);
  const browser = session.webBrowser;
  const vpnLabel = `${browser?.tunnel?.name ? `${browser.tunnel.name}'s ` : ''}${browser?.tunnel?.kind || 'VPN tunnel'}${session.status === 'connected' ? ' ACTIVE' : ''}`;
  const tab = browser?.tabs.find((candidate) => candidate.id === browser.activeTabId);
  const available = isActive && isAuthorized && session.status === 'connected';
  const ready = available && !isOccluded;
  const blank = tab?.url === 'about:blank';
  const visible = ready && !blank && !tab?.error;
  const showPreview = available && isOccluded && !blank && !tab?.error;
  const currentAddress =
    tab?.url ||
    session.webUrl ||
    `${session.protocol}://${session.host}${session.port ? `:${session.port}` : ''}`;
  const [address, setAddress] = useState(blank ? '' : currentAddress);
  const [commandError, setCommandError] = useState('');
  const pageKey = `${session.id}:${tab?.id ?? ''}`;
  const [preview, setPreview] = useState<{ id: string; image: string; pageKey: string }>();

  useLayoutEffect(() => {
    const list = tabListRef.current;
    const selected = list?.querySelector('[aria-selected="true"]')?.parentElement;
    if (!ready || !list || !selected) return;
    const viewport = list.getBoundingClientRect();
    const bounds = selected.getBoundingClientRect();
    if (bounds.left < viewport.left) list.scrollLeft += bounds.left - viewport.left;
    else if (bounds.right > viewport.right) list.scrollLeft += bounds.right - viewport.right;
  }, [ready, tab?.id, tab?.title]);

  useEffect(() => {
    setAddress(currentAddress === 'about:blank' ? '' : currentAddress);
    setCommandError('');
  }, [currentAddress, tab?.id]);

  useEffect(() => {
    if (ready && blank) addressRef.current?.focus();
  }, [ready, blank, tab?.id]);

  useEffect(
    () =>
      window.wormhole?.onWebEvent((event) => {
        if (event.sessionId === session.id && event.type === 'focus-address' && ready) {
          addressRef.current?.focus();
          addressRef.current?.select();
        }
      }),
    [session.id, ready],
  );

  useEffect(() => {
    if (!visible) {
      void window.wormhole?.closeBitwardenPopup(session.id).catch(() => undefined);
    }
  }, [session.id, visible]);

  function toggleBitwarden() {
    const api = window.wormhole;
    if (!api || !session.bitwardenPopupUrl) return;
    if (bitwardenOpen) {
      void api.closeBitwardenPopup(session.id).catch(() => undefined);
    } else {
      const bounds = bitwardenButtonRef.current?.getBoundingClientRect();
      if (!bounds) return;
      void api
        .openBitwardenPopup({
          sessionId: session.id,
          anchor: {
            x: bounds.x,
            y: bounds.y,
            width: bounds.width,
            height: bounds.height,
          },
        })
        .catch(() => undefined);
    }
  }

  useLayoutEffect(() => {
    const surface = surfaceRef.current;
    const api = window.wormhole;
    if (!surface || !api) return;

    let frame = 0;
    let current = true;
    let requestId = 0;
    const previewId = showPreview ? crypto.randomUUID() : undefined;
    previewIdRef.current = previewId;
    if (!available) setPreview(undefined);
    const sendBounds = () => {
      frame = 0;
      const bounds = surface.getBoundingClientRect();
      const hasBounds = bounds.width >= 1 && bounds.height >= 1;
      const id = ++requestId;
      void api
        .setWebSessionBounds({
          sessionId: session.id,
          x: hasBounds ? bounds.x : 0,
          y: hasBounds ? bounds.y : 0,
          width: Math.max(1, bounds.width),
          height: Math.max(1, bounds.height),
          visible: visible && hasBounds,
          capturePreview: showPreview && hasBounds,
          previewId: hasBounds ? previewId : undefined,
        })
        .then(async (image) => {
          if (!image || !previewId || !current || id !== requestId) return;
          const decoded = new Image();
          decoded.src = image;
          await decoded.decode();
          if (current && id === requestId) {
            setPreview((previous) =>
              previous?.id === previewId ? previous : { id: previewId, image, pageKey },
            );
          }
        })
        .catch(() => {
          if (current && id === requestId && showPreview) {
            // A failed image decode must not leave Chromium covering the menu.
            void api
              .setWebSessionBounds({
                sessionId: session.id,
                x: bounds.x,
                y: bounds.y,
                width: bounds.width,
                height: bounds.height,
                visible: false,
              })
              .catch(() => undefined);
          }
        });
    };
    const scheduleBounds = () => {
      if (!frame) frame = window.requestAnimationFrame(sendBounds);
    };

    sendBounds();
    const observer = new ResizeObserver(scheduleBounds);
    observer.observe(surface);
    window.addEventListener('resize', scheduleBounds);
    return () => {
      current = false;
      if (frame) window.cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener('resize', scheduleBounds);
    };
  }, [session.id, pageKey, available, visible, showPreview]);

  useLayoutEffect(() => {
    if (!available || !preview || preview.pageKey !== pageKey) return;
    if (showPreview && preview.id !== previewIdRef.current) return;
    let frame = window.requestAnimationFrame(() => {
      // Two frames let the decoded image reach the compositor before hiding its native sibling.
      frame = window.requestAnimationFrame(() => {
        if (!showPreview) {
          setPreview(undefined);
          return;
        }
        const bounds = surfaceRef.current?.getBoundingClientRect();
        if (!bounds || bounds.width < 1 || bounds.height < 1) return;
        void window.wormhole
          ?.setWebSessionBounds({
            sessionId: session.id,
            x: bounds.x,
            y: bounds.y,
            width: bounds.width,
            height: bounds.height,
            visible: false,
            previewId: preview.id,
          })
          .catch(() => undefined);
      });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [available, pageKey, preview, session.id, showPreview]);

  useLayoutEffect(() => {
    const api = window.wormhole;
    return () => {
      // Keep a backgrounded tab's remote content below the renderer. Closing is owned by the
      // session lifecycle, not by this component: navigation away from Sessions must preserve tabs.
      void api
        ?.setWebSessionBounds({
          sessionId: session.id,
          x: 0,
          y: 0,
          width: 1,
          height: 1,
          visible: false,
        })
        .catch(() => undefined);
    };
  }, [session.id]);

  const command = (
    operation: Parameters<NonNullable<Window['wormhole']>['commandWebSession']>[0]['operation'],
    details: { tabId?: string; url?: string } = {},
  ) => {
    setCommandError('');
    void window.wormhole
      ?.commandWebSession({ sessionId: session.id, operation, ...details })
      .catch((error: unknown) => {
        setCommandError(
          error instanceof Error ? error.message : 'The browser could not complete this action.',
        );
      });
  };
  const tabs = browser?.tabs ?? [];
  const panelId = `web-browser-${session.id}`;

  return (
    <section
      aria-label="Connection browser"
      className="relative flex h-full min-h-0 flex-col overflow-hidden bg-background"
      onKeyDown={(event) => {
        if (!ready || !(event.ctrlKey || event.metaKey)) return;
        const key = event.key.toLowerCase();
        if (!['t', 'w', 'l', 'tab'].includes(key)) return;
        event.preventDefault();
        event.stopPropagation();
        if (key === 't') command('new-tab');
        if (key === 'w' && tab) command('close-tab', { tabId: tab.id });
        if (key === 'l') {
          addressRef.current?.focus();
          addressRef.current?.select();
        }
        if (key === 'tab' && tabs.length) {
          const index = tabs.findIndex((candidate) => candidate.id === tab?.id);
          command('select-tab', {
            tabId: tabs[(index + (event.shiftKey ? -1 : 1) + tabs.length) % tabs.length].id,
          });
        }
      }}
    >
      <div className="flex h-9 shrink-0 items-center gap-1 border-b border-border bg-muted/40 px-2">
        <div
          aria-label="Browser tabs"
          className="flex min-w-0 items-center gap-1 overflow-x-auto"
          ref={tabListRef}
          role="tablist"
        >
          {tabs.map((item, index) => (
            <div
              className={`group flex h-7 min-w-24 max-w-48 shrink-0 items-center rounded-md border ${item.id === tab?.id ? 'border-border bg-background shadow-sm' : 'border-transparent hover:bg-accent/60'}`}
              key={item.id}
            >
              <button
                aria-controls={panelId}
                aria-selected={item.id === tab?.id}
                className="flex h-full min-w-0 flex-1 items-center gap-2 rounded-md px-2.5 text-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
                disabled={!ready}
                id={`web-tab-${item.id}`}
                onClick={() => command('select-tab', { tabId: item.id })}
                onKeyDown={(event) => {
                  const next =
                    event.key === 'ArrowRight'
                      ? (index + 1) % tabs.length
                      : event.key === 'ArrowLeft'
                        ? (index - 1 + tabs.length) % tabs.length
                        : event.key === 'Home'
                          ? 0
                          : event.key === 'End'
                            ? tabs.length - 1
                            : -1;
                  if (next < 0) return;
                  event.preventDefault();
                  command('select-tab', { tabId: tabs[next].id });
                  document.getElementById(`web-tab-${tabs[next].id}`)?.focus();
                }}
                role="tab"
                tabIndex={item.id === tab?.id ? 0 : -1}
                title={item.title}
                type="button"
              >
                {item.isLoading ? (
                  <LoaderCircle className="size-3 shrink-0 animate-spin" />
                ) : item.error ? (
                  <AlertCircle className="size-3 shrink-0 text-destructive" />
                ) : (
                  <WebTabFavicon favicon={item.favicon} />
                )}
                <span className="truncate">{item.title}</span>
              </button>
              <button
                aria-label={`Close ${item.title}`}
                className="mr-1 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-30 focus-visible:ring-2 focus-visible:ring-ring"
                disabled={!ready || tabs.length === 1}
                onClick={() => command('close-tab', { tabId: item.id })}
                type="button"
              >
                <X className="size-3" />
              </button>
            </div>
          ))}
        </div>
        <ToolbarButton
          disabled={!ready || tabs.length >= 32}
          label="New tab"
          onClick={() => command('new-tab')}
        >
          <Plus />
        </ToolbarButton>
        <span
          className="ml-auto flex max-w-[40%] shrink-0 items-center gap-1.5 border-l border-border pl-3 pr-1 text-[10px] font-medium text-muted-foreground"
          title={
            browser?.restrictedOrigin
              ? `${vpnLabel}. VPN access is limited to ${browser.restrictedOrigin}`
              : browser?.route === 'vpn'
                ? `${vpnLabel}. All tabs use this browser’s VPN tunnel`
                : 'No VPN tunnel is attached to this browser. Tabs use the normal network connection.'
          }
        >
          {browser?.route === 'vpn' ? (
            <ShieldCheck className="size-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
          ) : (
            <Globe className="size-3.5" />
          )}
          <span className="truncate">
            {session.status === 'connecting'
              ? 'Connecting…'
              : browser?.route === 'vpn'
                ? vpnLabel
                : 'No VPN'}
          </span>
        </span>
      </div>
      <header className="flex h-11 shrink-0 items-center gap-2 border-b border-border bg-card px-2">
        <div className="flex items-center gap-0.5">
          <ToolbarButton
            disabled={!ready || !(tab?.canGoBack ?? session.webCanGoBack)}
            label="Back"
            onClick={() => command('back')}
          >
            <ChevronLeft />
          </ToolbarButton>
          <ToolbarButton
            disabled={!ready || !(tab?.canGoForward ?? session.webCanGoForward)}
            label="Forward"
            onClick={() => command('forward')}
          >
            <ChevronRight />
          </ToolbarButton>
          <ToolbarButton
            disabled={!ready || blank}
            label={tab?.isLoading ? 'Stop loading' : 'Reload'}
            onClick={() => command(tab?.isLoading ? 'stop' : 'reload')}
          >
            {tab?.isLoading ? <X /> : <RefreshCcw />}
          </ToolbarButton>
        </div>
        <form
          className="flex min-w-0 flex-1 items-center gap-2 rounded-md border border-border bg-muted/25 px-2.5 focus-within:ring-1 focus-within:ring-ring"
          onSubmit={(event) => {
            event.preventDefault();
            command('navigate', { url: address });
          }}
        >
          {currentAddress.startsWith('https:') ? (
            <LockKeyhole aria-label="HTTPS" className="size-3.5 shrink-0 text-muted-foreground" />
          ) : (
            <Globe className="size-3.5 shrink-0 text-muted-foreground" />
          )}
          <input
            aria-label="Website address"
            autoCapitalize="none"
            autoComplete="off"
            className="h-7 w-full min-w-0 bg-transparent font-mono text-[11px] outline-none placeholder:text-muted-foreground"
            disabled={!ready}
            maxLength={8192}
            onChange={(event) => setAddress(event.target.value)}
            onFocus={(event) => event.target.select()}
            placeholder="Enter a website address"
            ref={addressRef}
            spellCheck={false}
            type="text"
            value={address}
          />
        </form>
        {session.protocol === 'https' ? (
          <div className="flex shrink-0 items-center gap-0.5 border-l border-border/70 pl-2">
            <ToolbarButton
              disabled={!visible}
              label="Decrease text size"
              onClick={() => command('zoom-out')}
            >
              <span aria-hidden="true" className="text-xs font-semibold">
                A−
              </span>
            </ToolbarButton>
            <ToolbarButton
              disabled={!visible}
              label="Increase text size"
              onClick={() => command('zoom-in')}
            >
              <span aria-hidden="true" className="text-xs font-semibold">
                A+
              </span>
            </ToolbarButton>
          </div>
        ) : null}
        {session.bitwardenPopupUrl ? (
          <ToolbarButton
            buttonRef={bitwardenButtonRef}
            disabled={!visible}
            label={bitwardenOpen ? 'Close Bitwarden' : 'Open Bitwarden'}
            onClick={() => toggleBitwarden()}
          >
            <img alt="" className="size-4" src={bitwardenIcon} />
          </ToolbarButton>
        ) : null}
      </header>
      {commandError ? (
        <p
          className="shrink-0 border-b border-border px-3 py-2 text-xs text-destructive"
          role="alert"
        >
          {commandError}
        </p>
      ) : null}

      <div
        aria-label="Web browser canvas"
        aria-labelledby={tab ? `web-tab-${tab.id}` : undefined}
        className="relative min-h-0 flex-1"
        id={panelId}
        ref={surfaceRef}
        role="tabpanel"
      >
        {available && preview?.pageKey === pageKey ? (
          <img
            alt=""
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 size-full"
            src={preview.image}
          />
        ) : null}
        {ready && blank ? (
          <StatusOverlay>
            <Globe className="size-9 text-muted-foreground/50" />
            <p className="text-sm font-medium">New tab</p>
            <p className="max-w-md text-xs leading-relaxed text-muted-foreground">
              Enter an address above to browse
              {browser?.route === 'vpn' ? ' through this VPN tunnel' : ''}.
            </p>
            {browser?.restrictedOrigin ? (
              <p className="text-xs text-muted-foreground">
                Available host: {browser.restrictedOrigin}
              </p>
            ) : null}
          </StatusOverlay>
        ) : null}
        {ready && tab?.error ? (
          <StatusOverlay>
            <AlertCircle className="size-8 text-destructive" />
            <p className="text-sm font-medium">This page could not load</p>
            <p className="max-w-md text-xs leading-relaxed text-muted-foreground">{tab.error}</p>
            <Button onClick={() => command('reload')} size="sm" type="button">
              Reload page
            </Button>
          </StatusOverlay>
        ) : null}
        {session.status === 'connecting' || session.status === 'placeholder' ? (
          session.tunnelProgress ? (
            <StatusOverlay>
              <ConnectionStepper tunnelProgress={session.tunnelProgress} />
            </StatusOverlay>
          ) : (
            <StatusOverlay>
              <LoaderCircle className="size-7 animate-spin text-primary" />
              <p className="text-sm font-medium">Opening browser…</p>
              <p className="max-w-md text-xs leading-relaxed text-muted-foreground">{address}</p>
            </StatusOverlay>
          )
        ) : null}
        {session.status === 'failed' ? (
          <StatusOverlay>
            <AlertCircle className="size-8 text-destructive" />
            <p className="text-sm font-medium">Connection failed</p>
            <p className="max-w-md text-center text-xs leading-relaxed text-muted-foreground">
              {session.error || 'The browser could not open this connection.'}
            </p>
            <Button onClick={() => onReconnect(session.id)} size="sm" type="button">
              <RefreshCcw data-icon="inline-start" />
              Retry
            </Button>
          </StatusOverlay>
        ) : null}
        {session.status === 'closed' ? (
          <StatusOverlay>
            <Globe className="size-8 text-muted-foreground" />
            <p className="text-sm font-medium">Disconnected</p>
            <Button onClick={() => onReconnect(session.id)} size="sm" type="button">
              Reconnect
            </Button>
          </StatusOverlay>
        ) : null}
      </div>
    </section>
  );
}

function WebTabFavicon({ favicon }: { favicon?: string }) {
  const [failed, setFailed] = useState<string>();
  return favicon && favicon !== failed ? (
    <img
      alt=""
      className="size-3 shrink-0 object-contain"
      draggable={false}
      src={favicon}
      onError={() => setFailed(favicon)}
    />
  ) : (
    <Globe className="size-3 shrink-0 text-muted-foreground" />
  );
}

function ToolbarButton({
  buttonRef,
  children,
  disabled,
  label,
  onClick,
}: {
  buttonRef?: Ref<HTMLButtonElement>;
  children: ReactNode;
  disabled: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <Button
      aria-label={label}
      ref={buttonRef}
      className="size-7 p-0"
      disabled={disabled}
      onClick={onClick}
      size="icon"
      type="button"
      variant="ghost"
    >
      {children}
    </Button>
  );
}

function StatusOverlay({ children }: { children: ReactNode }) {
  return (
    <div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-3 bg-background px-8 text-center">
      {children}
    </div>
  );
}
