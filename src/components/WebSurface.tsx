import { useEffect, useLayoutEffect, useRef, useState, type ReactNode, type Ref } from 'react';
import {
  AlertCircle,
  ArrowLeft,
  ArrowRight,
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
import { TextTooltip } from '@/components/ui/tooltip';
import { keepHorizontalItemVisible } from '@/horizontal-scroll';
import {
  BrowserConnectionLoading,
  ConnectionTransition,
  type BrowserLoadingSession,
} from './ConnectionTransition';

type WebSessionSurface = BrowserLoadingSession & {
  id: string;
  protocol: 'sftp' | 'smb' | 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
  status: 'connecting' | 'connected' | 'failed' | 'closed' | 'placeholder';
  error?: string;
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
  captureWhenOccluded?: boolean;
  bitwardenOpen: boolean;
  loadingFallbackShown?: boolean;
  onReconnect: (sessionId: string) => void;
};

export function WebSurface({ loadingFallbackShown, ...props }: WebSurfaceProps) {
  const { session } = props;
  const opening = session.status === 'connecting' || session.status === 'placeholder';
  const loading = <BrowserConnectionLoading session={session} />;
  return (
    <ConnectionTransition
      connected={session.status === 'connected'}
      initialPending={loadingFallbackShown ? loading : undefined}
      pending={opening ? loading : null}
    >
      {(covered) => <WebSurfaceContent {...props} connectionCovered={covered} />}
    </ConnectionTransition>
  );
}

function WebSurfaceContent({
  session,
  isActive,
  isAuthorized,
  isOccluded = false,
  captureWhenOccluded = true,
  bitwardenOpen,
  connectionCovered,
  onReconnect,
}: WebSurfaceProps & { connectionCovered: boolean }) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const tabListRef = useRef<HTMLDivElement>(null);
  const bitwardenButtonRef = useRef<HTMLButtonElement>(null);
  const addressRef = useRef<HTMLInputElement>(null);
  const previewIdRef = useRef<string | undefined>(undefined);
  const latestCommand = useRef(0);
  const browser = session.webBrowser;
  const vpnLabel = `${browser?.tunnel?.name ? `${browser.tunnel.name}'s ` : ''}${browser?.tunnel?.kind || 'VPN tunnel'}${session.status === 'connected' ? ' ACTIVE' : ''}`;
  const vpnReconnecting = browser?.vpnStatus === 'reconnecting';
  const vpnInterrupted = vpnReconnecting || browser?.vpnStatus === 'disconnected';
  const vpnRecoveryLabel = vpnReconnecting ? 'Reconnecting VPN…' : 'VPN disconnected. Reconnect?';
  const vpnDetails = vpnInterrupted
    ? vpnReconnecting
      ? session.tunnelProgress?.detail || vpnRecoveryLabel
      : vpnRecoveryLabel
    : browser?.restrictedOrigin
      ? `${vpnLabel}. VPN access is limited to ${browser.restrictedOrigin}`
      : browser?.route === 'vpn'
        ? `${vpnLabel}. All tabs use this browser’s VPN tunnel`
        : 'No VPN tunnel is attached to this browser. Tabs use the normal network connection.';
  const tab = browser?.tabs.find((candidate) => candidate.id === browser.activeTabId);
  // A WebContentsView is above the renderer, so attach it after the loading layer fades.
  const available =
    isActive && isAuthorized && session.status === 'connected' && !connectionCovered;
  const ready = available && !isOccluded;
  const blank = tab?.url === 'about:blank';
  const visible = ready && !blank && !tab?.error;
  const showPreview = available && isOccluded && captureWhenOccluded && !blank && !tab?.error;
  const currentAddress =
    tab?.url ||
    session.webUrl ||
    `${session.protocol}://${session.host}${session.port ? `:${session.port}` : ''}`;
  const pageKey = `${session.id}:${tab?.id ?? ''}`;
  const location = {
    pageKey,
    url: currentAddress,
    text: currentAddress === 'about:blank' ? '' : currentAddress,
  };
  const [address, setAddress] = useState(location);
  const [commandError, setCommandError] = useState('');
  if (address.pageKey !== pageKey || address.url !== currentAddress) {
    setAddress(location);
    setCommandError('');
  }
  const [preview, setPreview] = useState<{ id: string; image: string; pageKey: string }>();
  if (preview && (!available || !captureWhenOccluded || preview.pageKey !== pageKey))
    setPreview(undefined);

  useLayoutEffect(() => {
    const list = tabListRef.current;
    const selected = list?.querySelector('[aria-selected="true"]')?.parentElement;
    if (!ready || !list || !selected) return;
    return keepHorizontalItemVisible(list, selected);
  }, [ready, tab?.id]);

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
    let previousHasBounds: boolean | undefined;
    const previewId = showPreview ? crypto.randomUUID() : undefined;
    previewIdRef.current = previewId;
    const sendBounds = () => {
      frame = 0;
      const bounds = surface.getBoundingClientRect();
      const hasBounds = bounds.width >= 1 && bounds.height >= 1;
      // The renderer scales the captured image as the canvas resizes. Reuse it until occlusion
      // ends, while still reporting when the surface becomes measurable or loses its bounds.
      if (previewId && hasBounds === previousHasBounds) return;
      previousHasBounds = hasBounds;
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
  }, [session.id, pageKey, available, visible, showPreview, captureWhenOccluded]);

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

  useLayoutEffect(
    () => () => {
      latestCommand.current++;
    },
    [pageKey, currentAddress, isAuthorized],
  );

  const command = (
    operation: Parameters<NonNullable<Window['wormhole']>['commandWebSession']>[0]['operation'],
    details: { tabId?: string; url?: string } = {},
  ) => {
    const request = ++latestCommand.current;
    setCommandError('');
    void window.wormhole
      ?.commandWebSession({ sessionId: session.id, operation, ...details })
      .catch((error: unknown) => {
        if (request !== latestCommand.current) return;
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
      className="connection-browser @container relative flex h-full min-h-0 flex-col overflow-hidden bg-[var(--browser-toolbar)]"
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
      <div className="browser-tab-rail flex h-10 shrink-0 items-center gap-0.5 px-2.5">
        <div
          aria-label="Browser tabs"
          className="browser-tab-list flex min-w-0 items-start self-stretch overflow-x-auto overflow-y-hidden pt-1"
          ref={tabListRef}
          role="tablist"
        >
          {tabs.map((item, index) => (
            <div
              className={`flex h-8 w-[clamp(4rem,30cqw,11rem)] shrink-0 items-center rounded-t-[9px] border-t ${item.id === tab?.id ? 'browser-tab-active relative border-t-foreground/20 bg-[var(--browser-toolbar)] text-foreground' : 'border-transparent text-muted-foreground hover:bg-foreground/5 hover:text-foreground motion-safe:transition-colors'}`}
              key={item.id}
            >
              <TextTooltip text={item.title}>
                <button
                  aria-controls={panelId}
                  aria-selected={item.id === tab?.id}
                  className="flex h-full min-w-0 flex-1 items-center gap-2 rounded-t-lg pr-1 pl-3 text-xs font-medium outline-none aria-selected:font-semibold focus-visible:inset-ring-2 focus-visible:inset-ring-ring"
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
              </TextTooltip>
              <button
                aria-label={`Close ${item.title}`}
                className="mr-0.5 grid size-6 shrink-0 place-items-center rounded-full text-muted-foreground outline-none enabled:hover:bg-foreground/10 enabled:hover:text-foreground focus-visible:inset-ring-2 focus-visible:inset-ring-ring disabled:opacity-30"
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
        <TextTooltip text={vpnDetails}>
          <div aria-live="polite" className="ml-auto min-w-0 max-w-[36%] shrink-0">
            {vpnInterrupted ? (
              <button
                aria-label={vpnRecoveryLabel}
                className="flex h-6 max-w-full items-center gap-1.5 rounded-full bg-red-700 px-2.5 text-[11px] font-medium text-white enabled:cursor-pointer enabled:hover:bg-red-800"
                disabled={!ready || vpnReconnecting}
                onClick={() => command('reconnect-vpn')}
                type="button"
              >
                {vpnReconnecting ? (
                  <LoaderCircle aria-hidden="true" className="size-3.5 shrink-0 animate-spin" />
                ) : (
                  <AlertCircle aria-hidden="true" className="size-3.5 shrink-0" />
                )}
                <span className="truncate">{vpnRecoveryLabel}</span>
              </button>
            ) : (
              <span className="flex h-6 items-center gap-1.5 rounded-full bg-[var(--browser-toolbar)] px-2.5 text-[11px] font-medium text-muted-foreground">
                {browser?.route === 'vpn' ? (
                  <ShieldCheck className="size-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
                ) : (
                  <Globe className="size-3.5 shrink-0" />
                )}
                <span className="truncate">{browser?.route === 'vpn' ? vpnLabel : 'No VPN'}</span>
              </span>
            )}
          </div>
        </TextTooltip>
      </div>
      <header className="flex min-h-11 shrink-0 items-center gap-1.5 bg-[var(--browser-toolbar)] px-2.5 @max-[340px]:flex-wrap @max-[340px]:py-1.5">
        <div className="flex shrink-0 items-center gap-0.5 @max-[340px]:mr-auto">
          <ToolbarButton
            disabled={!ready || !(tab?.canGoBack ?? session.webCanGoBack)}
            label="Back"
            onClick={() => command('back')}
          >
            <ArrowLeft />
          </ToolbarButton>
          <ToolbarButton
            disabled={!ready || !(tab?.canGoForward ?? session.webCanGoForward)}
            label="Forward"
            onClick={() => command('forward')}
          >
            <ArrowRight />
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
          className="flex h-[34px] min-w-0 flex-1 items-center gap-2 rounded-full border border-transparent bg-[var(--browser-address)] px-3 focus-within:border-ring focus-within:ring-1 focus-within:ring-ring @max-[340px]:order-last @max-[340px]:basis-full"
          onSubmit={(event) => {
            event.preventDefault();
            command('navigate', { url: address.text });
          }}
        >
          {currentAddress.startsWith('https:') ? (
            <LockKeyhole aria-label="HTTPS" className="size-3.5 shrink-0 text-muted-foreground" />
          ) : (
            <Globe aria-hidden="true" className="size-3.5 shrink-0 text-muted-foreground" />
          )}
          <input
            aria-label="Website address"
            autoCapitalize="none"
            autoComplete="off"
            className="h-full w-full min-w-0 bg-transparent text-[13px] outline-none placeholder:text-muted-foreground"
            disabled={!ready}
            maxLength={8192}
            onChange={(event) => setAddress({ ...location, text: event.target.value })}
            onFocus={(event) => event.target.select()}
            placeholder="Enter a website address"
            ref={addressRef}
            spellCheck={false}
            type="text"
            value={address.text}
          />
        </form>
        {session.protocol === 'https' ? (
          <div className="flex shrink-0 items-center gap-0.5">
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
        className="relative min-h-0 flex-1 overflow-hidden rounded-[var(--workspace-canvas-radius)]"
        id={panelId}
        ref={surfaceRef}
        role="tabpanel"
      >
        {available && captureWhenOccluded && preview?.pageKey === pageKey ? (
          <img
            alt=""
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 size-full"
            src={preview.image}
          />
        ) : null}
        {ready && blank ? (
          <StatusOverlay>
            <Globe className="size-9 text-muted-foreground/50 dark:text-foreground" />
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
      className="size-7 rounded-full p-0"
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
