import { useEffect, useLayoutEffect, useRef, type ReactNode, type Ref } from 'react';
import {
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  Globe,
  LoaderCircle,
  RefreshCcw,
  X,
} from 'lucide-react';
import bitwardenIcon from '../../Assets/Bitwarden/bitwarden-icon.png';
import { Button } from '@/components/ui/button';
import { ConnectionStepper, type TunnelProgress } from './ConnectionStepper';

type WebSessionSurface = {
  id: string;
  protocol: 'ssh' | 'rdp' | 'http' | 'https' | 'vnc' | 'serial';
  host: string;
  port?: number;
  status: 'connecting' | 'connected' | 'failed' | 'closed' | 'placeholder';
  error?: string;
  tunnelProgress?: TunnelProgress | null;
  webUrl?: string;
  webCanGoBack?: boolean;
  webCanGoForward?: boolean;
  webIsLoading?: boolean;
  bitwardenPopupUrl?: string;
};

type WebSurfaceProps = {
  session: WebSessionSurface;
  isActive: boolean;
  isAuthorized: boolean;
  bitwardenOpen: boolean;
  onReconnect: (sessionId: string) => void;
};

export function WebSurface({
  session,
  isActive,
  isAuthorized,
  bitwardenOpen,
  onReconnect,
}: WebSurfaceProps) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const bitwardenButtonRef = useRef<HTMLButtonElement>(null);
  const visible = isActive && isAuthorized && session.status === 'connected';

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
    const sendBounds = () => {
      frame = 0;
      const bounds = surface.getBoundingClientRect();
      if (bounds.width < 1 || bounds.height < 1) return;
      void api.setWebSessionBounds({
        sessionId: session.id,
        x: bounds.x,
        y: bounds.y,
        width: bounds.width,
        height: bounds.height,
        visible,
      });
    };
    const scheduleBounds = () => {
      if (!frame) frame = window.requestAnimationFrame(sendBounds);
    };

    scheduleBounds();
    const observer = new ResizeObserver(scheduleBounds);
    observer.observe(surface);
    window.addEventListener('resize', scheduleBounds);
    return () => {
      if (frame) window.cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener('resize', scheduleBounds);
      // Keep a backgrounded tab's remote content below the renderer. Closing is owned by the
      // session lifecycle, not by this component: navigation away from Sessions must preserve tabs.
      void api.setWebSessionBounds({
        sessionId: session.id,
        x: 0,
        y: 0,
        width: 1,
        height: 1,
        visible: false,
      });
    };
  }, [session.id, visible]);

  const command = (operation: 'back' | 'forward' | 'reload' | 'stop') => {
    void window.wormhole?.commandWebSession({ sessionId: session.id, operation });
  };
  const address =
    session.webUrl ||
    `${session.protocol}://${session.host}${session.port ? `:${session.port}` : ''}`;

  return (
    <section className="relative flex h-full min-h-0 flex-col overflow-hidden bg-background">
      <header className="flex h-10 shrink-0 items-center gap-1 border-b border-border bg-card/80 px-2 backdrop-blur-sm">
        <div className="flex items-center gap-0.5 border-r border-border/70 pr-2">
          <ToolbarButton
            disabled={!visible || !session.webCanGoBack}
            label="Back"
            onClick={() => command('back')}
          >
            <ChevronLeft />
          </ToolbarButton>
          <ToolbarButton
            disabled={!visible || !session.webCanGoForward}
            label="Forward"
            onClick={() => command('forward')}
          >
            <ChevronRight />
          </ToolbarButton>
          <ToolbarButton
            disabled={!visible}
            label={session.webIsLoading ? 'Stop loading' : 'Reload'}
            onClick={() => command(session.webIsLoading ? 'stop' : 'reload')}
          >
            {session.webIsLoading ? <X /> : <RefreshCcw />}
          </ToolbarButton>
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
        </div>
        <div className="flex min-w-0 flex-1 items-center gap-2 rounded-md border border-border/70 bg-background/70 px-2.5 py-1 text-xs shadow-inner">
          <Globe className="size-3.5 shrink-0 text-primary" />
          <span className="truncate font-mono text-[11px] text-muted-foreground" title={address}>
            {address}
          </span>
        </div>
      </header>

      <div aria-label="Web browser canvas" className="relative min-h-0 flex-1" ref={surfaceRef}>
        {session.status === 'connecting' || session.status === 'placeholder' ? (
          session.tunnelProgress ? (
            <StatusOverlay>
              <ConnectionStepper tunnelProgress={session.tunnelProgress} />
            </StatusOverlay>
          ) : (
            <StatusOverlay>
              <LoaderCircle className="size-7 animate-spin text-primary" />
              <p className="text-sm font-medium">
                Opening {session.protocol.toUpperCase()} session…
              </p>
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
