import { useEffect, useRef } from 'react';
import { Monitor, RefreshCcw, ShieldAlert, Wifi } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { RdpUiStatus } from '../rdp-state';

export type { RdpUiStatus } from '../rdp-state';

type RdpSurfaceProps = {
  sessionId: string;
  isActive: boolean;
  isAuthorized: boolean;
  status: RdpUiStatus;
  backend?: 'activex' | 'freerdp';
  error?: string;
  onConnect: () => void;
  onRetry: () => void;
};

export function RdpSurface({
  sessionId,
  isActive,
  isAuthorized,
  status,
  backend,
  error,
  onConnect,
  onRetry,
}: RdpSurfaceProps) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const nativeSurfaceVisible = useRef(false);

  useEffect(() => {
    const surface = surfaceRef.current;
    const api = window.wormhole;

    const hideNativeSurface = () => {
      if (!nativeSurfaceVisible.current) return;
      nativeSurfaceVisible.current = false;
      void api?.commandRdpSession({ sessionId, operation: 'hide' }).catch(() => undefined);
    };

    if (!surface || !isActive || !isAuthorized || status !== 'connected') {
      hideNativeSurface();
      return;
    }

    const reportBounds = () => {
      const rect = surface.getBoundingClientRect();
      if (rect.width < 1 || rect.height < 1) return;
      const bounds = { x: rect.left, y: rect.top, width: rect.width, height: rect.height };
      void api
        ?.resizeRdpSession({
          sessionId,
          bounds,
        })
        .catch(() => undefined);
      nativeSurfaceVisible.current = true;
      void api?.commandRdpSession({ sessionId, operation: 'show', bounds }).catch(() => undefined);
    };

    reportBounds();
    const observer = new ResizeObserver(reportBounds);
    observer.observe(surface);
    window.addEventListener('resize', reportBounds);

    return () => {
      observer.disconnect();
      window.removeEventListener('resize', reportBounds);
      hideNativeSurface();
    };
  }, [isActive, isAuthorized, sessionId, status]);

  const isConnected = status === 'connected';
  const isStarting = status === 'starting';
  const isFailed = status === 'failed';

  return (
    <div
      aria-label="RDP remote desktop surface"
      className="relative flex h-full min-h-0 min-w-0 items-center justify-center overflow-hidden bg-black"
      ref={surfaceRef}
    >
      {isConnected ? (
        <div className="pointer-events-none absolute inset-x-0 bottom-3 z-10 flex justify-center opacity-0 transition-opacity hover:opacity-100">
          <span className="rounded-full border border-white/10 bg-black/70 px-3 py-1 text-[10px] text-white/70">
            {backend === 'activex' ? 'Windows ActiveX surface' : 'FreeRDP surface'}
          </span>
        </div>
      ) : (
        <div className="relative z-10 flex max-w-sm flex-col items-center px-6 text-center text-white">
          <div className="mb-4 grid size-14 place-items-center rounded-full border border-white/10 bg-white/[0.06] text-white/75">
            {isFailed ? <ShieldAlert className="size-6" /> : <Monitor className="size-6" />}
          </div>
          <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-white/45">
            Remote desktop
          </p>
          <h3 className="mt-2 text-sm font-semibold">
            {isStarting
              ? 'Starting RDP…'
              : isFailed
                ? 'RDP connection failed'
                : 'RDP session is disconnected'}
          </h3>
          <p className="mt-2 text-xs leading-relaxed text-white/50">
            {isStarting
              ? backend === 'activex'
                ? 'Initializing the native Windows ActiveX surface.'
                : 'Starting the FreeRDP client for this host.'
              : error || 'Connect to open the remote desktop in this tab.'}
          </p>
          {isStarting ? (
            <div className="mt-5 flex items-center gap-2 text-[10px] text-white/45">
              <Wifi className="size-3.5 animate-pulse" />
              Negotiating secure session
            </div>
          ) : (
            <Button
              className="mt-5"
              onClick={isFailed ? onRetry : onConnect}
              size="sm"
              variant="secondary"
            >
              <RefreshCcw data-icon="inline-start" />
              {isFailed ? 'Retry connection' : 'Connect'}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
