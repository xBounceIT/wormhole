import { useEffect, useRef } from 'react';
import { ExternalLink, Monitor, RefreshCcw, ShieldAlert, Wifi } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { ConnectionStepper, type TunnelProgress } from './ConnectionStepper';
import type { RdpUiStatus } from '../rdp-state';

export type { RdpUiStatus } from '../rdp-state';

type RdpSurfaceProps = {
  sessionId: string;
  isActive: boolean;
  isAuthorized: boolean;
  status: RdpUiStatus;
  backend?: 'activex' | 'freerdp';
  external?: boolean;
  error?: string;
  tunnelProgress?: TunnelProgress | null;
  onConnect: () => void;
  onOpenSystemClient: () => void;
  onRetry: () => void;
  canOpenSystemClient: boolean;
};

export function RdpSurface({
  sessionId,
  isActive,
  isAuthorized,
  status,
  backend,
  external = false,
  error,
  tunnelProgress,
  onConnect,
  onOpenSystemClient,
  onRetry,
  canOpenSystemClient,
}: RdpSurfaceProps) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const nativeSurfaceVisible = useRef(false);
  const boundsSignature = useRef('');

  useEffect(() => {
    const surface = surfaceRef.current;
    const api = window.wormhole;

    const hideNativeSurface = () => {
      if (!nativeSurfaceVisible.current) return;
      nativeSurfaceVisible.current = false;
      void api?.commandRdpSession({ sessionId, operation: 'hide' }).catch(() => undefined);
    };

    if (!surface || !api || !isActive || !isAuthorized) {
      hideNativeSurface();
      return;
    }

    const shouldShowNativeSurface = status === 'connected' && !external;
    if (!shouldShowNativeSurface) hideNativeSurface();

    const reportBounds = () => {
      const rect = surface.getBoundingClientRect();
      if (rect.width < 1 || rect.height < 1) return;
      const bounds = { x: rect.left, y: rect.top, width: rect.width, height: rect.height };
      const signature = `${bounds.x}:${bounds.y}:${bounds.width}:${bounds.height}`;
      if (signature === boundsSignature.current && nativeSurfaceVisible.current) return;
      boundsSignature.current = signature;
      // The native STA host coalesces resize commands just before applying HWND geometry. Do not
      // await an older native acknowledgement here: doing so makes a slow ActiveX layout frame
      // hold the next, newer rectangle outside the only queue that can safely supersede it.
      void api.resizeRdpSession({ sessionId, bounds }).catch(() => undefined);
      if (!shouldShowNativeSurface || nativeSurfaceVisible.current) return;
      nativeSurfaceVisible.current = true;
      void api?.commandRdpSession({ sessionId, operation: 'show', bounds }).catch(() => undefined);
    };

    // ResizeObserver is already delivered after layout. Reporting directly avoids adding a full
    // requestAnimationFrame of latency while Windows is in its native sizing loop; the STA host
    // performs the cross-process coalescing immediately before touching the HWND.
    reportBounds();
    const observer = new ResizeObserver(reportBounds);
    observer.observe(surface);
    window.addEventListener('resize', reportBounds);

    return () => {
      observer.disconnect();
      window.removeEventListener('resize', reportBounds);
      hideNativeSurface();
    };
  }, [external, isActive, isAuthorized, sessionId, status]);

  const isConnected = status === 'connected';
  const isStarting = status === 'starting';
  const isFailed = status === 'failed';

  return (
    <div
      aria-label="RDP remote desktop surface"
      data-rdp-session-id={sessionId}
      className="relative flex h-full min-h-0 min-w-0 flex-col overflow-hidden bg-black"
    >
      {isConnected && !external ? (
        <div
          className="flex shrink-0 items-center justify-end gap-2 border-b border-white/10 bg-black px-3 py-2"
          data-rdp-system-client-toolbar
        >
          <span className="pointer-events-none rounded-full border border-white/10 bg-black/70 px-3 py-1 text-[10px] text-white/70">
            {backend === 'activex' ? 'Windows ActiveX surface' : 'FreeRDP surface'}
          </span>
          {canOpenSystemClient ? (
            <Button onClick={onOpenSystemClient} size="sm" variant="secondary">
              <ExternalLink data-icon="inline-start" />
              Open in System Remote Desktop
            </Button>
          ) : null}
        </div>
      ) : null}
      {/* A native HWND is always above Chromium. Measure only this sibling region so the toolbar
          remains visible and interactive instead of being covered by the remote desktop surface. */}
      <div
        className="relative flex min-h-0 min-w-0 flex-1 items-center justify-center overflow-hidden"
        data-rdp-native-surface-region
        ref={surfaceRef}
      >
        {isConnected && external ? (
          <div className="relative z-10 flex max-w-sm flex-col items-center px-6 text-center text-white">
            <div className="mb-4 grid size-14 place-items-center rounded-full border border-white/10 bg-white/[0.06] text-white/75">
              <ExternalLink className="size-6" />
            </div>
            <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-white/45">
              External remote desktop
            </p>
            <h3 className="mt-2 text-sm font-semibold">System Remote Desktop is running</h3>
            <p className="mt-2 text-xs leading-relaxed text-white/50">
              The Windows client owns this connection. Disconnect or reconnect it from the tab menu.
            </p>
          </div>
        ) : null}
        {!isConnected ? (
          <div className="relative z-10 flex max-w-sm flex-col items-center px-6 text-center text-white">
            {isStarting && tunnelProgress ? (
              <ConnectionStepper tunnelProgress={tunnelProgress} />
            ) : (
              <>
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
                  <div className="mt-5 flex flex-wrap justify-center gap-2">
                    <Button onClick={isFailed ? onRetry : onConnect} size="sm" variant="secondary">
                      <RefreshCcw data-icon="inline-start" />
                      {isFailed ? 'Retry connection' : 'Connect'}
                    </Button>
                    {canOpenSystemClient ? (
                      <Button onClick={onOpenSystemClient} size="sm" variant="outline">
                        <ExternalLink data-icon="inline-start" />
                        Open in System Remote Desktop
                      </Button>
                    ) : null}
                  </div>
                )}
              </>
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}
