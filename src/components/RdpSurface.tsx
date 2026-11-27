import { useCallback, useEffect, useRef, useState } from 'react';
import { ExternalLink, Monitor, RefreshCcw, ShieldAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  ConnectionLoading,
  ConnectionTransition,
  type TunnelProgress,
} from './ConnectionTransition';
import type { RdpBackendKind, RdpUiStatus } from '../rdp-state';
import { RdpCanvas } from './RdpCanvas';

export type { RdpUiStatus } from '../rdp-state';

type RdpSurfaceProps = {
  sessionId: string;
  name?: string;
  destination?: string;
  inheritedTarget?: boolean;
  port?: number;
  isActive: boolean;
  isAuthorized: boolean;
  status: RdpUiStatus;
  backend?: RdpBackendKind;
  external?: boolean;
  error?: string;
  tunnelProgress?: TunnelProgress | null;
  onConnect: () => void;
  onOpenSystemClient?: () => void;
  onEnterCredentials?: () => void;
  onRetry: () => void;
  canOpenSystemClient: boolean;
  onReady?: (bounds: WormholeRdpSurfaceRect) => void;
};

export function RdpSurface({
  name,
  destination,
  inheritedTarget,
  port,
  tunnelProgress,
  ...surface
}: RdpSurfaceProps) {
  const [hasFrame, setHasFrame] = useState(false);
  const reportFrame = useCallback(() => setHasFrame(true), []);
  const connected = surface.status === 'connected';
  if (!connected && hasFrame) setHasFrame(false);
  const waitingForFrame =
    connected && surface.backend === 'freerdp' && !surface.external && !hasFrame;

  return (
    <ConnectionTransition
      connected={connected}
      pending={
        surface.status === 'starting' || waitingForFrame ? (
          <ConnectionLoading
            destination={destination}
            inheritedTarget={inheritedTarget}
            name={name}
            port={port}
            protocol="RDP"
            status={waitingForFrame ? 'Waiting for the remote desktop…' : 'Connecting to RDP…'}
            tunnelProgress={waitingForFrame ? undefined : tunnelProgress}
          />
        ) : null
      }
    >
      {(covered) => (
        <RdpSurfaceContent {...surface} connectionCovered={covered} onFirstFrame={reportFrame} />
      )}
    </ConnectionTransition>
  );
}

function RdpSurfaceContent({
  sessionId,
  isActive,
  isAuthorized,
  status,
  backend,
  external = false,
  error,
  connectionCovered,
  onFirstFrame,
  onConnect,
  onOpenSystemClient,
  onEnterCredentials,
  onRetry,
  canOpenSystemClient,
  onReady,
}: RdpSurfaceProps & { connectionCovered: boolean; onFirstFrame: () => void }) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const nativeSurfaceVisible = useRef(false);
  const boundsSignature = useRef('');
  const isConnected = status === 'connected';
  const canvasEnabled = isConnected && !external && isActive && isAuthorized;
  // FreeRDP paints into the canvas. Only the Windows native window would cover the fade.
  const shouldShowNativeSurface =
    isConnected && !external && (backend === 'freerdp' || !connectionCovered);

  useEffect(() => {
    const surface = surfaceRef.current;
    const api = window.wormhole;

    const hideNativeSurface = (force = false) => {
      if (!nativeSurfaceVisible.current && !force) return;
      nativeSurfaceVisible.current = false;
      void api?.commandRdpSession({ sessionId, operation: 'hide' }).catch(() => undefined);
    };

    if (!surface || !api || !isActive || !isAuthorized) {
      hideNativeSurface(true);
      return;
    }

    if (!shouldShowNativeSurface) hideNativeSurface();

    const reportBounds = () => {
      const rect = surface.getBoundingClientRect();
      if (rect.width < 1 || rect.height < 1) {
        hideNativeSurface();
        return;
      }
      const bounds = { x: rect.left, y: rect.top, width: rect.width, height: rect.height };
      const signature = `${bounds.x}:${bounds.y}:${bounds.width}:${bounds.height}`;
      if (signature === boundsSignature.current && nativeSurfaceVisible.current) return;
      boundsSignature.current = signature;
      onReady?.(bounds);
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
      hideNativeSurface(true);
    };
  }, [isActive, isAuthorized, onReady, sessionId, shouldShowNativeSurface]);

  const isFailed = status === 'failed';

  return (
    <div
      aria-label="RDP remote desktop surface"
      data-rdp-session-id={sessionId}
      className="relative flex h-full min-h-0 min-w-0 flex-col overflow-hidden bg-black"
    >
      <div
        className="relative flex min-h-0 min-w-0 flex-1 items-center justify-center overflow-hidden"
        data-rdp-native-surface-region
        ref={surfaceRef}
      >
        <RdpCanvas
          sessionId={sessionId}
          enabled={canvasEnabled}
          interactive={canvasEnabled && !connectionCovered}
          onFirstFrame={backend === 'freerdp' ? onFirstFrame : undefined}
        />
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
        {!isConnected && status !== 'starting' ? (
          <div className="relative z-10 flex max-w-sm flex-col items-center px-6 text-center text-white">
            <div className="mb-4 grid size-14 place-items-center rounded-full border border-white/10 bg-white/[0.06] text-white/75">
              {isFailed ? <ShieldAlert className="size-6" /> : <Monitor className="size-6" />}
            </div>
            <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-white/45">
              Remote desktop
            </p>
            <h3 className="mt-2 text-sm font-semibold">
              {isFailed ? 'RDP connection failed' : 'RDP session is disconnected'}
            </h3>
            <p className="mt-2 text-xs leading-relaxed text-white/50">
              {error || 'Connect to open the remote desktop in this tab.'}
            </p>
            <div className="mt-5 flex flex-wrap justify-center gap-2">
              <Button onClick={isFailed ? onRetry : onConnect} size="sm" variant="secondary">
                <RefreshCcw data-icon="inline-start" />
                {isFailed ? 'Retry connection' : 'Connect'}
              </Button>
              {onEnterCredentials ? (
                <Button onClick={onEnterCredentials} size="sm" variant="outline">
                  Enter credentials securely
                </Button>
              ) : null}
              {canOpenSystemClient ? (
                <Button onClick={onOpenSystemClient} size="sm" variant="outline">
                  <ExternalLink data-icon="inline-start" />
                  Open in System Remote Desktop
                </Button>
              ) : null}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
