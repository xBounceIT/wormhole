import { useEffect, useState, type ReactNode } from 'react';
import { Download, KeyRound, LoaderCircle, Shield, ShieldCheck } from 'lucide-react';

export type TunnelProgress = { phase: string; detail?: string };

const tunnelPhaseLabels: ReadonlyMap<string, string> = new Map([
  ['preparing', 'Preparing VPN configuration…'],
  ['authenticating', 'Authenticating with the VPN gateway…'],
  ['downloading', 'Downloading VPN configuration…'],
  ['starting', 'Bringing up the VPN tunnel…'],
]);

function ConnectionStatusIcon({ phase }: { phase?: string }) {
  const motion = !phase
    ? 'motion-safe:animate-spin'
    : phase === 'ready'
      ? 'motion-safe:animate-in motion-safe:zoom-in-75 motion-safe:duration-200'
      : 'motion-safe:animate-pulse';
  const props = { 'aria-hidden': true, className: `mt-0.5 size-4 shrink-0 text-primary ${motion}` };

  switch (phase) {
    case 'authenticating':
      return <KeyRound {...props} />;
    case 'downloading':
      return <Download {...props} />;
    case 'ready':
      return <ShieldCheck {...props} />;
    default:
      return phase ? <Shield {...props} /> : <LoaderCircle {...props} />;
  }
}

export type BrowserLoadingSession = {
  title?: string;
  protocol: string;
  host: string;
  nodeId?: string;
  webTargetNodeId?: string;
  port?: number;
  tunnelProgress?: TunnelProgress | null;
};

export function BrowserConnectionLoading({ session }: { session: BrowserLoadingSession }) {
  return (
    <ConnectionLoading
      destination={session.host}
      inheritedTarget={Boolean(session.webTargetNodeId ?? session.nodeId)}
      name={session.title}
      port={session.port}
      protocol={session.protocol.toUpperCase()}
      status="Opening browser…"
      tunnelProgress={session.tunnelProgress}
    />
  );
}

export function ConnectionLoading({
  name,
  protocol,
  destination,
  inheritedTarget,
  port,
  parameters,
  status,
  tunnelProgress,
}: {
  name?: string;
  protocol: string;
  destination?: string;
  inheritedTarget?: boolean;
  port?: number;
  parameters?: string;
  status: string;
  tunnelProgress?: TunnelProgress | null;
}) {
  const heading = name?.trim() || destination || `${protocol} connection`;
  const target = destination || (inheritedTarget ? 'Inherited target' : undefined);
  const metadata = parameters ?? (port && port > 0 ? `Port ${port}` : undefined);
  const tunnelPhase = tunnelProgress?.phase;
  const activity = !tunnelPhase
    ? status
    : tunnelPhase === 'ready'
      ? `VPN tunnel ready. ${status}`
      : tunnelProgress?.detail ||
        tunnelPhaseLabels.get(tunnelPhase) ||
        'Establishing the VPN tunnel…';

  return (
    <div className="w-full max-w-sm text-center text-foreground">
      <h3 className="text-xl leading-tight font-semibold tracking-tight wrap-anywhere">
        {heading}
      </h3>
      {target && target !== heading ? (
        <p className="mt-1.5 font-mono text-sm leading-snug wrap-anywhere text-muted-foreground">
          {target}
        </p>
      ) : null}
      <p className="mt-2 flex flex-wrap items-center justify-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
        <span className="font-medium">{protocol}</span>
        {metadata ? (
          <>
            <span aria-hidden="true">·</span>
            <span>{metadata}</span>
          </>
        ) : null}
      </p>
      <p
        className="mt-6 inline-flex items-start gap-2 text-left text-sm leading-5 text-muted-foreground"
        role="status"
      >
        <ConnectionStatusIcon key={tunnelPhase ?? 'connecting'} phase={tunnelPhase} />
        <span className="min-w-0 wrap-anywhere">{activity}</span>
      </p>
    </div>
  );
}

export function ConnectionTransition({
  children,
  pending,
  connected,
  initialPending = pending,
}: {
  children: ReactNode | ((covered: boolean) => ReactNode);
  pending: ReactNode;
  connected: boolean;
  initialPending?: ReactNode;
}) {
  const [snapshot, setSnapshot] = useState(initialPending);
  if (pending !== null && pending !== snapshot) setSnapshot(pending);
  else if (pending === null && !connected && snapshot !== null) setSnapshot(null);

  const exiting = pending === null && connected && snapshot !== null;
  useEffect(() => {
    if (!exiting) return;
    // A hidden pane may not deliver an animation event.
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const timeout = window.setTimeout(() => setSnapshot(null), reducedMotion ? 0 : 300);
    return () => window.clearTimeout(timeout);
  }, [exiting]);

  const covered = pending !== null || exiting;
  return (
    <div className="relative isolate h-full min-h-0 min-w-0 overflow-hidden rounded-[inherit]">
      {typeof children === 'function' ? children(covered) : children}
      {covered ? (
        <div
          aria-hidden={exiting || undefined}
          className="absolute inset-0 z-10 grid place-items-center overflow-auto bg-canvas p-5"
          data-connection-transition={exiting ? 'exit' : 'pending'}
          inert={exiting}
          onAnimationEnd={(event) => {
            if (exiting && event.target === event.currentTarget) setSnapshot(null);
          }}
        >
          {pending ?? snapshot}
        </div>
      ) : null}
    </div>
  );
}
