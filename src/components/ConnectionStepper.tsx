import { Check, LoaderCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

export type TunnelProgress = { phase: string; detail?: string };

const TUNNEL_PHASE_LABELS: Record<string, string> = {
  preparing: 'Preparing VPN configuration…',
  authenticating: 'Authenticating with the VPN gateway…',
  downloading: 'Downloading VPN configuration…',
  starting: 'Bringing up the VPN tunnel…',
};

type ConnectionStepperProps = {
  tunnelProgress?: TunnelProgress | null;
};

/**
 * Numbered, phased connecting stepper mirroring the WinUI3 ConnectionProgressView: a
 * "VPN tunnel" step that turns green once the shared tunnel reports ready, then a
 * "Connect" step that stays active until the target session attaches. Tunneled
 * connections show live sub-status beneath the steps; direct connections keep the
 * plain spinner overlay and never mount this component.
 */
export function ConnectionStepper({ tunnelProgress }: ConnectionStepperProps) {
  const phase = tunnelProgress?.phase;
  const tunnelActive = Boolean(phase) && phase !== 'ready';
  const tunnelDone = phase === 'ready';
  const connecting = !phase || tunnelDone;
  const phaseLabel =
    tunnelActive && phase
      ? (TUNNEL_PHASE_LABELS[phase] ?? 'Establishing the VPN tunnel…')
      : undefined;
  const detail = tunnelActive ? tunnelProgress?.detail : undefined;

  return (
    <div className="flex flex-col items-center gap-5 px-6 text-zinc-100">
      <div className="flex items-start">
        <Step active={tunnelActive} completed={tunnelDone} label="VPN tunnel" number={1} />
        <Connector filled={tunnelDone} />
        <Step active={connecting} completed={false} label="Connect" number={2} />
      </div>
      {tunnelActive ? (
        <div className="flex max-w-sm items-start gap-2 text-center text-xs leading-relaxed text-zinc-400">
          <span className="mt-1.5 size-1.5 shrink-0 animate-pulse rounded-full bg-amber-400" />
          <span>{detail || phaseLabel}</span>
        </div>
      ) : null}
    </div>
  );
}

function Step({
  active,
  completed,
  label,
  number,
}: {
  active: boolean;
  completed: boolean;
  label: string;
  number: number;
}) {
  return (
    <div className="flex w-24 flex-col items-center gap-2">
      <div
        className={cn(
          'grid size-8 place-items-center rounded-full border-2',
          completed
            ? 'border-emerald-400/50 bg-emerald-400/15 text-emerald-300'
            : active
              ? 'border-white/20 bg-white/[0.06]'
              : 'border-white/10 bg-white/[0.03] text-zinc-500',
        )}
      >
        {completed ? (
          <Check className="size-4" />
        ) : active ? (
          <LoaderCircle className="size-4 animate-spin text-amber-300" />
        ) : (
          <span className="text-[13px] font-medium">{number}</span>
        )}
      </div>
      <span
        className={cn(
          'text-center text-xs',
          active || completed ? 'text-zinc-200' : 'text-zinc-500',
        )}
      >
        {label}
      </span>
    </div>
  );
}

function Connector({ filled }: { filled: boolean }) {
  return (
    <div
      className={cn(
        'mt-[15px] h-0.5 w-10 rounded-full',
        filled ? 'bg-emerald-400/40' : 'bg-white/10',
      )}
    />
  );
}
