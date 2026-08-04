import { useCallback, useEffect, useRef, useState, type FormEvent, type PointerEvent } from 'react';
import { AlertCircle, KeyRound, LoaderCircle, Monitor, RefreshCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

type PointerLocation = Pick<PointerEvent<HTMLDivElement>, 'clientX' | 'clientY'>;
type PointerCommand = { x: number; y: number; buttons: number };
type PendingPointerMove = { generation: number; command: PointerCommand };

export type VncSurfaceSession = {
  id: string;
  nodeId?: string;
  host: string;
  port?: number;
};

type VncStatus = 'idle' | 'connecting' | 'connected' | 'failed' | 'disconnected';

const specialKeySymbols: Record<string, number> = {
  Backspace: 0xff08,
  Tab: 0xff09,
  Enter: 0xff0d,
  Escape: 0xff1b,
  Delete: 0xffff,
  Home: 0xff50,
  End: 0xff57,
  PageUp: 0xff55,
  PageDown: 0xff56,
  ArrowLeft: 0xff51,
  ArrowUp: 0xff52,
  ArrowRight: 0xff53,
  ArrowDown: 0xff54,
  Insert: 0xff63,
  CapsLock: 0xffe5,
  NumLock: 0xff7f,
  ScrollLock: 0xff14,
  PrintScreen: 0xff61,
  Pause: 0xff13,
  ContextMenu: 0xff67,
  F1: 0xffbe,
  F2: 0xffbf,
  F3: 0xffc0,
  F4: 0xffc1,
  F5: 0xffc2,
  F6: 0xffc3,
  F7: 0xffc4,
  F8: 0xffc5,
  F9: 0xffc6,
  F10: 0xffc7,
  F11: 0xffc8,
  F12: 0xffc9,
};

function keySymbol(event: KeyboardEvent): number | undefined {
  const modifierSymbols: Record<string, number> = {
    ShiftLeft: 0xffe1,
    ShiftRight: 0xffe2,
    ControlLeft: 0xffe3,
    ControlRight: 0xffe4,
    AltLeft: 0xffe9,
    AltRight: 0xfe03,
    MetaLeft: 0xffeb,
    MetaRight: 0xffec,
  };
  if (modifierSymbols[event.code]) return modifierSymbols[event.code];
  if (specialKeySymbols[event.key]) return specialKeySymbols[event.key];
  if (event.key.length === 1) {
    const codePoint = event.key.codePointAt(0);
    if (codePoint !== undefined && codePoint <= 0xff) return codePoint;
  }
  return undefined;
}

function pointerMask(event: PointerEvent<HTMLDivElement>): number {
  let mask = 0;
  if (event.buttons & 1) mask |= 1;
  if (event.buttons & 4) mask |= 2;
  if (event.buttons & 2) mask |= 4;
  return mask;
}

function isAuthenticationMessage(message: string | undefined): boolean {
  const value = message?.toLowerCase() ?? '';
  return value.includes('password') || value.includes('authentication');
}

function isFormInteraction(target: EventTarget | null): boolean {
  return target instanceof Element && target.closest('form, input, button') !== null;
}

export function VncSurface({ session }: { session: VncSurfaceSession }) {
  const [status, setStatus] = useState<VncStatus>('idle');
  const [message, setMessage] = useState('');
  const [passwordRequired, setPasswordRequired] = useState(false);
  const [password, setPassword] = useState('');
  const [frame, setFrame] = useState<string>();
  const [frameSize, setFrameSize] = useState({ width: 0, height: 0 });
  const imageRef = useRef<HTMLImageElement>(null);
  const surfaceRef = useRef<HTMLDivElement>(null);
  const pressedKeys = useRef(new Map<string, number>());
  const lastPointer = useRef<{ x: number; y: number } | null>(null);
  const pointerMoveGeneration = useRef(0);
  const pendingPointerMove = useRef<PendingPointerMove | null>(null);
  const pointerMoveSending = useRef<number | null>(null);
  const buttons = useRef(0);

  const sendCommand = useCallback(
    async (command: WormholeVncCommand, showError = false): Promise<boolean> => {
      const api = window.wormhole;
      if (!api) {
        if (showError) {
          setStatus('failed');
          setMessage('The native VNC bridge is unavailable.');
        }
        return false;
      }
      try {
        const response = await api.sendVncCommand(command);
        if (!response.ok && showError) {
          setStatus('failed');
          setMessage(response.error ?? 'The native VNC backend rejected the request.');
          setPasswordRequired(isAuthenticationMessage(response.error));
        }
        return response.ok;
      } catch (error) {
        if (showError) {
          setStatus('failed');
          setMessage(error instanceof Error ? error.message : 'The native VNC backend failed.');
        }
        return false;
      }
    },
    [],
  );

  const connect = useCallback(
    async (providedPassword?: string) => {
      setStatus('connecting');
      setMessage('');
      setPasswordRequired(false);
      setFrame(undefined);
      setFrameSize({ width: 0, height: 0 });
      lastPointer.current = null;
      pointerMoveGeneration.current += 1;
      pendingPointerMove.current = null;
      pressedKeys.current.clear();
      buttons.current = 0;
      await sendCommand(
        {
          action: 'vnc.connect',
          sessionId: session.id,
          nodeId: session.nodeId,
          host: session.host,
          port: session.port,
          ...(providedPassword === undefined ? {} : { password: providedPassword }),
        },
        true,
      );
    },
    [sendCommand, session.host, session.id, session.nodeId, session.port],
  );

  const queuePointerMove = useCallback(
    (command: PointerCommand) => {
      const generation = pointerMoveGeneration.current;
      pendingPointerMove.current = { generation, command };
      if (pointerMoveSending.current === generation) return;

      pointerMoveSending.current = generation;
      void (async () => {
        try {
          while (pendingPointerMove.current?.generation === generation) {
            const next = pendingPointerMove.current.command;
            pendingPointerMove.current = null;
            await sendCommand({
              action: 'vnc.pointer',
              sessionId: session.id,
              x: next.x,
              y: next.y,
              buttons: next.buttons,
            });
          }
        } finally {
          if (pointerMoveSending.current === generation) {
            pointerMoveSending.current = null;
          }
        }
      })();
    },
    [sendCommand, session.id],
  );

  useEffect(() => {
    const api = window.wormhole;
    if (!api) {
      setStatus('failed');
      setMessage('The native VNC bridge is unavailable.');
      return;
    }

    let mounted = true;
    const unsubscribe = api.onBackendEvent((event) => {
      if (!mounted || event.sessionId !== session.id) return;
      if (event.type === 'vnc.frame' && event.image) {
        setFrame(event.image);
        setFrameSize({ width: event.width ?? 0, height: event.height ?? 0 });
        return;
      }
      if (event.type !== 'vnc.status') return;
      const nextStatus = event.status as VncStatus | undefined;
      if (!nextStatus) return;
      setStatus(nextStatus);
      setMessage(event.message ?? '');
      setPasswordRequired(Boolean(event.passwordRequired));
    });

    void connect();
    const pressedKeysForCleanup = pressedKeys.current;
    return () => {
      mounted = false;
      unsubscribe();
      for (const keySym of pressedKeysForCleanup.values()) {
        void sendCommand({ action: 'vnc.key', sessionId: session.id, down: false, keysym: keySym });
      }
      pressedKeysForCleanup.clear();
      pointerMoveGeneration.current += 1;
      pendingPointerMove.current = null;
      buttons.current = 0;
      void sendCommand({ action: 'vnc.disconnect', sessionId: session.id });
    };
  }, [connect, sendCommand, session.id]);

  function mapPointer(event: PointerLocation): { x: number; y: number } | undefined {
    const image = imageRef.current;
    if (!image || frameSize.width <= 0 || frameSize.height <= 0) return undefined;
    const bounds = image.getBoundingClientRect();
    if (bounds.width <= 0 || bounds.height <= 0) return undefined;
    if (
      event.clientX < bounds.left ||
      event.clientX > bounds.right ||
      event.clientY < bounds.top ||
      event.clientY > bounds.bottom
    ) {
      return undefined;
    }
    const point = {
      x: Math.max(
        0,
        Math.min(
          frameSize.width - 1,
          Math.floor(((event.clientX - bounds.left) / bounds.width) * frameSize.width),
        ),
      ),
      y: Math.max(
        0,
        Math.min(
          frameSize.height - 1,
          Math.floor(((event.clientY - bounds.top) / bounds.height) * frameSize.height),
        ),
      ),
    };
    lastPointer.current = point;
    return point;
  }

  function sendPointer(
    event: PointerEvent<HTMLDivElement>,
    nextButtons: number,
    coalesceMove = false,
  ) {
    const point = mapPointer(event) ?? (nextButtons === 0 ? lastPointer.current : undefined);
    if (!point) return;
    const command = {
      action: 'vnc.pointer',
      sessionId: session.id,
      x: point.x,
      y: point.y,
      buttons: nextButtons,
    } satisfies WormholeVncCommand;
    if (coalesceMove) {
      queuePointerMove({ x: point.x, y: point.y, buttons: nextButtons });
      return;
    }
    pendingPointerMove.current = null;
    void sendCommand(command);
  }

  function onPointerDown(event: PointerEvent<HTMLDivElement>) {
    if (isFormInteraction(event.target)) return;
    surfaceRef.current?.focus();
    event.currentTarget.setPointerCapture(event.pointerId);
    buttons.current = pointerMask(event);
    sendPointer(event, buttons.current);
  }

  function onPointerMove(event: PointerEvent<HTMLDivElement>) {
    if (isFormInteraction(event.target)) return;
    sendPointer(event, buttons.current, true);
  }

  function onPointerUp(event: PointerEvent<HTMLDivElement>) {
    if (isFormInteraction(event.target)) return;
    buttons.current = pointerMask(event);
    sendPointer(event, buttons.current);
    if (buttons.current === 0 && event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }

  function onWheel(event: React.WheelEvent<HTMLDivElement>) {
    if (isFormInteraction(event.target)) return;
    event.preventDefault();
    const wheelMask =
      event.deltaY < 0
        ? 8
        : event.deltaY > 0
          ? 16
          : event.deltaX > 0
            ? 64
            : event.deltaX < 0
              ? 32
              : 0;
    if (wheelMask === 0) return;
    const point = mapPointer(event);
    if (!point) return;
    pendingPointerMove.current = null;
    void sendCommand({
      action: 'vnc.pointer',
      sessionId: session.id,
      x: point.x,
      y: point.y,
      buttons: buttons.current | wheelMask,
    });
    void sendCommand({
      action: 'vnc.pointer',
      sessionId: session.id,
      x: point.x,
      y: point.y,
      buttons: buttons.current,
    });
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.target !== event.currentTarget) return;
    const keySym = keySymbol(event.nativeEvent);
    if (keySym === undefined) return;
    event.preventDefault();
    if (!event.repeat) pressedKeys.current.set(event.code, keySym);
    void sendCommand({ action: 'vnc.key', sessionId: session.id, down: true, keysym: keySym });
  }

  function onKeyUp(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.target !== event.currentTarget) return;
    const keySym = pressedKeys.current.get(event.code) ?? keySymbol(event.nativeEvent);
    if (keySym === undefined) return;
    event.preventDefault();
    pressedKeys.current.delete(event.code);
    void sendCommand({ action: 'vnc.key', sessionId: session.id, down: false, keysym: keySym });
  }

  function releaseKeys() {
    for (const keySym of pressedKeys.current.values()) {
      void sendCommand({ action: 'vnc.key', sessionId: session.id, down: false, keysym: keySym });
    }
    pressedKeys.current.clear();
  }

  function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = password;
    setPassword('');
    void connect(value);
  }

  const showPasswordPrompt = status === 'failed' && passwordRequired;
  const displayHost = session.host || 'inherited target';

  return (
    <div
      ref={surfaceRef}
      aria-label={`VNC session for ${displayHost}`}
      className="relative flex min-h-0 flex-1 items-center justify-center overflow-hidden bg-[#0c0c0c] outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
      onBlur={releaseKeys}
      onKeyDown={onKeyDown}
      onKeyUp={onKeyUp}
      onPointerCancel={onPointerUp}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onWheel={onWheel}
      tabIndex={0}
    >
      {frame ? (
        <img
          ref={imageRef}
          alt={`Remote desktop from ${displayHost}`}
          className="max-h-full max-w-full select-none object-contain"
          draggable={false}
          src={frame}
        />
      ) : null}

      {status === 'connecting' ? (
        <div className="absolute inset-0 grid place-items-center bg-[#0c0c0c] text-center text-muted-foreground">
          <div className="grid justify-items-center gap-3">
            <LoaderCircle className="size-7 animate-spin" />
            <div>
              <p className="text-sm font-medium text-foreground">Connecting to VNC</p>
              <p className="mt-1 text-xs">
                {displayHost}:{session.port ?? 5900}
              </p>
            </div>
          </div>
        </div>
      ) : null}

      {status === 'failed' || status === 'disconnected' ? (
        <div className="absolute inset-0 grid place-items-center bg-[#0c0c0c]/95 p-6 text-center">
          <div className="grid w-full max-w-sm justify-items-center gap-3">
            {status === 'failed' ? (
              <AlertCircle className="size-8 text-destructive" />
            ) : (
              <Monitor className="size-8 text-muted-foreground" />
            )}
            <div>
              <p className="text-sm font-medium text-foreground">
                {status === 'failed' ? 'VNC connection failed' : 'VNC disconnected'}
              </p>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                {message ||
                  (status === 'failed'
                    ? 'The remote desktop could not be opened.'
                    : 'The remote host closed the connection.')}
              </p>
            </div>
            {showPasswordPrompt ? (
              <form className="grid w-full gap-2 text-left" onSubmit={submitPassword}>
                <label className="text-xs font-medium" htmlFor={`vnc-password-${session.id}`}>
                  VNC password
                </label>
                <div className="flex gap-2">
                  <Input
                    autoFocus
                    id={`vnc-password-${session.id}`}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="Enter password"
                    type="password"
                    value={password}
                  />
                  <Button disabled={!password} type="submit">
                    <KeyRound data-icon="inline-start" />
                    Connect
                  </Button>
                </div>
              </form>
            ) : (
              <Button onClick={() => void connect()} variant="outline">
                <RefreshCcw data-icon="inline-start" />
                Reconnect
              </Button>
            )}
          </div>
        </div>
      ) : null}

      {status === 'idle' ? (
        <p className="absolute text-xs text-muted-foreground">Waiting for native VNC backend…</p>
      ) : null}
    </div>
  );
}
