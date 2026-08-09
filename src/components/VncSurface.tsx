import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
  type PointerEvent,
} from 'react';
import { AlertCircle, KeyRound, LoaderCircle, Monitor, RefreshCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { isBitwardenUnlockError } from '@/runtime-credential-errors';
import { ConnectionStepper, type TunnelProgress } from './ConnectionStepper';

type PointerLocation = Pick<PointerEvent<HTMLDivElement>, 'clientX' | 'clientY'>;
type PointerCommand = { x: number; y: number; buttons: number };
type PendingPointerMove = { generation: number; command: PointerCommand };

export type VncSurfaceSession = {
  id: string;
  nodeId?: string;
  credentialId?: string;
  tunnelConfigId?: string;
  host: string;
  port?: number;
  tunnelProgress?: TunnelProgress | null;
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

// VNC input, frame, connection, tunnel, and credential flows share one native session lifetime;
// independent state setters avoid coupling high-frequency frames to low-frequency auth transitions.
// react-doctor-disable-next-line react-doctor/no-giant-component, react-doctor/prefer-useReducer
export function VncSurface({
  isAuthorized,
  session,
  connectionGeneration,
  disconnected,
  bitwardenUnlockPending,
  onBitwardenUnlockRequired,
  onReconnect,
  onStatusChange,
}: {
  isAuthorized: boolean;
  session: VncSurfaceSession;
  connectionGeneration: number;
  disconnected: boolean;
  bitwardenUnlockPending: boolean;
  onBitwardenUnlockRequired?: (reason: string, retry: () => void) => void;
  onReconnect?: () => void;
  onStatusChange?: (status: VncStatus) => void;
  // react-doctor-disable-next-line react-doctor/prefer-useReducer
}) {
  const [status, setStatus] = useState<VncStatus>(disconnected ? 'disconnected' : 'idle');
  const [message, setMessage] = useState(disconnected ? 'The session was disconnected.' : '');
  const [passwordRequired, setPasswordRequired] = useState(false);
  const [bitwardenUnlockRequired, setBitwardenUnlockRequired] = useState(false);
  const [password, setPassword] = useState('');
  const [tunnelProgress, setTunnelProgress] = useState<TunnelProgress | null>(null);
  const [frame, setFrame] = useState<string>();
  const frameSize = useRef({ width: 0, height: 0 });
  const imageRef = useRef<HTMLImageElement>(null);
  const surfaceRef = useRef<HTMLDivElement>(null);
  const pressedKeys = useRef(new Map<string, number>());
  const lastPointer = useRef<{ x: number; y: number } | null>(null);
  const pointerMoveGeneration = useRef(0);
  const connectAttempt = useRef(0);
  const pendingPointerMove = useRef<PendingPointerMove | null>(null);
  const pointerMoveSending = useRef<number | null>(null);
  const buttons = useRef(0);
  const connectRef = useRef<(providedPassword?: string) => Promise<void>>(() => Promise.resolve());
  const onStatusChangeRef = useRef(onStatusChange);
  const bitwardenUnlockRequestRef = useRef({ isAuthorized, onBitwardenUnlockRequired });

  useLayoutEffect(() => {
    onStatusChangeRef.current = onStatusChange;
    bitwardenUnlockRequestRef.current = { isAuthorized, onBitwardenUnlockRequired };
  }, [isAuthorized, onBitwardenUnlockRequired, onStatusChange]);

  // Disconnection is an external native lifecycle transition, and authorization loss must scrub
  // the renderer-held password immediately. Synchronizing those boundaries cannot be derived from
  // the local VNC event stream alone.
  // react-doctor-disable-next-line react-hooks-js/set-state-in-effect
  useEffect(() => {
    if (!isAuthorized) {
      setPassword(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
      setPasswordRequired(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
      setBitwardenUnlockRequired(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    }
    if (!disconnected) return;
    connectAttempt.current += 1;
    setStatus('disconnected'); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setMessage('The session was disconnected.'); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setPasswordRequired(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setBitwardenUnlockRequired(false); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setPassword(''); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setTunnelProgress(null); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    setFrame(undefined); // react-doctor-disable-line react-doctor/no-adjust-state-on-prop-change
    frameSize.current = { width: 0, height: 0 };
    lastPointer.current = null;
    pointerMoveGeneration.current += 1;
    pendingPointerMove.current = null;
    pressedKeys.current.clear();
    buttons.current = 0;
  }, [disconnected, isAuthorized]);

  const updateStatus = useCallback((nextStatus: VncStatus) => {
    setStatus(nextStatus);
    onStatusChangeRef.current?.(nextStatus);
  }, []);
  const notifyBitwardenUnlockRequired = useCallback((reason: string) => {
    const request = bitwardenUnlockRequestRef.current;
    if (!request.isAuthorized) return;
    request.onBitwardenUnlockRequired?.(reason, () => void connectRef.current());
  }, []);
  const applyBitwardenUnlockRequirement = useCallback(
    (error: string | undefined, reason: string): boolean => {
      const unlockRequired = isBitwardenUnlockError(error);
      const promptAllowed = unlockRequired && bitwardenUnlockRequestRef.current.isAuthorized;
      setBitwardenUnlockRequired(promptAllowed);
      if (promptAllowed) notifyBitwardenUnlockRequired(reason);
      return unlockRequired;
    },
    [notifyBitwardenUnlockRequired],
  );

  const sendCommand = useCallback(
    async (
      command: WormholeVncCommand,
      showError = false,
      expectedConnectAttempt?: number,
    ): Promise<boolean> => {
      const canShowError = () =>
        showError &&
        (expectedConnectAttempt === undefined || connectAttempt.current === expectedConnectAttempt);
      const api = window.wormhole;
      if (!api) {
        if (canShowError()) {
          updateStatus('failed');
          setMessage('The VNC service is unavailable.');
        }
        return false;
      }
      try {
        const response = await api.sendVncCommand(command);
        if (!response.ok && canShowError()) {
          const message = response.error ?? 'The VNC request could not be completed.';
          updateStatus('failed');
          setMessage(message);
          const unlockRequired = applyBitwardenUnlockRequirement(response.error, message);
          setPasswordRequired(!unlockRequired && isAuthenticationMessage(response.error));
        }
        return response.ok;
      } catch (error) {
        if (canShowError()) {
          updateStatus('failed');
          const message = error instanceof Error ? error.message : 'The VNC service failed.';
          setMessage(message);
          applyBitwardenUnlockRequirement(message, message);
        }
        return false;
      }
    },
    [applyBitwardenUnlockRequirement, updateStatus],
  );

  const connect = useCallback(
    async (providedPassword?: string) => {
      const attempt = connectAttempt.current + 1;
      connectAttempt.current = attempt;
      updateStatus('connecting');
      setMessage('');
      setPasswordRequired(false);
      setBitwardenUnlockRequired(false);
      setFrame(undefined);
      frameSize.current = { width: 0, height: 0 };
      setTunnelProgress(null);
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
          credentialId: session.credentialId,
          tunnelConfigId: session.tunnelConfigId,
          host: session.host,
          port: session.port,
          ...(providedPassword === undefined
            ? {}
            : { password: providedPassword, passwordProvided: true }),
        },
        true,
        attempt,
      );
    },
    [
      sendCommand,
      session.credentialId,
      session.host,
      session.id,
      session.nodeId,
      session.port,
      session.tunnelConfigId,
      updateStatus,
    ],
  );

  useLayoutEffect(() => {
    connectRef.current = connect;
  }, [connect]);

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
      updateStatus('failed');
      setMessage('The VNC service is unavailable.');
      return;
    }

    let mounted = true;
    const unsubscribe = api.onBackendEvent((event) => {
      if (!mounted || event.sessionId !== session.id) return;
      if (event.type === 'tunnel.progress' && event.phase) {
        setTunnelProgress({ phase: event.phase, detail: event.detail });
        return;
      }
      if (event.type === 'vnc.frame' && event.image) {
        setFrame(event.image);
        frameSize.current = { width: event.width ?? 0, height: event.height ?? 0 };
        return;
      }
      if (event.type !== 'vnc.status') return;
      const nextStatus = event.status as VncStatus | undefined;
      if (!nextStatus) return;
      const message = event.message ?? '';
      updateStatus(nextStatus);
      setMessage(message);
      const unlockRequired = applyBitwardenUnlockRequirement(event.message, message);
      setPasswordRequired(!unlockRequired && Boolean(event.passwordRequired));
    });

    if (!disconnected) void connect();
    const pressedKeysForCleanup = pressedKeys.current;
    return () => {
      mounted = false;
      unsubscribe();
      setTunnelProgress(null);
      for (const keySym of pressedKeysForCleanup.values()) {
        void sendCommand({ action: 'vnc.key', sessionId: session.id, down: false, keysym: keySym });
      }
      pressedKeysForCleanup.clear();
      pointerMoveGeneration.current += 1;
      connectAttempt.current += 1;
      pendingPointerMove.current = null;
      buttons.current = 0;
    };
  }, [
    connect,
    connectionGeneration,
    disconnected,
    applyBitwardenUnlockRequirement,
    sendCommand,
    session.id,
    updateStatus,
  ]);

  function mapPointer(event: PointerLocation): { x: number; y: number } | undefined {
    const image = imageRef.current;
    const sourceSize = frameSize.current;
    if (!image || sourceSize.width <= 0 || sourceSize.height <= 0) return undefined;
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
          sourceSize.width - 1,
          Math.floor(((event.clientX - bounds.left) / bounds.width) * sourceSize.width),
        ),
      ),
      y: Math.max(
        0,
        Math.min(
          sourceSize.height - 1,
          Math.floor(((event.clientY - bounds.top) / bounds.height) * sourceSize.height),
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

  async function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = password;
    setPassword('');
    if (bitwardenUnlockRequired) {
      try {
        await window.wormhole?.unlockBitwardenCli(value);
        await connect();
      } catch (error: unknown) {
        const message =
          error instanceof Error ? error.message : 'Bitwarden could not unlock the vault.';
        updateStatus('failed');
        setMessage(message);
        applyBitwardenUnlockRequirement(message, message);
      }
      return;
    }
    await connect(value);
  }

  const globalBitwardenUnlockPending =
    isAuthorized && bitwardenUnlockRequired && bitwardenUnlockPending;
  const showPasswordPrompt =
    status === 'failed' &&
    (passwordRequired || (bitwardenUnlockRequired && !globalBitwardenUnlockPending));
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
      role="application"
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
          {tunnelProgress ? (
            <ConnectionStepper tunnelProgress={tunnelProgress} />
          ) : (
            <div className="grid justify-items-center gap-3">
              <LoaderCircle className="size-7 animate-spin" />
              <div>
                <p className="text-sm font-medium text-foreground">Connecting to VNC</p>
                <p className="mt-1 text-xs">
                  {displayHost}:{session.port ?? 5900}
                </p>
              </div>
            </div>
          )}
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
            {globalBitwardenUnlockPending ? (
              <p className="text-xs text-muted-foreground">
                Unlock Bitwarden in the shared prompt to continue this session.
              </p>
            ) : showPasswordPrompt ? (
              <form className="grid w-full gap-2 text-left" onSubmit={submitPassword}>
                <label className="text-xs font-medium" htmlFor={`vnc-password-${session.id}`}>
                  {bitwardenUnlockRequired ? 'Bitwarden master password' : 'VNC password'}
                </label>
                <div className="flex gap-2">
                  <Input
                    autoFocus
                    id={`vnc-password-${session.id}`}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder={
                      bitwardenUnlockRequired ? 'Unlock the Bitwarden vault' : 'Enter password'
                    }
                    type="password"
                    value={password}
                  />
                  <Button disabled={bitwardenUnlockRequired && !password} type="submit">
                    <KeyRound data-icon="inline-start" />
                    {bitwardenUnlockRequired ? 'Unlock and connect' : 'Connect'}
                  </Button>
                </div>
              </form>
            ) : (
              <Button
                onClick={() => (disconnected ? onReconnect?.() : void connect())}
                variant="outline"
              >
                <RefreshCcw data-icon="inline-start" />
                Reconnect
              </Button>
            )}
          </div>
        </div>
      ) : null}

      {status === 'idle' ? (
        <p className="absolute text-xs text-muted-foreground">Preparing the VNC connection…</p>
      ) : null}
    </div>
  );
}
