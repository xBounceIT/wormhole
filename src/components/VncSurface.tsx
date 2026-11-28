import { vncConnectRequest } from '@/vnc-connect';
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type PointerEvent,
} from 'react';
import { AlertCircle, KeyRound, Monitor, RefreshCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { PasswordInput } from '@/components/ui/password-input';
import { clearSecretInput, takeOneShotSecret } from '@/secret-input';
import { formatBitwardenAuthenticationError } from '@/bitwarden-cli-view';
import { isBitwardenUnlockError } from '@/runtime-credential-errors';
import {
  ConnectionLoading,
  ConnectionTransition,
  type TunnelProgress,
} from './ConnectionTransition';

type PointerLocation = Pick<PointerEvent<HTMLDivElement>, 'clientX' | 'clientY'>;
type PointerCommand = { x: number; y: number; buttons: number };
type PendingPointerMove = { generation: number; command: PointerCommand };

export type VncSurfaceSession = {
  id: string;
  title?: string;
  nodeId?: string;
  manualPassword?: boolean;
  quickTarget?: import('../../electron/vault-quick-target').VaultQuickTarget;
  credentialId?: string;
  tunnelConfigId?: string;
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

async function sendNativeCommand(command: WormholeVncCommand) {
  try {
    if (!window.wormhole) return { ok: false, error: 'The VNC service is unavailable.' };
    return await window.wormhole.sendVncCommand(command);
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'The VNC service failed.' };
  }
}

type VncSurfaceProps = {
  isAuthorized: boolean;
  vault?: boolean;
  session: VncSurfaceSession;
  connectionGeneration: number;
  disconnected: boolean;
  bitwardenUnlockPending: boolean;
  onBitwardenUnlockRequired?: (reason: string, retry: () => void) => void;
  onReconnect?: () => void;
  onStatusChange?: (status: VncStatus, manualPassword?: boolean) => void;
  managed?: {
    status: 'opening' | 'connected' | 'failed' | 'closing';
    error?: string;
    canReconnect: boolean;
    active: boolean;
    ready: () => void;
    label?: string;
    passwordRequired?: boolean;
    manualReconnect?: () => void;
  };
};

export function VncSurface({
  connectionGeneration,
  isAuthorized,
  vault = false,
  managed,
  session,
  disconnected,
  bitwardenUnlockPending,
  onBitwardenUnlockRequired,
  onReconnect,
  onStatusChange,
}: VncSurfaceProps) {
  const managedRef = useRef(managed);
  const controlled = managed !== undefined;
  useLayoutEffect(() => {
    managedRef.current = managed;
  }, [managed]);
  const initialStatus = !window.wormhole ? 'failed' : disconnected ? 'disconnected' : 'connecting';
  const initialMessage = !window.wormhole
    ? 'The VNC service is unavailable.'
    : disconnected
      ? 'The session was disconnected.'
      : '';
  const [status, setStatus] = useState<VncStatus>(initialStatus);
  const [message, setMessage] = useState(initialMessage);
  const [passwordRequired, setPasswordRequired] = useState(false);
  const [bitwardenUnlockRequired, setBitwardenUnlockRequired] = useState(false);
  const [hasPassword, setHasPassword] = useState(false);
  const passwordInput = useRef<HTMLInputElement>(null);
  const bindPasswordInput = useCallback((input: HTMLInputElement | null) => {
    clearSecretInput(passwordInput.current);
    passwordInput.current = input;
    setHasPassword(false);
  }, []);
  const [tunnelProgress, setTunnelProgress] = useState<TunnelProgress | null>(null);
  const [frame, setFrame] = useState<string>();
  const [hasLoadedFrame, setHasLoadedFrame] = useState(false);
  const frameSize = useRef({ width: 0, height: 0 });
  const imageRef = useRef<HTMLImageElement>(null);
  const surfaceRef = useRef<HTMLDivElement>(null);
  const pressedKeys = useRef(new Map<string, number>());
  const lastPointer = useRef<{ x: number; y: number } | null>(null);
  const pointerMoveGeneration = useRef(0);
  const connectAttempt = useRef(0);
  const [authLifetime, setAuthLifetime] = useState({ isAuthorized, vault });
  const pendingPointerMove = useRef<PendingPointerMove | null>(null);
  const pointerMoveSending = useRef<number | null>(null);
  const buttons = useRef(0);
  const connectRef = useRef<(providedPassword?: string) => Promise<void>>(() => Promise.resolve());
  const onStatusChangeRef = useRef(onStatusChange);
  const bitwardenUnlockRequestRef = useRef({ authLifetime, onBitwardenUnlockRequired });

  useLayoutEffect(() => {
    onStatusChangeRef.current = onStatusChange;
    bitwardenUnlockRequestRef.current = { authLifetime, onBitwardenUnlockRequired };
  }, [authLifetime, onBitwardenUnlockRequired, onStatusChange]);

  if (authLifetime.isAuthorized !== isAuthorized || authLifetime.vault !== vault) {
    setAuthLifetime({ isAuthorized, vault });
    if (!isAuthorized || vault) {
      setPasswordRequired(false);
      setBitwardenUnlockRequired(false);
    }
  }

  const updateStatus = useCallback((nextStatus: VncStatus) => {
    setStatus(nextStatus);
    onStatusChangeRef.current?.(nextStatus);
  }, []);
  const notifyBitwardenUnlockRequired = useCallback((reason: string) => {
    const request = bitwardenUnlockRequestRef.current;
    if (!request.authLifetime.isAuthorized) return;
    const attempt = connectAttempt.current;
    request.onBitwardenUnlockRequired?.(reason, () => {
      if (
        attempt === connectAttempt.current &&
        bitwardenUnlockRequestRef.current.authLifetime === request.authLifetime
      ) {
        void connectRef.current();
      }
    });
  }, []);
  const applyBitwardenUnlockRequirement = useCallback(
    (error: string | undefined, reason: string): boolean => {
      const unlockRequired = isBitwardenUnlockError(error);
      const promptAllowed =
        unlockRequired &&
        bitwardenUnlockRequestRef.current.authLifetime.isAuthorized &&
        !bitwardenUnlockRequestRef.current.authLifetime.vault;
      setBitwardenUnlockRequired(promptAllowed);
      if (promptAllowed) notifyBitwardenUnlockRequired(reason);
      return unlockRequired;
    },
    [notifyBitwardenUnlockRequired],
  );

  const sendCommand = useCallback((command: WormholeVncCommand) => {
    const control = managedRef.current;
    const releasing =
      (command.action === 'vnc.key' && command.down === false) ||
      (command.action === 'vnc.pointer' && command.buttons === 0);
    if (
      control &&
      command.action !== 'vnc.disconnect' &&
      (command.action === 'vnc.connect' || (!releasing && !control.active))
    ) {
      return Promise.resolve({ ok: false, error: 'Managed VNC session is inactive.' });
    }
    return sendNativeCommand(command);
  }, []);

  const manualPasswordMode = useRef({
    sessionId: session.id,
    enabled: session.manualPassword === true,
  });
  useLayoutEffect(() => {
    if (manualPasswordMode.current.sessionId !== session.id || session.manualPassword !== undefined)
      manualPasswordMode.current = {
        sessionId: session.id,
        enabled: session.manualPassword === true,
      };
  }, [session.id, session.manualPassword]);
  const {
    protocol: quickProtocol,
    host: quickHost,
    port: quickPort,
    credentialId: quickCredentialId,
    tunnelId: quickTunnelId,
    sshAutoSudo: quickSudo,
    httpPath: quickPath,
    ignoreCertificateErrors: quickIgnoreCertificateErrors,
    rdp: quickRdp,
  } = session.quickTarget ?? {};

  const target = useMemo(
    () => ({
      id: session.id,
      quickTarget: quickProtocol
        ? {
            protocol: quickProtocol!,
            host: quickHost!,
            port: quickPort!,
            credentialId: quickCredentialId!,
            tunnelId: quickTunnelId!,
            sshAutoSudo: quickSudo!,
            httpPath: quickPath!,
            ignoreCertificateErrors: quickIgnoreCertificateErrors!,
            rdp: quickRdp!,
          }
        : undefined,

      nodeId: session.nodeId,
      credentialId: session.credentialId,
      tunnelConfigId: session.tunnelConfigId,
      host: session.host,
      port: session.port,
    }),
    [
      session.credentialId,
      session.host,
      session.id,
      session.nodeId,
      quickProtocol,
      quickHost,
      quickPort,
      quickCredentialId,
      quickTunnelId,
      quickSudo,
      quickPath,
      quickIgnoreCertificateErrors,
      quickRdp,
      session.port,
      session.tunnelConfigId,
    ],
  );
  const connect = useCallback(
    async (providedPassword?: string, manualPassword = false) => {
      const attempt = connectAttempt.current + 1;
      connectAttempt.current = attempt;
      frameSize.current = { width: 0, height: 0 };
      lastPointer.current = null;
      pointerMoveGeneration.current += 1;
      pendingPointerMove.current = null;
      pressedKeys.current.clear();
      buttons.current = 0;
      let request: ReturnType<typeof sendCommand>;
      try {
        const command = vncConnectRequest(
          target,
          vault,
          providedPassword,
          manualPassword ||
            (vault &&
              manualPasswordMode.current.sessionId === target.id &&
              manualPasswordMode.current.enabled),
        );
        if (vault && command.action === 'vnc.connect') {
          manualPasswordMode.current = {
            sessionId: target.id,
            enabled: command.manualPassword === true,
          };
          onStatusChangeRef.current?.('connecting', command.manualPassword === true);
        } else {
          onStatusChangeRef.current?.('connecting');
        }
        request = sendCommand(command);
      } catch (error) {
        request = Promise.resolve({
          ok: false,
          error: error instanceof Error ? error.message : 'The VNC request is invalid.',
        });
      }
      const response = await request;
      if (connectAttempt.current !== attempt || response.ok) return;
      const message = response.error ?? 'The VNC request could not be completed.';
      updateStatus('failed');
      setMessage(message);
      const unlockRequired = applyBitwardenUnlockRequirement(response.error, message);
      if (!vault) setPasswordRequired(!unlockRequired && isAuthenticationMessage(response.error));
    },
    [applyBitwardenUnlockRequirement, sendCommand, updateStatus, target, vault],
  );

  const resetConnectionView = useCallback((nextStatus: VncStatus, nextMessage: string) => {
    setStatus(nextStatus);
    setMessage(nextMessage);
    setPasswordRequired(false);
    setBitwardenUnlockRequired(false);
    setFrame(undefined);
    setHasLoadedFrame(false);
    setTunnelProgress(null);
  }, []);

  // Keep the desktop mounted while retiring the previous connection's frame and prompts.
  const [connection, setConnection] = useState({ target, connectionGeneration, disconnected });
  if (
    connection.target !== target ||
    connection.connectionGeneration !== connectionGeneration ||
    connection.disconnected !== disconnected
  ) {
    setConnection({ target, connectionGeneration, disconnected });
    resetConnectionView(initialStatus, initialMessage);
  }

  const retryConnection = useCallback(
    (providedPassword?: string, manualPassword = false) => {
      if (!window.wormhole) {
        updateStatus('failed');
        setMessage('The VNC service is unavailable.');
        return Promise.resolve();
      }
      resetConnectionView('connecting', '');
      return connect(providedPassword, manualPassword);
    },
    [connect, resetConnectionView, updateStatus],
  );

  useLayoutEffect(() => {
    connectRef.current = retryConnection;
    return () => {
      connectAttempt.current++;
      connectRef.current = () => Promise.resolve();
    };
  }, [retryConnection, connectionGeneration, disconnected]);

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
      onStatusChangeRef.current?.('failed');
      return;
    }

    let mounted = true;
    const unsubscribe = api.onBackendEvent((event) => {
      if (!mounted || disconnected || event.sessionId !== session.id) return;
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

    if (controlled) managedRef.current?.ready();
    else if (!disconnected) void connect();
    const pressedKeysForCleanup = pressedKeys.current;
    return () => {
      mounted = false;
      unsubscribe();
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
    controlled,
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

  const releaseKeys = useCallback(() => {
    for (const keySym of pressedKeys.current.values()) {
      void sendCommand({ action: 'vnc.key', sessionId: session.id, down: false, keysym: keySym });
    }
    pressedKeys.current.clear();
  }, [sendCommand, session.id]);

  async function submitPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!isAuthorized || disconnected || !passwordInput.current) return;
    const value = takeOneShotSecret(passwordInput.current);
    setHasPassword(false);
    if (bitwardenUnlockRequired) {
      if (!value) return;
      const attempt = connectAttempt.current;
      const isCurrent = () =>
        attempt === connectAttempt.current &&
        authLifetime === bitwardenUnlockRequestRef.current.authLifetime;
      try {
        await window.wormhole?.unlockBitwardenCli(value);
        if (!isCurrent()) return;
        await connectRef.current();
      } catch (error: unknown) {
        if (!isCurrent()) return;
        const message = formatBitwardenAuthenticationError(error, 'unlock');
        updateStatus('failed');
        setMessage(message);
        setBitwardenUnlockRequired(true);
        notifyBitwardenUnlockRequired(message);
      }
      return;
    }
    await retryConnection(value);
  }

  useLayoutEffect(() => {
    if (!controlled || managed?.active) return;
    pointerMoveGeneration.current += 1;
    pendingPointerMove.current = null;
    releaseKeys();
    const point = lastPointer.current;
    if (buttons.current && point)
      void sendCommand({ action: 'vnc.pointer', sessionId: session.id, ...point, buttons: 0 });
    buttons.current = 0;
  }, [controlled, managed?.active, releaseKeys, sendCommand, session.id]);
  const viewStatus = managed
    ? managed.status === 'opening'
      ? 'connecting'
      : managed.status === 'closing'
        ? 'disconnected'
        : managed.status
    : status;
  const viewMessage = managed?.error ?? message;

  const globalBitwardenUnlockPending =
    isAuthorized && bitwardenUnlockRequired && bitwardenUnlockPending && !vault;
  const showPasswordPrompt =
    isAuthorized &&
    !vault &&
    status === 'failed' &&
    (passwordRequired || (bitwardenUnlockRequired && !globalBitwardenUnlockPending));
  const displayHost = managed?.label ?? (session.host || 'inherited target');
  const loading =
    viewStatus === 'idle' ||
    viewStatus === 'connecting' ||
    (viewStatus === 'connected' && !hasLoadedFrame);

  return (
    <ConnectionTransition
      connected={viewStatus === 'connected'}
      pending={
        loading ? (
          <ConnectionLoading
            destination={controlled ? managed?.label : session.host}
            inheritedTarget={Boolean(session.nodeId)}
            name={session.title}
            port={session.port ?? (session.nodeId ? undefined : 5900)}
            protocol="VNC"
            status={
              viewStatus === 'connected' ? 'Waiting for the remote desktop…' : 'Connecting to VNC…'
            }
            tunnelProgress={viewStatus === 'connecting' ? tunnelProgress : undefined}
          />
        ) : null
      }
    >
      {(covered) => {
        const interactive = viewStatus === 'connected' && isAuthorized && !covered;
        return (
          <div
            ref={surfaceRef}
            aria-label={`VNC session for ${displayHost}`}
            className="relative flex h-full min-h-0 items-center justify-center overflow-hidden bg-[#0c0c0c] outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
            onBlur={releaseKeys}
            onKeyDown={interactive ? onKeyDown : undefined}
            onKeyUp={interactive ? onKeyUp : undefined}
            onPointerCancel={interactive ? onPointerUp : undefined}
            onPointerDown={interactive ? onPointerDown : undefined}
            onPointerMove={interactive ? onPointerMove : undefined}
            onPointerUp={interactive ? onPointerUp : undefined}
            onWheel={interactive ? onWheel : undefined}
            role="application"
            tabIndex={interactive ? 0 : -1}
          >
            {frame ? (
              <img
                ref={imageRef}
                alt={`Remote desktop from ${displayHost}`}
                className="max-h-full max-w-full select-none object-contain"
                draggable={false}
                onLoad={hasLoadedFrame ? undefined : () => setHasLoadedFrame(true)}
                src={frame}
              />
            ) : null}

            {viewStatus === 'failed' || viewStatus === 'disconnected' ? (
              <div className="absolute inset-0 grid place-items-center overflow-auto bg-canvas p-6 text-center text-foreground">
                <div className="grid w-full max-w-sm justify-items-center gap-3">
                  {viewStatus === 'failed' ? (
                    <AlertCircle className="size-8 text-destructive" />
                  ) : (
                    <Monitor className="size-8 text-muted-foreground" />
                  )}
                  <div>
                    <p className="text-sm font-medium text-foreground">
                      {viewStatus === 'failed' ? 'VNC connection failed' : 'VNC disconnected'}
                    </p>
                    <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                      {viewMessage ||
                        (viewStatus === 'failed'
                          ? 'The remote desktop could not be opened.'
                          : 'The remote host closed the connection.')}
                    </p>
                  </div>
                  {vault && (managed ? managed.passwordRequired : passwordRequired) ? (
                    <Button
                      disabled={managed ? !managed.canReconnect : false}
                      onClick={() =>
                        controlled
                          ? managedRef.current?.manualReconnect?.()
                          : void retryConnection(undefined, true)
                      }
                      variant="outline"
                    >
                      <KeyRound data-icon="inline-start" />
                      Enter password securely
                    </Button>
                  ) : null}
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
                        <PasswordInput
                          autoFocus
                          key={bitwardenUnlockRequired ? 'bitwarden' : session.id}
                          id={`vnc-password-${session.id}`}
                          onChange={(event) => setHasPassword(Boolean(event.currentTarget.value))}
                          placeholder={
                            bitwardenUnlockRequired
                              ? 'Unlock the Bitwarden vault'
                              : 'Enter password'
                          }
                          ref={bindPasswordInput}
                        />
                        <Button disabled={bitwardenUnlockRequired && !hasPassword} type="submit">
                          <KeyRound data-icon="inline-start" />
                          {bitwardenUnlockRequired ? 'Unlock and connect' : 'Connect'}
                        </Button>
                      </div>
                    </form>
                  ) : (
                    <Button
                      disabled={managed ? !managed.canReconnect : false}
                      onClick={() =>
                        controlled || disconnected ? onReconnect?.() : void retryConnection()
                      }
                      variant="outline"
                    >
                      <RefreshCcw data-icon="inline-start" />
                      Reconnect
                    </Button>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        );
      }}
    </ConnectionTransition>
  );
}
