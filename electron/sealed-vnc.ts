import {
  parseVaultVncPlan,
  parseVaultVncManualBundle,
  type VaultVncManualRequest,
} from './vault-vnc-manual.ts';
import {
  parseVaultVncPasswordContext,
  parseVaultVncPasswordEnvelope,
  type VaultVncPasswordContext,
  type VaultVncPasswordEnvelope,
} from './vault-vnc-password.ts';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { stopChildProcess } from './rdp.ts';
import { parseVaultNativeObject, vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';
import {
  parseVaultConnectionRoute,
  parseVaultRouteBinding,
  type VaultRoutePlanRequest,
} from './vault-route.ts';
import {
  parseVaultVncBundle,
  parseVaultRoutedVncBundle,
  type VaultVncRequest,
  type VaultVncBundle,
  type VaultRoutedVncRequest,
  type VaultRoutedVncBundle,
} from './vault-vnc.ts';
import type { VaultVNCBitwardenRequest } from './vault-vnc-bitwarden.ts';
import type { SealedRouteBroker, SealedRouteLease } from './sealed-route.ts';

export type SealedVncOpen = {
  sessionId: string;
  nodeId: string;
  credentialId?: string;
  manualPassword?: true;
};
export type SealedVncEvent =
  | {
      type: 'vnc.status';
      sessionId: string;
      status: 'connecting' | 'connected' | 'failed' | 'disconnected';
      message?: string;
      passwordRequired?: boolean;
    }
  | { type: 'vnc.frame'; sessionId: string; width: number; height: number; image: string };

type Options = {
  executable: () => string;
  workspaceId: () => string | undefined;
  authorized: (epoch: number) => boolean;
  bundle: (q: VaultVncRequest) => Promise<VaultVncBundle>;
  bitwarden?: (
    request: VaultVNCBitwardenRequest,
    signal: AbortSignal,
    accepted: () => boolean,
  ) => Promise<VaultVncBundle | VaultRoutedVncBundle | undefined>;
  onEvent: (event: SealedVncEvent) => void;
  route?: {
    resolve: (
      q: VaultRoutePlanRequest,
    ) => Promise<import('./vault-route.ts').VaultRouteBinding | null>;
    broker: Pick<SealedRouteBroker, 'acquire' | 'close'>;
    bundle: (q: VaultRoutedVncRequest) => Promise<VaultRoutedVncBundle>;
  };
  manual?: {
    plan: (q: VaultRoutePlanRequest) => Promise<VaultVncBundle['binding']>;
    prompt: (
      context: VaultVncPasswordContext,
      active: () => boolean,
      signal: AbortSignal,
    ) => Promise<VaultVncPasswordEnvelope>;
    bundle: (q: VaultVncManualRequest) => Promise<VaultVncBundle | VaultRoutedVncBundle>;
  };
  timeoutMs?: number;
};
type Session = {
  request: VaultVncRequest;
  manual?: AbortController;
  bitwarden?: { abort: AbortController; finished: Promise<unknown> };
  owner: () => boolean;
  phase: 'planning' | 'recipient' | 'bundle' | 'connecting' | 'connected' | 'retired';
  child?: ChildProcessWithoutNullStreams;
  route?: SealedRouteLease;
  routePending: boolean;
  chunks: Buffer[];
  bytes: number;
  timer: NodeJS.Timeout;
  resolve: () => void;
  reject: (error: Error) => void;
  terminal: boolean;
  stop?: Promise<void>;
};

export function parseSealedVncEvent(value: unknown, sessionId: string): SealedVncEvent | undefined {
  if (!vaultRecord(value) || value.sessionId !== sessionId) return undefined;
  if (value.type === 'vnc.status') {
    if (
      !vaultFields(value, [
        'type',
        'sessionId',
        'status',
        ...(value.message !== undefined ? ['message'] : []),
        ...(value.passwordRequired !== undefined ? ['passwordRequired'] : []),
      ]) ||
      !['connecting', 'connected', 'failed', 'disconnected'].includes(value.status as string) ||
      (value.message !== undefined &&
        value.message !==
          (value.status === 'failed'
            ? 'VNC connection failed'
            : value.status === 'disconnected'
              ? 'VNC connection closed'
              : '')) ||
      (value.passwordRequired !== undefined &&
        (value.status !== 'failed' || typeof value.passwordRequired !== 'boolean'))
    )
      return undefined;
    return {
      type: 'vnc.status',
      sessionId,
      status: value.status as 'connecting' | 'connected' | 'failed' | 'disconnected',
      ...(value.message !== undefined ? { message: value.message as string } : {}),
      ...(value.passwordRequired !== undefined
        ? { passwordRequired: value.passwordRequired as boolean }
        : {}),
    };
  }
  if (
    value.type !== 'vnc.frame' ||
    !vaultFields(value, ['type', 'sessionId', 'width', 'height', 'image']) ||
    !Number.isInteger(value.width) ||
    !Number.isInteger(value.height) ||
    (value.width as number) < 1 ||
    (value.height as number) < 1 ||
    (value.width as number) > 16384 ||
    (value.height as number) > 16384 ||
    (value.width as number) * (value.height as number) > 64 * 1024 * 1024 ||
    typeof value.image !== 'string' ||
    !value.image.startsWith('data:image/png;base64,')
  )
    return undefined;
  const encoded = value.image.slice(22);
  if (!canonicalBase64(encoded, 33, 20 * 1024 * 1024)) return undefined;
  const header = Buffer.from(encoded.slice(0, 44), 'base64');
  if (
    !header.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) ||
    header.readUInt32BE(8) !== 13 ||
    header.toString('ascii', 12, 16) !== 'IHDR' ||
    header.readUInt32BE(16) !== value.width ||
    header.readUInt32BE(20) !== value.height
  )
    return undefined;
  return {
    type: 'vnc.frame',
    sessionId,
    width: value.width as number,
    height: value.height as number,
    image: value.image,
  };
}

/** One native recipient per VNC session. Main handles ciphertext and public events. */
export class SealedVncBackend {
  private readonly sessions = new Map<string, Session>();
  private closing?: Promise<void>;
  private closingPending = false;
  private readonly options: Options;
  private readonly spawnChild: (exe: string, args: string[]) => ChildProcessWithoutNullStreams;
  constructor(
    options: Options,
    spawnChild = (exe: string, args: string[]) =>
      spawn(exe, args, { stdio: 'pipe', windowsHide: true }),
  ) {
    if (
      options.timeoutMs !== undefined &&
      (!Number.isSafeInteger(options.timeoutMs) ||
        options.timeoutMs < 1 ||
        options.timeoutMs > 360000)
    )
      throw Error('Invalid VNC timeout.');
    this.options = options;
    this.spawnChild = spawnChild;
  }
  has(id: string): boolean {
    return this.sessions.has(id);
  }
  open(value: SealedVncOpen, epoch: number, owner: () => boolean = () => true): Promise<void> {
    const q = { ...value },
      workspaceId = this.options.workspaceId();
    if (
      !vaultRecord(value) ||
      Object.keys(value).some(
        (k) => !['sessionId', 'nodeId', 'credentialId', 'manualPassword'].includes(k),
      ) ||
      (q.manualPassword !== undefined && (q.manualPassword !== true || !this.options.manual)) ||
      !vaultID(q.sessionId) ||
      !vaultID(q.nodeId) ||
      (q.credentialId !== undefined && !vaultID(q.credentialId)) ||
      !vaultID(workspaceId) ||
      !Number.isSafeInteger(epoch) ||
      epoch < 1 ||
      !this.options.authorized(epoch) ||
      !owner() ||
      this.closing ||
      this.sessions.has(q.sessionId) ||
      this.sessions.size >= 32
    )
      return Promise.reject(Error('Vault VNC is unavailable.'));
    return new Promise((resolve, reject) => {
      const s: Session = {
        request: {
          workspaceId,
          nodeId: q.nodeId,
          sessionId: q.sessionId,
          requestId: randomUUID(),
          credentialOverride: q.credentialId ?? '',
          epoch,
          publicKey: '',
        },
        owner,
        ...(q.manualPassword ? { manual: new AbortController() } : {}),
        phase: 'planning',
        routePending: false,
        chunks: [],
        bytes: 0,
        terminal: false,
        resolve,
        reject,
        timer: setTimeout(
          () => this.fail(s),
          this.options.timeoutMs ?? (this.options.route ? 330000 : 45000),
        ),
      };
      this.sessions.set(q.sessionId, s);
      void this.prepare(s).catch(() => this.fail(s));
    });
  }
  private current(s: Session): boolean {
    return (
      !this.closing &&
      s.phase !== 'retired' &&
      this.sessions.get(s.request.sessionId) === s &&
      this.options.workspaceId() === s.request.workspaceId &&
      this.options.authorized(s.request.epoch) &&
      s.owner()
    );
  }
  private usable(s: Session): boolean {
    return this.current(s) && (!s.route || s.route.active);
  }
  private async prepare(s: Session): Promise<void> {
    const routeOptions = this.options.route;
    if (routeOptions) {
      const { publicKey: _, ...context } = s.request;
      const plan = parseVaultConnectionRoute(await routeOptions.resolve({ ...context }), context);
      if (!this.usable(s) || plan === undefined) throw Error('Invalid VNC route.');
      if (plan !== null) {
        if (plan.protocol !== 'vnc') throw Error('Unsupported VNC route.');
        s.routePending = true;
        const lease = await routeOptions.broker.acquire(
          {
            sessionId: context.sessionId,
            nodeId: context.nodeId,
            ...(context.credentialOverride ? { credentialId: context.credentialOverride } : {}),
          },
          context.epoch,
          () => this.current(s),
        );
        s.routePending = false;
        if (!this.usable(s)) {
          await lease.release();
          return;
        }
        const binding = parseVaultRouteBinding(lease.binding, {
          ...context,
          requestId: lease.binding.requestId,
        });
        if (!binding || binding.protocol !== 'vnc' || !lease.active) {
          await lease.release();
          throw Error('Invalid VNC route.');
        }
        s.route = lease;
        s.request.requestId = binding.requestId;
        void lease.closed.then(() => this.fail(s));
      }
    }
    if (!this.usable(s)) throw Error('VNC opening cancelled.');
    s.child = this.spawnChild(this.options.executable(), [
      '--operation',
      s.manual ? 'vnc-manual-sealed' : 'vnc-sealed',
    ]);
    s.phase = 'recipient';
    clearTimeout(s.timer);
    s.timer = setTimeout(() => this.fail(s), this.options.timeoutMs ?? (s.manual ? 330000 : 45000));
    const child = s.child;
    child.on('error', () => this.fail(s));
    child.stdin.on('error', () => this.fail(s));
    child.stdout.on('error', () => this.fail(s));
    child.stderr.on('error', () => this.fail(s));
    child.stderr.on('data', () => {});
    child.stdout.on('data', (chunk: Buffer) => this.receive(s, chunk));
    child.stdout.on('end', () => this.fail(s));
    child.once('close', () => this.fail(s));
  }
  private receive(s: Session, chunk: Buffer): void {
    try {
      if (!this.usable(s) || !Buffer.isBuffer(chunk)) throw Error('VNC process unavailable.');
      let offset = 0;
      while (offset < chunk.length && s.phase !== 'retired') {
        const newline = chunk.indexOf(10, offset),
          end = newline < 0 ? chunk.length : newline,
          part = chunk.subarray(offset, end);
        const limit = s.phase === 'recipient' ? 1024 : 32 * 1024 * 1024;
        if (s.bytes + part.length > limit || s.chunks.length >= 4096)
          throw Error('VNC output exceeds limit.');
        s.chunks.push(part);
        s.bytes += part.length;
        if (newline < 0) return;
        const raw = Buffer.concat(s.chunks, s.bytes);
        s.chunks = [];
        s.bytes = 0;
        this.line(
          s,
          new TextDecoder('utf-8', { fatal: true }).decode(
            raw.at(-1) === 13 ? raw.subarray(0, -1) : raw,
          ),
        );
        offset = newline + 1;
      }
    } catch {
      this.fail(s);
    }
  }
  private line(s: Session, line: string): void {
    const value = parseVaultNativeObject(line);
    if (s.phase === 'recipient') {
      if (
        !vaultRecord(value) ||
        !vaultFields(value, ['type', 'publicKey']) ||
        value.type !== 'recipient' ||
        !canonicalBase64(value.publicKey, 32, 32)
      )
        throw Error('Invalid recipient.');
      s.request.publicKey = value.publicKey;
      s.phase = 'bundle';
      const request = { ...s.request },
        routed = s.route
          ? { ...request, route: { ...s.route.binding }, endpoint: s.route.endpoint }
          : undefined;
      void Promise.resolve()
        .then(async (): Promise<VaultVncBundle | VaultRoutedVncBundle> => {
          if (!this.usable(s)) throw Error('VNC opening cancelled.');
          if (s.manual) {
            const { publicKey, ...planRequest } = request;
            const context = parseVaultVncPasswordContext(
              routed
                ? { binding: routed.route, publicKey, endpoint: routed.endpoint }
                : {
                    binding: parseVaultVncPlan(
                      { binding: await this.options.manual!.plan(planRequest) },
                      planRequest,
                    ),
                    publicKey,
                  },
            );
            if (!context || !this.usable(s)) throw Error('Invalid temporary VNC context.');
            const manual = parseVaultVncPasswordEnvelope(
              await this.options.manual!.prompt(context, () => this.usable(s), s.manual.signal),
            );
            if (!manual || !this.usable(s)) throw Error('Temporary VNC opening cancelled.');
            const q = { context, manual, credentialOverride: request.credentialOverride };
            const result = await this.options.manual!.bundle(q);
            if (!this.usable(s)) throw Error('Temporary VNC opening cancelled.');
            const bundle = parseVaultVncManualBundle(result, q);
            if (!bundle) throw Error('Invalid temporary VNC bundle.');
            return bundle;
          }
          if (this.options.bitwarden) {
            const abort = new AbortController();
            const finished = this.options.bitwarden(routed ?? request, abort.signal, () =>
              this.usable(s),
            );
            s.bitwarden = { abort, finished };
            try {
              const result = await finished;
              if (!this.usable(s)) throw Error('VNC opening cancelled.');
              if (result) return result;
            } finally {
              s.bitwarden = undefined;
            }
          }
          return routed ? this.options.route!.bundle(routed) : this.options.bundle(request);
        })
        .then((result) => {
          if (!this.usable(s)) throw Error('VNC opening cancelled.');
          const bundle = s.manual
            ? result
            : routed
              ? parseVaultRoutedVncBundle(result, routed)
              : parseVaultVncBundle(result, request);
          if (!bundle) throw Error('Invalid VNC bundle.');
          s.phase = 'connecting';
          if (s.manual) {
            clearTimeout(s.timer);
            s.timer = setTimeout(() => this.fail(s), this.options.timeoutMs ?? 45000);
          }
          this.write(s, bundle, 32768);
        })
        .catch(() => this.fail(s));
      return;
    }
    const event = parseSealedVncEvent(value, s.request.sessionId);
    if (!event || s.phase === 'bundle') throw Error('Invalid VNC event.');
    if (event.type === 'vnc.frame') {
      if (s.phase !== 'connected') throw Error('Early VNC frame.');
    } else if (event.status === 'connecting') {
      if (s.phase !== 'connecting') throw Error('Invalid VNC transition.');
    } else if (event.status === 'connected') {
      if (s.phase !== 'connecting') throw Error('Invalid VNC transition.');
      s.phase = 'connected';
      clearTimeout(s.timer);
    } else {
      if (s.phase !== 'connecting' && s.phase !== 'connected')
        throw Error('Invalid VNC termination.');
      s.terminal = true;
    }
    this.options.onEvent(event);
    if (!this.usable(s)) {
      this.fail(s);
      return;
    }
    if (s.terminal) {
      this.fail(s);
      return;
    }
    if (event.type === 'vnc.status' && event.status === 'connected') s.resolve();
  }
  private write(s: Session, value: unknown, limit = 4096): void {
    if (!this.usable(s) || !s.child || s.child.stdin.destroyed || s.child.stdin.writableEnded)
      throw Error('Vault VNC is unavailable.');
    const frame = JSON.stringify(value) + '\n';
    if (Buffer.byteLength(frame) + s.child.stdin.writableLength > limit)
      throw Error('VNC input exceeds limit.');
    s.child.stdin.write(frame, (error) => {
      if (error) this.fail(s);
    });
  }
  send(id: string, value: unknown): void {
    const s = this.sessions.get(id);
    if (!s || s.phase !== 'connected' || !vaultRecord(value) || value.sessionId !== id)
      throw Error('VNC session is unavailable.');
    const pointer = value.type === 'pointer';
    if (
      pointer
        ? !vaultFields(value, ['type', 'sessionId', 'x', 'y', 'buttons']) ||
          ![value.x, value.y].every(
            (n) => Number.isInteger(n) && (n as number) >= 0 && (n as number) <= 65535,
          ) ||
          !Number.isInteger(value.buttons) ||
          (value.buttons as number) < 0 ||
          (value.buttons as number) > 255
        : value.type !== 'key' ||
          !vaultFields(value, ['type', 'sessionId', 'keysym', 'down']) ||
          !Number.isInteger(value.keysym) ||
          (value.keysym as number) < 1 ||
          (value.keysym as number) > 0xffffffff ||
          typeof value.down !== 'boolean'
    )
      throw Error('Invalid VNC input.');
    try {
      this.write(s, { ...value });
    } catch {
      this.fail(s);
      throw Error('Vault VNC is unavailable.');
    }
  }
  private fail(s: Session): void {
    void this.stop(s).catch(() => {});
  }
  private stop(s: Session): Promise<void> {
    if (s.stop) return s.stop;
    s.phase = 'retired';
    s.manual?.abort();
    const bitwarden = s.bitwarden;
    bitwarden?.abort.abort();
    clearTimeout(s.timer);
    s.chunks = [];
    s.bytes = 0;
    s.reject(Error('Vault VNC connection stopped.'));
    const task = Promise.resolve().then(async () => {
      const result = await Promise.allSettled([
        bitwarden?.finished.catch(() => undefined),
        s.child
          ? stopChildProcess(s.child, {
              gracefulTimeoutMs: 1500,
              forceKillTimeoutMs: 1500,
              nativeExecutable: this.options.executable(),
            }).then((stopped) => {
              if (!stopped) throw Error('VNC shutdown unconfirmed.');
            })
          : Promise.resolve(),
        s.route
          ? s.route.release()
          : s.routePending
            ? this.options.route!.broker.close(s.request.sessionId)
            : Promise.resolve(),
      ]);
      if (result.some((r) => r.status === 'rejected'))
        throw Error('VNC shutdown could not be confirmed.');
      if (this.sessions.get(s.request.sessionId) === s) this.sessions.delete(s.request.sessionId);
    });
    const tracked = task.catch((error) => {
      if (s.stop === tracked) s.stop = undefined;
      throw error;
    });
    s.stop = tracked;
    if (!s.terminal) {
      s.terminal = true;
      try {
        this.options.onEvent({
          type: 'vnc.status',
          sessionId: s.request.sessionId,
          status: 'disconnected',
          message: 'VNC connection closed',
        });
      } catch {
        /* presentation owner has gone */
      }
    }
    return tracked;
  }
  close(id: string): Promise<void> {
    const s = this.sessions.get(id);
    return s ? this.stop(s) : Promise.resolve();
  }
  closeAll(): Promise<void> {
    if (this.closing && this.closingPending) return this.closing;
    this.closingPending = true;
    const task = Promise.resolve().then(async () => {
      const results = await Promise.allSettled(
        [...this.sessions.values()].map((s) => this.stop(s)),
      );
      if (results.some((r) => r.status === 'rejected'))
        throw Error('VNC shutdown could not be confirmed.');
    });
    const tracked = task.then(
      () => {
        if (this.closing === tracked) {
          this.closing = undefined;
          this.closingPending = false;
        }
      },
      (error) => {
        if (this.closing === tracked) this.closingPending = false;
        // Keep the failed shutdown as an admission barrier until an explicit retry
        // confirms every original resource has stopped.
        throw error;
      },
    );
    this.closing = tracked;
    return tracked;
  }
}
