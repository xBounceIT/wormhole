import {
  parseVaultRdpPlan,
  parseVaultRdpManualBundle,
  type VaultRdpManualRequest,
} from './vault-rdp-manual.ts';
import {
  parseVaultRdpCredentialsContext,
  parseVaultRdpCredentialsEnvelope,
  type VaultRdpCredentialsContext,
  type VaultRdpCredentialsEnvelope,
} from './vault-rdp-credentials.ts';
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
  parseVaultRdpBundle,
  parseVaultRoutedRdpBundle,
  type VaultRdpRequest,
  type VaultRdpBundle,
  type VaultRoutedRdpRequest,
  type VaultRoutedRdpBundle,
} from './vault-rdp.ts';
import {
  parseVaultRDPBitwardenBundle,
  type VaultRDPBitwardenBundle,
  type VaultRDPBitwardenRequest,
} from './vault-rdp-bitwarden.ts';
import type { SealedRouteBroker, SealedRouteLease } from './sealed-route.ts';

import {
  parseSealedRdpOpen,
  parseSealedRdpControl,
  parseSealedRdpEvent,
  type SealedRdpOpen,
  type SealedRdpControl,
} from './sealed-rdp-contract.ts';
import type { RdpBackendEvent } from './rdp-contract.ts';
export type { SealedRdpOpen, SealedRdpControl } from './sealed-rdp-contract.ts';

type Options = {
  executable: () => string;
  workspaceId: () => string | undefined;
  authorized: (epoch: number) => boolean;
  bundle: (q: VaultRdpRequest) => Promise<VaultRdpBundle>;
  bitwarden?: (
    request: VaultRDPBitwardenRequest,
    signal: AbortSignal,
    accepted: () => boolean,
  ) => Promise<VaultRDPBitwardenBundle | undefined>;
  onEvent: (event: RdpBackendEvent) => void;
  route?: {
    resolve: (
      q: VaultRoutePlanRequest,
    ) => Promise<import('./vault-route.ts').VaultRouteBinding | null>;
    broker: Pick<SealedRouteBroker, 'acquire' | 'close'>;
    bundle: (q: VaultRoutedRdpRequest) => Promise<VaultRoutedRdpBundle>;
  };
  manual?: {
    plan: (q: VaultRoutePlanRequest) => Promise<VaultRdpBundle['binding']>;
    prompt: (
      context: VaultRdpCredentialsContext,
      active: () => boolean,
      signal: AbortSignal,
    ) => Promise<VaultRdpCredentialsEnvelope>;
    bundle: (q: VaultRdpManualRequest) => Promise<VaultRdpBundle | VaultRoutedRdpBundle>;
    bitwarden?: (
      q: VaultRdpManualRequest,
      signal: AbortSignal,
      accepted: () => boolean,
    ) => Promise<VaultRDPBitwardenBundle | undefined>;
  };
  timeoutMs?: number;
};
type Session = {
  request: VaultRdpRequest;
  manual?: AbortController;
  bitwarden?: { abort: AbortController; finished: Promise<unknown> };
  opening: SealedRdpOpen;
  pending: Map<
    string,
    {
      resolve: (event: RdpBackendEvent) => void;
      reject: (error: Error) => void;
      timer: NodeJS.Timeout;
    }
  >;
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

/** One native recipient per RDP surface. Main handles ciphertext and public events. */
export class SealedRdpBackend {
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
      throw Error('Invalid RDP timeout.');
    this.options = options;
    this.spawnChild = spawnChild;
  }
  has(id: string): boolean {
    return this.sessions.has(id);
  }
  open(value: SealedRdpOpen, epoch: number, owner: () => boolean = () => true): Promise<void> {
    const q = parseSealedRdpOpen(value),
      workspaceId = this.options.workspaceId();
    if (
      !q ||
      (q.manualCredentials === true && !this.options.manual) ||
      !vaultID(workspaceId) ||
      (process.platform === 'win32' && !q.ownerWindow) ||
      !Number.isSafeInteger(epoch) ||
      epoch < 1 ||
      !this.options.authorized(epoch) ||
      !owner() ||
      this.closing ||
      this.sessions.has(q.sessionId) ||
      this.sessions.size >= 32
    )
      return Promise.reject(Error('Vault RDP is unavailable.'));
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
        ...(q.manualCredentials ? { manual: new AbortController() } : {}),
        opening: q,
        pending: new Map(),
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
      if (!this.usable(s) || plan === undefined) throw Error('Invalid RDP route.');
      if (plan !== null) {
        if (plan.protocol !== 'rdp') throw Error('Unsupported RDP route.');
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
        if (!binding || binding.protocol !== 'rdp' || !lease.active) {
          await lease.release();
          throw Error('Invalid RDP route.');
        }
        s.route = lease;
        s.request.requestId = binding.requestId;
        void lease.closed.then(() => this.fail(s));
      }
    }
    if (!this.usable(s)) throw Error('RDP opening cancelled.');
    s.child = this.spawnChild(this.options.executable(), [
      '--operation',
      s.manual ? 'rdp-manual-sealed' : 'rdp-sealed',
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
      if (!this.usable(s) || !Buffer.isBuffer(chunk)) throw Error('RDP process unavailable.');
      let offset = 0;
      while (offset < chunk.length && s.phase !== 'retired') {
        const newline = chunk.indexOf(10, offset),
          end = newline < 0 ? chunk.length : newline,
          part = chunk.subarray(offset, end);
        const limit = s.phase === 'recipient' ? 1024 : 256 * 1024;
        if (s.bytes + part.length > limit || s.chunks.length >= 4096)
          throw Error('RDP output exceeds limit.');
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
        .then(
          async (): Promise<VaultRdpBundle | VaultRoutedRdpBundle | VaultRDPBitwardenBundle> => {
            if (!this.usable(s)) throw Error('RDP opening cancelled.');
            if (s.manual) {
              const { publicKey, ...planRequest } = request;
              const context = parseVaultRdpCredentialsContext(
                routed
                  ? { binding: routed.route, publicKey, endpoint: routed.endpoint }
                  : {
                      binding: parseVaultRdpPlan(
                        { binding: await this.options.manual!.plan(planRequest) },
                        planRequest,
                      ),
                      publicKey,
                    },
              );
              if (!context || !this.usable(s)) throw Error('Invalid temporary RDP context.');
              const manual = parseVaultRdpCredentialsEnvelope(
                await this.options.manual!.prompt(context, () => this.usable(s), s.manual.signal),
              );
              if (!manual || !this.usable(s)) throw Error('Temporary RDP opening cancelled.');
              const q = { context, manual, credentialOverride: request.credentialOverride };
              if (!routed && this.options.manual!.bitwarden) {
                const result = await this.resolveBitwarden(s, (signal, accepted) =>
                  this.options.manual!.bitwarden!(q, signal, accepted),
                );
                if (result) return result;
              }
              const result = await this.options.manual!.bundle(q);
              if (!this.usable(s)) throw Error('Temporary RDP opening cancelled.');
              const bundle = parseVaultRdpManualBundle(result, q);
              if (!bundle) throw Error('Invalid temporary RDP bundle.');
              return bundle;
            }
            if (this.options.bitwarden) {
              const result = await this.resolveBitwarden(s, (signal, accepted) =>
                this.options.bitwarden!(routed ?? request, signal, accepted),
              );
              if (result) return result;
            }
            return routed ? this.options.route!.bundle(routed) : this.options.bundle(request);
          },
        )
        .then((result) => {
          if (!this.usable(s)) throw Error('RDP opening cancelled.');
          const bundle =
            'bitwarden' in result
              ? parseVaultRDPBitwardenBundle(result, routed ?? request)
              : s.manual
                ? result
                : routed
                  ? parseVaultRoutedRdpBundle(result, routed)
                  : parseVaultRdpBundle(result, request);
          if (!bundle) throw Error('Invalid RDP bundle.');
          s.phase = 'connecting';
          if (s.manual) {
            clearTimeout(s.timer);
            s.timer = setTimeout(() => this.fail(s), this.options.timeoutMs ?? 45000);
          }
          this.write(
            s,
            {
              ...bundle,
              ownerWindow: s.opening.ownerWindow,
              bounds: s.opening.bounds,
              ...(s.opening.requireContentProtection ? { requireContentProtection: true } : {}),
              ...(s.opening.visible !== undefined ? { visible: s.opening.visible } : {}),
            },
            128 * 1024,
          );
        })
        .catch(() => this.fail(s));
      return;
    }
    const event = parseSealedRdpEvent(value, s.request.sessionId);
    if (!event || s.phase === 'bundle') throw Error('Invalid RDP event.');
    if (event.requestId === s.request.requestId) {
      if (s.phase !== 'connecting' || !['ready', 'started', 'error'].includes(event.type))
        throw Error('Invalid RDP initialization.');
      if (event.type === 'error') {
        this.fail(s);
        return;
      }
      s.phase = 'connected';
      clearTimeout(s.timer);
    } else if (event.requestId) {
      const pending = s.pending.get(event.requestId);
      if (!pending || (event.type !== 'ack' && event.type !== 'error'))
        throw Error('Invalid RDP acknowledgement.');
      clearTimeout(pending.timer);
      s.pending.delete(event.requestId);
      if (event.type === 'error') pending.reject(Error('RDP operation failed.'));
      else pending.resolve(event);
      return;
    } else if (event.type === 'ready' || event.type === 'started' || event.type === 'ack') {
      throw Error('Uncorrelated RDP acknowledgement.');
    }
    this.options.onEvent(event);
    if (!this.usable(s)) {
      this.fail(s);
      return;
    }
    if (['exited', 'disconnected', 'fatalError', 'error'].includes(event.type)) {
      s.terminal = true;
      this.fail(s);
    } else if (event.requestId === s.request.requestId) {
      s.resolve();
    }
  }
  private async resolveBitwarden(
    s: Session,
    resolve: (
      signal: AbortSignal,
      accepted: () => boolean,
    ) => Promise<VaultRDPBitwardenBundle | undefined>,
  ): Promise<VaultRDPBitwardenBundle | undefined> {
    const abort = new AbortController();
    const finished = resolve(abort.signal, () => this.usable(s));
    s.bitwarden = { abort, finished };
    try {
      const bundle = await finished;
      if (!this.usable(s)) throw Error('RDP opening cancelled.');
      return bundle;
    } finally {
      s.bitwarden = undefined;
    }
  }
  private write(s: Session, value: unknown, limit = 4096): void {
    if (!this.usable(s) || !s.child || s.child.stdin.destroyed || s.child.stdin.writableEnded)
      throw Error('Vault RDP is unavailable.');
    const frame = JSON.stringify(value) + '\n';
    if (Buffer.byteLength(frame) + s.child.stdin.writableLength > limit)
      throw Error('RDP input exceeds limit.');
    s.child.stdin.write(frame, (error) => {
      if (error) this.fail(s);
    });
  }
  command(id: string, value: SealedRdpControl): Promise<RdpBackendEvent> {
    const s = this.sessions.get(id),
      command = parseSealedRdpControl(value);
    if (!s || !this.usable(s) || !command || s.pending.size >= 128)
      return Promise.reject(Error('RDP session is unavailable.'));
    if (command.op === 'resize' || command.op === 'show') s.opening.bounds = { ...command.bounds };
    if (command.op === 'show' || command.op === 'hide') s.opening.visible = command.op === 'show';
    if (!['connecting', 'connected'].includes(s.phase)) {
      return ['resize', 'show', 'hide'].includes(command.op)
        ? Promise.resolve({ type: 'ack', sessionId: id })
        : Promise.reject(Error('RDP session is unavailable.'));
    }
    const requestId = randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(s), 15000);
      s.pending.set(requestId, { resolve, reject, timer });
      try {
        this.write(s, { ...command, sessionId: id, requestId });
      } catch {
        this.fail(s);
      }
    });
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
    for (const pending of s.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(Error('RDP session stopped.'));
    }
    s.pending.clear();
    clearTimeout(s.timer);
    s.chunks = [];
    s.bytes = 0;
    s.reject(Error('Vault RDP connection stopped.'));
    const task = Promise.resolve().then(async () => {
      const result = await Promise.allSettled([
        bitwarden?.finished.catch(() => undefined),
        s.child
          ? stopChildProcess(s.child, {
              gracefulTimeoutMs: 1500,
              forceKillTimeoutMs: 1500,
              nativeExecutable: this.options.executable(),
            }).then((stopped) => {
              if (!stopped) throw Error('RDP shutdown unconfirmed.');
            })
          : Promise.resolve(),
        s.route
          ? s.route.release()
          : s.routePending
            ? this.options.route!.broker.close(s.request.sessionId)
            : Promise.resolve(),
      ]);
      if (result.some((r) => r.status === 'rejected'))
        throw Error('RDP shutdown could not be confirmed.');
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
          type: 'exited',
          sessionId: s.request.sessionId,
          lifecycleId: s.request.sessionId,
          external: false,
          code: 0,
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
        throw Error('RDP shutdown could not be confirmed.');
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
