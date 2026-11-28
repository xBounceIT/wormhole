import { sealedSftpEditCommand } from './vault-sftp-edit.ts';
import {
  parseVaultSshManualPlan,
  parseVaultSshManualContext,
  parseVaultSshManualEnvelope,
  type VaultSshManualMode,
  type VaultSshManualPlanRequest,
  type VaultSshManualPlan,
  type VaultSshManualContext,
  type VaultSshManualRequest,
  type VaultSshManualEnvelope,
} from './vault-ssh-manual.ts';
import {
  parseVaultSshHostPlan,
  validVaultSshFingerprint,
  type VaultSshHostRequest,
  type VaultSshHostPlan,
} from './vault-ssh-host.ts';
import {
  parseVaultConnectionRoute,
  parseVaultRouteBinding,
  type VaultRouteBinding,
  type VaultRoutePlanRequest,
} from './vault-route.ts';
import {
  parseVaultRoutedSshBundle,
  type VaultRoutedSshRequest,
  type VaultRoutedSshBundle,
} from './vault-ssh-route.ts';
import type { SealedRouteBroker, SealedRouteLease } from './sealed-route.ts';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { stopChildProcess } from './rdp.ts';
import {
  vaultFields,
  vaultID,
  vaultRecord,
  vaultMetadataText,
  parseVaultNativeObject,
} from './vault-contract.ts';
import {
  canonicalBase64,
  parseVaultSshBundle,
  type VaultSshBundle,
  type VaultSshRequest,
} from './vault-ssh.ts';

export type SealedSshOpen = {
  mode?: 'terminal' | 'sftp';
  sessionId: string;
  nodeId: string;
  credentialId?: string;
  columns: number;
  rows: number;
  manualCredentials?: true;
  manualKeyPassphrase?: true;
};
export type SealedSshConnected = {
  sessionId: string;
  host: string;
  port: number;
  username: string;
  fingerprint: string;
};
export type SealedSshAdmission = {
  accepted: boolean;
  result: Promise<SealedSshConnected>;
};
type Options = {
  executable: () => string;
  fileEditing?: () => { databasePath: string; userDataPath: string };
  workspaceId: () => string | undefined;
  authorized: (epoch: number) => boolean;
  bundle: (request: VaultSshRequest) => Promise<VaultSshBundle>;
  bitwarden?: (
    request: VaultSshRequest | VaultRoutedSshRequest,
    signal: AbortSignal,
    accepted: () => boolean,
  ) => Promise<VaultSshBundle | VaultRoutedSshBundle | undefined>;
  parseEvent: (line: string) => { type: string; sessionId: string } | undefined;
  onLine: (line: string) => void;
  timeoutMs?: number;
  manual?: {
    close: (sessionId: string) => Promise<void>;
    plan: (request: VaultSshManualPlanRequest) => Promise<VaultSshManualPlan>;
    bundle: (request: VaultSshManualRequest) => Promise<VaultSshBundle | VaultRoutedSshBundle>;
    prompt: (
      context: VaultSshManualContext,
      current: () => boolean,
      signal: AbortSignal,
    ) => Promise<VaultSshManualEnvelope>;
  };
  host?: {
    plan: (request: VaultSshHostRequest) => Promise<VaultSshHostPlan>;
    confirm: (
      request: VaultSshHostRequest,
      plan: VaultSshHostPlan,
      received: string,
      accepted: () => boolean,
      signal: AbortSignal,
    ) => Promise<void>;
  };
  route?: {
    resolve: (request: VaultRoutePlanRequest) => Promise<VaultRouteBinding | null>;
    broker: Pick<SealedRouteBroker, 'acquire' | 'close' | 'closeAll'>;
    bundle: (request: VaultRoutedSshRequest) => Promise<VaultRoutedSshBundle>;
  };
};
type Member = {
  id: string;
  state: 'opening' | 'connected' | 'closing' | 'closed';
  ownerCurrent: () => boolean;
  resolve: (value: SealedSshConnected) => void;
  reject: (error: Error) => void;
  closed: Promise<void>;
  finish: () => void;
  failClose: (error: Error) => void;
  timer?: NodeJS.Timeout;
};
function sessionMember(
  id: string,
  ownerCurrent: () => boolean,
  resolve: Member['resolve'],
  reject: Member['reject'],
): Member {
  let finish!: () => void;
  let failClose!: (error: Error) => void;
  const closed = new Promise<void>((done, fail) => {
    finish = done;
    failClose = fail;
  });
  // Most members are retired by events, without a caller awaiting close().
  void closed.catch(() => {});
  return { id, state: 'opening', ownerCurrent, resolve, reject, closed, finish, failClose };
}

type Session = {
  protocol: 'ssh' | 'sftp';
  members: Map<string, Member>;
  connected?: SealedSshConnected;
  abort: AbortController;
  hostBinding?: VaultSshHostPlan['binding'];
  verifiedFingerprint?: string;
  manualMode?: VaultSshManualMode;
  child?: ChildProcessWithoutNullStreams;
  route?: SealedRouteLease;
  routePending?: boolean;
  request: VaultSshRequest;
  phase: 'planning' | 'recipient' | 'bundle' | 'connecting' | 'connected' | 'retired';
  chunks: Buffer[];
  bytes: number;
  timer: NodeJS.Timeout;
  resolve: (value: SealedSshConnected) => void;
  reject: (error: Error) => void;
  stop?: Promise<void>;
  onStopped?: () => Promise<void>;
  binding?: VaultSshBundle['binding'] | VaultRouteBinding;
};
type Spawn = (executable: string, args: string[]) => ChildProcessWithoutNullStreams;

// Field selection is intentionally separate from legacy SSH control messages.
// The Go owner performs strict value and nested-item validation before file I/O.
const sealedSftpCommandFields: Record<string, readonly string[]> = {
  'sftp-edit': [
    'request_id',
    'operation',
    'pane',
    'path',
    'edit_id',
    'editor_id',
    'allow_binary',
    'decision',
    'destination_path',
  ],
  'sftp-open': ['request_id'],
  'sftp-close': [],
  'sftp-list': ['request_id', 'path'],
  'sftp-local-list': ['request_id', 'path'],
  'sftp-tree-list': ['request_id', 'path', 'pane'],
  'sftp-operation': ['request_id', 'pane', 'operation', 'path', 'destination_path'],
  'sftp-transfer': ['transfer_id', 'direction', 'destination_path', 'items'],
  'sftp-transfer-decision': ['transfer_id', 'item_id', 'decision', 'apply_to_all'],
  'sftp-transfer-cancel': ['transfer_id', 'item_id'],
};
const sealedSftpEvents = [
  'sftp.edit',
  'sftp.opening',
  'sftp.closed',
  'sftp.ready',
  'sftp.local.ready',
  'sftp.error',
  'sftp.local.error',
  'sftp.operation',
  'sftp.conflict',
  'sftp.transfer',
];

/** Main owns the child/key association. No renderer can select a recipient key. */
export class SealedSshBackend {
  private readonly sessions = new Map<string, Session>();
  private readonly aliases = new Map<string, Session>();
  private readonly options: Options;
  private readonly spawnChild: Spawn;
  constructor(
    options: Options,
    spawnChild: Spawn = (executable, args) =>
      spawn(executable, args, { stdio: 'pipe', windowsHide: true }),
  ) {
    if (
      options.timeoutMs !== undefined &&
      (!Number.isSafeInteger(options.timeoutMs) ||
        options.timeoutMs <= 0 ||
        options.timeoutMs > 120000)
    )
      throw new Error('Invalid SSH timeout.');
    this.options = options;
    this.spawnChild = spawnChild;
  }
  has(sessionId: string): boolean {
    return this.aliases.has(sessionId);
  }
  hasReservation(sessionId: string): boolean {
    return this.aliases.has(sessionId) || this.sessions.has(sessionId);
  }

  connectedSessionIds(): string[] {
    return [...this.aliases]
      .filter(([id, session]) => {
        const member = session.members.get(id)!;
        return this.usable(session) && member.state === 'connected' && member.ownerCurrent();
      })
      .map(([id]) => id);
  }

  open(
    input: SealedSshOpen,
    epoch: number,
    ownerCurrent: () => boolean = () => true,
    onStopped?: () => Promise<void>,
  ): Promise<SealedSshConnected> {
    return this.admit(input, epoch, ownerCurrent, onStopped).result;
  }

  // Main can transfer a newly registered target only when this synchronous
  // receipt confirms that the underlying cohort accepted its retirement hook.
  admit(
    input: SealedSshOpen,
    epoch: number,
    ownerCurrent: () => boolean = () => true,
    onStopped?: () => Promise<void>,
  ): SealedSshAdmission {
    const q = { ...input };
    const workspaceId = this.options.workspaceId();
    const unavailable = (message: string): SealedSshAdmission => ({
      accepted: false,
      result: Promise.reject(Error(message)),
    });
    if (
      !workspaceId ||
      !vaultID(workspaceId) ||
      !vaultID(q.nodeId) ||
      (q.mode !== undefined && q.mode !== 'terminal' && q.mode !== 'sftp') ||
      !vaultID(q.sessionId) ||
      (q.credentialId !== undefined && !vaultID(q.credentialId)) ||
      (q.manualCredentials !== undefined && q.manualCredentials !== true) ||
      (q.manualKeyPassphrase !== undefined && q.manualKeyPassphrase !== true) ||
      (q.manualCredentials && (q.manualKeyPassphrase || q.credentialId !== undefined)) ||
      ((q.manualCredentials || q.manualKeyPassphrase) &&
        (!this.options.manual || !this.options.host)) ||
      ![q.columns, q.rows].every((n) => Number.isInteger(n) && n > 0 && n <= 500) ||
      !Number.isSafeInteger(epoch) ||
      epoch < 1 ||
      !this.options.authorized(epoch) ||
      !ownerCurrent()
    )
      return unavailable('Vault SSH is unavailable.');
    if (this.hasReservation(q.sessionId) || this.sessions.size >= 32 || this.aliases.size >= 128)
      return unavailable('SSH session is unavailable.');
    return {
      accepted: true,
      result: new Promise((resolve, reject) => {
        const s: Session = {
          protocol: q.mode === 'sftp' ? 'sftp' : 'ssh',
          onStopped,
          manualMode: q.manualCredentials
            ? 'account'
            : q.manualKeyPassphrase
              ? 'passphrase'
              : undefined,
          abort: new AbortController(),
          members: new Map(),
          request: {
            workspaceId,
            nodeId: q.nodeId,
            credentialOverride: q.credentialId ?? '',
            sessionId: q.sessionId,
            requestId: randomUUID(),
            epoch,
            publicKey: '',
            ...(q.mode === 'sftp' ? { sftpOnly: true } : {}),
          },
          phase: 'planning',
          chunks: [],
          bytes: 0,
          resolve,
          reject,
          timer: setTimeout(
            () => this.fail(s),
            this.options.timeoutMs ?? (this.options.route ? 330000 : 45000),
          ),
        };
        s.members.set(q.sessionId, sessionMember(q.sessionId, ownerCurrent, resolve, reject));
        this.sessions.set(q.sessionId, s);
        this.aliases.set(q.sessionId, s);
        if (this.options.route || this.options.host)
          void this.prepareRoute(s, q.columns, q.rows).catch(() => this.fail(s));
        else this.start(s, q.columns, q.rows);
      }),
    };
  }
  shareSftp(
    sourceId: string,
    sessionId: string,
    ownerCurrent: () => boolean,
  ): Promise<SealedSshConnected> {
    const s = this.aliases.get(sourceId),
      source = s?.members.get(sourceId);
    if (
      !s ||
      !source ||
      source.state !== 'connected' ||
      !source.ownerCurrent() ||
      !this.usable(s) ||
      !ownerCurrent() ||
      !vaultID(sessionId) ||
      this.aliases.has(sessionId) ||
      this.sessions.has(sessionId) ||
      s.members.has(sessionId) ||
      this.aliases.size >= 128 ||
      s.members.size >= 1024 ||
      [...s.members.values()].filter((member) => member.state !== 'closed').length >= 32
    )
      return Promise.reject(Error('Source SSH connection is unavailable.'));
    return new Promise((resolve, reject) => {
      const member = sessionMember(sessionId, ownerCurrent, resolve, reject);
      s.members.set(sessionId, member);
      this.aliases.set(sessionId, s);
      member.timer = setTimeout(() => {
        member.reject(Error('SFTP opening timed out.'));
        void this.close(sessionId).catch(() => undefined);
      }, this.options.timeoutMs ?? 45000);
      try {
        this.write(s, { type: 'sftp-share', sessionId: sourceId, newSessionId: sessionId });
      } catch {
        this.fail(s);
      }
    });
  }
  private async prepareRoute(s: Session, columns: number, rows: number): Promise<void> {
    const options = this.options.route;
    const { publicKey: _, sftpOnly: _fileMode, ...context } = s.request;
    const planned = options
      ? parseVaultConnectionRoute(await options.resolve({ ...context }), context)
      : null;
    if (!this.current(s) || planned === undefined) throw Error('Vault route is unavailable.');
    if (planned !== null) {
      if (
        s.protocol === 'ssh'
          ? planned.protocol !== 'ssh'
          : !['ssh', 'sftp'].includes(planned.protocol)
      )
        throw Error('Unsupported SSH route.');
      s.routePending = true;
      const lease = await options!.broker.acquire(
        {
          sessionId: s.request.sessionId,
          nodeId: s.request.nodeId,
          ...(s.request.credentialOverride ? { credentialId: s.request.credentialOverride } : {}),
        },
        s.request.epoch,
        () => this.current(s),
      );
      s.routePending = false;
      // Keep the exact receipt even when cancellation or validation requires
      // releasing it. A rejected release is still an owned native resource.
      s.route = lease;
      if (!this.current(s)) {
        await lease.release();
        if (s.route === lease) s.route = undefined;
        return;
      }
      const binding = parseVaultRouteBinding(lease.binding, {
        ...context,
        requestId: lease.binding.requestId,
      });
      if (!binding || binding.protocol !== planned.protocol || !lease.active) {
        await lease.release();
        if (s.route === lease) s.route = undefined;
        throw Error('Invalid SSH route.');
      }
      s.request.requestId = binding.requestId;
      void lease.closed.then(() => this.fail(s));
    }
    if (this.options.host) {
      const { publicKey: _, sftpOnly: _fileMode, ...currentRequest } = s.request;
      const request: VaultSshHostRequest = { ...currentRequest, route: s.route?.binding ?? null };
      const plan = parseVaultSshHostPlan(await this.options.host.plan(request), request);
      if (!plan || (s.protocol === 'ssh' && plan.binding.protocol !== 'ssh') || !this.usable(s))
        throw Error('SSH host plan is unavailable.');
      s.hostBinding = plan.binding;
      const received = await this.probeHost(s, plan);
      if (!this.usable(s)) throw Error('SSH host verification was cancelled.');
      s.verifiedFingerprint = received;
      if (received !== plan.fingerprint)
        await this.options.host.confirm(
          request,
          plan,
          received,
          () => this.usable(s),
          s.abort.signal,
        );
      if (!this.usable(s)) throw Error('SSH host verification was cancelled.');
    }
    this.start(s, columns, rows);
  }
  private probeHost(s: Session, plan: VaultSshHostPlan): Promise<string> {
    const child = this.spawnChild(this.options.executable(), ['--operation', 'ssh-host-probe']);
    s.child = child;
    return new Promise((resolve, reject) => {
      let bytes = Buffer.alloc(0),
        chunks = 0,
        fingerprint: string | undefined,
        failed = false;
      const fail = () => {
        failed = true;
        reject(Error('SSH host verification failed.'));
      };
      const timer = setTimeout(() => {
        fail();
        this.fail(s);
      }, 20000);
      const receive = (chunk: Buffer) => {
        try {
          if (
            !this.usable(s) ||
            !Buffer.isBuffer(chunk) ||
            fingerprint ||
            ++chunks > 64 ||
            bytes.length + chunk.length > 1024
          ) {
            fail();
            return;
          }
          bytes = Buffer.concat([bytes, chunk]);
          const newline = bytes.indexOf(10);
          if (newline < 0) return;
          if (newline !== bytes.length - 1) {
            fail();
            return;
          }
          const value = parseVaultNativeObject(
            new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, newline)),
          );
          if (
            !vaultRecord(value) ||
            !vaultFields(value, ['requestId', 'fingerprint']) ||
            value.requestId !== s.request.requestId ||
            !validVaultSshFingerprint(value.fingerprint)
          ) {
            fail();
            return;
          }
          fingerprint = value.fingerprint;
          bytes = Buffer.alloc(0);
          // The probe watches stdin for cancellation and joins that reader before exiting.
          child.stdin.end();
        } catch {
          fail();
        }
      };
      child.on('error', fail);
      child.stdin.on('error', fail);
      child.stdout.on('error', fail);
      child.stderr.on('error', fail);
      child.stderr.on('data', () => {});
      child.stdout.on('data', receive);
      child.once('close', () => {
        clearTimeout(timer);
        if (!failed && fingerprint && child.exitCode === 0 && this.usable(s)) resolve(fingerprint);
        else fail();
      });
      try {
        child.stdin.write(
          JSON.stringify({
            host: plan.binding.host,
            port: plan.binding.port,
            endpoint: s.route?.endpoint ?? '',
            requestId: s.request.requestId,
          }) + '\n',
          (error) => {
            if (error) fail();
          },
        );
      } catch {
        fail();
      }
    });
  }
  private start(s: Session, columns: number, rows: number): void {
    if (!this.usable(s)) {
      this.fail(s);
      return;
    }
    let child: ChildProcessWithoutNullStreams;
    try {
      const args = [
        '--operation',
        s.manualMode ? `ssh-manual-${s.manualMode}-sealed` : 'ssh-sealed',
      ];
      const editing = this.options.fileEditing?.();
      if (editing)
        args.push('--database', editing.databasePath, '--electron-user-data', editing.userDataPath);
      child = this.spawnChild(this.options.executable(), args);
    } catch {
      s.reject(new Error('SSH process could not start.'));
      this.fail(s);
      return;
    }
    s.child = child;
    s.phase = 'recipient';
    clearTimeout(s.timer);
    s.timer = setTimeout(
      () => this.fail(s),
      this.options.timeoutMs ?? (s.manualMode ? 330000 : 45000),
    );
    child.on('error', () => this.fail(s));
    child.stdin.on('error', () => this.fail(s));
    child.stdout.on('error', () => this.fail(s));
    child.stderr.on('error', () => this.fail(s));
    child.stderr.on('data', () => {});
    child.stdout.on('data', (chunk: Buffer) => this.receive(s, chunk, columns, rows));
    child.stdout.on('end', () => this.fail(s));
    child.once('close', () => {
      this.fail(s);
    });
  }
  private finishMember(s: Session, member: Member): void {
    if (member.state === 'closed') return;
    member.state = 'closed';
    clearTimeout(member.timer);
    member.reject(Error('SSH session stopped.'));
    member.finish();
    if (this.aliases.get(member.id) !== s) return;
    this.aliases.delete(member.id);
    try {
      this.options.onLine(JSON.stringify({ type: 'closed', session_id: member.id }));
    } catch {
      /* presentation owner has gone */
    }
  }
  private closed(s: Session): void {
    this.retire(s);
    if (this.sessions.get(s.request.sessionId) !== s) return;
    this.sessions.delete(s.request.sessionId);
    for (const member of s.members.values()) this.finishMember(s, member);
  }
  private usable(s: Session): boolean {
    return this.current(s) && (!s.route || s.route.active);
  }

  private current(s: Session): boolean {
    if (
      s.phase === 'retired' ||
      this.sessions.get(s.request.sessionId) !== s ||
      this.options.workspaceId() !== s.request.workspaceId ||
      !this.options.authorized(s.request.epoch)
    )
      return false;
    for (const member of s.members.values()) {
      if (member.state !== 'closed' && member.state !== 'closing' && member.ownerCurrent())
        return true;
    }
    return false;
  }
  private receive(s: Session, chunk: Buffer, columns: number, rows: number): void {
    try {
      if (!this.usable(s)) {
        this.fail(s);
        return;
      }
      if (!Buffer.isBuffer(chunk)) {
        this.fail(s);
        return;
      }
      let offset = 0;
      while (offset < chunk.length && s.phase !== 'retired') {
        const newline = chunk.indexOf(10, offset),
          end = newline < 0 ? chunk.length : newline;
        const part = chunk.subarray(offset, end);
        const limit = s.phase === 'recipient' ? 1024 : 8 * 1024 * 1024;
        if (s.bytes + part.length > limit || s.chunks.length >= 4096) {
          this.fail(s);
          return;
        }
        s.chunks.push(part);
        s.bytes += part.length;
        if (newline < 0) return;
        const raw = Buffer.concat(s.chunks, s.bytes);
        s.chunks = [];
        s.bytes = 0;
        const line = new TextDecoder('utf-8', { fatal: true }).decode(
          raw.at(-1) === 13 ? raw.subarray(0, -1) : raw,
        );
        this.line(s, line, columns, rows);
        offset = newline + 1;
      }
    } catch {
      this.fail(s);
    }
  }
  private line(s: Session, line: string, columns: number, rows: number): void {
    if (!this.usable(s)) {
      this.fail(s);
      return;
    }
    const value = parseVaultNativeObject(line);
    if (s.phase === 'recipient') {
      if (
        !vaultRecord(value) ||
        !vaultFields(value, ['type', 'publicKey']) ||
        value.type !== 'recipient' ||
        !canonicalBase64(value.publicKey, 32, 32)
      ) {
        this.fail(s);
        return;
      }
      s.request.publicKey = value.publicKey;
      s.phase = 'bundle';
      const route = s.route;
      const request = { ...s.request };
      const routedRequest: VaultRoutedSshRequest | undefined = route
        ? { ...request, route: { ...route.binding }, endpoint: route.endpoint }
        : undefined;
      void Promise.resolve()
        .then(async (): Promise<VaultSshBundle | VaultRoutedSshBundle> => {
          if (!this.usable(s)) throw Error('Vault SSH is unavailable.');
          if (s.manualMode) {
            const { publicKey: _, sftpOnly: _file, ...base } = request;
            const q: VaultSshManualPlanRequest = {
              ...base,
              route: route?.binding ?? null,
              mode: s.manualMode,
              sftpOnly: request.sftpOnly === true,
            };
            const plan = parseVaultSshManualPlan(await this.options.manual!.plan(q), q);
            const context =
              plan &&
              parseVaultSshManualContext({
                plan,
                route: q.route,
                endpoint: route?.endpoint ?? '',
                publicKey: request.publicKey,
              });
            if (
              !context ||
              !this.usable(s) ||
              plan!.host.fingerprint !== s.verifiedFingerprint ||
              !s.hostBinding ||
              Object.entries(s.hostBinding).some(
                ([key, value]) => plan!.host.binding[key as keyof typeof s.hostBinding] !== value,
              )
            )
              throw Error('SSH credential context changed.');
            const manual = parseVaultSshManualEnvelope(
              await this.options.manual!.prompt(context, () => this.usable(s), s.abort.signal),
            );
            if (!manual || !this.usable(s)) throw Error('SSH credential entry was cancelled.');
            return this.options.manual!.bundle({
              context,
              credentialOverride: request.credentialOverride,
              manual,
            });
          }
          const bitwarden = await this.options.bitwarden?.(
            routedRequest ?? request,
            s.abort.signal,
            () => this.usable(s),
          );
          if (!this.usable(s)) throw Error('SSH authorization expired.');
          if (bitwarden) return bitwarden;
          return routedRequest
            ? this.options.route!.bundle(routedRequest)
            : this.options.bundle(request);
        })
        .then((result) => {
          if (!this.usable(s)) {
            this.fail(s);
            return;
          }
          const bundle = routedRequest
            ? parseVaultRoutedSshBundle(result, routedRequest)
            : parseVaultSshBundle(result, request);
          if (
            !bundle ||
            (s.protocol === 'ssh' && bundle.binding.protocol !== 'ssh') ||
            (s.hostBinding &&
              Object.entries(s.hostBinding).some(
                ([key, value]) => bundle.binding[key as keyof typeof bundle.binding] !== value,
              ))
          ) {
            this.fail(s);
            return;
          }
          s.binding = bundle.binding;
          s.phase = 'connecting';
          if (s.manualMode) {
            clearTimeout(s.timer);
            s.timer = setTimeout(() => this.fail(s), this.options.timeoutMs ?? 45000);
          }
          this.write(s, { ...bundle, columns, rows });
        })
        .catch(() => this.fail(s));
      return;
    }
    if (!vaultRecord(value) || s.phase === 'bundle') {
      this.fail(s);
      return;
    }
    const event = this.options.parseEvent(line);
    const member = event ? s.members.get(event.sessionId) : undefined;
    if (
      !event ||
      !member ||
      !['connected', 'screen', 'terminal-output', 'error', 'closed', ...sealedSftpEvents].includes(
        event.type,
      ) ||
      ((s.protocol === 'sftp' || member.id !== s.request.sessionId) &&
        ['screen', 'terminal-output'].includes(event.type))
    ) {
      this.fail(s);
      return;
    }
    if (member.state === 'closed') return;
    if (event.type === 'closed') {
      this.finishMember(s, member);
      if (![...s.members.values()].some((entry) => entry.state !== 'closed')) this.fail(s);
      return;
    }
    if (member.state === 'closing') return;
    if (!member.ownerCurrent()) {
      this.fail(s);
      return;
    }
    let connected: SealedSshConnected | undefined;
    if (event.type === 'connected') {
      const primary = member.id === s.request.sessionId;
      if (
        member.state !== 'opening' ||
        (primary ? s.phase !== 'connecting' : s.phase !== 'connected') ||
        !s.binding ||
        value.host !== s.binding.host ||
        value.port !== s.binding.port ||
        !vaultMetadataText(value.username, 2048) ||
        !value.username.length ||
        /\p{Cc}/u.test(value.username) ||
        typeof value.fingerprint !== 'string' ||
        !value.fingerprint.startsWith('SHA256:') ||
        !canonicalBase64(value.fingerprint.slice(7) + '=', 32, 32) ||
        (!primary &&
          (!s.connected ||
            value.username !== s.connected.username ||
            value.fingerprint !== s.connected.fingerprint))
      ) {
        this.fail(s);
        return;
      }
      connected = {
        sessionId: member.id,
        host: s.binding.host,
        port: s.binding.port,
        username: value.username,
        fingerprint: value.fingerprint,
      };
      member.state = 'connected';
      clearTimeout(member.timer);
      if (primary) {
        s.phase = 'connected';
        clearTimeout(s.timer);
        s.connected = connected;
      }
    } else if (event.type === 'error') {
      if (member.id === s.request.sessionId || member.state !== 'opening') {
        this.fail(s);
        return;
      }
      this.options.onLine(line);
      this.finishMember(s, member);
      if (![...s.members.values()].some((entry) => entry.state !== 'closed')) this.fail(s);
      return;
    } else if (s.phase !== 'connected' || member.state !== 'connected') {
      this.fail(s);
      return;
    }
    this.options.onLine(line);
    if (connected) {
      if (this.usable(s) && member.state === 'connected' && member.ownerCurrent())
        member.resolve(connected);
      else this.fail(s);
    }
  }

  private write(s: Session, command: unknown): void {
    if (!this.usable(s) || !s.child) throw new Error('Vault SSH is unavailable.');
    const frame = JSON.stringify(command) + '\n';
    if (Buffer.byteLength(frame) + s.child.stdin.writableLength > 8 * 1024 * 1024)
      throw new Error('SSH command is too large.');
    s.child.stdin.write(frame, (error) => {
      if (error) this.fail(s);
    });
  }
  send(sessionId: string, command: Record<string, unknown>): void {
    const s = this.aliases.get(sessionId);
    const member = s?.members.get(sessionId);
    if (
      !s ||
      !member ||
      member.state !== 'connected' ||
      !member.ownerCurrent() ||
      s.phase !== 'connected'
    )
      throw new Error('SSH session is unavailable.');
    const kind = typeof command.type === 'string' ? command.type : '';
    if (kind === 'sftp-edit') {
      if (!this.options.fileEditing) throw Error('Vault file editing is unavailable.');
      command = sealedSftpEditCommand(command);
    }
    const allowedFields = Object.hasOwn(sealedSftpCommandFields, kind)
      ? sealedSftpCommandFields[kind]
      : ['input', 'resize', 'snapshot', 'terminal-ack', 'auto-sudo-cancel'].includes(kind)
        ? ['data', 'paste', 'columns', 'rows', 'sequence']
        : undefined;
    if (
      !allowedFields ||
      ((s.protocol === 'sftp' || sessionId !== s.request.sessionId) &&
        !Object.hasOwn(sealedSftpCommandFields, kind)) ||
      Object.keys(command).some((k) => !['type', 'session_id', ...allowedFields].includes(k)) ||
      command.session_id !== sessionId
    )
      throw new Error('Unsupported vault SSH command.');
    const { session_id: _, ...fields } = command;
    try {
      this.write(s, { ...fields, sessionId });
    } catch {
      this.fail(s);
      throw new Error('Vault SSH is unavailable.');
    }
  }
  private retire(s: Session): void {
    s.phase = 'retired';
    s.abort.abort();
    clearTimeout(s.timer);
    s.chunks = [];
    s.bytes = 0;
    s.reject(new Error('Vault SSH connection stopped.'));
    for (const member of s.members.values()) {
      clearTimeout(member.timer);
      member.reject(new Error('Vault SSH connection stopped.'));
    }
  }
  private fail(s: Session): void {
    void this.stop(s).catch(() => undefined);
  }
  private stop(s: Session): Promise<void> {
    if (s.stop) return s.stop;
    this.retire(s);
    // Assign before ending stdin: stream callbacks can synchronously reenter.
    const task = Promise.resolve().then(async () => {
      const results = await Promise.allSettled([
        s.child
          ? stopChildProcess(s.child, {
              gracefulTimeoutMs: 1500,
              forceKillTimeoutMs: 1500,
              nativeExecutable: this.options.executable(),
            }).then((stopped) => {
              if (!stopped) throw Error('SSH shutdown could not be confirmed.');
            })
          : Promise.resolve(),
        s.route
          ? s.route.release()
          : s.routePending
            ? this.options.route!.broker.close(s.request.sessionId)
            : Promise.resolve(),
        s.manualMode
          ? Promise.resolve().then(() => this.options.manual!.close(s.request.sessionId))
          : Promise.resolve(),
      ]);
      if (results.some((result) => result.status === 'rejected')) {
        throw Error('SSH shutdown could not be confirmed.');
      }
      // An admitted temporary target belongs to the underlying native cohort,
      // including SFTP aliases that outlive the original terminal tab.
      if (s.onStopped) await s.onStopped();
      this.closed(s);
    });
    const tracked = task.catch(() => {
      const error = Error('SSH shutdown could not be confirmed.');
      for (const member of s.members.values()) member.failClose(error);
      if (s.stop === tracked) s.stop = undefined;
      throw error;
    });
    s.stop = tracked;
    return tracked;
  }
  close(sessionId: string): Promise<void> {
    const original = this.sessions.get(sessionId);
    const s = this.aliases.get(sessionId) ?? (original?.phase === 'retired' ? original : undefined),
      member = s?.members.get(sessionId);
    if (!s || !member) return Promise.resolve();
    if (
      s.phase !== 'connected' ||
      [...s.members.values()].filter((entry) => entry.state !== 'closed').length <= 1
    )
      return this.stop(s);
    if (member.state === 'closing') return member.closed;
    member.state = 'closing';
    clearTimeout(member.timer);
    member.reject(Error('SSH session stopped.'));
    member.timer = setTimeout(() => this.fail(s), this.options.timeoutMs ?? 5000);
    try {
      this.write(s, { type: 'close', sessionId });
    } catch {
      return this.stop(s);
    }
    return member.closed;
  }
  async closeCohorts(sessionIds: readonly string[]): Promise<void> {
    const cohorts = new Set<Session>();
    for (const id of sessionIds) {
      const s = this.aliases.get(id) ?? this.sessions.get(id);
      if (s) cohorts.add(s);
    }
    const results = await Promise.allSettled([...cohorts].map((s) => this.stop(s)));
    if (results.some((r) => r.status === 'rejected'))
      throw Error('SSH shutdown could not be confirmed.');
  }
  async closeAll(): Promise<void> {
    const results = await Promise.allSettled(
      [...this.sessions.values()]
        .map((s) => this.stop(s))
        .concat(this.options.route ? [this.options.route.broker.closeAll()] : []),
    );
    if (results.some((r) => r.status === 'rejected'))
      throw new Error('SSH shutdown could not be confirmed.');
  }
}
