import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import type { WebContents } from 'electron';
import { stopChildProcess } from './rdp.ts';
import {
  parseSerialBackendEvent,
  type SerialConnectedResponse,
  type SerialOpenRequest,
} from './serial.ts';
import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import {
  normalizeQuickSerial,
  parseSharedSerialUse,
  parseVaultSerialBundle,
  type VaultSerialBundle,
  type VaultSerialRequest,
} from './vault-serial-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';

type Owner = Pick<WebContents, 'isDestroyed' | 'on' | 'removeListener' | 'send'>;
type Session = {
  id: string;
  owner: Owner;
  accepted: () => boolean;
  child: ReturnType<typeof spawn>;
  executable: string;
  retire: () => void;
  resolve: (value: SerialConnectedResponse) => void;
  reject: (error: Error) => void;
  phase: 'recipient' | 'authorizing' | 'connecting' | 'connected' | 'stopped';
  timer?: NodeJS.Timeout;
  stop?: Promise<void>;
  portName?: string;
  shared?: { workspaceId: string; nodeId: string };
  chunks: Buffer[];
  bytes: number;
};

type Options = {
  executable: () => string;
  workspaceId: () => string | undefined;
  authorize: (request: VaultSerialRequest, accepted: () => boolean) => Promise<VaultSerialBundle>;
  sharedUse?: {
    active: () => boolean;
    check: (workspaceId: string, nodeIds: readonly string[]) => Promise<boolean[]>;
  };
  spawnChild?: typeof spawn;
};

/** One native recipient and renderer owner per protected serial line. */
export class SealedSerialBackend {
  private readonly sessions = new Map<string, Session>();
  private readonly options: Options;
  private permissionsTimer?: NodeJS.Timeout;
  private permissionsCheck?: Promise<void>;
  private permissionsRequested = false;

  constructor(options: Options) {
    this.options = options;
  }

  handles(id: string): boolean {
    return this.sessions.has(id);
  }

  async open(
    owner: Owner,
    q: SerialOpenRequest,
    epoch: number,
    accepted: () => boolean,
  ): Promise<SerialConnectedResponse> {
    const workspaceId = this.options.workspaceId();
    if (
      !workspaceId ||
      owner.isDestroyed() ||
      !accepted() ||
      !vaultID(q.sessionId) ||
      (q.nodeId !== undefined && !vaultID(q.nodeId)) ||
      this.sessions.has(q.sessionId) ||
      this.sessions.size >= 32
    )
      throw Error('Protected serial session is unavailable.');
    const quick = q.nodeId ? undefined : normalizeQuickSerial(q.portName, q.settings);
    if (!q.nodeId && !quick) throw Error('Invalid serial line.');
    const shared = this.options.sharedUse?.active();
    if (shared && !q.nodeId) throw Error('Select a saved shared serial connection.');
    const request = {
      workspaceId,
      nodeId: q.nodeId ?? randomUUID(),
      sessionId: q.sessionId,
      requestId: randomUUID(),
      epoch,
      ...(quick ? { quick } : {}),
    };
    const executable = this.options.executable();
    const child = (this.options.spawnChild ?? spawn)(executable, ['--operation', 'serial-sealed'], {
      stdio: 'pipe',
      windowsHide: true,
    });
    return new Promise((resolve, reject) => {
      const s: Session = {
        id: q.sessionId,
        owner,
        child,
        executable,
        resolve,
        reject,
        phase: 'recipient',
        shared: shared ? { workspaceId, nodeId: request.nodeId } : undefined,
        chunks: [],
        bytes: 0,
        accepted: () =>
          accepted() && this.options.workspaceId() === workspaceId && !owner.isDestroyed(),
        retire: () => this.fail(s),
      };
      this.sessions.set(s.id, s);
      if (s.shared) this.schedulePermissionsCheck();
      owner.on('did-start-loading', s.retire);
      owner.on('destroyed', s.retire);
      s.timer = setTimeout(s.retire, 30_000);
      child.on('error', s.retire);
      child.on('close', s.retire);
      child.stdin?.on('error', s.retire);
      child.stderr?.on('data', () => {});
      child.stdout?.on('error', s.retire);
      child.stdout?.on('data', (chunk: Buffer) =>
        this.receive(s, request, q.columns, q.rows, chunk),
      );
    });
  }

  private receive(
    s: Session,
    q: Omit<VaultSerialRequest, 'publicKey'>,
    columns: number,
    rows: number,
    chunk: Buffer,
  ): void {
    try {
      for (let offset = 0; offset < chunk.length && s.phase !== 'stopped';) {
        if (!s.accepted()) throw Error('Protected serial session is unavailable.');
        const newline = chunk.indexOf(10, offset),
          end = newline < 0 ? chunk.length : newline;
        const part = chunk.subarray(offset, end);
        const max = s.phase === 'recipient' || s.phase === 'authorizing' ? 1024 : 32 * 1024 * 1024;
        if (s.bytes + part.length > max || s.chunks.length >= 8192)
          throw Error('Serial frame exceeds limit.');
        s.chunks.push(part);
        s.bytes += part.length;
        if (newline < 0) return;
        const line = new TextDecoder('utf-8', { fatal: true }).decode(
          Buffer.concat(s.chunks, s.bytes),
        );
        s.chunks = [];
        s.bytes = 0;
        this.line(s, q, columns, rows, line);
        offset = end + 1;
      }
    } catch {
      this.fail(s);
    }
  }

  private line(
    s: Session,
    q: Omit<VaultSerialRequest, 'publicKey'>,
    columns: number,
    rows: number,
    line: string,
  ): void {
    if (s.phase === 'recipient') {
      const value: unknown = JSON.parse(line);
      if (
        !vaultRecord(value) ||
        !vaultFields(value, ['type', 'publicKey']) ||
        value.type !== 'recipient' ||
        !canonicalBase64(value.publicKey, 32, 32)
      )
        throw Error('Invalid serial recipient.');
      const request = { ...q, publicKey: value.publicKey };
      s.phase = 'authorizing';
      const current = () => s.phase === 'authorizing' && s.accepted();
      void this.options
        .authorize(request, current)
        .then((value) => {
          const bundle = parseVaultSerialBundle(value, request);
          if (!bundle || !current()) throw Error('Serial opening cancelled.');
          s.portName = bundle.binding.host;
          s.phase = 'connecting';
          this.write(s, { ...bundle, columns, rows });
        })
        .catch(() => this.fail(s));
      return;
    }
    const event = parseSerialBackendEvent(line);
    if (!event || event.sessionId !== s.id || (s.phase !== 'connecting' && s.phase !== 'connected'))
      throw Error('Invalid protected serial event.');
    if (event.type === 'connected') {
      if (s.phase !== 'connecting' || event.portName !== s.portName)
        throw Error('Unsolicited serial start.');
      s.phase = 'connected';
      clearTimeout(s.timer);
      s.resolve(event);
    } else if (event.type === 'screen' && s.phase !== 'connected') {
      throw Error('Unsolicited serial screen.');
    }
    s.owner.send('serial:event', event);
    if (event.type === 'closed' || (event.type === 'error' && s.phase === 'connecting'))
      void this.stop(s).catch(() => {});
  }

  private write(s: Session, value: unknown): void {
    const input = s.child.stdin;
    const data = JSON.stringify(value) + '\n';
    if (
      !s.accepted() ||
      !input ||
      input.destroyed ||
      input.writableEnded ||
      Buffer.byteLength(data) + input.writableLength > 2 * 1024 * 1024
    )
      throw Error('Protected serial session is unavailable.');
    input.write(data, (error) => {
      if (error) this.fail(s);
    });
  }

  command(
    owner: Owner,
    id: string,
    command: { type: 'input'; data: string } | { type: 'resize'; columns: number; rows: number },
  ): void {
    const s = this.sessions.get(id);
    if (!s || s.owner !== owner || !s.accepted() || s.phase === 'stopped')
      throw Error('Invalid serial owner.');
    if (s.phase === 'connected') this.write(s, { ...command, session_id: id });
  }

  async close(owner: Owner, id: string): Promise<void> {
    const s = this.sessions.get(id);
    if (!s) return;
    if (s.owner !== owner) throw Error('Invalid serial owner.');
    await this.stop(s);
  }

  async closeAll(): Promise<void> {
    const stopped = await Promise.allSettled([...this.sessions.values()].map((s) => this.stop(s)));
    if (stopped.some((result) => result.status === 'rejected'))
      throw Error('Serial shutdown could not be confirmed.');
  }

  requestSnapshots(): void {
    for (const s of this.sessions.values()) {
      if (s.phase !== 'connected') continue;
      try {
        this.write(s, { type: 'snapshot', session_id: s.id });
      } catch {
        this.fail(s);
      }
    }
  }

  verifySharedUse(): Promise<void> {
    clearTimeout(this.permissionsTimer);
    this.permissionsTimer = undefined;
    this.permissionsRequested = true;
    if (this.permissionsCheck) return this.permissionsCheck;
    this.permissionsCheck = Promise.resolve()
      .then(async () => {
        while (this.permissionsRequested) {
          this.permissionsRequested = false;
          await this.checkSharedUse();
        }
      })
      .finally(() => {
        this.permissionsCheck = undefined;
        this.schedulePermissionsCheck();
      });
    return this.permissionsCheck;
  }

  private async checkSharedUse(): Promise<void> {
    const active = [...this.sessions.values()].filter(
      (s) => s.shared && s.phase !== 'stopped' && s.accepted(),
    );
    if (!active.length || !this.options.sharedUse) return;
    const ids = [...new Set(active.map((s) => s.shared!.nodeId))];
    let flags: boolean[] | undefined;
    try {
      const current = await this.options.sharedUse.check(active[0].shared!.workspaceId, ids);
      flags = parseSharedSerialUse({ current }, ids.length);
    } catch {
      // Continuing requires a successful read from the current workspace owner.
    }
    const allowed = new Set(ids.filter((_, index) => flags?.[index] === true));
    for (const s of active) {
      if (!allowed.has(s.shared!.nodeId) && s.phase !== 'stopped') this.fail(s);
    }
  }

  private schedulePermissionsCheck(): void {
    if (![...this.sessions.values()].some((s) => s.shared && s.phase !== 'stopped')) {
      clearTimeout(this.permissionsTimer);
      this.permissionsTimer = undefined;
    } else if (!this.permissionsTimer && !this.permissionsCheck) {
      this.permissionsTimer = setTimeout(() => void this.verifySharedUse(), 30_000);
      this.permissionsTimer.unref();
    }
  }

  private fail(s: Session): void {
    const notify = s.phase === 'connected' && s.accepted();
    void this.stop(s).catch(() => {});
    if (notify) {
      try {
        s.owner.send('serial:event', { type: 'closed', sessionId: s.id });
      } catch {
        /* Owner retired. */
      }
    }
  }

  private stop(s: Session): Promise<void> {
    if (s.stop) return s.stop;
    s.phase = 'stopped';
    if (s.shared) this.schedulePermissionsCheck();
    clearTimeout(s.timer);
    s.chunks = [];
    s.bytes = 0;
    s.reject(Error('Protected serial connection stopped.'));
    s.stop = Promise.resolve()
      .then(() => stopChildProcess(s.child, { nativeExecutable: s.executable }))
      .then((stopped) => {
        if (!stopped) throw Error('Serial process is still running.');
        s.owner.removeListener('did-start-loading', s.retire);
        s.owner.removeListener('destroyed', s.retire);
        if (this.sessions.get(s.id) === s) this.sessions.delete(s.id);
      })
      .catch((error: unknown) => {
        s.stop = undefined;
        throw error;
      });
    return s.stop;
  }
}
