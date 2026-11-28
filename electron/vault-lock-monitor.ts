import {
  parseVaultSecurity,
  type VaultSecurity,
  type VaultProfile,
  type VaultProfileStatus,
} from './vault-security.ts';
import type { EventEmitter } from 'node:events';

type Options = {
  idleSeconds(): number;
  idleState(threshold: number): string;
  security(): Promise<VaultSecurity>;
  lock(): Promise<void>;
  applyProfile?(profile: VaultProfile, source: 'unlock' | 'refresh'): void;
  profileChanged?(): void;
  now?: () => number;
  intervalMs?: number;
};

const ranks: VaultProfile[] = ['default', 'standard', 'hardened', 'paranoid'];
const limits = [900, 900, 300, 120];

/** Main owns the timer and OS-wide activity samples. No renderer timer/input
 * can extend a vault lifetime. An in-flight policy read never stops idle checks. */
export class VaultLockMonitor {
  private readonly options: Options;
  private timer: ReturnType<typeof setInterval> | undefined;
  private profile: VaultSecurity | undefined;
  private rank = 0;
  private enforcedSource: VaultSecurity['source'] = 'workspace';
  private unlockedAt = 0;
  private generation = 0;
  private reading: number | undefined;
  private locking: Promise<void> | undefined;
  private retiring = false;

  constructor(options: Options) {
    if (
      options.intervalMs !== undefined &&
      (!Number.isSafeInteger(options.intervalMs) ||
        options.intervalMs < 1 ||
        options.intervalMs > 1000)
    )
      throw new Error('Invalid vault monitor interval.');
    this.options = options;
  }

  get active(): boolean {
    return this.profile !== undefined;
  }

  get effectiveProfile(): VaultProfile | undefined {
    return this.active ? ranks[this.rank] : undefined;
  }

  get profileStatus(): VaultProfileStatus | undefined {
    if (!this.profile) return undefined;
    const effective = ranks[this.rank]!;
    return {
      effective,
      source: this.enforcedSource,
      ...(effective === 'default' && this.profile.canTightenToStandard
        ? { canTightenToStandard: true }
        : {}),
      retainedUntilLock:
        this.profile.retainedUntilLock === true || this.profile.effective !== effective,
    };
  }

  activate(value: VaultSecurity): void {
    const profile = parseVaultSecurity(value);
    const now = this.now();
    if (!profile || !Number.isFinite(now) || this.locking || this.retiring)
      throw new Error('Vault monitor is unavailable.');
    this.deactivate();
    this.options.applyProfile?.(profile.effective, 'unlock');
    this.profile = profile;
    this.rank = ranks.indexOf(profile.effective);
    this.enforcedSource = profile.source;
    this.unlockedAt = now;
    this.timer = setInterval(() => this.check(), this.options.intervalMs ?? 1000);
    this.timer.unref();
    this.check();
    if (!this.active) throw new Error('Vault monitor is unavailable.');
    this.notifyProfileChanged();
  }

  deactivate(): void {
    const wasActive = this.active;
    this.generation++;
    clearInterval(this.timer);
    this.timer = undefined;
    this.profile = undefined;
    this.reading = undefined;
    if (wasActive) this.notifyProfileChanged();
  }

  minimized(): void {
    if (this.active && this.rank >= 2) this.requestLock();
  }

  private now(): number {
    return (this.options.now ?? (() => performance.now()))();
  }

  private notifyProfileChanged(): void {
    try {
      this.options.profileChanged?.();
    } catch {
      // A closing desktop window cannot interrupt admission or lock cleanup.
    }
  }

  private requestLock(): void {
    if (!this.active || this.locking) return;
    this.retiring = true;
    this.deactivate();
    // Invoke synchronously so retirement starts before another queued IPC can run.
    try {
      const result = this.options.lock();
      this.locking = Promise.resolve(result)
        .catch(() => undefined)
        .finally(() => {
          this.locking = undefined;
          this.retiring = false;
        });
    } catch {
      // The application lock callback owns diagnostics; never resume the timer.
      this.retiring = false;
    }
  }

  private check(): void {
    const previous = this.profile;
    if (!previous) return;
    try {
      const now = this.now();
      const idle = this.options.idleSeconds();
      const state = this.options.idleState(limits[this.rank]!);
      if (
        !Number.isFinite(now) ||
        now < this.unlockedAt ||
        !Number.isSafeInteger(idle) ||
        idle < 0 ||
        !['active', 'idle', 'locked'].includes(state) ||
        state === 'locked' ||
        Math.min(idle, (now - this.unlockedAt) / 1000) >= limits[this.rank]!
      ) {
        this.requestLock();
        return;
      }
    } catch {
      this.requestLock();
      return;
    }

    const generation = this.generation;
    if (this.reading === generation) return;
    this.reading = generation;
    let result: Promise<VaultSecurity>;
    try {
      result = this.options.security();
    } catch {
      this.requestLock();
      return;
    }
    void result
      .then(
        (value) => {
          if (generation !== this.generation || !this.profile) return;
          const next = parseVaultSecurity(value);
          if (
            !next ||
            BigInt(next.sequence) < BigInt(previous.sequence) ||
            (next.sequence === previous.sequence &&
              (next.workspace !== previous.workspace || next.user !== previous.user))
          ) {
            this.requestLock();
            return;
          }
          // A looser OS or workspace policy takes effect only after a new unlock.
          const rank = ranks.indexOf(next.effective);
          if (rank > this.rank) {
            try {
              this.options.applyProfile?.(next.effective, 'refresh');
            } catch {
              this.requestLock();
              return;
            }
            this.rank = rank;
          }
          if (rank === this.rank) this.enforcedSource = next.source;
          this.profile = next;
          if (
            previous.effective !== next.effective ||
            previous.source !== next.source ||
            previous.retainedUntilLock !== next.retainedUntilLock ||
            previous.canTightenToStandard !== next.canTightenToStandard
          )
            this.notifyProfileChanged();
        },
        () => {
          if (generation === this.generation) this.requestLock();
        },
      )
      .finally(() => {
        if (this.reading === generation) this.reading = undefined;
      });
  }
}

export function bindVaultPowerEvents(
  power: Pick<EventEmitter, 'on' | 'removeListener'>,
  lock: () => void,
): () => void {
  const events = ['lock-screen', 'suspend', 'resume', 'user-did-resign-active', 'shutdown'];
  for (const event of events) power.on(event, lock);
  return () => {
    for (const event of events) power.removeListener(event, lock);
  };
}
