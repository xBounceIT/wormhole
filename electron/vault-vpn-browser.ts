import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash } from 'node:crypto';
import { stopChildProcess } from './rdp.ts';
import { parseVaultNativeObject, vaultFields, vaultID } from './vault-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';
import {
  parseVPNSSOManifest,
  parseVPNSSOContext,
  parseVPNSSOPacket,
  vpnSSOArchiveBytes,
  vpnSSOChunkBytes,
  vpnSSOChunkCount,
  type VPNSSOManifest,
  type VPNSSOOffer,
  type VPNSSOPacket,
  type VPNSSOContext,
} from './vault-vpn-sso.ts';

type Frame = { header: Record<string, unknown>; body: Buffer; wireBytes: number };
type Spawn = (executable: string, args: string[]) => ChildProcessWithoutNullStreams;
type Options = { executable: string; signal: AbortSignal; current(): boolean };
const unavailable = () => Error('Native VPN browser storage is unavailable.');
const headerLimit = 8 * 1024 * 1024;

// The only plaintext endpoint is the owning native Chromium adapter. Recipient
// private keys stay in Go, no archive path/secret flag enters argv, and this module
// is intentionally absent from preload and all ordinary renderer IPC.
export class VaultVPNBrowserRecipient {
  private static readonly uncertain = new Set<VaultVPNBrowserRecipient>();
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly options: Options;
  private part = Buffer.alloc(4);
  private filled = 0;
  private reading: 'prefix' | 'header' | 'body' = 'prefix';
  private headerBytes = 0;
  private header: Record<string, unknown> | undefined;
  private readonly frames: Frame[] = [];
  private queuedBytes = 0;
  private waiter: { resolve(f: Frame): void; reject(e: Error): void } | undefined;
  private readonly writes = new Set<{ reject(e: Error): void }>();
  private stopped = false;
  private closing: Promise<void> | undefined;
  private work: Promise<unknown> | undefined;
  private phase: 'new' | 'restored' | 'captured' = 'new';
  private info: { profileId: string; publicKey: string; lockedMemory: boolean } | undefined;
  private bound: VPNSSOContext | undefined;
  private readonly timer: NodeJS.Timeout;
  private readonly abort = () => {
    void this.shutdown().catch(() => {});
  };

  private constructor(options: Options, launch: Spawn) {
    this.options = options;
    this.child = launch(options.executable, ['--operation', 'vault-vpn-browser']);
    this.child.stdout.on('data', (chunk: Buffer) => {
      if (this.stopped) {
        chunk.fill(0);
        return;
      }
      try {
        this.receive(chunk);
      } catch {
        this.abort();
      } finally {
        chunk.fill(0);
      }
    });
    this.child.stderr.on('data', () => {});
    this.child.stdin.on('error', this.abort);
    this.child.once('error', this.abort);
    this.child.stdout.once('end', this.abort);
    this.child.once('close', this.abort);
    options.signal.addEventListener('abort', this.abort, { once: true });
    this.timer = setTimeout(this.abort, 300000);
    this.timer.unref();
  }
  static async open(
    options: Options,
    launch: Spawn = (exe, args) => spawn(exe, args, { windowsHide: true, stdio: 'pipe' }),
    reserved?: (recipient: VaultVPNBrowserRecipient) => void,
  ) {
    options = {
      executable: options.executable,
      signal: options.signal,
      current: options.current.bind(options),
    };
    if (!options.executable || options.signal.aborted || !options.current()) throw unavailable();
    await Promise.all(
      [...VaultVPNBrowserRecipient.uncertain].map((recipient) => recipient.close()),
    );
    if (options.signal.aborted || !options.current()) throw unavailable();
    const recipient = new VaultVPNBrowserRecipient(options, launch);
    try {
      reserved?.(recipient);
      const h = await recipient.control();
      if (
        !vaultFields(h, ['type', 'profileId', 'publicKey', 'lockedMemory']) ||
        h.type !== 'recipient' ||
        !vaultID(h.profileId) ||
        !canonicalBase64(h.publicKey, 32, 32) ||
        typeof h.lockedMemory !== 'boolean'
      )
        throw unavailable();
      recipient.info = {
        profileId: h.profileId,
        publicKey: h.publicKey,
        lockedMemory: h.lockedMemory,
      };
      recipient.check();
      return recipient;
    } catch {
      await recipient.close();
      throw unavailable();
    }
  }
  get metadata() {
    if (!this.info) throw unavailable();
    return { ...this.info };
  }
  private check() {
    if (this.stopped || this.options.signal.aborted || !this.options.current()) throw unavailable();
  }
  private receive(chunk: Buffer) {
    for (let offset = 0; offset < chunk.length;) {
      const n = Math.min(this.part.length - this.filled, chunk.length - offset);
      this.part.set(chunk.subarray(offset, offset + n), this.filled);
      offset += n;
      this.filled += n;
      if (this.filled !== this.part.length) continue;
      this.filled = 0;
      if (this.reading === 'prefix') {
        this.headerBytes = this.part.readUInt32BE();
        this.part.fill(0);
        if (!this.headerBytes || this.headerBytes > headerLimit) throw unavailable();
        this.part = Buffer.alloc(this.headerBytes);
        this.reading = 'header';
        continue;
      }
      if (this.reading === 'header') {
        const raw = this.part;
        try {
          this.header = parseVaultNativeObject(
            new TextDecoder('utf-8', { fatal: true }).decode(raw),
          );
        } finally {
          raw.fill(0);
        }
        if (!this.header) throw unavailable();
        const bytes = this.header.type === 'archive' ? this.header.bytes : 0;
        if (
          !Number.isInteger(bytes) ||
          (bytes as number) < 0 ||
          (bytes as number) > vpnSSOChunkBytes
        )
          throw unavailable();
        if (bytes) {
          this.part = Buffer.alloc(bytes as number);
          this.reading = 'body';
          continue;
        }
        this.deliver(Buffer.alloc(0));
      } else {
        this.deliver(this.part);
      }
    }
  }
  private deliver(body: Buffer) {
    const size = 4 + this.headerBytes + body.length;
    const frame = { header: this.header!, body, wireBytes: size };
    this.header = undefined;
    this.headerBytes = 0;
    this.reading = 'prefix';
    this.part = Buffer.alloc(4);
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = undefined;
      waiter.resolve(frame);
    } else {
      this.frames.push(frame);
      this.queuedBytes += size;
      if (this.frames.length > 18 || this.queuedBytes > 96 * 1024 * 1024) throw unavailable();
    }
  }
  private async next(): Promise<Frame> {
    this.check();
    const frame = this.frames.shift();
    if (frame) {
      this.queuedBytes -= frame.wireBytes;
      return frame;
    }
    if (this.waiter) throw unavailable();
    return new Promise<Frame>((resolve, reject) => {
      this.waiter = { resolve, reject };
    });
  }
  private async control(): Promise<Record<string, unknown>> {
    const frame = await this.next();
    try {
      if (frame.body.length) throw unavailable();
      return frame.header;
    } finally {
      frame.body.fill(0);
    }
  }
  private async write(header: Record<string, unknown>, body?: Uint8Array) {
    this.check();
    const raw = Buffer.from(JSON.stringify(header)),
      size = Buffer.alloc(4);
    if (!raw.length || raw.length > headerLimit || (body && body.byteLength > vpnSSOChunkBytes))
      throw unavailable();
    size.writeUInt32BE(raw.length);
    try {
      for (const part of [size, raw, ...(body ? [body] : [])]) {
        this.check();
        await new Promise<void>((resolve, reject) => {
          const entry = { reject };
          this.writes.add(entry);
          try {
            this.child.stdin.write(part, (error) => {
              this.writes.delete(entry);
              if (error) reject(unavailable());
              else resolve();
            });
          } catch {
            this.writes.delete(entry);
            reject(unavailable());
          }
        });
        this.check();
      }
    } finally {
      raw.fill(0);
      size.fill(0);
    }
  }
  private run<T>(action: () => Promise<T>): Promise<T> {
    if (this.work) return Promise.reject(Error('Native VPN browser storage is busy.'));
    const work = Promise.resolve()
      .then(async () => {
        this.check();
        return action();
      })
      .then((value) => {
        try {
          this.check();
          return value;
        } catch (error) {
          if (Buffer.isBuffer(value)) value.fill(0);
          throw error;
        }
      })
      .catch(async () => {
        await this.shutdown();
        throw unavailable();
      })
      .finally(() => {
        if (this.work === work) this.work = undefined;
      });
    this.work = work;
    return work;
  }
  restore(offer: VPNSSOOffer, take: (index: number) => Promise<VPNSSOPacket>): Promise<Buffer> {
    const c = parseVPNSSOContext(offer.context),
      m = c && parseVPNSSOManifest(offer.manifest, c, 'restore');
    return this.run(async () => {
      if (
        this.phase !== 'new' ||
        !c ||
        !m ||
        c.profileId !== this.info?.profileId ||
        c.restorePublicKey !== this.info.publicKey
      )
        throw unavailable();
      const archive = Buffer.alloc(m.bytes);
      try {
        await this.write({ type: 'bind', context: c, manifest: m });
        const count = vpnSSOChunkCount(m);
        for (let index = 0; index < count; index++) {
          const p = parseVPNSSOPacket(await take(index), c, 'restore');
          if (
            !p ||
            p.index !== index ||
            p.manifest.bytes !== m.bytes ||
            p.manifest.digest !== m.digest
          )
            throw unavailable();
          await this.write({ type: 'restore', packet: p });
        }
        for (let index = 0; index < count; index++) {
          const f = await this.next(),
            h = f.header;
          try {
            if (
              !vaultFields(h, ['type', 'index', 'bytes']) ||
              h.type !== 'archive' ||
              h.index !== index ||
              h.bytes !== Math.min(vpnSSOChunkBytes, m.bytes - index * vpnSSOChunkBytes) ||
              f.body.length !== h.bytes
            )
              throw unavailable();
            archive.set(f.body, index * vpnSSOChunkBytes);
          } finally {
            f.body.fill(0);
          }
        }
        const h = await this.control(),
          actual = parseVPNSSOManifest(h.manifest, c, 'restore');
        if (
          !vaultFields(h, ['type', 'manifest']) ||
          h.type !== 'restored' ||
          !actual ||
          actual.bytes !== m.bytes ||
          actual.digest !== m.digest ||
          createHash('sha256').update(archive).digest('base64') !== m.digest
        )
          throw unavailable();
        this.phase = 'restored';
        this.bound = c;
        return archive;
      } catch (error) {
        archive.fill(0);
        throw error;
      }
    });
  }
  capture(
    archive: Uint8Array,
    push: (packet: VPNSSOPacket) => Promise<void>,
  ): Promise<VPNSSOManifest> {
    return this.run(async () => {
      try {
        if (
          this.phase !== 'restored' ||
          !(archive instanceof Uint8Array) ||
          !archive.length ||
          archive.length > vpnSSOArchiveBytes
        )
          throw unavailable();
        const c = this.bound,
          m = {
            bytes: archive.length,
            digest: createHash('sha256').update(archive).digest('base64'),
          };
        if (!c) throw unavailable();
        await this.write({ type: 'capture', bytes: m.bytes });
        const ready = await this.control();
        if (!vaultFields(ready, ['type']) || ready.type !== 'capturing') throw unavailable();
        const count = vpnSSOChunkCount(m);
        for (let index = 0; index < count; index++) {
          const body = archive.subarray(index * vpnSSOChunkBytes, (index + 1) * vpnSSOChunkBytes);
          await this.write({ type: 'chunk', index, bytes: body.length }, body);
          body.fill(0);
        }
        for (let index = 0; index < count; index++) {
          const h = await this.control(),
            p = parseVPNSSOPacket(h.packet, c, 'capture');
          if (
            !vaultFields(h, ['type', 'packet']) ||
            h.type !== 'packet' ||
            !p ||
            p.index !== index ||
            p.manifest.bytes !== m.bytes ||
            p.manifest.digest !== m.digest
          )
            throw unavailable();
          this.check();
          await push(p);
          this.check();
        }
        const h = await this.control(),
          actual = parseVPNSSOManifest(h.manifest, c, 'capture');
        if (
          !vaultFields(h, ['type', 'manifest']) ||
          h.type !== 'captured' ||
          !actual ||
          actual.bytes !== m.bytes ||
          actual.digest !== m.digest
        )
          throw unavailable();
        this.phase = 'captured';
        return actual;
      } finally {
        if (archive instanceof Uint8Array) archive.fill(0);
      }
    }).finally(() => {
      if (archive instanceof Uint8Array) archive.fill(0);
    });
  }
  private shutdown(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true;
    clearTimeout(this.timer);
    this.options.signal.removeEventListener('abort', this.abort);
    this.waiter?.reject(unavailable());
    this.waiter = undefined;
    this.header = undefined;
    this.headerBytes = 0;
    for (const entry of this.writes) entry.reject(unavailable());
    this.writes.clear();
    this.part.fill(0);
    this.filled = 0;
    for (const frame of this.frames) frame.body.fill(0);
    this.frames.length = 0;
    this.queuedBytes = 0;
    const closing = stopChildProcess(this.child, {
      gracefulTimeoutMs: 1000,
      forceKillTimeoutMs: 1000,
      nativeExecutable: this.options.executable,
    })
      .then((exited) => {
        if (!exited) throw unavailable();
        VaultVPNBrowserRecipient.uncertain.delete(this);
      })
      .catch((error: unknown) => {
        VaultVPNBrowserRecipient.uncertain.add(this);
        if (this.closing === closing) this.closing = undefined;
        throw error;
      });
    this.closing = closing;
    return closing;
  }
  async close(): Promise<void> {
    const work = this.work;
    await this.shutdown();
    await work?.catch(() => {});
  }
}
