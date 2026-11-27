import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { VaultVPNBrowserRecipient } from '../electron/vault-vpn-browser.ts';
import { vpnSSOFixture } from './fixtures/vault-vpn-sso.ts';

const tick = () => new Promise<void>((r) => setImmediate(r));
function frame(header: unknown, body = Buffer.alloc(0)) {
  const raw = Buffer.from(JSON.stringify(header)),
    prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(raw.length);
  return Buffer.concat([prefix, raw, body]);
}
class Child extends EventEmitter {
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  pid = process.pid;
  exitCode: number | null = null;
  signalCode = null;
  exitOnEnd = true;
  exitOnKill = true;
  writeError = false;
  kills = 0;
  readonly profileId = randomUUID();
  readonly publicKey = Buffer.alloc(32, 7).toString('base64');
  readonly commands: any[] = [];
  private incoming = Buffer.alloc(0);
  private headerBytes: number | undefined;
  private header: any;
  onCommand: (header: any, body: Buffer) => void = (h) => {
    if (h.type === 'bind') this.emitFrame({ type: 'restored', manifest: h.manifest });
    if (h.type === 'capture') this.emitFrame({ type: 'capturing' });
  };
  readonly stdin = new Writable({
    write: (chunk, _encoding, callback) => {
      if (this.writeError) {
        callback(Error('fixture-private-diagnostic'));
        return;
      }
      this.incoming = Buffer.concat([this.incoming, chunk]);
      while (true) {
        if (this.headerBytes === undefined) {
          if (this.incoming.length < 4) break;
          this.headerBytes = this.incoming.readUInt32BE();
          this.incoming = this.incoming.subarray(4);
        }
        if (!this.header) {
          if (this.incoming.length < this.headerBytes) break;
          this.header = JSON.parse(this.incoming.subarray(0, this.headerBytes).toString());
          this.incoming = this.incoming.subarray(this.headerBytes);
        }
        const n = this.header.type === 'chunk' ? this.header.bytes : 0;
        if (this.incoming.length < n) break;
        const header = this.header,
          body = Buffer.from(this.incoming.subarray(0, n));
        this.incoming = this.incoming.subarray(n);
        this.header = undefined;
        this.headerBytes = undefined;
        this.commands.push(header);
        this.onCommand(header, body);
        body.fill(0);
      }
      callback();
    },
    final: (callback) => {
      callback();
      if (this.exitOnEnd) this.exit();
    },
  });
  emitFrame(header: unknown, body?: Buffer) {
    this.stdout.write(frame(header, body));
  }
  ready() {
    this.emitFrame({
      type: 'recipient',
      profileId: this.profileId,
      publicKey: this.publicKey,
      lockedMemory: true,
    });
  }
  exit() {
    if (this.exitCode !== null) return;
    this.exitCode = 0;
    this.emit('exit', 0, null);
    this.stdout.end();
    this.stderr.end();
    this.emit('close', 0, null);
  }
  kill() {
    this.kills++;
    if (this.exitOnKill) this.exit();
    return true;
  }
  process() {
    return this as unknown as ChildProcessWithoutNullStreams;
  }
}
async function fixture(start?: (c: Child) => void) {
  const child = new Child(),
    controller = new AbortController();
  let allowed = true;
  const native = await VaultVPNBrowserRecipient.open(
    { executable: 'fixture', signal: controller.signal, current: () => allowed },
    () => {
      queueMicrotask(() => (start ? start(child) : child.ready()));
      return child.process();
    },
  );
  const { offer } = vpnSSOFixture();
  offer.context.profileId = child.profileId;
  offer.context.restorePublicKey = child.publicKey;
  return {
    child,
    native,
    controller,
    offer,
    revoke: () => {
      allowed = false;
    },
  };
}

test('native recipient rejects malformed, oversized, noncanonical and queued startup frames', async () => {
  const bad = [
    Buffer.from([0, 0, 0, 0]),
    Buffer.from([0, 128, 0, 1]),
    frame({ type: 'recipient', profileId: 'bad', publicKey: 'AA==', lockedMemory: false }),
    frame({ type: 'archive', bytes: 4 * 1024 * 1024 + 1 }),
    Buffer.concat([Buffer.from([0, 0, 0, 3]), Buffer.from([123, 255, 125])]),
    Buffer.concat([Buffer.from([0, 0, 0, 2]), Buffer.from('[]')]),
    Buffer.alloc(12 * 1024 * 1024 + 65537),
  ];
  for (const data of bad) {
    let child!: Child;
    await assert.rejects(
      VaultVPNBrowserRecipient.open(
        { executable: 'fixture', signal: new AbortController().signal, current: () => true },
        () => {
          child = new Child();
          queueMicrotask(() => child.stdout.write(data));
          return child.process();
        },
      ),
    );
    assert.equal(child.exitCode, 0);
  }
  await assert.rejects(
    fixture((child) => {
      child.ready();
      for (let i = 0; i < 19; i++) child.emitFrame({ type: 'unexpected' });
    }),
  );
  await assert.rejects(
    VaultVPNBrowserRecipient.open({
      executable: '',
      signal: new AbortController().signal,
      current: () => true,
    }),
  );
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(
    VaultVPNBrowserRecipient.open({
      executable: 'fixture',
      signal: aborted.signal,
      current: () => true,
    }),
  );
  let checks = 0,
    launched = false;
  await assert.rejects(
    VaultVPNBrowserRecipient.open(
      {
        executable: 'fixture',
        signal: new AbortController().signal,
        current: () => ++checks === 1,
      },
      () => {
        launched = true;
        return new Child().process();
      },
    ),
  );
  assert.equal(launched, false);
});

test('native recipient parses fragmented frames and rejects foreign restore data without retaining plaintext', async () => {
  const f = await fixture((child) => {
    const bytes = frame({
      type: 'recipient',
      profileId: child.profileId,
      publicKey: child.publicKey,
      lockedMemory: false,
    });
    for (const n of bytes) child.stdout.write(Buffer.from([n]));
  });
  try {
    const restore = f.native.restore(f.offer, async () =>
      assert.fail('empty source requested chunks'),
    );
    f.offer.context.profileId = randomUUID();
    assert.equal((await restore).length, 0);
    await assert.rejects(f.native.restore(f.offer, async () => assert.fail()));
  } finally {
    await f.native.close();
  }
  for (const bad of ['recipient', 'manifest', 'body', 'write']) {
    const f = await fixture();
    try {
      if (bad === 'recipient')
        f.offer.context.restorePublicKey = Buffer.alloc(32, 4).toString('base64');
      if (bad === 'write') f.child.writeError = true;
      if (bad === 'manifest')
        f.child.onCommand = () =>
          f.child.emitFrame({
            type: 'restored',
            manifest: { bytes: 0, digest: Buffer.alloc(32, 1).toString('base64') },
          });
      if (bad === 'body')
        f.child.onCommand = () =>
          f.child.emitFrame({ type: 'archive', bytes: 1, index: 0 }, Buffer.from([0x72]));
      await assert.rejects(f.native.restore(f.offer, async () => assert.fail()));
      assert.equal(f.child.exitCode, 0);
    } finally {
      await f.native.close();
    }
  }
});

test('native restore accepts byte-fragmented plaintext and joins a complete digest before release', async () => {
  const f = await fixture(),
    plain = Buffer.alloc(65537, 0x68),
    manifest = { bytes: plain.length, digest: createHash('sha256').update(plain).digest('base64') };
  f.offer.context.sourceRevision = '1';
  f.offer.context.sourceDigest = Buffer.alloc(32, 3).toString('base64');
  f.offer.manifest = manifest;
  f.child.onCommand = (h) => {
    if (h.type !== 'restore') return;
    const raw = frame({ type: 'archive', index: 0, bytes: plain.length }, plain);
    for (const byte of raw) f.child.stdout.write(Buffer.from([byte]));
    f.child.emitFrame({ type: 'restored', manifest });
  };
  try {
    const restored = await f.native.restore(f.offer, async () => ({
      context: f.offer.context,
      direction: 'restore',
      manifest,
      index: 0,
      bundle: {
        formatVersion: 1,
        suiteId: 2,
        enc: Buffer.alloc(32, 4).toString('base64'),
        ciphertext: Buffer.alloc(plain.length + 16).toString('base64'),
      },
    }));
    assert.deepEqual(restored, plain);
    restored.fill(0);
  } finally {
    plain.fill(0);
    await f.native.close();
  }
});

test('native capture consumes input on failures and serializes lifecycle operations', async () => {
  for (const mode of ['phase', 'empty', 'ready', 'packet', 'receipt', 'push']) {
    const f = await fixture();
    try {
      if (mode !== 'phase') await f.native.restore(f.offer, async () => assert.fail());
      const plain = mode === 'empty' ? Buffer.alloc(0) : Buffer.from('native-storage-fixture');
      const digest = createHash('sha256').update(plain).digest('base64');
      f.child.onCommand = (header) => {
        if (header.type === 'capture')
          f.child.emitFrame({ type: mode === 'ready' ? 'wrong' : 'capturing' });
        if (header.type === 'chunk') {
          const packet = {
            context: f.offer.context,
            direction: 'capture',
            index: 0,
            manifest: { bytes: plain.length, digest },
            bundle: {
              formatVersion: 1,
              suiteId: 2,
              enc: Buffer.alloc(32, 5).toString('base64'),
              ciphertext: Buffer.alloc(plain.length + 16).toString('base64'),
            },
          };
          f.child.emitFrame(mode === 'packet' ? { type: 'wrong' } : { type: 'packet', packet });
          f.child.emitFrame({
            type: mode === 'receipt' ? 'wrong' : 'captured',
            manifest: packet.manifest,
          });
        }
      };
      await assert.rejects(
        f.native.capture(plain, async () => {
          if (mode === 'push') throw Error('root denial');
        }),
      );
      assert.ok(plain.every((v) => v === 0));
    } finally {
      await f.native.close();
    }
  }
  const f = await fixture();
  let finish!: () => void;
  f.child.onCommand = (h) => {
    if (h.type === 'bind')
      finish = () => f.child.emitFrame({ type: 'restored', manifest: h.manifest });
  };
  const pending = f.native.restore(f.offer, async () => assert.fail());
  await tick();
  const denied = Buffer.from('second capture');
  await assert.rejects(
    f.native.capture(denied, async () => {}),
    /busy/,
  );
  assert.ok(denied.every((v) => v === 0));
  f.revoke();
  finish();
  await assert.rejects(pending);
  await f.native.close();
});

test('unconfirmed native exit bars new recipients until matching cleanup is proved', async () => {
  const f = await fixture();
  f.child.exitOnEnd = false;
  f.child.exitOnKill = false;
  try {
    await assert.rejects(f.native.close());
    let spawned = false;
    await assert.rejects(
      VaultVPNBrowserRecipient.open(
        { executable: 'fixture', signal: new AbortController().signal, current: () => true },
        () => {
          spawned = true;
          return new Child().process();
        },
      ),
    );
    assert.equal(spawned, false);
    assert.ok(f.child.kills >= 2);
    f.child.exit();
    await f.native.close();
    const fresh = await fixture();
    await fresh.native.close();
  } finally {
    f.child.exit();
    await f.native.close();
  }
});

test('native admission captures the original executable and authority function before awaiting', async () => {
  const child = new Child(),
    options = {
      executable: 'fixture',
      signal: new AbortController().signal,
      allowed: true,
      current() {
        return this.allowed;
      },
    };
  const pending = VaultVPNBrowserRecipient.open(options, (exe) => {
    assert.equal(exe, 'fixture');
    queueMicrotask(() => child.ready());
    return child.process();
  });
  options.executable = 'replacement';
  options.current = () => true;
  const native = await pending;
  try {
    options.allowed = false;
    const { offer } = vpnSSOFixture();
    offer.context.profileId = child.profileId;
    offer.context.restorePublicKey = child.publicKey;
    await assert.rejects(native.restore(offer, async () => assert.fail('revoked original owner')));
  } finally {
    await native.close();
  }
});
