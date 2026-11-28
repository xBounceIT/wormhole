import { LinuxVaultClipboard, linuxClipboardIO } from '../electron/vault-linux-clipboard.ts';
import {
  createClipboardRecipient,
  decodeClipboardRelease,
  parseClipboardReleaseRequest,
} from '../electron/vault-clipboard-release.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseVaultClipboardRequest,
  parseVaultClipboardResult,
  vaultClipboardField,
} from '../electron/vault-clipboard.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
const id = '11111111-1111-4111-8111-111111111111',
  node = '22222222-2222-4222-8222-222222222222';
const request = { workspaceId: id, nodeId: node, rowVersion: '7', field: 'secret' };
test('clipboard contracts reject plaintext, caller TTLs, ambiguous fields and malformed acknowledgments', () => {
  for (const field of ['username', 'domain', 'secret']) {
    assert.equal(vaultClipboardField(field), true);
    assert.deepEqual(parseVaultClipboardRequest({ ...request, field }), { ...request, field });
  }
  for (const value of [
    null,
    [],
    {},
    { ...request, workspaceId: 'bad' },
    { ...request, nodeId: 'bad' },
    { ...request, rowVersion: '0' },
    { ...request, field: 'privateKey' },
    { ...request, expiresInSeconds: 999 },
    { ...request, value: 'plaintext' },
  ])
    assert.equal(parseVaultClipboardRequest(value), undefined);
  for (const expiresInSeconds of [20, 30])
    assert.deepEqual(parseVaultClipboardResult({ expiresInSeconds }), { expiresInSeconds });
  for (const value of [
    null,
    [],
    {},
    { expiresInSeconds: '20' },
    { expiresInSeconds: 21 },
    { expiresInSeconds: 20, secret: 'plaintext' },
  ])
    assert.equal(parseVaultClipboardResult(value), undefined);
});
test('clipboard host binds fresh authentication and lifetime to an immutable field selection', async () => {
  let profile = 'standard',
    calls = 0,
    delay = false,
    release!: () => void,
    received: any;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    lock: async () => {},
    security: async () => ({ effective: profile }),
    describe: async () => ({ vaultId: id, slots: [{ id: node, kind: 'password' }] }),
    copyCredential: async (q: any) => {
      calls++;
      received = q;
      if (delay) await new Promise<void>((r) => (release = r));
      return { expiresInSeconds: profile === 'default' ? 30 : 20 };
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  const factor = () => ({
    vaultId: id,
    slotId: node,
    kind: 'password' as const,
    factor: new Uint8Array([7]),
  });
  await assert.rejects(host.copyCredential(null), /Invalid/);
  await assert.rejects(host.copyCredential(request), /locked/);
  await host.unlock(factor());
  await assert.rejects(host.copyCredential({ ...request, workspaceId: node }), /locked/);
  await assert.rejects(host.copyCredential(request), /Fresh authentication/);
  const input = { ...request },
    auth = factor();
  assert.deepEqual(
    await host.copyCredential(input, async (op, _descriptor, submit) => {
      assert.equal(op, 'credential-copy');
      input.field = 'domain';
      return submit(auth);
    }),
    { expiresInSeconds: 20 },
  );
  assert.deepEqual(received, request);
  assert.ok(auth.factor.every((x) => x === 0));
  let accepted = true;
  await assert.rejects(
    host.copyCredential(
      request,
      async (_op, _desc, submit) => {
        accepted = false;
        return submit(factor());
      },
      () => accepted,
    ),
    /locked/,
  );
  assert.equal(calls, 1);
  profile = 'hardened';
  await assert.rejects(host.copyCredential(request), /Fresh authentication/);
  profile = 'default';
  assert.deepEqual(await host.copyCredential(request), { expiresInSeconds: 30 });
  delay = true;
  const pending = host.copyCredential(request);
  await new Promise(setImmediate);
  await host.stop();
  release();
  await assert.rejects(pending, /locked/);
});

test('isolated clipboard preload advertises supported desktop platforms and sends field identifiers', async () => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../electron/vault-credentials-preload.cts', import.meta.url), 'utf8'),
  ).replace(/^import .*?;\s*/gms, '');
  for (const platform of ['win32', 'darwin', 'linux', 'freebsd']) {
    let api: any;
    const calls: any[] = [];
    runInNewContext(source, {
      process: { platform },
      contextBridge: {
        exposeInMainWorld: (name: string, value: any) => {
          assert.equal(name, 'vaultCredentials');
          api = value;
        },
      },
      ipcRenderer: {
        invoke: async (...args: any[]) => {
          calls.push(args);
          return { expiresInSeconds: 20 };
        },
      },
    });
    assert.equal(api.copyAvailable, ['win32', 'darwin', 'linux'].includes(platform));
    assert.deepEqual(await api.copy('secret'), { expiresInSeconds: 20 });
    assert.deepEqual(calls, [['vault-credentials:copy', 'secret']]);
  }
});

const releaseContext = {
  ...request,
  field: 'secret' as const,
  requestId: '33333333-3333-4333-8333-333333333333',
};
test('clipboard release contracts accept only a selected field and a bound public recipient', async () => {
  const request = { ...releaseContext, publicKey: Buffer.alloc(32, 1).toString('base64') };
  assert.deepEqual(parseClipboardReleaseRequest(request), request);
  for (const value of [
    null,
    [],
    {},
    { ...request, field: 'privateKey' },
    { ...request, ttl: 20 },
    { ...request, publicKey: 'bad' },
    { ...request, requestId: node, rowVersion: '0' },
  ]) {
    assert.equal(parseClipboardReleaseRequest(value), undefined);
  }
  const client = new VaultBackendClient({ executable: 'unused', databasePath: 'unused' });
  const authentication = {
    vaultId: id,
    slotId: node,
    kind: 'password' as const,
    factor: new Uint8Array([7]),
  };
  await assert.rejects(client.releaseClipboard(null, authentication), /Invalid/);
  assert.equal(authentication.factor[0], 0);
  await client.lock();
});
test('clipboard decoder validates bytes without retaining a password string or a second buffer', () => {
  for (const ttl of [20, 30]) {
    const raw = Buffer.concat([Buffer.from([1, ttl]), Buffer.from('\ufeffcopy🪱')]);
    const parsed = decodeClipboardRelease(raw);
    assert.equal(parsed.expiresInSeconds, ttl);
    assert.equal(Buffer.from(parsed.value).toString(), '\ufeffcopy🪱');
    raw.fill(0);
    assert.ok(parsed.value.every((x) => x === 0));
  }
  assert.equal(
    decodeClipboardRelease(Buffer.concat([Buffer.from([1, 20]), Buffer.alloc(16384, 97)])).value
      .length,
    16384,
  );
  for (const raw of [
    Buffer.alloc(0),
    Buffer.from([1, 20]),
    Buffer.from([2, 20, 65]),
    Buffer.from([1, 21, 65]),
    Buffer.from([1, 20, 0]),
    Buffer.from([1, 20, 255]),
    Buffer.alloc(16387, 65),
  ])
    assert.throws(() => decodeClipboardRelease(raw));
});
test('main clipboard recipient authenticates the field, purpose and context and consumes its key', async () => {
  await assert.rejects(createClipboardRecipient({ ...releaseContext, field: 'privateKey' } as any));
  await assert.rejects(createClipboardRecipient({ ...releaseContext, rowVersion: '0' }));
  for (const mode of [
    'valid',
    'wrong-field',
    'wrong-purpose',
    'wrong-binding',
    'wrong-envelope',
    'oversize',
    'disposed',
    'late',
  ]) {
    const context = { ...releaseContext };
    const recipient = await createClipboardRecipient(context);
    context.field = 'domain' as any;
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const publicKey = await suite.kem.deserializePublicKey(
      Buffer.from(recipient.publicKey, 'base64'),
    );
    const fields = [
      releaseContext.workspaceId,
      releaseContext.nodeId,
      releaseContext.requestId,
      releaseContext.rowVersion,
    ];
    if (mode === 'wrong-binding') fields[3] = '8';
    const domain =
      mode === 'wrong-purpose'
        ? 'wormhole/v1/credential-display'
        : 'wormhole/v1/clipboard/' + (mode === 'wrong-field' ? 'username' : 'secret');
    const info = Buffer.concat([
      Buffer.from(domain),
      ...fields.flatMap((value) => {
        const length = Buffer.alloc(4);
        length.writeUInt32BE(value.length);
        return [length, Buffer.from(value)];
      }),
    ]);
    const sender = await suite.createSenderContext({ recipientPublicKey: publicKey, info });
    const payload = mode === 'oversize' ? Buffer.alloc(16387) : Buffer.from([1, 20, 65]);
    const { field: _field, ...envelopeContext } = releaseContext;
    const envelope = {
      ...envelopeContext,
      bundle: {
        formatVersion: 1,
        suiteId: 2,
        enc: Buffer.from(sender.enc).toString('base64'),
        ciphertext: Buffer.from(await sender.seal(payload)).toString('base64'),
      },
    };
    if (mode === 'wrong-envelope') envelope.nodeId = id;
    if (mode === 'disposed') recipient.dispose();
    const pending = recipient.open(envelope);
    if (mode === 'late') recipient.dispose();
    if (mode === 'valid') {
      const bytes = await pending;
      assert.deepEqual(Array.from(bytes), [1, 20, 65]);
      bytes.fill(0);
    } else await assert.rejects(pending);
    await assert.rejects(recipient.open(envelope));
    recipient.dispose();
  }
});

const tickClipboard = () => new Promise(setImmediate);
test('Linux copies an invitation code only from the sealed main-process recipient and clears it on lock', async () => {
  const fixture = linuxFixture();
  const scope = { workspaceId: id, inviteId: node, requestId: releaseContext.requestId };
  const value = Buffer.from('0123456789abcdef'.repeat(2));
  const result = await fixture.manager.copyMemberCode(
    scope,
    async (request, current) => {
      assert.ok(current());
      assert.equal(request.requestId, scope.requestId);
      assert.equal(request.inviteId, scope.inviteId);
      const suite = new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes256Gcm(),
      });
      const key = await suite.kem.deserializePublicKey(Buffer.from(request.recipient!, 'base64'));
      const fields = [scope.workspaceId, scope.requestId, scope.inviteId, request.copyId];
      const info = Buffer.concat([
        Buffer.from('wormhole/v1/member-invitation-clipboard'),
        ...fields.flatMap((field) => {
          const size = Buffer.alloc(4);
          size.writeUInt32BE(Buffer.byteLength(field));
          return [size, Buffer.from(field)];
        }),
      ]);
      const sender = await suite.createSenderContext({ recipientPublicKey: key, info });
      const ciphertext = await sender.seal(Buffer.concat([Buffer.from([1, 20]), value]));
      return {
        status: 'sealed',
        bundle: {
          formatVersion: 1,
          suiteId: 2,
          enc: Buffer.from(sender.enc).toString('base64'),
          ciphertext: Buffer.from(ciphertext).toString('base64'),
        },
      };
    },
    () => true,
  );
  assert.deepEqual(result, { expiresInSeconds: 20 });
  assert.deepEqual(fixture.state.value, value);
  await fixture.manager.reset();
  assert.equal(fixture.state.clears, 1);
  await assert.rejects(
    fixture.manager.copyMemberCode(
      scope,
      async () => ({ status: 'unavailable' }),
      () => true,
    ),
  );
  assert.equal(fixture.state.writes, 1);
});
function linuxFixture(ttl = 20) {
  const raw = Buffer.from([1, ttl, 65, 66, 67]);
  const state = {
    marker: '',
    value: Buffer.alloc(0),
    writes: 0,
    clears: 0,
    disposed: 0,
    now: 0,
    hasFailure: false,
    clearFailure: false,
    writeFailure: false,
    accepted: true,
    calls: 0,
    request: undefined as any,
  };
  const hooks: {
    factory?: () => Promise<void>;
    release?: () => Promise<void>;
    open?: () => Promise<void>;
    write?: () => Promise<void>;
    has?: () => Promise<void>;
  } = {};
  const timers: { callback: () => void; milliseconds: number; stopped: boolean }[] = [];
  const host = {
    unlockedWorkspaceId: id as string | undefined,
    releaseClipboard: async (request: any, _confirm: any, accepted: () => boolean) => {
      state.calls++;
      state.request = request;
      assert.equal(accepted(), true);
      await hooks.release?.();
      return {} as any;
    },
  };
  const io = {
    write: async (value: Uint8Array, marker: string) => {
      state.writes++;
      state.marker = marker;
      state.value = Buffer.from(value);
      await hooks.write?.();
      if (state.writeFailure) throw Error('driver diagnostics containing private material');
    },
    has: async (marker: string) => {
      await hooks.has?.();
      if (state.hasFailure) throw Error('private diagnostics');
      return state.marker === marker;
    },
    clear: () => {
      if (state.clearFailure) throw Error('private diagnostics');
      state.clears++;
      state.value.fill(0);
      state.value = Buffer.alloc(0);
      state.marker = '';
    },
  };
  const options = {
    host,
    io,
    now: () => state.now,
    timer: (callback: () => void, milliseconds: number) => {
      const timer = { callback, milliseconds, stopped: false };
      timers.push(timer);
      return () => {
        timer.stopped = true;
      };
    },
    recipient: async () => {
      await hooks.factory?.();
      return {
        publicKey: 'fixture-public-key',
        dispose: () => {
          state.disposed++;
        },
        open: async () => {
          await hooks.open?.();
          return raw;
        },
      };
    },
  };
  const manager = new LinuxVaultClipboard(options);
  return {
    manager,
    options,
    host,
    io,
    raw,
    state,
    hooks,
    timers,
    copy: () => manager.copy(request, undefined, () => state.accepted),
  };
}
test('Linux copy holds only an ownership marker, uses authenticated TTL and preserves replacement content', async () => {
  for (const ttl of [20, 30]) {
    const f = linuxFixture(ttl);
    assert.deepEqual(await f.copy(), { expiresInSeconds: ttl });
    assert.equal(f.state.value.toString(), 'ABC');
    assert.ok(f.raw.every((x) => x === 0));
    assert.equal(f.timers[0].milliseconds, ttl * 1000);
    assert.match(f.state.request.requestId, /^[0-9a-f-]{36}$/);
    assert.equal(f.state.request.field, 'secret');
    assert.equal(f.state.request.publicKey, 'fixture-public-key');
    f.timers[0].callback();
    await tickClipboard();
    assert.equal(f.state.clears, 1);
    await f.manager.reset();
  }
  const f = linuxFixture();
  await f.copy();
  f.state.marker = 'new-user-content';
  f.state.value = Buffer.from('new');
  await f.manager.reset();
  assert.equal(f.state.value.toString(), 'new');
  assert.equal(f.state.clears, 0);
});
test('Linux copy rejects invalid, concurrent and obsolete authority and wipes every decoded failure', async () => {
  const f = linuxFixture();
  await assert.rejects(f.manager.copy(null), /Invalid/);
  await assert.rejects(f.manager.copy({ ...request, workspaceId: node }), /locked/);
  f.state.accepted = false;
  await assert.rejects(f.copy(), /locked/);
  f.state.accepted = true;
  let release!: () => void;
  f.hooks.release = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const pending = f.copy();
  await tickClipboard();
  await assert.rejects(f.copy(), /Invalid/);
  f.host.unlockedWorkspaceId = undefined;
  release();
  await assert.rejects(pending, /unavailable/);
  assert.equal(f.state.writes, 0);
  const malformed = linuxFixture(99);
  await assert.rejects(malformed.copy(), /unavailable/);
  assert.ok(malformed.raw.every((x) => x === 0));
});
test('Linux lock cancels each asynchronous copy stage, including a late OS write', async () => {
  for (const phase of ['factory', 'release', 'open', 'write'] as const) {
    const f = linuxFixture();
    let release!: () => void;
    f.hooks[phase] = () =>
      new Promise((resolve) => {
        release = resolve;
      });
    const pending = f.copy();
    await tickClipboard();
    const reset = f.manager.reset();
    release();
    await assert.rejects(pending, /unavailable/);
    await reset;
    assert.equal(f.state.marker, '');
    assert.ok(f.state.disposed > 0);
    if (phase === 'open' || phase === 'write') assert.ok(f.raw.every((x) => x === 0));
    assert.equal(f.state.writes, phase === 'write' ? 1 : 0);
  }
});
test('Linux copy expiry retries transient cleanup and clears partially committed writes', async () => {
  for (const failure of ['hasFailure', 'clearFailure'] as const) {
    const f = linuxFixture();
    await f.copy();
    f.state[failure] = true;
    f.timers[0].callback();
    await tickClipboard();
    assert.equal(f.timers.at(-1)!.milliseconds, 1000);
    assert.notEqual(f.state.marker, '');
    await assert.rejects(f.manager.reset(), /cleanup/);
    f.state[failure] = false;
    f.timers.at(-1)!.callback();
    await tickClipboard();
    assert.equal(f.state.marker, '');
  }
  const partial = linuxFixture();
  partial.state.writeFailure = true;
  await assert.rejects(
    partial.copy(),
    (error) => String(error) === 'Error: Secure copy is unavailable.',
  );
  assert.equal(partial.state.clears, 1);
  assert.ok(partial.raw.every((x) => x === 0));
  const late = linuxFixture();
  late.hooks.write = async () => {
    late.state.now = 21000;
  };
  await assert.rejects(late.copy(), /unavailable/);
  assert.equal(late.state.clears, 1);
});
test('stale Linux expiry callbacks cannot erase a newer copy queued behind an ownership read', async () => {
  const f = linuxFixture();
  await f.copy();
  const old = f.timers[0];
  f.raw.set([1, 20, 68, 69, 70]);
  let release!: () => void;
  f.hooks.has = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const pending = f.copy();
  await tickClipboard();
  old.callback();
  f.hooks.has = undefined;
  release();
  await pending;
  await tickClipboard();
  assert.equal(f.state.value.toString(), 'DEF');
  assert.equal(f.state.clears, 1);
  old.callback();
  await tickClipboard();
  assert.equal(f.state.clears, 1);
  await f.manager.reset();
  assert.equal(f.state.clears, 2);
});
test('default Linux timer can be retired without waiting for expiry', async () => {
  const f = linuxFixture();
  const manager = new LinuxVaultClipboard({ ...f.options, timer: undefined, now: undefined });
  await manager.copy(request);
  await manager.reset();
  assert.equal(f.state.clears, 1);
});
test('Linux Electron adapter commits raw UTF-8 and exclusion formats atomically without touching PRIMARY', async () => {
  let items: any[] = [];
  let checked = '';
  let clears = 0;
  class Item {
    formats: Record<string, Blob>;
    constructor(formats: Record<string, Blob>) {
      this.formats = formats;
    }
  }
  const adapter = linuxClipboardIO(
    {
      write: async (value) => {
        items = value;
      },
      has: async (format) => {
        checked = format;
        return true;
      },
      clear: () => {
        clears++;
      },
    } as any,
    Item as any,
  );
  const raw = Buffer.from('\ufeffsecret🪱');
  await adapter.write(raw, 'application/x-wormhole-clipboard-fixture');
  raw.fill(0);
  assert.equal(items.length, 1);
  const formats = items[0].formats;
  assert.equal(Object.keys(formats).length, 5);
  for (const name of ['text/plain', 'text/plain;charset=utf-8', 'UTF8_STRING']) {
    assert.equal(
      Buffer.from(
        await formats[`electron application/osclipboard;format="${name}"`].arrayBuffer(),
      ).toString(),
      '\ufeffsecret🪱',
    );
  }
  assert.equal(
    await formats['electron application/osclipboard;format="x-kde-passwordManagerHint"'].text(),
    'secret',
  );
  assert.equal(await adapter.has('marker'), true);
  assert.equal(checked, 'electron application/osclipboard;format="marker"');
  adapter.clear();
  assert.equal(clears, 1);
});

test('Linux release host binds Standard authentication, recipient and workspace lifetime', async () => {
  let profile = 'standard',
    calls = 0,
    delay = false,
    complete!: () => void;
  const client: any = {
    unlock: async () => ({ unlocked: true, lockedMemory: true }),
    lock: async () => {},
    security: async () => ({ effective: profile }),
    describe: async () => ({ vaultId: id, slots: [{ id: node, kind: 'password' }] }),
    releaseClipboard: async (request: any) => {
      calls++;
      assert.equal(request.field, 'secret');
      if (delay)
        await new Promise<void>((resolve) => {
          complete = resolve;
        });
      return { opaque: true };
    },
  };
  const host = new VaultBackendHost(
    () => client,
    () => true,
  );
  const q = { ...releaseContext, publicKey: Buffer.alloc(32, 1).toString('base64') };
  const factor = () => ({
    vaultId: id,
    slotId: node,
    kind: 'password' as const,
    factor: new Uint8Array([7]),
  });
  await assert.rejects(host.releaseClipboard(null), /Invalid/);
  await assert.rejects(host.releaseClipboard(q), /locked/);
  await host.unlock(factor());
  await assert.rejects(host.releaseClipboard({ ...q, workspaceId: node }), /locked/);
  await assert.rejects(host.releaseClipboard(q), /Fresh authentication/);
  const mutable = { ...q },
    auth = factor();
  assert.deepEqual(
    await host.releaseClipboard(mutable, async (op, _desc, submit) => {
      assert.equal(op, 'credential-copy');
      mutable.field = 'username' as any;
      return submit(auth);
    }),
    { opaque: true },
  );
  assert.ok(auth.factor.every((x) => x === 0));
  let accepted = true;
  await assert.rejects(
    host.releaseClipboard(
      q,
      async (_op, _desc, submit) => {
        accepted = false;
        return submit(factor());
      },
      () => accepted,
    ),
    /locked/,
  );
  assert.equal(calls, 1);
  profile = 'default';
  delay = true;
  const pending = host.releaseClipboard(q);
  await tickClipboard();
  await host.stop();
  complete();
  await assert.rejects(pending, /locked/);
});

test('closing the protected dialog or locking during previous-clipboard cleanup prevents publication', async () => {
  const closed = linuxFixture();
  closed.hooks.write = async () => {
    closed.state.accepted = false;
  };
  await assert.rejects(closed.copy(), /unavailable/);
  assert.equal(closed.state.marker, '');
  const f = linuxFixture();
  await f.copy();
  f.raw.set([1, 20, 65, 66, 67]);
  let release!: () => void;
  f.hooks.has = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const pending = f.copy();
  await tickClipboard();
  const reset = f.manager.reset();
  assert.ok(f.raw.every((x) => x === 0));
  f.hooks.has = undefined;
  release();
  await assert.rejects(pending, /unavailable/);
  await reset;
  assert.equal(f.state.writes, 1);
  assert.equal(f.state.marker, '');
});
