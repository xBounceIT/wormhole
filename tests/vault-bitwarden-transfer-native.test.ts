import { VaultBitwardenSynchronizer } from '../electron/vault-bitwarden-sync.ts';
import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { Script } from 'node:vm';
import { promisify } from 'node:util';
import { mkdtemp, rm, readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { build } from 'vite';
import {
  createBitwardenTransferCapture,
  createBitwardenTransferRecipient,
} from '../src/vault-bitwarden-transfer-recipient.ts';
import {
  browserTransferAreaBytes,
  browserTransferChunkCount,
  parseBrowserTransferContext,
} from '../electron/vault-bitwarden-transfer.ts';
import { stopChildProcess } from '../electron/rdp.ts';
import { randomUUID } from 'node:crypto';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { beginNativeBrowserTransfer } from '../electron/vault-bitwarden-native.ts';
import { createBitwardenExtensionBridge } from '../src/vault-bitwarden-extension-bridge.ts';
import {
  createBitwardenExtensionStorage,
  type ExtensionStorageArea,
} from '../src/vault-bitwarden-extension-storage.ts';
const require = createRequire(import.meta.url),
  cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
let directory: string, fixture: string;
before(
  async () => {
    directory = await mkdtemp(join(tmpdir(), 'wormhole-bitwarden-transfer-'));
    fixture = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
    await promisify(execFile)('go', ['test', '-c', '-o', fixture, '.'], {
      cwd,
      windowsHide: true,
      timeout: 120000,
    });
  },
  { timeout: 180000 },
);
after(async () => {
  if (directory) {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
  }
});

test(
  'extension controller interoperates with the production Go service and acknowledges actual restored storage',
  { timeout: 120000 },
  async () => {
    const databasePath = join(directory, 'controller-workspace.db');
    const client = new VaultBackendClient(
      { executable: fixture, databasePath, requestTimeoutMs: 60000 },
      () =>
        spawn(
          fixture,
          ['-test.run=^TestVaultBitwardenTransferServiceFixture$', '-test.timeout=100s'],
          {
            cwd,
            windowsHide: true,
            stdio: 'pipe',
            env: { ...process.env, WORMHOLE_TEST_BITWARDEN_SERVICE: databasePath },
          },
        ),
    );
    const bridges: ReturnType<typeof createBitwardenExtensionBridge>[] = [];
    const synchronizers: VaultBitwardenSynchronizer[] = [];
    const create = (workspaceId: string) => {
      const local: Record<string, unknown> = {},
        session: Record<string, unknown> = {};
      const area = (values: Record<string, unknown>): ExtensionStorageArea => ({
        get: (key, done) =>
          queueMicrotask(() =>
            done(
              key === null
                ? { ...values }
                : Object.hasOwn(values, key)
                  ? { [key]: values[key] }
                  : {},
            ),
          ),
        set: (next, done) => {
          Object.assign(values, next);
          queueMicrotask(done);
        },
        remove: (key, done) => {
          delete values[key];
          queueMicrotask(done);
        },
      });
      const owner = { workspaceId, profileId: randomUUID(), epoch: 2 };
      const bridge = createBitwardenExtensionBridge(
        owner,
        createBitwardenExtensionStorage({
          manifestVersion: 3,
          local: area(local),
          session: area(session),
          lastError: () => undefined,
        }),
      );
      bridges.push(bridge);
      const sync = new VaultBitwardenSynchronizer({ owner, client, bridge, current: () => true });
      synchronizers.push(sync);
      return { bridge, local, session, sync };
    };
    const exchange = async (
      bridge: ReturnType<typeof createBitwardenExtensionBridge>,
      action: string,
      source: string,
    ) => {
      const q = await bridge.prepare();
      assert.equal(q.action, action);
      assert.equal(q.sourceRevision, source);
      const c = await client.beginBitwardenTransfer(q);
      try {
        const capture = await bridge.bind(c);
        for (let i = 0; i < capture.chunks; i++) {
          const packet = await bridge.next();
          assert.equal(JSON.stringify(packet).includes('native-bridge-private'), false);
          await client.pushBitwardenTransfer(packet);
        }
        const manifest = await client.commitBitwardenTransfer(c);
        let receipt;
        for (let i = 0; i < browserTransferChunkCount(manifest); i++)
          receipt = await bridge.accept(await client.takeBitwardenTransfer(c, i));
        assert.ok(receipt?.complete);
        assert.equal(receipt.revision, manifest.revision);
        return { ...receipt, chunks: browserTransferChunkCount(manifest) };
      } finally {
        await client.cancelBitwardenTransfer(c);
        await bridge.cancel();
      }
    };
    try {
      const descriptor = await client.describe();
      assert.ok(descriptor);
      const slot = descriptor.slots.find((s) => s.kind === 'recovery');
      assert.ok(slot);
      await client.unlock({
        vaultId: descriptor.vaultId,
        slotId: slot.id,
        kind: 'recovery',
        factor: new Uint8Array(32).fill(0x32),
      });
      const a = create(descriptor.vaultId),
        b = create(descriptor.vaultId);
      assert.equal((await exchange(a.bridge, 'hydrate', '0')).restore, false);
      a.local.account = 'native-bridge-private-account';
      a.session.token = 'native-bridge-private-session';
      assert.equal((await exchange(a.bridge, 'capture', '0')).revision, '1');
      assert.equal((await exchange(b.bridge, 'hydrate', '0')).restore, true);
      assert.deepEqual(b.local, a.local);
      assert.deepEqual(b.session, a.session);
      assert.equal((await exchange(b.bridge, 'capture', '1')).restore, false);
      delete a.local.account;
      delete a.session.token;
      a.local.v = 'x'.repeat(browserTransferAreaBytes - 8);
      a.session.v = a.local.v;
      const max = await exchange(a.bridge, 'capture', '1');
      assert.equal(max.chunks, 5);
      assert.equal(max.revision, '2');
      const refresh = await exchange(b.bridge, 'capture', '1');
      assert.equal(refresh.restore, true);
      assert.equal(refresh.chunks, 5);
      assert.deepEqual(b.local, a.local);
      assert.deepEqual(b.session, a.session);
      assert.equal((await exchange(b.bridge, 'capture', '2')).restore, false);
      const coordinated = create(descriptor.vaultId);
      assert.deepEqual(await coordinated.sync.synchronize(), {
        rounds: 2,
        checkpointPending: false,
      });
      assert.deepEqual(coordinated.local, a.local);
      assert.deepEqual(coordinated.session, a.session);
      delete coordinated.local.v;
      delete coordinated.session.v;
      coordinated.local.account = 'native-bridge-private-coordinated';
      coordinated.session.token = 'native-bridge-private-coordinated-session';
      assert.deepEqual(await coordinated.sync.synchronize(), {
        rounds: 1,
        checkpointPending: false,
      });
      const peer = create(descriptor.vaultId);
      assert.deepEqual(await peer.sync.synchronize(), { rounds: 2, checkpointPending: false });
      assert.deepEqual(peer.local, coordinated.local);
      assert.deepEqual(peer.session, coordinated.session);
    } finally {
      for (const sync of synchronizers) await sync.close();
      for (const bridge of bridges) await bridge.dispose();
      await client.lock();
    }
  },
);

test(
  'production Go service stages Bitwarden transfers through the native Electron client and encrypted SQLite',
  { timeout: 120000 },
  async () => {
    const databasePath = join(directory, 'staged-workspace.db'),
      clients: VaultBackendClient[] = [];
    let trafficTail = '',
      sawPlaintext = false,
      lastOperation = 'spawn';
    const inspect = (raw: Buffer) => {
      const text = trafficTail + raw.toString('utf8');
      if (text.includes('native-only-account')) sawPlaintext = true;
      trafficTail = text.slice(-64);
    };
    const open = async () => {
      const client = new VaultBackendClient(
        { executable: fixture, databasePath, requestTimeoutMs: 60000 },
        () => {
          const child = spawn(
            fixture,
            ['-test.run=^TestVaultBitwardenTransferServiceFixture$', '-test.timeout=100s'],
            {
              cwd,
              windowsHide: true,
              stdio: 'pipe',
              env: { ...process.env, WORMHOLE_TEST_BITWARDEN_SERVICE: databasePath },
            },
          );
          child.stdout.on('data', inspect);
          const write = child.stdin.write.bind(child.stdin);
          child.stdin.write = ((chunk: any, ...args: any[]) => {
            lastOperation = JSON.parse(Buffer.from(chunk).toString()).operation;
            inspect(Buffer.from(chunk));
            return (write as any)(chunk, ...args);
          }) as any;
          return child;
        },
      );
      for (const name of [
        'beginBitwardenTransfer',
        'pushBitwardenTransfer',
        'commitBitwardenTransfer',
        'takeBitwardenTransfer',
        'cancelBitwardenTransfer',
      ] as const) {
        const invoke = client[name].bind(client) as (...args: any[]) => Promise<any>;
        (client as any)[name] = async (...args: any[]) => {
          try {
            return await invoke(...args);
          } catch (error) {
            throw new Error(name + ' failed', { cause: error });
          }
        };
      }
      clients.push(client);
      const descriptor = await client.describe();
      assert.ok(descriptor);
      const slot = descriptor.slots.find((s) => s.kind === 'recovery');
      assert.ok(slot);
      await client.unlock({
        vaultId: descriptor.vaultId,
        slotId: slot.id,
        kind: 'recovery',
        factor: new Uint8Array(32).fill(0x32),
      });
      return { client, workspaceId: descriptor.vaultId };
    };
    const transfer = async (
      client: VaultBackendClient,
      workspaceId: string,
      profileId: string,
      action: 'hydrate' | 'capture',
      sourceRevision: string,
      local: string,
      session: string,
      expectedLocal: string,
      expectedSession: string,
    ) => {
      let restored = false;
      const receiver = await createBitwardenTransferRecipient((state) => {
        assert.equal(new TextDecoder().decode(state.localJSON), expectedLocal);
        assert.equal(new TextDecoder().decode(state.sessionJSON), expectedSession);
        restored = true;
      });
      const handle = await beginNativeBrowserTransfer(
        client,
        {
          workspaceId,
          profileId,
          requestId: randomUUID(),
          epoch: 2,
          action,
          sourceRevision,
          restorePublicKey: receiver.publicKey,
        },
        () => true,
      );
      try {
        receiver.bind(handle.context);
        const capture = await createBitwardenTransferCapture(
          handle.context,
          new TextEncoder().encode(local),
          new TextEncoder().encode(session),
        );
        for (let i = 0; i < capture.chunks; i++) await handle.push(await capture.next());
        const manifest = await handle.commit();
        let receipt;
        for (let i = 0; i < browserTransferChunkCount(manifest); i++)
          receipt = await receiver.accept(await handle.take(i));
        assert.ok(restored);
        assert.equal(receipt?.revision, manifest.revision);
        await assert.rejects(client.takeBitwardenTransfer(handle.context, 0), /failed/);
        return manifest;
      } finally {
        receiver.dispose();
        await handle.cancel();
      }
    };
    try {
      const { client, workspaceId } = await open(),
        profile = randomUUID(),
        second = randomUUID();
      await transfer(client, workspaceId, profile, 'hydrate', '0', '{}', '{}', '{}', '{}');
      const local = '{"account":"native-only-account-🔑","n":9007199254740993}',
        session = '{"token":"native-only-account-session"}';
      const saved = await transfer(
        client,
        workspaceId,
        profile,
        'capture',
        '0',
        local,
        session,
        local,
        session,
      );
      assert.equal(saved.revision, '1');
      const hydrated = await transfer(
        client,
        workspaceId,
        second,
        'hydrate',
        '0',
        '{}',
        '{}',
        local,
        session,
      );
      assert.equal(hydrated.restore, true);
      // A restore request is not proof that the extension applied it. A fresh
      // capture acknowledges the actual local/session contents before later edits.
      await transfer(client, workspaceId, second, 'capture', '1', local, session, local, session);
      const large = '{"v":"' + 'x'.repeat(browserTransferAreaBytes - 8) + '"}';
      const maximum = await transfer(
        client,
        workspaceId,
        second,
        'capture',
        '1',
        large,
        large,
        large,
        large,
      );
      assert.equal(browserTransferChunkCount(maximum), 5);
      assert.deepEqual(await client.closeBitwardenProfile(profile), { closed: true });
      await client.lock();
      const restarted = await open();
      await transfer(
        restarted.client,
        workspaceId,
        randomUUID(),
        'hydrate',
        '0',
        '{}',
        '{}',
        large,
        '{}',
      );
      const pendingReceiver = await createBitwardenTransferRecipient(() => {});
      try {
        const context = await restarted.client.beginBitwardenTransfer({
          workspaceId,
          profileId: randomUUID(),
          requestId: randomUUID(),
          epoch: 2,
          action: 'hydrate',
          sourceRevision: '0',
          restorePublicKey: pendingReceiver.publicKey,
        });
        assert.deepEqual(await restarted.client.cancelBitwardenTransfer(context), {
          cancelled: true,
        });
        await assert.rejects(restarted.client.commitBitwardenTransfer(context), /failed/);
      } finally {
        pendingReceiver.dispose();
      }
      assert.equal(sawPlaintext, false);
      assert.equal(
        (await readFile(databasePath)).includes(Buffer.from('native-only-account')),
        false,
      );
      assert.equal((await readFile(databasePath)).includes(Buffer.from('x'.repeat(128))), false);
    } catch (error) {
      throw new Error('Native Bitwarden service failed at ' + lastOperation, { cause: error });
    } finally {
      for (const client of clients) await client.lock();
    }
  },
);
for (const mode of ['small', 'large'])
  test(
    `sealed Bitwarden transfer interoperates with real Go (${mode})`,
    { timeout: 90000 },
    async () => {
      let restored = false,
        borrowed: Uint8Array[] = [];
      const receiver = await createBitwardenTransferRecipient((state) => {
        const local =
          mode === 'large'
            ? '{"v":"' + 'y'.repeat(browserTransferAreaBytes - 8) + '"}'
            : '{"restore":"synthetic-saved"}';
        const session = mode === 'large' ? local : '{"session":"ready"}';
        assert.equal(new TextDecoder().decode(state.localJSON), local);
        assert.equal(new TextDecoder().decode(state.sessionJSON), session);
        borrowed = [state.localJSON, state.sessionJSON];
        restored = true;
      });
      const child = spawn(
        fixture,
        ['-test.run=^TestVaultBitwardenTransferInteropFixture$', '-test.timeout=60s'],
        {
          cwd,
          windowsHide: true,
          stdio: 'pipe',
          env: { ...process.env, WORMHOLE_TEST_BITWARDEN_TRANSFER: mode },
        },
      );
      child.stderr.resume();
      const closed = new Promise<number | null>((yes, no) => {
        child.once('close', yes);
        child.once('error', no);
      });
      void closed.catch(() => {});
      const reader = createInterface({ input: child.stdout }),
        iterator = reader[Symbol.asyncIterator]();
      const next = async () => {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          const item = await Promise.race([
            iterator.next(),
            new Promise<never>((_, no) => {
              timer = setTimeout(
                () => no(Error('Native browser transfer fixture timed out.')),
                60000,
              );
            }),
          ]);
          assert.equal(item.done, false);
          return JSON.parse(item.value!);
        } finally {
          clearTimeout(timer);
        }
      };
      try {
        child.stdin.write(JSON.stringify(receiver.publicKey) + '\n');
        const context = parseBrowserTransferContext(await next());
        assert.ok(context);
        assert.equal(context.sourceRevision, '9223372036854775805');
        receiver.bind(context);
        const local =
          mode === 'large'
            ? '{"v":"' + 'x'.repeat(browserTransferAreaBytes - 8) + '"}'
            : '{"capture":"synthetic-🔑","n":9007199254740993}';
        const input = new TextEncoder().encode(local),
          session = new TextEncoder().encode(mode === 'large' ? local : '{"session":"temporary"}');
        const sender = await createBitwardenTransferCapture(context, input, session);
        assert.ok(input.every((x) => x === 0) && session.every((x) => x === 0));
        for (let i = 0; i < sender.chunks; i++) {
          const packet = await sender.next();
          const raw = JSON.stringify(packet);
          assert.ok(Buffer.byteLength(raw) < 8 * 1024 * 1024);
          assert.equal(raw.includes('synthetic-🔑'), false);
          if (!child.stdin.write(raw + '\n'))
            await new Promise<void>((yes) => child.stdin.once('drain', yes));
        }
        const first = await next(),
          count = browserTransferChunkCount(first.manifest);
        let receipt = await receiver.accept(first);
        for (let i = 1; i < count; i++) receipt = await receiver.accept(await next());
        assert.equal(restored, true);
        assert.deepEqual(receipt, { revision: '9223372036854775806', restore: true });
        assert.ok(borrowed.every((p) => p.every((x) => x === 0)));
        child.stdin.end('{"ok":true}\n');
        assert.equal(await closed, 0);
      } finally {
        receiver.dispose();
        reader.close();
        child.stdout.resume();
        await stopChildProcess(child);
        await closed;
      }
    },
  );

test(
  'real isolated Chromium exchanges only sealed Bitwarden packets with the native Go recipient',
  { timeout: 90000 },
  async () => {
    const browserDirectory = join(directory, 'browser');
    await mkdir(browserDirectory);
    const output = await build({
      configFile: false,
      logLevel: 'silent',
      build: {
        write: false,
        minify: false,
        lib: {
          entry: fileURLToPath(
            new URL('./fixtures/bitwarden-transfer-browser.ts', import.meta.url),
          ),
          formats: ['iife'],
          name: 'BrowserTransfer',
        },
      },
    });
    const chunks = (Array.isArray(output) ? output : [output])
      .flatMap((x) => x.output)
      .filter((x) => x.type === 'chunk');
    assert.equal(chunks.length, 1);
    await writeFile(join(browserDirectory, 'bundle.js'), chunks[0].code);
    await writeFile(
      join(browserDirectory, 'document.html'),
      `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'"><script src="bundle.js"></script>`,
    );
    await writeFile(join(browserDirectory, 'settings.json'), JSON.stringify({ fixture, cwd }));
    await writeFile(
      join(browserDirectory, 'main.cjs'),
      String.raw`
const {app,BrowserWindow}=require('electron');const assert=require('node:assert/strict');const {spawn}=require('node:child_process');const {createInterface}=require('node:readline');const {readFileSync}=require('node:fs');const {join}=require('node:path');
const settings=JSON.parse(readFileSync(join(__dirname,'settings.json'),'utf8'));app.disableHardwareAcceleration();app.setPath('userData',__dirname);app.setPath('sessionData',__dirname);
app.whenReady().then(async()=>{const window=new BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,offscreen:true}});const child=spawn(settings.fixture,['-test.run=^TestVaultBitwardenTransferInteropFixture$','-test.timeout=45s'],{cwd:settings.cwd,windowsHide:true,stdio:'pipe',env:{...process.env,WORMHOLE_TEST_BITWARDEN_TRANSFER:'browser'}});child.stderr.resume();const closed=new Promise((yes,no)=>{child.once('close',yes);child.once('error',no)});void closed.catch(()=>{});const reader=createInterface({input:child.stdout}),iterator=reader[Symbol.asyncIterator]();const diagnostics=[];const next=async()=>{for(;;){const result=await iterator.next();if(result.done)throw Error('Native transfer fixture stopped: '+diagnostics.join(' | '));if(result.value.startsWith('{'))return JSON.parse(result.value);diagnostics.push(result.value.slice(0,2000));if(diagnostics.length>20)throw Error('Excess native fixture diagnostics')}};
try{await window.loadFile(join(__dirname,'document.html'));assert.equal(await window.webContents.executeJavaScript("typeof process==='undefined' && typeof require==='undefined' && !window.wormhole"),true);assert.equal(await window.webContents.executeJavaScript('BrowserTransfer.verifyExtensionStorageInPage()'),true);const publicKey=await window.webContents.executeJavaScript('BrowserTransfer.makeBridge().then(bridge=>{globalThis.bridge=bridge;return bridge.request})');child.stdin.write(JSON.stringify(publicKey)+'\n');const context=await next();await window.webContents.executeJavaScript('bridge.bind('+JSON.stringify(context)+')');const count=await window.webContents.executeJavaScript('bridge.capture('+JSON.stringify(context)+').then(sender=>{globalThis.sender=sender;return sender.chunks})');for(let i=0;i<count;i++){const packet=await window.webContents.executeJavaScript('sender.next()');const raw=JSON.stringify(packet);assert.equal(raw.includes('synthetic-🔑'),false);child.stdin.write(raw+'\n')}const packet=await next();const receipt=await window.webContents.executeJavaScript('bridge.accept('+JSON.stringify(packet)+')');assert.deepEqual(receipt,{complete:true,revision:'1',restore:true});assert.equal(await window.webContents.executeJavaScript('bridge.wiped()'),true);child.stdin.end('{"ok":true}\n');assert.equal(await closed,0);console.log('Isolated Bitwarden transfer passed.')}finally{reader.close();child.stdout.resume();if(child.exitCode===null&&child.signalCode===null)child.kill();await closed;window.destroy()}app.quit()}).catch(error=>{console.error(error);app.exit(1)});
`,
    );
    new Script(await readFile(join(browserDirectory, 'main.cjs'), 'utf8'), {
      filename: 'bitwarden-transfer-main.cjs',
    });
    const { ELECTRON_RUN_AS_NODE: _unused, ...env } = process.env;
    const electron = require('electron') as string;
    const display = process.platform === 'linux' && !env.DISPLAY;
    const result = await promisify(execFile)(
      display ? 'xvfb-run' : electron,
      display
        ? ['--auto-servernum', electron, '--no-sandbox', join(browserDirectory, 'main.cjs')]
        : [join(browserDirectory, 'main.cjs')],
      { env, windowsHide: true, timeout: 75000 },
    );
    assert.match(result.stdout, /Isolated Bitwarden transfer passed/);
  },
);
