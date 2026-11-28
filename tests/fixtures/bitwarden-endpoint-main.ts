import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { app, session, webContents, type WebContents } from 'electron';
import { createRequire } from 'node:module';
import { VaultBitwardenDocumentEndpoint } from '../../electron/vault-bitwarden-endpoint.ts';
import { VaultBitwardenSynchronizer } from '../../electron/vault-bitwarden-sync.ts';
import { VaultBackendClient } from '../../electron/vault-client.ts';

process.on('uncaughtException', () => {
  console.error('Native endpoint fixture failed.');
  app.exit(1);
});
const { ElectronChromeExtensions } = createRequire(process.env.WORMHOLE_ENDPOINT_TEST_PACKAGE!)(
  'electron-chrome-extensions',
);
const directory = process.env.WORMHOLE_ENDPOINT_TEST_DIRECTORY!;
const executable = process.env.WORMHOLE_ENDPOINT_TEST_EXECUTABLE!;
const assetPath = process.env.WORMHOLE_ENDPOINT_TEST_ASSET!;
app.setPath('userData', join(directory, 'profile'));
app.setPath('sessionData', join(directory, 'profile'));
app.disableHardwareAcceleration();
const marker = 'endpoint-native-private-account',
  sessionMarker = 'endpoint-native-private-session';

const stage = (name: string) => console.log('ENDPOINT_STAGE ' + name);
async function run() {
  stage('start');
  const asset = await readFile(assetPath, 'utf8'),
    databasePath = join(directory, 'vault.db');
  const profiles: { session: Electron.Session; contents: WebContents; extensionId: string }[] = [];
  const endpoints: VaultBitwardenDocumentEndpoint[] = [],
    synchronizers: VaultBitwardenSynchronizer[] = [],
    clients: VaultBackendClient[] = [];
  let transportLeaked = false,
    browserLeaked = false;
  const inspect = (raw: string) => {
    if (raw.includes(marker) || raw.includes(sessionMarker)) transportLeaked = true;
  };
  const open = async () => {
    const client = new VaultBackendClient(
      { executable, databasePath, requestTimeoutMs: 60000 },
      () => {
        const child = spawn(
          executable,
          ['-test.run=^TestVaultBitwardenTransferServiceFixture$', '-test.timeout=120s'],
          {
            windowsHide: true,
            stdio: 'pipe',
            env: { ...process.env, WORMHOLE_TEST_BITWARDEN_SERVICE: databasePath },
          },
        );
        child.stdout.on('data', (chunk) => inspect(chunk.toString()));
        const write = child.stdin.write.bind(child.stdin);
        child.stdin.write = ((chunk: any, ...args: any[]) => {
          const raw = Buffer.from(chunk).toString(),
            q = JSON.parse(raw);
          if (q.operation.startsWith('bitwarden-')) inspect(raw);
          return (write as any)(chunk, ...args);
        }) as any;
        return child;
      },
    );
    clients.push(client);
    stage('go-describe');
    const descriptor = await client.describe();
    assert.ok(descriptor);
    const slot = descriptor.slots.find((s) => s.kind === 'recovery');
    assert.ok(slot);
    stage('go-unlock');
    await client.unlock({
      vaultId: descriptor.vaultId,
      slotId: slot.id,
      kind: 'recovery',
      factor: new Uint8Array(32).fill(0x32),
    });
    return { client, workspaceId: descriptor.vaultId };
  };
  const background = async (index: number) => {
    // Diagnostic only: stock Electron rejects loadExtension on temporary sessions.
    // This persistent test profile must never be selected by the native vault app.
    const ses = session.fromPartition(`persist:wormhole-endpoint-native-${index}`, {
      cache: false,
    });
    new ElectronChromeExtensions({ session: ses, license: 'GPL-3.0' });
    const ready = new Promise<void>((yes, no) => {
      const timer = setTimeout(() => no(Error('Extension readiness timeout')), 15000);
      ses.extensions.once('extension-ready', () => {
        clearTimeout(timer);
        yes();
      });
    });
    void ready.catch(() => {});
    stage('extension-load');
    const extension = await ses.extensions.loadExtension(join(directory, 'extension'));
    stage('extension-loaded');
    await ready;
    stage('extension-ready');
    const contents = webContents
      .getAllWebContents()
      .find((c) => c.session === ses && c.getType() === 'backgroundPage');
    assert.ok(contents);
    const profile = { session: ses, contents, extensionId: extension.id };
    profiles.push(profile);
    const deadline = Date.now() + 15000;
    const readyDocument = async () => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        // Contents execution follows the committed document; capturing an early
        // mainFrame at extension-ready can leave an uninitialized frame pending.
        return await Promise.race([
          contents.executeJavaScript('globalThis.fixtureReady===true'),
          new Promise<never>((_, no) => {
            timer = setTimeout(
              () => no(Error('Background document timeout')),
              Math.max(1, deadline - Date.now()),
            );
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    };
    while (!(await readyDocument())) {
      if (Date.now() > deadline) throw Error('Extension initialization timeout');
      await new Promise<void>((yes) => setTimeout(yes, 10));
    }
    stage('background-ready');
    return profile;
  };
  try {
    const temporary = session.fromPartition('wormhole-endpoint-native-temporary');
    await assert.rejects(
      temporary.extensions.loadExtension(join(directory, 'extension')),
      /temporary session/,
    );
    const first = await background(1);
    const sandboxed = ({ osProcessId }: { osProcessId: number }) =>
      app.getAppMetrics().some((metric) => metric.pid === osProcessId && metric.sandboxed === true);
    if (!sandboxed(first.contents.mainFrame)) {
      assert.throws(
        () =>
          new VaultBitwardenDocumentEndpoint({
            ...first,
            url: first.contents.getURL(),
            owner: { workspaceId: randomUUID(), profileId: randomUUID(), epoch: 2 },
            asset,
            current: () => true,
            sandboxed,
          }),
        /unavailable/,
      );
      console.log(
        JSON.stringify({
          complete: true,
          nativeSandboxProof: false,
          persistentDiagnosticOnly: true,
        }),
      );
      return;
    }
    const initial = await open();
    const connect = async (
      profile: typeof first,
      client: VaultBackendClient,
      workspaceId: string,
    ) => {
      const frame = profile.contents.mainFrame,
        execute = frame.executeJavaScript.bind(frame);
      let lastResult: unknown,
        lastKind = '';
      const oldIdentity = {
        token: frame.frameToken,
        process: frame.processId,
        os: frame.osProcessId,
        routing: frame.routingId,
      };
      frame.executeJavaScript = async (code, gesture) => {
        if (code.includes(marker) || code.includes(sessionMarker)) browserLeaked = true;
        lastKind = code.includes('WormholeVaultBitwarden.install')
          ? 'install'
          : code.includes('WormholeVaultBitwarden.invoke')
            ? 'invoke'
            : 'probe';
        const result = await execute(code, gesture ?? false);
        lastResult = typeof result === 'boolean' ? result : typeof result;
        if (
          typeof result === 'string' &&
          (result.includes(marker) || result.includes(sessionMarker))
        )
          browserLeaked = true;
        return result;
      };
      const owner = { workspaceId, profileId: randomUUID(), epoch: 2 };
      const endpoint = new VaultBitwardenDocumentEndpoint({
        ...profile,
        url: profile.contents.getURL(),
        owner,
        asset,
        current: () => true,
        sandboxed,
      });
      endpoints.push(endpoint);
      stage('endpoint-initialize');
      try {
        await endpoint.initialize();
      } catch (error) {
        const flags = await execute(
          '({secure:isSecureContext,process:typeof process,require:typeof require,appBridge:typeof wormhole,crypto:typeof crypto?.subtle,runtime:typeof chrome.runtime?.id,manifest:chrome.runtime.getManifest().manifest_version,memory:typeof bitwardenMain?.memoryStorageForStateProviders,factory:typeof globalThis.WormholeVaultBitwarden,slot:!!globalThis.__wormhole_vault_bitwarden_document_v1__})',
        );
        console.log(
          'ENDPOINT_FLAGS ' +
            JSON.stringify({
              ...(flags as object),
              lastKind,
              lastResult,
              sameFrame: profile.contents.mainFrame === frame,
              sameToken: frame.frameToken === oldIdentity.token,
              sameProcess: frame.processId === oldIdentity.process,
              sameOs: frame.osProcessId === oldIdentity.os,
              sameRouting: frame.routingId === oldIdentity.routing,
              loading: profile.contents.isLoadingMainFrame(),
              sandbox: sandboxed(frame),
            }),
        );
        throw error;
      }
      stage('endpoint-ready');
      const sync = new VaultBitwardenSynchronizer({
        owner,
        client,
        bridge: endpoint,
        current: () => true,
      });
      synchronizers.push(sync);
      return { endpoint, sync, execute };
    };
    const a = await connect(first, initial.client, initial.workspaceId);
    stage('checkpoint-first');
    assert.deepEqual(await a.sync.synchronize(), { rounds: 1, checkpointPending: false });
    assert.equal(await a.execute('fixtureLogin().then(()=>true)'), true);
    assert.deepEqual(await a.sync.synchronize(), { rounds: 1, checkpointPending: false });
    stage('checkpoint-first-done');
    const second = await background(2),
      b = await connect(second, initial.client, initial.workspaceId);
    stage('checkpoint-second');
    assert.deepEqual(await b.sync.synchronize(), { rounds: 2, checkpointPending: false });
    const restored = await b.execute('fixtureMatches(true)');
    assert.equal(restored, true);
    await b.sync.close();
    await a.sync.close();
    await initial.client.lock();

    stage('restart');
    const restarted = await open(),
      third = await background(3),
      c = await connect(third, restarted.client, restarted.workspaceId);
    assert.deepEqual(await c.sync.synchronize(), { rounds: 2, checkpointPending: false });
    const cold = await c.execute('fixtureMatches(false)');
    assert.equal(cold, true);
    await c.sync.close();
    await restarted.client.lock();
    assert.equal(transportLeaked, false);
    assert.equal(browserLeaked, false);
    assert.equal((await readFile(databasePath)).includes(Buffer.from(marker)), false);
    assert.equal((await readFile(databasePath)).includes(Buffer.from(sessionMarker)), false);
    console.log(
      JSON.stringify({
        complete: true,
        nativeSandboxProof: true,
        persistentDiagnosticOnly: true,
        restored: true,
        coldRestart: true,
      }),
    );
  } finally {
    stage('cleanup');
    // Retire every owned resource even when the test itself fails. Process exit
    // plus actual document destruction is stronger than an unavailable profile RPC.
    await Promise.allSettled(synchronizers.map((sync) => sync.close()));
    const results = await Promise.allSettled(
      profiles.map(async (profile) => {
        profile.session.extensions.removeExtension(profile.extensionId);
        if (!profile.contents.isDestroyed())
          await new Promise<void>((yes, no) => {
            const timer = setTimeout(() => no(Error('Document destruction timeout')), 10000);
            profile.contents.once('destroyed', () => {
              clearTimeout(timer);
              yes();
            });
            profile.contents.close({ waitForBeforeUnload: false });
          });
        await profile.session.clearStorageData();
        await profile.session.clearCache();
        await profile.session.closeAllConnections();
      }),
    );
    const native = await Promise.allSettled(clients.map((client) => client.lock()));
    const documents = await Promise.allSettled(endpoints.map((endpoint) => endpoint.dispose()));
    if ([...results, ...native, ...documents].some((result) => result.status === 'rejected'))
      throw Error('Native endpoint fixture cleanup was not confirmed.');
  }
}
app
  .whenReady()
  .then(run)
  .then(() => app.quit())
  .catch((error) => {
    console.error(error);
    app.exit(1);
  });
