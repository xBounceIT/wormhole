import { EventEmitter } from 'node:events';
import { VaultRdpIpc } from '../electron/vault-rdp-ipc.ts';
import { VaultRdpController } from '../electron/vault-rdp-controller.ts';
import { vaultRdpConnectRequest } from '../src/rdp-connect.ts';
import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { randomUUID } from 'node:crypto';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { sealRdpTemporaryCredentials } from '../src/vault-rdp-credentials-sender.ts';
import { stopChildProcess } from '../electron/rdp.ts';

test(
  'real vault RPC admits a temporary RDP target, seals only to Go and leaves the catalog unchanged',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-quick-native-'));
    const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
    const executable = join(directory, process.platform === 'win32' ? 'backend.exe' : 'backend');
    const fixture = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
    const database = join(directory, 'vault.db');
    let child: ReturnType<typeof spawn> | undefined,
      host: VaultBackendHost | undefined,
      ipc: VaultRdpIpc | undefined,
      reader: ReturnType<typeof createInterface> | undefined;
    try {
      for (const args of [
        ['build', '-o', executable, '.'],
        ['test', '-c', '-o', fixture, '.'],
      ])
        await promisify(execFile)('go', args, { cwd, windowsHide: true, timeout: 120000 });
      child = spawn(
        fixture,
        ['-test.run=^TestVaultQuickTargetInteropFixture$', '-test.timeout=45s'],
        {
          cwd,
          windowsHide: true,
          stdio: 'pipe',
          env: { ...process.env, WORMHOLE_TEST_QUICK_INTEROP_DATABASE: database },
        },
      );
      child.stderr!.resume();
      const exited = new Promise<number | null>((resolve, reject) => {
        child!.once('exit', resolve);
        child!.once('error', reject);
      });
      void exited.catch(() => {});
      reader = createInterface({ input: child.stdout! });
      const next = () =>
        new Promise<string>((resolve, reject) => {
          const timer = setTimeout(() => reject(Error('Native quick fixture timeout')), 30000);
          reader!.once('line', (line) => {
            clearTimeout(timer);
            resolve(line);
          });
        });
      const setup = JSON.parse(await next());
      const client = new VaultBackendClient({
        executable,
        databasePath: database,
        userDataPath: directory,
      });
      host = new VaultBackendHost(
        () => client,
        () => true,
      );
      const descriptor = await host.describe();
      assert.ok(descriptor);
      assert.equal(descriptor.vaultId, setup.workspaceId);
      const slot = descriptor.slots.find((s) => s.kind === 'recovery')!;
      await host.unlock({
        vaultId: descriptor.vaultId,
        slotId: slot.id,
        kind: 'recovery',
        factor: new Uint8Array(32).fill(0x32),
      });
      assert.equal((await host.workspace()).tree.length, 0);
      const target = {
        protocol: 'rdp',
        host: 'quick.example',
        port: 0,
        credentialId: '',
        tunnelId: '',
        sshAutoSudo: false,
        httpPath: '',
        ignoreCertificateErrors: false,
        rdp: null,
      };
      const owner = Object.assign(new EventEmitter(), { isDestroyed: () => false, send() {} });
      const nativeHost = host;
      let lease: Awaited<ReturnType<VaultBackendHost['beginQuickTarget']>> | undefined;
      let admittedNode: string | undefined;
      const controller = new VaultRdpController(
        (receive) => ({
          open: async (request) => {
            admittedNode = request.nodeId;
            receive({
              type: 'ready',
              sessionId: request.sessionId,
              requestId: randomUUID(),
              external: false,
            });
          },
          close: async () => {},
          closeAll: async () => {},
          command: async (sessionId) => ({ type: 'ack', sessionId }),
        }),
        (epoch) => epoch === 1,
      );
      ipc = new VaultRdpIpc({
        controller,
        workspace: () => true,
        trusted: () => true,
        unlocked: async () => {},
        authorize: async (run) => run(1),
        surface: () => ({ ownerWindow: '123', bounds: { x: 0, y: 0, width: 800, height: 600 } }),
        forget() {},
        quickTarget: async (target, sessionId, epoch, accepted) => {
          lease = await nativeHost.beginQuickTarget(
            { workspaceId: setup.workspaceId, sessionId, epoch, target },
            accepted,
          );
          return lease;
        },
      });
      await ipc.open(
        { sender: owner },
        vaultRdpConnectRequest(
          {
            sessionId: setup.sessionId,
            quickTarget: target as any,
            bounds: { x: 0, y: 0, width: 800, height: 600 },
          },
          true,
        ),
      );
      assert.ok(lease);
      assert.equal(admittedNode, lease.reference.id);
      const q = {
        workspaceId: setup.workspaceId,
        nodeId: lease.reference.id,
        sessionId: setup.sessionId,
        requestId: randomUUID(),
        epoch: 1,
        credentialOverride: '',
      };
      await assert.rejects(host.rdpPlan({ ...q, sessionId: randomUUID() }));
      const sshLease = await host.beginQuickTarget({
        workspaceId: setup.workspaceId,
        sessionId: setup.sessionId,
        epoch: 1,
        target: {
          protocol: 'ssh',
          host: 'quick-ssh.example',
          port: 0,
          credentialId: '',
          tunnelId: '',
          sshAutoSudo: false,
          httpPath: '',
          ignoreCertificateErrors: false,
          rdp: null,
        },
      });
      const sshQuery = {
        ...q,
        nodeId: sshLease.reference.id,
        requestId: randomUUID(),
        route: null,
      };
      const expected = await host.sshHostPlan(sshQuery);
      const received = 'SHA256:' + Buffer.alloc(32, 7).toString('base64').slice(0, -1);
      const trusted = await host.trustQuickSshHost({ ...sshQuery, expected, received });
      assert.equal(trusted.fingerprint, received);
      assert.notEqual(trusted.revision, expected.revision);
      assert.equal(
        (await host.workspace()).tree.length,
        0,
        'ephemeral host trust must not create a saved node',
      );
      await sshLease.release();
      const binding = await host.rdpPlan(q);
      assert.equal(binding.host, 'quick.example');
      assert.equal(binding.port, 3389);
      const context = { binding, publicKey: setup.publicKey };
      const input = {
        username: new TextEncoder().encode('quick-browser-user'),
        domain: new TextEncoder().encode('QUICK'),
        password: new TextEncoder().encode('one-use-quick'),
      };
      const manual = await sealRdpTemporaryCredentials(context, input);
      assert.ok(Object.values(input).every((bytes) => bytes.every((value) => value === 0)));
      const bundle = await host.rdpManualBundle({ context, credentialOverride: '', manual });
      const serialized = JSON.stringify(bundle);
      for (const secret of ['quick-browser-user', 'QUICK', 'one-use-quick'])
        assert.equal(serialized.includes(secret), false);
      const receipt = next();
      child.stdin!.end(serialized + '\n');
      assert.deepEqual(JSON.parse(await receipt), { ok: true });
      assert.equal(await exited, 0);
      assert.equal((await host.workspace()).tree.length, 0);
      await ipc.command({ sender: owner }, { sessionId: setup.sessionId, operation: 'disconnect' });
      assert.equal(controller.has(setup.sessionId), false);
      await assert.rejects(host.rdpPlan(q));
      assert.equal((await host.workspace()).tree.length, 0);
    } finally {
      reader?.close();
      const cleanup = await Promise.allSettled([
        ipc?.closeAll(),
        host?.stop(),
        child
          ? stopChildProcess(child, { gracefulTimeoutMs: 1000, forceKillTimeoutMs: 1000 })
          : Promise.resolve(true),
      ]);
      for (const result of cleanup)
        assert.equal(result.status, 'fulfilled', 'native cleanup must be confirmed');
      assert.equal(cleanup[2].status === 'fulfilled' && cleanup[2].value, true);
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
    }
  },
);
