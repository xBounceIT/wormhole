import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SealedRouteBroker } from '../electron/sealed-route.ts';
import { hasChildExited } from '../electron/child-process-exit.ts';
import { stopChildProcess } from '../electron/rdp.ts';
import type { VaultRouteBinding } from '../electron/vault-route.ts';
import type { VaultTunnelFallbackBinding } from '../electron/vault-tunnel-fallback.ts';

test(
  'real native route controllers wait for their original slow sidecar after ready and startup failure',
  { timeout: 180000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-route-retirement-'));
    const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
    try {
      const fixture = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
      await promisify(execFile)('go', ['test', '-c', '-o', fixture, '.'], {
        cwd,
        windowsHide: true,
        timeout: 120000,
      });
      for (const mode of ['ready', 'startup-error']) {
        const workspace = randomUUID(),
          sessionId = randomUUID(),
          nodeId = randomUUID();
        let binding: VaultRouteBinding;
        let child: ReturnType<typeof spawn> | undefined;
        let kills = 0,
          diagnostics = '';
        let started!: () => void;
        const start = new Promise<void>((resolve) => {
          started = resolve;
        });
        let exited: Promise<number | null> | undefined;
        const env = (mode: string) => ({
          ...process.env,
          WORMHOLE_TEST_ROUTE_RETIREMENT: mode,
          WORMHOLE_TEST_ROUTE_BINDING: JSON.stringify(binding),
        });
        const args = ['-test.run=^TestSealedTunnelRetirementInteropFixture$', '-test.timeout=30s'];
        const broker = new SealedRouteBroker(
          {
            executable: () => fixture,
            workspaceId: () => workspace,
            authorized: (epoch) => epoch === 1,
            plan: async (q) =>
              (binding = {
                workspaceId: q.workspaceId,
                nodeId: q.nodeId,
                sessionId: q.sessionId,
                requestId: q.requestId,
                epoch: q.epoch,
                fileId: randomUUID(),
                protocol: 'ssh',
                host: 'test.example',
                port: 22,
                tunnelConfigId: randomUUID(),
                kind: 1,
                rowVersion: '1',
                configurationVersion: '1',
                useExternalClient: false,
              }),
            bundle: async (q) => {
              const sealing = promisify(execFile)(fixture, args, {
                cwd,
                windowsHide: true,
                env: env('seal'),
                timeout: 10000,
              });
              sealing.child.stdin!.end(JSON.stringify(q.publicKey) + '\n');
              return JSON.parse((await sealing).stdout);
            },
          },
          (_exe, suppliedArgs) => {
            assert.deepEqual(suppliedArgs, ['--operation', 'tunnel-sealed']);
            const original = spawn(fixture, args, {
              cwd,
              windowsHide: true,
              env: env(mode),
              stdio: 'pipe',
            });
            child = original;
            const kill = original.kill.bind(original);
            original.kill = (...args) => {
              kills++;
              return kill(...args);
            };
            original.stderr.on('data', (data) => {
              diagnostics += data.toString();
              if (diagnostics.includes('sidecar-started\n')) started();
            });
            exited = new Promise((resolve, reject) => {
              original.once('close', resolve);
              original.once('error', reject);
            });
            void exited.catch(() => {});
            return original;
          },
        );
        const acquiring = broker.acquire({ sessionId, nodeId }, 1);
        void acquiring.catch(() => {});
        try {
          if (mode === 'ready') {
            const lease = await acquiring;
            assert.equal(lease.active, true);
            const retiring = lease.release();
            assert.equal(lease.active, false);
            try {
              await retiring;
            } catch (error) {
              // A bounded wait may expire. Retry the same lease only after
              // the original controller acknowledges its sidecar and exits.
              assert.ok(error instanceof Error);
              assert.equal(error.message, 'VPN shutdown could not be confirmed.');
              assert.equal(await exited, 0);
              await lease.release();
            }
            assert.ok(child && hasChildExited(child), 'release returned before controller exit');
          } else {
            await Promise.race([
              start,
              acquiring.then(() => {
                throw Error('Failed startup unexpectedly became ready.');
              }),
            ]);
            await broker.close(sessionId);
            await assert.rejects(acquiring);
          }
          assert.equal(await exited, mode === 'ready' ? 0 : 1);
          assert.equal(diagnostics, 'sidecar-started\nsidecar-retired\n');
          assert.equal(kills, 0, 'main must let the original Go owner confirm sidecar exit');
        } finally {
          await broker.closeAll();
          if (child)
            assert.equal(
              await stopChildProcess(child as any, { gracefulTimeoutMs: 8000, forceKill: false }),
              true,
            );
        }
      }
      await verifyNativeFallback(fixture, cwd);
    } finally {
      assert.equal(resolve(directory, '..'), resolve(tmpdir()));
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  },
);

async function verifyNativeFallback(fixture: string, cwd: string): Promise<void> {
  const workspace = randomUUID(),
    fileId = randomUUID(),
    primaryId = randomUUID(),
    fallbackId = randomUUID(),
    sessionId = randomUUID(),
    nodeId = randomUUID();
  let pair: VaultTunnelFallbackBinding;
  const children: ReturnType<typeof spawn>[] = [],
    diagnostics: string[] = [],
    exits: Promise<number | null>[] = [],
    recipients: string[] = [];
  let plans = 0,
    kills = 0;
  const args = ['-test.run=^TestSealedTunnelFallbackInteropFixture$', '-test.timeout=30s'];
  const env = (mode: string) => ({
    ...process.env,
    WORMHOLE_TEST_ROUTE_FALLBACK: mode,
    WORMHOLE_TEST_ROUTE_PAIR: JSON.stringify(pair),
  });
  const seal = async (mode: string, publicKey: string) => {
    recipients.push(publicKey);
    const sealing = promisify(execFile)(fixture, args, {
      cwd,
      windowsHide: true,
      env: env(mode),
      timeout: 10000,
    });
    sealing.child.stdin!.end(JSON.stringify(publicKey) + '\n');
    return JSON.parse((await sealing).stdout);
  };
  const broker = new SealedRouteBroker(
    {
      executable: () => fixture,
      workspaceId: () => workspace,
      authorized: (epoch) => epoch === 1,
      plan: async (q) => {
        const primary: VaultRouteBinding = {
          ...q,
          fileId,
          protocol: 'ssh',
          host: 'test.example',
          port: 22,
          tunnelConfigId: primaryId,
          kind: 9,
          rowVersion: '1',
          configurationVersion: '1',
          useExternalClient: false,
        };
        delete (primary as any).credentialOverride;
        pair = {
          primary,
          fallback: { ...primary, kind: 2, tunnelConfigId: fallbackId, requestId: randomUUID() },
        };
        return primary;
      },
      bundle: (q) => seal('seal-primary', q.publicKey),
      fallback: {
        plan: async (q) => {
          plans++;
          assert.equal(children.length, 1);
          assert.equal(children[0].exitCode, 1, 'original controller OS exit precedes target Use');
          assert.equal(diagnostics[0], 'sidecar-started\nsidecar-retired\n');
          assert.deepEqual(q.primary, pair.primary);
          pair = {
            primary: q.primary,
            fallback: { ...pair.fallback, requestId: q.fallbackRequestId },
          };
          return pair;
        },
        bundle: (q) => seal('seal-secondary', q.publicKey),
      },
    },
    (_exe, suppliedArgs) => {
      const index = children.length;
      assert.ok(index < 2, 'fallback must run at most once');
      assert.deepEqual(suppliedArgs, [
        '--operation',
        index === 0 ? 'tunnel-primary-sealed' : 'tunnel-fallback-sealed',
      ]);
      if (index === 1) {
        assert.equal(children[0].exitCode, 1);
        assert.equal(plans, 1);
      }
      const child = spawn(fixture, args, {
        cwd,
        windowsHide: true,
        env: env(index === 0 ? 'primary' : 'secondary'),
        stdio: 'pipe',
      });
      diagnostics.push('');
      const kill = child.kill.bind(child);
      child.kill = (...args) => {
        kills++;
        return kill(...args);
      };
      child.stderr.on('data', (data) => {
        diagnostics[index] += data.toString();
      });
      exits.push(
        new Promise((resolve, reject) => {
          child.once('close', resolve);
          child.once('error', reject);
        }),
      );
      void exits[index].catch(() => {});
      children.push(child);
      return child;
    },
  );
  try {
    const lease = await broker.acquire({ sessionId, nodeId }, 1);
    assert.equal(lease.binding.kind, 9, 'credential consumers retain their logical primary route');
    assert.deepEqual(lease.binding, pair!.primary);
    assert.equal(lease.active, true);
    assert.equal(children.length, 2);
    assert.equal(recipients.length, 2);
    assert.notEqual(recipients[0], recipients[1]);
    assert.equal(lease.endpoint, '127.0.0.1:12345');
    await lease.release();
    assert.equal(lease.active, false);
    assert.deepEqual(await Promise.all(exits), [1, 0]);
    assert.deepEqual(diagnostics, [
      'sidecar-started\nsidecar-retired\n',
      'sidecar-started\nsidecar-retired\n',
    ]);
    assert.equal(kills, 0);
  } finally {
    await broker.closeAll();
    for (const child of children)
      assert.equal(
        await stopChildProcess(child as any, { gracefulTimeoutMs: 8000, forceKill: false }),
        true,
      );
  }
}
