import { VaultVncIpc } from '../electron/vault-vnc-ipc.ts';
import { vncConnectRequest, vaultVncQuickTarget } from '../src/vnc-connect.ts';
import { sealVncTemporaryPassword } from '../src/vault-vnc-password-sender.ts';
import { EventEmitter } from 'node:events';
import { VaultVncController } from '../electron/vault-vnc-controller.ts';
import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { randomUUID } from 'node:crypto';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { SealedVncBackend } from '../electron/sealed-vnc.ts';
import { SealedRouteBroker } from '../electron/sealed-route.ts';
import { stopChildProcess } from '../electron/rdp.ts';
let buildDirectory: string, executable: string, fixture: string;
const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
before(
  async () => {
    buildDirectory = await mkdtemp(join(tmpdir(), 'wormhole-vnc-relay-build-'));
    executable = join(buildDirectory, process.platform === 'win32' ? 'backend.exe' : 'backend');
    fixture = join(buildDirectory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
    await promisify(execFile)('go', ['build', '-o', executable, '.'], {
      cwd,
      windowsHide: true,
      timeout: 120000,
    });
    await promisify(execFile)('go', ['test', '-c', '-o', fixture, '.'], {
      cwd,
      windowsHide: true,
      timeout: 120000,
    });
  },
  { timeout: 180000 },
);
after(async () => {
  if (buildDirectory) {
    assert.equal(resolve(buildDirectory, '..'), resolve(tmpdir()));
    await rm(buildDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
  }
});
for (const quick of [false, true])
  for (const [routed, manual] of [
    [false, false],
    [true, false],
    [false, true],
    [true, true],
  ])
    for (const special of quick
      ? manual
        ? ['normal', 'empty']
        : ['normal', 'absent']
      : ['normal'])
      test(
        `Electron ${quick ? 'unsaved Quick' : 'saved'} VNC relay authenticates and streams through ${routed ? 'a native VPN route' : 'a direct socket'} with ${special === 'empty' ? 'an explicitly empty temporary password' : special === 'absent' ? 'no password' : manual ? 'a temporary password' : 'a saved credential'}`,
        { timeout: 120000 },
        async () => {
          const directory = await mkdtemp(join(tmpdir(), 'wormhole-vnc-relay-')),
            database = join(directory, 'vault.db');
          const trace: unknown[] = [];
          const closedChildren = new Set<ReturnType<typeof spawn>>();
          const started = Date.now();
          const observe = (child: ReturnType<typeof spawn>, kind: string) => {
            const record = (event: string, value?: unknown) =>
              trace.push({ kind, event, value, ms: Date.now() - started });
            child.once('spawn', () => record('spawn', { pid: child.pid }));
            child.stdout?.once('end', () => record('output-end'));
            child.stdout?.once('close', () => record('output-close'));
            child.stderr?.once('end', () => record('diagnostics-end'));
            child.stderr?.once('close', () => record('diagnostics-close'));
            child.stdin?.once('close', () => record('input-close'));
            child.once('error', (error) => record('error', (error as NodeJS.ErrnoException).code));
            child.once('exit', (code, signal) => record('exit', { code, signal }));
            child.once('close', () => {
              closedChildren.add(child);
              record('close');
            });
            child.stdin?.once('finish', () => record('input-end'));
            const kill = child.kill.bind(child);
            child.kill = (...args) => {
              try {
                const ok = kill(...args);
                let probe: unknown = 'present';
                try {
                  process.kill(child.pid!, 0);
                } catch (error) {
                  probe = (error as NodeJS.ErrnoException).code;
                }
                record('kill', { ok, probe, exit: child.exitCode });
                return ok;
              } catch (error) {
                record('kill-error', (error as NodeJS.ErrnoException).code);
                throw error;
              }
            };
          };
          const children: ReturnType<typeof spawn>[] = [],
            events: any[] = [];
          let server: ReturnType<typeof spawn> | undefined,
            allowed = true,
            port = 0;
          const owners: ReturnType<typeof spawn>[] = [];
          const host = new VaultBackendHost(
            () =>
              new VaultBackendClient(
                { executable, databasePath: database, userDataPath: directory },
                (exe, args) => {
                  const child = spawn(exe, args, { stdio: 'pipe', windowsHide: true });
                  observe(child, 'vault');
                  owners.push(child);
                  return child;
                },
              ),
            () => true,
          );
          const routes = new SealedRouteBroker(
            {
              executable: () => executable,
              workspaceId: () => host.unlockedWorkspaceId,
              authorized: (epoch) => allowed && epoch === 1,
              plan: (q) => host.tunnelPlan(q),
              bundle: (q) => host.tunnelBundle(q),
            },
            (exe, args) => {
              const child = spawn(exe, args, {
                windowsHide: true,
                stdio: 'pipe',
                env: {
                  ...process.env,
                  WORMHOLE_CISCOPROXY_PATH: fixture,
                  WORMHOLE_TEST_VPN_SOCKS_TARGET: `127.0.0.1:${port}`,
                },
              });
              observe(child, 'route');
              children.push(child);
              return child;
            },
          );
          let dispatch = (event: any) => {
            events.push(event);
          };
          const broker = new SealedVncBackend(
            {
              executable: () => executable,
              workspaceId: () => host.unlockedWorkspaceId,
              authorized: (epoch) => allowed && epoch === 1,
              bundle: (q) => {
                assert.equal(manual, false, 'manual flow must never borrow a saved password');
                return host.vncBundle(q);
              },
              manual: {
                plan: (q) => host.vncPlan(q),
                bundle: (q) => host.vncManualBundle(q),
                prompt: async (context, active, signal) => {
                  assert.equal(manual, true);
                  assert.equal(active(), true);
                  assert.equal(signal.aborted, false);
                  const bytes = new TextEncoder().encode(
                    special === 'empty' ? '' : 'temporary-only-password',
                  );
                  const result = await sealVncTemporaryPassword(context, bytes, signal);
                  assert.ok(bytes.every((v) => v === 0));
                  return result;
                },
              },
              route: {
                resolve: (q) => host.connectionRoute(q),
                broker: routes,
                bundle: (q) => host.routedVncBundle(q),
              },
              onEvent: (event) => dispatch(event),
            },
            (exe, args) => {
              const child = spawn(exe, args, { stdio: 'pipe', windowsHide: true });
              observe(child, 'vnc');
              children.push(child);
              return child;
            },
          );
          const owner = Object.assign(new EventEmitter(), {
            isDestroyed: () => false,
            send: (channel: string, event: any) => {
              assert.equal(channel, 'backend:event');
              events.push(event);
            },
          });
          const controller = new VaultVncController(
            (onEvent) => {
              dispatch = onEvent;
              return broker;
            },
            (epoch) => allowed && epoch === 1,
          );
          let quickRef: any;
          const ipc = new VaultVncIpc({
            controller,
            workspace: () => host.isVaultWorkspace,
            trusted: () => true,
            authorize: async (run) => {
              if (!allowed) throw Error('locked');
              return run(1);
            },
            quickTarget: async (target, sessionId, epoch, accepted) => {
              const lease = await host.beginQuickTarget(
                { workspaceId: host.unlockedWorkspaceId!, sessionId, epoch, target },
                accepted,
              );
              quickRef = lease.reference;
              return lease;
            },
          });
          let testError: unknown;
          try {
            server = spawn(fixture, ['-test.run=^TestVaultVNCRelayFixture$', '-test.timeout=60s'], {
              cwd,
              stdio: 'pipe',
              windowsHide: true,
              env: {
                ...process.env,
                WORMHOLE_TEST_VNC_RELAY: database,
                WORMHOLE_TEST_VNC_RELAY_ROUTE: routed ? '1' : '0',
                WORMHOLE_TEST_VNC_RELAY_MANUAL: manual ? '1' : '0',
                WORMHOLE_TEST_VNC_RELAY_QUICK: quick ? '1' : '0',
                WORMHOLE_TEST_VNC_RELAY_SPECIAL: special,
              },
            });
            server.stderr!.resume();
            const reader = createInterface({ input: server.stdout! });
            const metadata = await new Promise<any>((resolve, reject) => {
              const timer = setTimeout(() => reject(Error('VNC fixture did not start')), 30000);
              reader.once('line', (line) => {
                clearTimeout(timer);
                try {
                  resolve(JSON.parse(line));
                } catch {
                  reject(Error('Invalid fixture metadata'));
                }
              });
            });
            reader.close();
            server.stdout!.resume();
            port = metadata.port;
            const exited = new Promise<number | null>((resolve, reject) => {
              server!.once('exit', resolve);
              server!.once('error', reject);
            });
            void exited.catch(() => {});
            const descriptor = await host.describe();
            assert.ok(descriptor);
            assert.equal(descriptor.vaultId, metadata.workspaceId);
            const slot = descriptor.slots.find((s) => s.kind === 'recovery')!;
            await host.unlock({
              vaultId: descriptor.vaultId,
              slotId: slot.id,
              kind: 'recovery',
              factor: new Uint8Array(32).fill(0x32),
            });
            assert.equal((await host.workspace()).tree.length, quick ? 0 : 1);
            const id = randomUUID();
            await ipc.command(
              { sender: owner },
              vncConnectRequest(
                {
                  id,
                  host: metadata.host,
                  ...(quick
                    ? {
                        quickTarget: vaultVncQuickTarget({
                          host: metadata.host,
                          port: metadata.port,
                          credentialId: special === 'absent' ? undefined : metadata.credentialId,
                          tunnelId: metadata.tunnelId ?? undefined,
                        }),
                      }
                    : { nodeId: metadata.nodeId }),
                },
                true,
                undefined,
                manual,
              ),
            );
            const deadline = Date.now() + 10000;
            while (!events.some((e) => e.type === 'vnc.frame') && Date.now() < deadline)
              await new Promise((r) => setTimeout(r, 10));
            const frame = events.find((e) => e.type === 'vnc.frame');
            assert.ok(frame);
            assert.equal(frame.sessionId, id);
            assert.equal(frame.width, 1);
            assert.equal(frame.height, 1);
            const bytes = Buffer.from(frame.image.slice(22), 'base64');
            assert.ok(bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])));
            await ipc.command(
              { sender: owner },
              { action: 'vnc.pointer', sessionId: id, x: 0, y: 0, buttons: 1 },
            );
            await ipc.command(
              { sender: owner },
              { action: 'vnc.key', sessionId: id, keysym: 0xff0d, down: true },
            );
            assert.equal(await exited, 0);
            assert.equal(JSON.stringify(events).includes('temporary-only-password'), false);
            assert.equal(JSON.stringify(events).includes('relay-native-only-password'), false);
            assert.equal(JSON.stringify(events).includes('route-sidecar-password'), false);
            const contents = await readFile(database);
            assert.equal(contents.includes(Buffer.from('temporary-only-password')), false);
            assert.equal(contents.includes(Buffer.from('relay-native-only-password')), false);
            assert.equal(children.length, routed ? 2 : 1);
            await ipc.command({ sender: owner }, { action: 'vnc.disconnect', sessionId: id });
            assert.equal((await host.workspace()).tree.length, quick ? 0 : 1);
            if (quick) {
              assert.ok(quickRef);
              await assert.rejects(
                host.vncPlan({
                  workspaceId: metadata.workspaceId,
                  nodeId: quickRef.id,
                  sessionId: id,
                  requestId: randomUUID(),
                  epoch: 1,
                  credentialOverride: '',
                }),
              );
            }
            allowed = false;
            await ipc.closeAll();
            await routes.closeAll();
            await host.stop();
            // Exit was confirmed by the relay. Await Node's pipe/handle notifications
            // separately before deleting executable fixtures (Windows can deliver them late).
          } catch (error) {
            testError = error;
          }
          allowed = false;
          const cleanup = await Promise.allSettled([
            ipc.closeAll(),
            routes.closeAll(),
            host.stop(),
          ]);
          const stopped = await Promise.allSettled(
            children
              .concat(owners)
              .concat(server ? [server] : [])
              .map((child) =>
                stopChildProcess(child, { gracefulTimeoutMs: 1000, forceKillTimeoutMs: 1000 }),
              ),
          );
          const handles = await Promise.allSettled(
            children.concat(owners).map((child) =>
              closedChildren.has(child)
                ? Promise.resolve()
                : new Promise<void>((resolve, reject) => {
                    const closed = () => {
                      clearTimeout(timer);
                      resolve();
                    };
                    const timer = setTimeout(() => {
                      child.removeListener('close', closed);
                      trace.push({
                        kind: 'handles-timeout',
                        pid: child.pid,
                        exitCode: child.exitCode,
                        signalCode: child.signalCode,
                        input: {
                          destroyed: child.stdin?.destroyed,
                          ended: child.stdin?.writableEnded,
                        },
                        output: {
                          destroyed: child.stdout?.destroyed,
                          ended: child.stdout?.readableEnded,
                          flowing: child.stdout?.readableFlowing,
                        },
                        diagnostics: {
                          destroyed: child.stderr?.destroyed,
                          ended: child.stderr?.readableEnded,
                          flowing: child.stderr?.readableFlowing,
                        },
                      });
                      reject(Error('Native fixture handles did not close.'));
                    }, 10000);
                    child.once('close', closed);
                  }),
            ),
          );
          assert.equal(resolve(directory, '..'), resolve(tmpdir()));
          const removed = await Promise.allSettled([
            rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 }),
          ]);
          if (testError) {
            const processes = children.map((c) => ({
              pid: c.pid,
              exitCode: c.exitCode,
              signalCode: c.signalCode,
              killed: c.killed,
            }));
            const statuses = events
              .filter((e) => e.type === 'vnc.status')
              .map((e) => ({ status: e.status, passwordRequired: e.passwordRequired }));
            throw Error(
              `VNC integration failed; processes=${JSON.stringify(processes)}; statuses=${JSON.stringify(statuses)}; trace=${JSON.stringify(trace)}`,
              { cause: testError },
            );
          }
          for (const result of [...cleanup, ...stopped, ...handles, ...removed])
            if (result.status === 'rejected')
              throw Error('VNC native cleanup failed; trace=' + JSON.stringify(trace), {
                cause: result.reason,
              });
          assert.ok(
            children.concat(owners).every((c) => c.exitCode !== null || c.signalCode !== null),
          );
          assert.ok(
            stopped.every((result) => result.status === 'fulfilled' && result.value),
            'native fixture shutdown must be confirmed',
          );
        },
      );
