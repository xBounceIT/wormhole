import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { randomUUID } from 'node:crypto';
import { stripTypeScriptTypes } from 'node:module';
import { runInNewContext } from 'node:vm';
import { VaultSshIpc } from '../electron/vault-ssh-ipc.ts';
import { vaultSshQuickTarget, sshConnectRequest } from '../src/ssh-connect.ts';
import { mainSshHarness, mainSshSource } from './fixtures/vault-ssh-main.ts';
import { declarations } from './fixtures/main-source.ts';
import { sealSshTemporaryCredentials } from '../src/vault-ssh-credentials-sender.ts';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { SealedSshBackend } from '../electron/sealed-ssh.ts';
import { SealedRouteBroker } from '../electron/sealed-route.ts';
import { stopChildProcess } from '../electron/rdp.ts';

let buildDirectory: string | undefined;
let executable: string, fixture: string;
const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
before(
  async () => {
    buildDirectory = await mkdtemp(join(tmpdir(), 'wormhole-ssh-relay-build-'));
    executable = join(buildDirectory, process.platform === 'win32' ? 'backend.exe' : 'backend');
    fixture = join(buildDirectory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
    // Build immutable tools once; every scenario still owns its database/processes.
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
  if (buildDirectory)
    await rm(buildDirectory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
});

for (const protocol of ['ssh', 'sftp'] as const)
  for (const routed of [false, true])
    for (const manual of [false, true])
      test(
        `actual main opens ${routed ? 'routed' : 'direct'} Quick ${protocol} with ${manual ? 'isolated temporary' : 'saved'} credentials and a real Go owner and server`,
        { timeout: 120000 },
        async (t) => {
          const directory = await mkdtemp(join(tmpdir(), 'wormhole-quick-ssh-relay-'));
          const database = join(directory, 'vault.db');
          const host = new VaultBackendHost(
            () =>
              new VaultBackendClient({
                executable,
                databasePath: database,
                userDataPath: directory,
              }),
            () => true,
          );
          const children: ReturnType<typeof spawn>[] = [];
          let server: ReturnType<typeof spawn> | undefined,
            routeChild: ReturnType<typeof spawn> | undefined;
          let ipc: VaultSshIpc | undefined, native: any;
          let testError: unknown;
          try {
            server = spawn(fixture, ['-test.run=^TestVaultSSHRelayFixture$', '-test.timeout=80s'], {
              cwd,
              windowsHide: true,
              stdio: 'pipe',
              env: {
                ...process.env,
                WORMHOLE_TEST_SSH_RELAY: database,
                WORMHOLE_TEST_SSH_RELAY_ROUTE: routed ? '1' : '0',
                WORMHOLE_TEST_SSH_RELAY_PROBE: '1',
                WORMHOLE_TEST_SSH_RELAY_SFTP: protocol === 'sftp' ? '1' : '0',
                WORMHOLE_TEST_SSH_RELAY_FILE_ONLY: protocol === 'sftp' ? '1' : '0',
              },
            });
            const exited = new Promise<number | null>((resolve, reject) => {
              server!.once('exit', resolve);
              server!.once('error', reject);
            });
            void exited.catch(() => {});
            server.stderr!.resume();
            const reader = createInterface({ input: server.stdout! });
            const metadata = await new Promise<any>((resolve, reject) => {
              const timer = setTimeout(() => reject(Error('SSH fixture did not start')), 30000);
              reader.once('line', (line) => {
                clearTimeout(timer);
                try {
                  resolve(JSON.parse(line));
                } catch {
                  reject(Error('Invalid metadata'));
                }
              });
            });
            reader.close();
            const descriptor = (await host.describe())!;
            await host.unlock({
              vaultId: descriptor.vaultId,
              slotId: descriptor.slots.find((s) => s.kind === 'recovery')!.id,
              kind: 'recovery',
              factor: new Uint8Array(32).fill(0x32),
            });
            const h = mainSshHarness(SealedSshBackend, host, {
              backendPath: () => executable,
              wormholeDatabasePath: () => database,
              electronUserDataPath: () => directory,
              SealedRouteBroker: class extends SealedRouteBroker {
                constructor(options: any) {
                  super(options, (exe, args) => {
                    const child = spawn(exe, args, {
                      windowsHide: true,
                      stdio: 'pipe',
                      env: {
                        ...process.env,
                        WORMHOLE_CISCOPROXY_PATH: fixture,
                        WORMHOLE_TEST_VPN_SOCKS_TARGET: `127.0.0.1:${metadata.port}`,
                      },
                    });
                    children.push(child);
                    routeChild = child;
                    return child;
                  });
                }
              },
              VaultSshIpc,
              vaultSshCredentialsDialog: {
                cancel: async () => {},
                cancelSession: async () => {},
                open: async (
                  _parent: unknown,
                  current: () => boolean,
                  context: unknown,
                  signal: AbortSignal,
                ) => {
                  assert.ok(manual);
                  assert.ok(current());
                  assert.equal(signal.aborted, false);
                  const encode = (s: string) => new TextEncoder().encode(s);
                  return sealSshTemporaryCredentials(
                    context,
                    {
                      username: encode('relay-user'),
                      password: encode('relay-native-only-password'),
                      privateKey: encode(''),
                      passphrase: encode(''),
                      certificate: encode(''),
                    },
                    signal,
                  );
                },
              },
              requireNativeResourcesRunning() {},
              isSshSessionId: (id: unknown) => typeof id === 'string',
              runAuthorizedOperation: (run: any) => run(4),
            });
            const runtime = runInNewContext(
              stripTypeScriptTypes(
                declarations(mainSshSource, ['sshBackend', 'vaultSshIpc']) +
                  '\n({ipc:vaultSshIpc,native:sshBackend})',
              ),
              h.context,
            );
            ipc = runtime.ipc;
            native = runtime.native;
            const handlers = h.register(['ssh:open', 'ssh:sftp-share', 'ssh:close']);
            const sessionId = randomUUID();
            const request = sshConnectRequest(
              {
                sessionId,
                mode: protocol === 'sftp' ? 'sftp' : 'terminal',
                manualCredentials: manual,
                quickTarget: vaultSshQuickTarget({
                  protocol,
                  host: metadata.host,
                  port: metadata.port,
                  credentialId: manual ? undefined : metadata.credentialId,
                  tunnelId: metadata.tunnelId ?? undefined,
                }),
              },
              undefined,
              true,
            );
            const result = await handlers.get('ssh:open')(h.event, request);
            assert.equal(result.username, 'relay-user');
            assert.equal(result.host, metadata.host);
            assert.match(result.fingerprint, /^SHA256:/);
            assert.equal(
              h.dialogs.length,
              1,
              'temporary first-use identity must be explicitly confirmed',
            );
            assert.equal(
              (await host.workspace()).tree.length,
              1,
              'Quick must not create a saved connection',
            );
            const cohort = native.sealed.sessions.get(sessionId);
            const stage = cohort.request.nodeId;
            const hostRequest = {
              workspaceId: metadata.workspaceId,
              nodeId: stage,
              sessionId,
              requestId: cohort.request.requestId,
              epoch: 5,
              credentialOverride: '',
              route: cohort.route?.binding ?? null,
            };
            assert.notEqual(stage, metadata.nodeId);
            assert.equal(JSON.stringify(result).includes(stage), false);
            const alias = randomUUID();
            await handlers.get('ssh:sftp-share')(h.event, sessionId, alias);
            await handlers.get('ssh:close')(h.event, sessionId);
            assert.ok(native.hasProtectedReservation(sessionId));
            assert.equal((await host.sshHostPlan(hostRequest)).fingerprint, result.fingerprint);
            const second = randomUUID();
            await handlers.get('ssh:sftp-share')(h.event, alias, second);
            await handlers.get('ssh:close')(h.event, alias);
            assert.ok(native.hasProtectedReservation(sessionId));
            if (routed) {
              assert.ok(routeChild);
              assert.equal(routeChild.exitCode, null);
            }
            await handlers.get('ssh:close')(h.event, second);
            assert.equal(native.hasProtectedReservation(sessionId), false);
            await assert.rejects(host.sshHostPlan(hostRequest));
            assert.equal(await exited, 0);
            assert.doesNotMatch(
              JSON.stringify(h.events),
              /relay-native-only-password|ciphertext|publicKey|requestId/,
            );
          } catch (error) {
            testError = error;
          } finally {
            const results = await Promise.allSettled([
              ipc?.closeAll(),
              native?.stopSealedSessions(),
              host.stop(),
              ...children.map((c) => stopChildProcess(c)),
              ...(server ? [stopChildProcess(server)] : []),
            ]);
            const [removed] = await Promise.allSettled([
              rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 }),
            ]);
            const failed = results.find((r) => r.status === 'rejected');
            if (failed?.status === 'rejected') {
              t.diagnostic('Quick native shutdown failed');
              testError ??= failed.reason;
            }
            if (removed.status === 'rejected') testError ??= removed.reason;
            if (results.some((r) => r.status === 'fulfilled' && r.value === false))
              testError ??= Error('Quick fixture process shutdown must be confirmed.');
          }
          if (testError) throw testError;
        },
      );

for (const mode of ['ssh', 'sftp', 'sftp-from-ssh'] as const)
  for (const routed of [false, true])
    test(
      `Electron relays ${routed ? 'VPN-routed' : 'direct'} native credentials to a real ${mode.toUpperCase()} server while vault owns SQLite`,
      { timeout: 180000 },
      async (t) => {
        const directory = await mkdtemp(join(tmpdir(), 'wormhole-ssh-relay-'));
        const database = join(directory, 'vault.db');
        let server: ReturnType<typeof spawn> | undefined;
        const host = new VaultBackendHost(
          () =>
            new VaultBackendClient({ executable, databasePath: database, userDataPath: directory }),
          () => true,
        );
        const events: any[] = [];
        const nativeChildren: ReturnType<typeof spawn>[] = [];
        let phase = 'initial open',
          testError: unknown;
        let allowed = true,
          routePort = 0;
        let routeChild: ReturnType<typeof spawn> | undefined;
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
                WORMHOLE_TEST_VPN_SOCKS_TARGET: `127.0.0.1:${routePort}`,
              },
            });
            nativeChildren.push(child);
            routeChild = child;
            return child;
          },
        );
        let confirmations = 0;
        const broker = new SealedSshBackend(
          {
            executable: () => executable,
            fileEditing: () => ({ databasePath: database, userDataPath: directory }),
            workspaceId: () => host.unlockedWorkspaceId,
            authorized: (epoch) => allowed && epoch === 1,
            bundle: (request) => host.sshBundle(request),
            route: {
              resolve: (q) => host.connectionRoute(q),
              broker: routes,
              bundle: (q) => host.routedSshBundle(q),
            },
            host: {
              plan: (q) => host.sshHostPlan(q),
              confirm: async (q, expected, received, accepted, signal) => {
                assert.ok(routed);
                assert.equal(expected.fingerprint, '');
                assert.ok(accepted());
                assert.ok(!signal.aborted);
                confirmations++;
                await host.trustSshHost({ ...q, expected, received }, undefined, accepted);
              },
            },
            parseEvent: (line) => {
              const e = JSON.parse(line);
              return { type: e.type, sessionId: e.session_id };
            },
            onLine: (line) => events.push(JSON.parse(line)),
          },
          (exe, args) => {
            const child = spawn(exe, args, { windowsHide: true, stdio: 'pipe' });
            nativeChildren.push(child);
            return child;
          },
        );
        try {
          server = spawn(fixture, ['-test.run=^TestVaultSSHRelayFixture$', '-test.timeout=60s'], {
            cwd,
            windowsHide: true,
            stdio: 'pipe',
            env: {
              ...process.env,
              WORMHOLE_TEST_SSH_RELAY: database,
              WORMHOLE_TEST_SSH_RELAY_ROUTE: routed ? '1' : '0',
              WORMHOLE_TEST_SSH_RELAY_PROBE: '1',
              WORMHOLE_TEST_SSH_RELAY_SFTP: mode === 'sftp' ? '1' : '0',
              WORMHOLE_TEST_SSH_RELAY_FILE_ONLY: mode !== 'ssh' ? '1' : '0',
              WORMHOLE_TEST_SSH_RELAY_RECONNECT: mode === 'sftp-from-ssh' ? '1' : '0',
            },
          });
          const exited = new Promise<number | null>((resolve, reject) => {
            server!.once('exit', resolve);
            server!.once('error', reject);
          });
          void exited.catch(() => {});
          server.stderr!.resume();
          const reader = createInterface({ input: server.stdout! });
          const metadata = await new Promise<any>((resolve, reject) => {
            const timer = setTimeout(() => reject(Error('SSH fixture did not start')), 30000);
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
          routePort = metadata.port;
          phase = 'vault descriptor';
          const descriptor = await host.describe();
          assert.ok(descriptor);
          assert.equal(descriptor.vaultId, metadata.workspaceId);
          const slot = descriptor.slots.find((s) => s.kind === 'recovery')!;
          phase = 'vault unlock';
          await host.unlock({
            vaultId: descriptor.vaultId,
            slotId: slot.id,
            kind: 'recovery',
            factor: new Uint8Array(32).fill(0x32),
          });
          phase = 'vault preferences';
          assert.equal((await host.preferences()).sidebarWidth, 320);
          phase = 'vault workspace';
          assert.equal((await host.workspace()).tree.length, 1);
          phase = 'SSH recipient open';
          const sessionId = randomUUID();
          const result = await broker.open(
            {
              sessionId,
              nodeId: metadata.nodeId,
              columns: 80,
              rows: 24,
              mode: mode !== 'ssh' ? 'sftp' : 'terminal',
            },
            1,
          );
          assert.equal(result.host, routed ? '127.0.0.2' : '127.0.0.1');
          assert.equal(result.port, metadata.port);
          assert.equal(result.username, 'relay-user');
          assert.match(result.fingerprint, /^SHA256:/);
          assert.equal(confirmations, routed ? 1 : 0);
          const waitEvent = async (kind: string, key?: string, value?: string) => {
            const deadline = Date.now() + 10000;
            while (Date.now() < deadline) {
              const event = events.find((e) => e.type === kind && (!key || e[key] === value));
              if (event) return event;
              await new Promise((resolve) => setTimeout(resolve, 10));
            }
            throw Error(`Missing ${kind} event`);
          };
          broker.send(sessionId, { type: 'sftp-open', session_id: sessionId, request_id: 'open' });
          assert.equal((await waitEvent('sftp.ready')).path, '/');
          const local = join(directory, 'payload');
          await writeFile(local, 'sealed-SFTP-bytes');
          broker.send(sessionId, {
            type: 'sftp-transfer',
            session_id: sessionId,
            transfer_id: 'upload',
            direction: 'local-to-remote',
            destination_path: '/',
            items: [{ source_path: local, name: 'payload', is_directory: false, size: 17 }],
          });
          await waitEvent('sftp.transfer', 'transfer_state', 'batch-completed');
          events.splice(0, events.length, ...events.filter((e) => e.type !== 'sftp.transfer'));
          const sharedId = randomUUID();
          const shared = await broker.shareSftp(sessionId, sharedId, () => true);
          assert.equal(shared.username, result.username);
          assert.equal(shared.fingerprint, result.fingerprint);
          if (mode === 'ssh')
            broker.send(sessionId, {
              type: 'input',
              session_id: sessionId,
              data: Buffer.from('echo-relay\r').toString('base64'),
            });
          await broker.close(sessionId);
          assert.equal(broker.has(sessionId), false);
          assert.equal(broker.has(sharedId), true);
          if (routed) assert.equal(routeChild!.exitCode, null);
          const filesId = randomUUID();
          await broker.shareSftp(sharedId, filesId, () => true);
          await broker.close(sharedId);
          broker.send(filesId, {
            type: 'sftp-open',
            session_id: filesId,
            request_id: 'shared-open',
          });
          assert.equal((await waitEvent('sftp.ready', 'request_id', 'shared-open')).path, '/');

          broker.send(filesId, {
            type: 'sftp-transfer',
            session_id: filesId,
            transfer_id: 'download',
            direction: 'remote-to-local',
            destination_path: directory,
            items: [{ source_path: '/payload', name: 'received', is_directory: false, size: 17 }],
          });
          await waitEvent('sftp.transfer', 'transfer_state', 'batch-completed');
          assert.equal(await readFile(join(directory, 'received'), 'utf8'), 'sealed-SFTP-bytes');
          phase = 'external editor upload';
          const editorScript = join(directory, 'edit-fixture.mjs');
          await writeFile(
            editorScript,
            "import {writeFileSync} from 'node:fs'; writeFileSync(process.argv[2], 'saved by sealed editor');",
          );
          assert.equal((await host.fileEditSettings()).defaultEditor, 'auto');
          const editorSettings = {
            editors: [
              {
                id: 'fixture',
                name: 'Fixture editor',
                executable: process.execPath,
                arguments: [editorScript, '{file}'],
                patterns: '',
              },
            ],
            defaultEditor: 'fixture',
            maxFileSize: 1024 * 1024,
            swapPanels: false,
          };
          assert.deepEqual(await host.fileEditSettings(editorSettings), editorSettings);
          broker.send(filesId, {
            type: 'sftp-edit',
            session_id: filesId,
            request_id: 'edit-start',
            operation: 'start',
            pane: 'remote',
            path: '/payload',
          });
          const edited = await waitEvent('sftp.edit', 'request_id', 'edit-start');
          assert.equal(edited.error, undefined);
          assert.equal(edited.edits.length, 1);
          const edit = edited.edits[0];
          assert.deepEqual(await host.sftpRecoveryScopes(), {
            nodeIds: [metadata.nodeId],
            after: '',
          });
          assert.equal(
            (await host.sftpRecoveryRecords({ nodeId: metadata.nodeId, operation: 'list' })).busy,
            true,
          );
          const waitUploaded = async () => {
            const deadline = Date.now() + 10000;
            while (Date.now() < deadline) {
              if (
                events.some(
                  (e) =>
                    e.type === 'sftp.edit' &&
                    e.edits?.some((item: any) => item.id === edit.id && item.state === 'Uploaded'),
                )
              )
                return;
              await new Promise((resolve) => setTimeout(resolve, 10));
            }
            throw Error('External editor did not upload');
          };
          await waitUploaded();
          events.splice(0, events.length, ...events.filter((e) => e.type !== 'sftp.transfer'));
          broker.send(filesId, {
            type: 'sftp-transfer',
            session_id: filesId,
            transfer_id: 'editor-download',
            direction: 'remote-to-local',
            destination_path: directory,
            items: [
              { source_path: '/payload', name: 'editor-received', is_directory: false, size: 22 },
            ],
          });
          await waitEvent('sftp.transfer', 'transfer_state', 'batch-completed');
          assert.equal(
            await readFile(join(directory, 'editor-received'), 'utf8'),
            'saved by sealed editor',
          );
          if (mode === 'sftp-from-ssh') {
            phase = 'first transport shutdown';
            await broker.closeAll();
            await writeFile(
              join(
                directory,
                'vault-sftp-edit',
                metadata.workspaceId,
                metadata.nodeId,
                'sftp-edit',
                edit.id,
                'files',
                edit.name,
              ),
              'saved while disconnected',
            );
            const offline = await host.sftpRecoveryRecords({
              nodeId: metadata.nodeId,
              operation: 'list',
            });
            assert.equal(offline.busy, false);
            assert.equal(offline.edits[0].id, edit.id);
            phase = 'file reconnect';
            const reopenedId = randomUUID();
            const reopened = await broker.open(
              {
                sessionId: reopenedId,
                nodeId: metadata.nodeId,
                mode: 'sftp',
                columns: 80,
                rows: 24,
              },
              1,
            );
            assert.equal(reopened.username, result.username);
            assert.equal(reopened.fingerprint, result.fingerprint);
            assert.equal(confirmations, routed ? 1 : 0);
            broker.send(reopenedId, {
              type: 'sftp-open',
              session_id: reopenedId,
              request_id: 'reconnected',
            });
            const listing = await waitEvent('sftp.ready', 'request_id', 'reconnected');
            assert.ok(listing.entries.some((entry: any) => entry.name === 'payload'));
            phase = 'editor recovery';
            broker.send(reopenedId, {
              type: 'sftp-edit',
              session_id: reopenedId,
              request_id: 'recovery-list',
              operation: 'list',
            });
            const recovery = await waitEvent('sftp.edit', 'request_id', 'recovery-list');
            assert.equal(recovery.edits[0].id, edit.id);
            assert.equal(recovery.edits[0].recovered, true);
            events.splice(0, events.length, ...events.filter((e) => e.type !== 'sftp.edit'));
            broker.send(reopenedId, {
              type: 'sftp-edit',
              session_id: reopenedId,
              request_id: 'recover',
              operation: 'recover',
              edit_id: edit.id,
            });
            assert.equal((await waitEvent('sftp.edit', 'request_id', 'recover')).error, undefined);
            await waitUploaded();
            events.splice(0, events.length, ...events.filter((e) => e.type !== 'sftp.transfer'));
            broker.send(reopenedId, {
              type: 'sftp-transfer',
              session_id: reopenedId,
              transfer_id: 'recovery-download',
              direction: 'remote-to-local',
              destination_path: directory,
              items: [
                {
                  source_path: '/payload',
                  name: 'recovery-received',
                  is_directory: false,
                  size: 24,
                },
              ],
            });
            await waitEvent('sftp.transfer', 'transfer_state', 'batch-completed');
            assert.equal(
              await readFile(join(directory, 'recovery-received'), 'utf8'),
              'saved while disconnected',
            );
          }
          if (routed) {
            assert.ok(routeChild);
            routeChild.kill();
            // Losing only the VPN must close SSH and let the real server finish.
            assert.equal(await exited, 0);
          } else assert.equal(routeChild, undefined);
          phase = 'final transport shutdown';
          allowed = false;
          await broker.closeAll();
          assert.equal(await exited, 0);
          assert.ok(events.some((e) => e.type === 'connected'));
          assert.ok(events.some((e) => e.type === 'closed'));
          assert.doesNotMatch(
            JSON.stringify(events),
            /relay-native-only-password|ciphertext|publicKey|requestId/,
          );
        } catch (error) {
          testError = new Error(`Native relay failed during ${phase}`, { cause: error });
        } finally {
          // Failed confirmation is still a test failure, but must never strand the
          // owning vault process or mask the original failure with a cleanup error.
          const cleanup = await Promise.allSettled([
            broker.closeAll(),
            host.stop(),
            ...nativeChildren.map((child) => stopChildProcess(child)),
            ...(server ? [stopChildProcess(server)] : []),
          ]);
          const removed = await Promise.allSettled([
            rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 }),
          ]);
          if (
            testError ||
            cleanup.some((result) => result.status === 'rejected' || result.value === false)
          )
            t.diagnostic(
              JSON.stringify({
                phase,
                children: nativeChildren.map((child) => ({
                  pid: child.pid,
                  exit: child.exitCode,
                  signal: child.signalCode,
                  killed: child.killed,
                })),
              }),
            );
          if (testError) throw testError;
          const failed = cleanup.find((result) => result.status === 'rejected');
          if (failed?.status === 'rejected') throw failed.reason;
          if (removed[0]?.status === 'rejected') throw removed[0].reason;
          assert.ok(
            cleanup.every((result) => result.status !== 'fulfilled' || result.value !== false),
            'fixture process shutdown must be confirmed',
          );
        }
      },
    );
