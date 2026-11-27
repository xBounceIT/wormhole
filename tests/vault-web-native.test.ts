import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { VaultBackendClient } from '../electron/vault-client.ts';
import { VaultBackendHost } from '../electron/vault-host.ts';
import { vaultWebQuickTarget } from '../src/web-connect.ts';
const cwd = fileURLToPath(new URL('../tools/wormhole-backend/', import.meta.url));
let directory: string, executable: string, fixture: string;
before(
  async () => {
    directory = await mkdtemp(join(tmpdir(), 'wormhole-web-plan-'));
    executable = join(directory, process.platform === 'win32' ? 'backend.exe' : 'backend');
    fixture = join(directory, process.platform === 'win32' ? 'fixture.exe' : 'fixture');
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
  if (directory) {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 250 });
  }
});
test(
  'native Chromium restores scoped vault cookies and preserves logout across a vault restart',
  { timeout: 120000 },
  async () => {
    const profile = join(directory, 'browser-cookies');
    await mkdir(profile);
    const electron = createRequire(import.meta.url)('electron') as string;
    const browser = fileURLToPath(new URL('./fixtures/vault-web-cookie-main.mjs', import.meta.url));
    const { ELECTRON_RUN_AS_NODE: _node, ...env } = process.env;
    const virtualDisplay = process.platform === 'linux' && !env.DISPLAY;
    const flags = ['--headless', '--disable-gpu', '--user-data-dir=' + join(profile, 'electron')];
    const result = await promisify(execFile)(
      virtualDisplay ? 'xvfb-run' : electron,
      virtualDisplay
        ? ['--auto-servernum', electron, ...flags, '--no-sandbox', browser]
        : [...flags, browser],
      {
        windowsHide: true,
        timeout: 90000,
        env: {
          ...env,
          WORMHOLE_TEST_WEB_COOKIE_DIRECTORY: profile,
          WORMHOLE_TEST_WEB_COOKIE_FIXTURE: fixture,
          WORMHOLE_TEST_WEB_COOKIE_BACKEND: executable,
        },
      },
    );
    assert.match(result.stdout, /Web cookies survived reopening and stayed erased after logout\./);
  },
);
for (const routed of [false, true])
  test(
    `native web plan authenticates a real vault ${routed ? 'with a tunnel' : 'without a tunnel'}`,
    { timeout: 60000 },
    async () => {
      const profile = join(directory, routed ? 'routed' : 'direct');
      await mkdir(profile);
      const databasePath = join(profile, 'vault.db');
      const created = await promisify(execFile)(
        fixture,
        ['-test.run=^TestVaultWebPlanFixture$', '-test.timeout=30s'],
        {
          cwd,
          windowsHide: true,
          timeout: 45000,
          env: {
            ...process.env,
            WORMHOLE_TEST_WEB_PLAN_DATABASE: databasePath,
            WORMHOLE_TEST_WEB_PLAN_ROUTED: routed ? '1' : '0',
          },
        },
      );
      const metadata = JSON.parse(created.stdout.split(/\r?\n/)[0]);
      const children: { child: ReturnType<typeof spawn>; closed: boolean }[] = [];
      const host = new VaultBackendHost(
        () =>
          new VaultBackendClient(
            { executable, databasePath, userDataPath: profile },
            (exe, args) => {
              const child = spawn(exe, args, { stdio: 'pipe', windowsHide: true }),
                entry = { child, closed: false };
              children.push(entry);
              child.once('close', () => (entry.closed = true));
              return child;
            },
          ),
        () => true,
      );
      try {
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
        const q = {
          workspaceId: metadata.workspaceId,
          nodeId: metadata.nodeId,
          credentialOverride: '',
          sessionId: randomUUID(),
          requestId: randomUUID(),
          epoch: 1,
        };
        await assert.rejects(host.webPlan({ ...q, host: 'redirect.example' }), /Invalid/);
        const plan = await host.webPlan(q);
        assert.equal(plan.binding.workspaceId, q.workspaceId);
        assert.equal(plan.binding.nodeId, q.nodeId);
        assert.equal(plan.binding.sessionId, q.sessionId);
        assert.equal(plan.binding.requestId, q.requestId);
        assert.deepEqual(plan.target, {
          url: 'https://127.0.0.1:8443/native%2Fpath',
          host: '127.0.0.1',
          port: 8443,
          protocol: 'https',
          ignoreCertErrors: true,
          ...(routed ? { tunnelConfigId: plan.binding.tunnelConfigId } : {}),
        });
        assert.equal(!!plan.route, routed);
        if (plan.route) {
          assert.equal(plan.route.kind, 6);
          assert.equal(plan.route.rowVersion, '1');
          assert.equal(plan.route.configurationVersion, '1');
          assert.equal(plan.route.tunnelConfigId, plan.target.tunnelConfigId);
        }
        assert.equal(JSON.stringify(plan).includes('web-native-private-vpn-settings'), false);
        assert.equal(
          (await readFile(databasePath)).includes(Buffer.from('web-native-private-vpn-settings')),
          false,
        );
        const catalog = await host.workspace();
        for (const protocol of ['http', 'https']) {
          const sessionId = randomUUID();
          const lease = await host.beginQuickTarget(
            {
              workspaceId: metadata.workspaceId,
              sessionId,
              epoch: 1,
              target: vaultWebQuickTarget({
                protocol,
                host: 'HTTPS://[::1]:9443/quick%2Fpath?q=ephemeral#page',
                tunnelId: plan.binding.tunnelConfigId || undefined,
                ignoreCertificateErrors: protocol === 'https',
              }),
            },
            () => true,
          );
          try {
            const query = { ...q, sessionId, nodeId: lease.reference.id, requestId: randomUUID() };
            const quick = await host.webPlan(query);
            assert.equal(
              quick.target.url,
              protocol + '://[::1]:9443/quick%2Fpath?q=ephemeral#page',
            );
            assert.equal(quick.target.ignoreCertErrors, protocol === 'https');
            assert.equal(!!quick.route, routed);
            assert.equal(
              host.webSessionArchive(quick, () => true),
              undefined,
            );
            if (quick.route) {
              assert.equal(quick.route.tunnelConfigId, plan.binding.tunnelConfigId);
              assert.equal(quick.route.rowVersion, '1');
              assert.equal(quick.route.configurationVersion, '1');
            }
            await assert.rejects(host.webPlan({ ...query, sessionId: randomUUID() }));
            await assert.rejects(host.webPlan({ ...query, epoch: 2 }));
            assert.deepEqual(await host.workspace(), catalog, 'Quick URLs never become saved rows');
            await lease.release();
            await assert.rejects(host.webPlan(query));
          } finally {
            await lease.release();
          }
        }
        const expected = new Uint8Array(routed ? 1024 * 1024 : 100).fill(0x6b);
        let accepted = true;
        const archive = host.webSessionArchive(plan, () => accepted)!;
        assert.deepEqual(await archive.read(), { revision: '0' });
        const payload = expected.slice();
        assert.equal(await archive.save('0', payload), '1');
        assert.ok(payload.every((byte) => byte === 0));
        await assert.rejects(archive.save('0', new Uint8Array([42])));
        const invalid = new Uint8Array([0x2a]);
        await assert.rejects(archive.save('01', invalid), /Invalid/);
        assert.equal(invalid[0], 0);
        await assert.rejects(archive.forget('01'), /Invalid/);
        accepted = false;
        await assert.rejects(archive.read(), /closed/);
        const closed = new Uint8Array([0x2a]);
        await assert.rejects(archive.save('1', closed), /closed/);
        assert.equal(closed[0], 0);

        await host.stop();
        await assert.rejects(host.webPlan(q), /locked/);
        await host.unlock({
          vaultId: descriptor.vaultId,
          slotId: slot.id,
          kind: 'recovery',
          factor: new Uint8Array(32).fill(0x32),
        });
        await assert.rejects(archive.forget('1'), /closed/);
        const reopened = await host.webPlan({ ...q, requestId: randomUUID() });
        const current = host.webSessionArchive(reopened, () => true)!;
        const recovered = await current.read();
        assert.equal(recovered.revision, '1');
        assert.deepEqual(recovered.bytes, expected);
        recovered.bytes?.fill(0);
        assert.equal(await current.forget(recovered.revision), '2');
        assert.deepEqual(await current.read(), { revision: '2' });
      } finally {
        await host.stop();
        // Process absence is a lock proof. Node's later pipe/handle closure is a separate
        // prerequisite for deleting executable fixtures on Windows.
        await Promise.all(
          children.map((entry) =>
            entry.closed
              ? Promise.resolve()
              : new Promise<void>((yes, no) => {
                  const closed = () => {
                    clearTimeout(timer);
                    yes();
                  };
                  const timer = setTimeout(() => {
                    entry.child.removeListener('close', closed);
                    no(Error('Native web fixture handles did not close.'));
                  }, 10000);
                  entry.child.once('close', closed);
                }),
          ),
        );
      }
    },
  );
