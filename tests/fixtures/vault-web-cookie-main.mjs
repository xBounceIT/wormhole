import { app, BaseWindow, WebContentsView } from 'electron';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { writeSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { setImmediate } from 'node:timers/promises';
import { promisify } from 'node:util';
import { VaultBackendClient } from '../../electron/vault-client.ts';
import { VaultBackendHost } from '../../electron/vault-host.ts';
import { VaultWebCookieCheckpoint } from '../../electron/vault-web-cookies.ts';

const {
  WORMHOLE_TEST_WEB_COOKIE_DIRECTORY: root,
  WORMHOLE_TEST_WEB_COOKIE_FIXTURE: fixture,
  WORMHOLE_TEST_WEB_COOKIE_BACKEND: executable,
} = process.env;
const databasePath = join(root, 'vault.db');
const observed = new Map();
const ordinary = 'ordinary_fixture=synthetic_ordinary_web_cookie; Secure; HttpOnly; Path=/';
const chips =
  'partition_fixture=synthetic_partitioned_web_cookie; Secure; HttpOnly; Partitioned; Path=/';
const deeperPath = 'path_fixture=synthetic_path_web_cookie; Secure; HttpOnly; Path=/app';
const server = createServer((request, response) => {
  observed.set(request.url, request.headers.cookie || '');
  if (request.url === '/login') response.setHeader('Set-Cookie', [ordinary, chips, deeperPath]);
  if (request.url === '/logout')
    response.setHeader(
      'Set-Cookie',
      [ordinary, chips, deeperPath].map((cookie) => cookie + '; Max-Age=0'),
    );
  response.end('fixture');
});
const host = new VaultBackendHost(
  () => new VaultBackendClient({ executable, databasePath, userDataPath: root }),
  () => true,
);
// This fixture replaces all browser views between restore attempts.
app.on('window-all-closed', () => {});

async function run() {
  await app.whenReady();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  const result = await promisify(execFile)(fixture, ['-test.run=^TestVaultWebPlanFixture$'], {
    env: {
      ...process.env,
      WORMHOLE_TEST_WEB_PLAN_DATABASE: databasePath,
      WORMHOLE_TEST_WEB_PLAN_ROUTED: '0',
      WORMHOLE_TEST_WEB_COOKIE_PORT: String(port),
    },
    windowsHide: true,
    timeout: 30000,
  });
  const { workspaceId, nodeId } = JSON.parse(result.stdout.split(/\r?\n/)[0]);
  const description = await host.describe();
  assert.equal(description.vaultId, workspaceId);
  const slot = description.slots.find(({ kind }) => kind === 'recovery');
  async function unlock() {
    await host.unlock({
      vaultId: workspaceId,
      slotId: slot.id,
      kind: 'recovery',
      factor: new Uint8Array(32).fill(0x32),
    });
  }
  async function browse(action) {
    const plan = await host.webPlan({
      workspaceId,
      nodeId,
      sessionId: randomUUID(),
      requestId: randomUUID(),
      epoch: 1,
      credentialOverride: '',
    });
    assert.equal(plan.target.url, `http://127.0.0.1:${port}/login`);
    const window = new BaseWindow({ show: false });
    const view = new WebContentsView({
      webPreferences: {
        partition: 'test-vault-web-' + randomUUID(),
        sandbox: true,
        devTools: false,
        contextIsolation: true,
        nodeIntegration: false,
      },
    });
    window.contentView.addChildView(view);
    const contents = view.webContents;
    let active = true;
    const store = host.webSessionArchive(plan, () => active);
    assert.ok(store);
    const checkpoint = new VaultWebCookieCheckpoint({
      url: plan.target.url,
      store,
      jar: contents.session.cookies,
      views: () => [contents],
      authorized: () => active,
    });
    try {
      await checkpoint.restore(contents);
      await action(new URL(plan.target.url).origin, contents);
      await setImmediate();
      await checkpoint.flush();
    } finally {
      checkpoint.stop();
      active = false;
      await contents.session.clearStorageData();
      contents.close({ waitForBeforeUnload: false });
      window.destroy();
    }
  }
  await unlock();
  await browse(async (origin, contents) => contents.loadURL(origin + '/login'));
  await host.stop();
  const disk = await readFile(databasePath);
  assert.ok(
    !disk.includes('synthetic_ordinary_web_cookie') &&
      !disk.includes('synthetic_partitioned_web_cookie'),
  );
  await unlock();
  await browse(async (origin, contents) => {
    await contents.loadURL(origin + '/app/resume');
    const header = observed.get('/app/resume');
    assert.match(header, /ordinary_fixture=synthetic_ordinary_web_cookie/);
    assert.match(header, /partition_fixture=synthetic_partitioned_web_cookie/);
    assert.match(header, /path_fixture=synthetic_path_web_cookie/);
    await contents.loadURL(origin + '/logout');
  });
  await host.stop();
  await unlock();
  await browse(async (origin, contents) => {
    await contents.loadURL(origin + '/app/signed-out');
    assert.equal(observed.get('/app/signed-out'), '');
  });
}

async function main() {
  try {
    await run();
    await host.stop();
    server.close();
    writeSync(1, 'Web cookies survived reopening and stayed erased after logout.\n');
    app.exit(0);
  } catch (error) {
    await host.stop().catch(() => {});
    server.close();
    writeSync(2, String(error) + '\n');
    app.exit(1);
  }
}

void main();
