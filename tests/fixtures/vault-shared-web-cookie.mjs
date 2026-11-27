import assert from 'node:assert/strict';
import { BaseWindow, WebContentsView } from 'electron';
import { randomUUID } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { VaultWebConnections } from '../../electron/vault-web-connections.ts';
import { VaultWebCookieCheckpoint } from '../../electron/vault-web-cookies.ts';

export async function exerciseSharedWebCookies(host, admit, port) {
  const catalog = await host.sharedCatalog(
    { after: '', epoch: '0', changeSeq: '0', limit: 32 },
    () => true,
  );
  const node = catalog.nodes.find(({ name }) => name === 'Shared web fixture');
  assert.ok(node?.canUse);
  const connection = new VaultWebConnections({
    workspaceId: () => host.unlockedWorkspaceId,
    authorized: () => Boolean(host.unlockedWorkspaceId),
    plan: (q) => host.webPlan(q),
    archive: (plan, current) => host.webSessionArchive(plan, current),
    checkViews: (workspace, views) => host.checkWebSessionViews(workspace, views),
    routes: {
      acquire: async () => {
        throw Error('The web fixture must use its direct connection.');
      },
      close: async () => {},
      closeAll: async () => {},
    },
  });
  async function browse(path) {
    const sessionId = randomUUID();
    const prepared = await connection.open(
      { nodeId: node.id, sessionId },
      1,
      () => true,
      () => {
        assert.fail('The fixture lost its View generation');
      },
    );
    assert.equal(prepared.target.url, `http://127.0.0.1:${port}/login`);
    assert.ok(prepared.archive, 'The shared Go plan must issue archive custody.');
    await connection.verifyViews();
    assert.equal(prepared.active(), true);
    const window = new BaseWindow({ show: false });
    const view = new WebContentsView({
      webPreferences: {
        partition: 'fixture-shared-web-' + randomUUID(),
        sandbox: true,
        devTools: false,
        nodeIntegration: false,
        contextIsolation: true,
      },
    });
    window.contentView.addChildView(view);
    const contents = view.webContents;
    const checkpoint = new VaultWebCookieCheckpoint({
      url: prepared.target.url,
      store: prepared.archive,
      jar: contents.session.cookies,
      views: () => [contents],
      authorized: prepared.active,
    });
    try {
      await checkpoint.restore(contents);
      await contents.loadURL(new URL(path, prepared.target.url).href);
      await setImmediate();
      await checkpoint.flush();
    } finally {
      checkpoint.stop();
      await contents.session.clearStorageData();
      contents.close({ waitForBeforeUnload: false });
      window.destroy();
      await connection.close(sessionId);
    }
  }
  try {
    await browse('/login');
    await host.stop();
    assert.ok((await admit()).admitted);
    await browse('/shared-resume');
  } finally {
    await connection.closeAll();
  }
}
