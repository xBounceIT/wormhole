const assert = require('node:assert/strict');
const { readSync } = require('node:fs');
const { writeFile } = require('node:fs/promises');
const { join, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');
const { app, BrowserWindow, ipcMain } = require('electron');

const root = resolve(__dirname, '../..');
const asset = (directory, name) => pathToFileURL(join(root, directory, name)).href;
const compiled = (name) => asset('dist-electron', name + '.js');
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function readFixture() {
  const data = Buffer.alloc(2 * 1024 * 1024 + 8192 + 49);
  let size = 0;
  try {
    while (size < data.length) {
      const count = readSync(0, data, size, data.length - size, null);
      if (!count) break;
      size += count;
    }
    if (size <= 48 || size >= data.length) throw Error('Invalid reset fixture length.');
    return {
      code: data.subarray(0, 16),
      ask: data.subarray(16, 48),
      offer: data.subarray(48, size),
    };
  } catch (error) {
    data.fill(0);
    throw error;
  }
}

async function run() {
  const directory = process.env.WORMHOLE_TEST_RESET_ELECTRON_DATA;
  assert.ok(directory && resolve(directory) === directory);
  app.setPath('userData', directory);
  const { ask, code, offer } = readFixture();
  const password = 'Synthetic protected-window reset password';
  const stage = process.env.WORMHOLE_TEST_RESET_ELECTRON_STAGE;
  const registering = stage === 'register';
  const activating = stage === 'activate';
  let host, dialog, parent, child;
  try {
    const offerPath = join(directory, 'account.whreset');
    const parentPath = join(directory, 'parent.html');
    if (!activating) await writeFile(offerPath, offer, { mode: 0o600 });
    await writeFile(parentPath, '<!doctype html><title>Shared account test</title>');
    await app.whenReady();
    const { VaultBackendClient } = await import(compiled('vault-client'));
    const { VaultBackendHost } = await import(compiled('vault-host'));
    const { VaultSharedAuthenticationDialog } = await import(compiled('vault-shared-dialog'));
    const { registerSharedAuthenticationIpc } = await import(compiled('vault-shared-ipc'));
    let activated = 0;
    host = new VaultBackendHost(
      () =>
        new VaultBackendClient({
          executable: process.env.WORMHOLE_TEST_RESET_ELECTRON_NATIVE,
          databasePath: join(directory, 'workspace.db'),
          userDataPath: directory,
        }),
      () => true,
    );
    parent = new BrowserWindow({
      show: false,
      webPreferences: {
        preload: join(root, 'dist-electron', 'preload.cjs'),
        sandbox: true,
        contextIsolation: true,
        offscreen: true,
      },
    });
    dialog = new VaultSharedAuthenticationDialog({
      host,
      ipc: ipcMain,
      createWindow: (options) => {
        child = new BrowserWindow({
          ...options,
          webPreferences: {
            ...options.webPreferences,
            offscreen: true,
            backgroundThrottling: false,
          },
        });
        child.show = () => {};
        return child;
      },
      pickResetOffer: async () => offerPath,
      url: asset('dist', 'vault-shared.html'),
      preload: join(root, 'dist-electron', 'vault-shared-preload.cjs'),
      appVersion: '2.4.3',
    });
    registerSharedAuthenticationIpc({
      host,
      dialog,
      ipc: ipcMain,
      trusted: (event) =>
        event.sender === parent.webContents &&
        event.senderFrame === parent.webContents.mainFrame &&
        event.senderFrame.url === pathToFileURL(parentPath).href,
      parent: () => parent,
      activate: () => {
        activated++;
      },
    });
    const wait = async (expression, view = () => child) => {
      for (let i = 0; i < 200; i++) {
        const window = view();
        if (window?.isDestroyed()) return false;
        if (window && (await window.webContents.executeJavaScript(expression).catch(() => false)))
          return;
        await delay(25);
      }
      throw Error('Protected reset input did not become ready.');
    };
    await parent.loadFile(parentPath);
    const initialStartup = await host.startup();
    assert.equal(initialStartup.newWorkspace, !activating);
    if (activating) assert.equal(initialStartup.sharedJoin?.accountReset, true);
    const modes = activating
      ? ['recover-enrollment', 'admit']
      : ['join-initial', registering ? 'recover-enrollment' : 'admit'];
    for (const mode of modes) {
      child = undefined;
      const initial = mode === 'join-initial';
      const admission = parent.webContents.executeJavaScript(
        `window.wormhole.authenticateSharedVault(${JSON.stringify(mode)})`,
      );
      void admission.catch(() => {});
      if (initial) {
        await wait('!!document.querySelector("textarea")');
        await child.webContents.executeJavaScript(`
          [...document.querySelectorAll('button')].find(b => b.textContent === 'Use an account reset file').click();
          [...document.querySelectorAll('button')].find(b => b.textContent === 'Open reset file…').click();
        `);
      }
      await wait('document.querySelector("[type=submit]")?.disabled === false');
      const apply = initial
        ? `for (const [name, value] of Object.entries(${JSON.stringify({
            code: code.toString('hex'),
            ask: ask.toString('hex'),
            password,
            'password-confirm': password,
            'device-name': 'Electron reset fixture',
          })})) document.querySelector('[name="' + name + '"]').value = value;`
        : `const fields = document.querySelectorAll('input[type=password]');
           fields[0].value = ${JSON.stringify(password)};
           fields[1].value = ${JSON.stringify(ask.toString('hex'))};`;
      await child.webContents.executeJavaScript(`(() => {${apply}
        document.querySelector('form').dispatchEvent(new Event('submit', { cancelable: true }));
      })()`);
      if (registering) {
        await wait(
          'document.querySelector(".startup-status")?.textContent?.startsWith("This device is registered.")',
        );
        assert.equal(host.unlockedWorkspaceId, undefined);
        const staged = await host.startup();
        assert.equal(staged.sharedJoin?.accountReset, true);
        assert.equal(staged.shared, undefined);
        if (initial)
          assert.equal(
            await child.webContents.executeJavaScript(
              'document.querySelector("[type=submit]").disabled',
            ),
            true,
          );
        await child.webContents.executeJavaScript(
          `[...document.querySelectorAll('button')].find(b => b.textContent === '${initial ? 'Close' : 'Cancel'}').click()`,
        );
        assert.equal(await admission, null);
        await host.stop();
        continue;
      }
      const submittedWindow = child;
      const rejected = wait(
        '/^Could not reset the account|^Could not sign in/.test(document.querySelector(".startup-status")?.textContent || "")',
        () => submittedWindow,
      ).then(
        (closed) => {
          if (closed === false) return admission;
          throw Error('Protected reset input was rejected.');
        },
        () => admission,
      );
      const result = await Promise.race([admission, rejected]);
      assert.equal(result?.admitted, true);
      assert.equal(result?.tls, 'verified');
      assert.equal(host.isSharedWorkspace, true);
      const startup = await host.startup();
      assert.ok(startup.shared && !startup.sharedJoin);
      await host.stop();
    }
    assert.equal(activated, registering ? 0 : 2);
  } finally {
    code.fill(0);
    ask.fill(0);
    offer.fill(0);
    await dialog?.cancel();
    await host?.stop();
    if (child && !child.isDestroyed()) child.destroy();
    if (parent && !parent.isDestroyed()) parent.destroy();
  }
}

run().then(
  () => app.exit(0),
  (error) => {
    console.error(error);
    app.exit(1);
  },
);
