const assert = require('node:assert/strict');
const { readFileSync, existsSync } = require('node:fs');
const { writeFile } = require('node:fs/promises');
const { join, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');
const { app, BrowserWindow, ipcMain } = require('electron');

const root = resolve(__dirname, '../..');
const artifact = (dir, name) => join(root, dir, name);
const compiled = (name) => pathToFileURL(artifact('dist-electron', name + '.js')).href;
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function run() {
  const directory = process.env.WORMHOLE_TEST_RESET_ELECTRON_DATA;
  assert.ok(directory && resolve(directory) === directory);
  app.setPath('userData', directory);
  app.on('window-all-closed', () => {});
  const frame = readFileSync(0);
  const input = JSON.parse(frame.toString());
  frame.fill(0);
  const ask = Buffer.from(input.ask, 'base64');
  const code = Buffer.from(input.code, 'base64');
  const password = 'Synthetic protected custodian password';
  const destination = join(directory, 'replacement.whreset');
  let parent, child, host, wizard, handover;
  try {
    await app.whenReady();
    const { VaultBackendClient } = await import(compiled('vault-client'));
    const { VaultBackendHost } = await import(compiled('vault-host'));
    const { VaultSharedSetupDialog } = await import(compiled('vault-shared-setup-dialog'));
    const { registerSharedAdministrationIpc } = await import(compiled('vault-shared-ipc'));
    host = new VaultBackendHost(
      () =>
        new VaultBackendClient({
          executable: process.env.WORMHOLE_TEST_RESET_ELECTRON_NATIVE,
          databasePath: join(directory, 'workspace.db'),
          userDataPath: directory,
        }),
      () => true,
    );
    const admitted = await host.sharedJoinInitial(
      {
        invitation: input.invitation,
        code: Uint8Array.from(code),
        ask: Uint8Array.from(ask),
        password: new TextEncoder().encode(password),
        deviceName: 'Application issuer fixture',
        acknowledgeTLSOff: false,
      },
      '2.4.3',
      () => true,
    );
    assert.ok(admitted.administrator && admitted.recoveryBackup);
    const parentPath = join(directory, 'parent.html');
    await writeFile(parentPath, '<!doctype html><title>Custodian fixture</title>');
    parent = new BrowserWindow({
      show: false,
      webPreferences: { sandbox: true, preload: artifact('dist-electron', 'preload.cjs') },
    });
    wizard = new VaultSharedSetupDialog({
      host,
      ipc: ipcMain,
      pickExport: async () => null,
      pickAccountReset: async () => destination,
      url: pathToFileURL(artifact('dist', 'vault-shared-setup.html')).href,
      preload: artifact('dist-electron', 'vault-shared-setup-preload.cjs'),
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
    });
    registerSharedAdministrationIpc({
      host,
      dialog: wizard,
      ipc: ipcMain,
      trusted: (event) =>
        event.sender === parent.webContents && event.senderFrame === parent.webContents.mainFrame,
      parent: () => parent,
    });
    await parent.loadFile(parentPath);
    const opened = parent.webContents.executeJavaScript(
      'window.wormhole.openSharedAdministration()',
    );
    void opened.catch(() => {});
    const wait = async (expression, label) => {
      for (let i = 0; i < 350; i++) {
        if (
          child &&
          !child.isDestroyed() &&
          (await child.webContents.executeJavaScript(expression).catch(() => false))
        )
          return;
        await pause(20);
      }
      throw Error('Protected issuer window did not reach ' + label + '.');
    };
    const selector = (label, login) => `[...document.querySelectorAll('button')].find(b =>
      b.textContent === ${JSON.stringify(label)} && !b.closest('[hidden]') && !b.disabled
      ${login ? '&& b.closest("li")?.textContent.includes(' + JSON.stringify(login) + ')' : ''})`;
    const click = async (label, login) => {
      const button = selector(label, login);
      await wait('!!(' + button + ')', label);
      await child.webContents.executeJavaScript(button + '.click()');
    };
    const submit = (factor) =>
      child.webContents.executeJavaScript(`(() => {
      document.querySelector('[name=password]').value = ${JSON.stringify(factor)};
      document.querySelector('[name=ask]').value = ${JSON.stringify(ask.toString('hex'))};
      document.querySelector('form').requestSubmit();
    })()`);
    await click('Review access at suspension', input.login);
    await click('Restore personal keys…');
    await click('Issue re-enrollment offer…');
    await wait(
      'document.querySelector("[name=target-login]")?.readOnly === true',
      'the bound recipient',
    );
    assert.equal(
      await child.webContents.executeJavaScript(
        'document.querySelector("[name=target-login]").value',
      ),
      input.login,
    );
    await submit('Wrong synthetic password');
    await wait(
      'document.querySelector(".startup-status")?.textContent.includes("Check your password")',
      'fresh authentication rejection',
    );
    assert.equal(existsSync(destination), false);
    await submit(password);
    await wait(
      'document.querySelector(".startup-status")?.textContent.includes("Offer issued.")',
      'the confirmed offer',
    );
    assert.ok(existsSync(destination));
    assert.equal(
      await child.webContents.executeJavaScript(
        '[...document.querySelectorAll("form input[type=password]")].every(i => !i.value)',
      ),
      true,
    );
    const fields = await child.webContents.executeJavaScript(
      '[...document.querySelectorAll("code")].map(c => c.textContent)',
    );
    assert.ok(
      fields.length === 2 && /^[0-9a-f]{32}$/.test(fields[0]) && /^[0-9a-f]{64}$/.test(fields[1]),
    );
    handover = Buffer.from(fields.join(''), 'hex');
    fields.fill('');
    await click('Back to suspension');
    assert.equal(
      await child.webContents.executeJavaScript('document.querySelectorAll("code").length'),
      0,
    );
    await wait('!!(' + selector('Refresh inventory') + ')', 'the suspension inventory');
    await wizard.cancel();
    await opened;
    await new Promise((resolve) => {
      process.stdout.write('WHRESET-FIXTURE-1:');
      process.stdout.write(handover, resolve);
    });
  } finally {
    ask.fill(0);
    code.fill(0);
    handover?.fill(0);
    await wizard?.cancel();
    await host?.stop();
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
