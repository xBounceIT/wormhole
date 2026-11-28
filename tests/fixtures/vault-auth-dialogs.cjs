const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { mkdir, writeFile } = require('node:fs/promises');
const { join, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');
const { BrowserWindow, ipcMain, nativeTheme } = require('electron');

// This marker is never issued to a vault. Only its sealed display travels
// through the real enrollment preload during the layout check.
const demoRecovery = 'WHREC1-' + Array(11).fill('DEMOA').join('-') + '-ABC';
async function demoEnrollment(_event, input) {
  const { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } = await import('@hpke/core');
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  input.password.fill(0);
  const vaultId = randomUUID(),
    enrollmentId = randomUUID();
  const info = [Buffer.from('wormhole/v1/recovery-display')];
  for (const id of [vaultId, enrollmentId]) {
    const field = Buffer.alloc(40);
    field.writeUInt32BE(36);
    field.write(id, 4);
    info.push(field);
  }
  const publicKey = await crypto.subtle.importKey('raw', input.publicKey, 'X25519', true, []);
  const sender = await suite.createSenderContext({
    recipientPublicKey: publicKey,
    info: Buffer.concat(info),
  });
  return {
    vaultId,
    enrollmentId,
    groups: [1, 2],
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: Buffer.from(sender.enc).toString('base64'),
      ciphertext: Buffer.from(await sender.seal(Buffer.from(demoRecovery))).toString('base64'),
    },
  };
}

module.exports = async function checkVaultAuthDialogs(parent) {
  const root = resolve(__dirname, '../..');
  const output = join(root, 'artifacts/vault');
  await mkdir(output, { recursive: true });
  const compiled = join(root, 'dist-electron');
  const { createVaultDialogWindow } = await import(
    pathToFileURL(join(compiled, 'vault-dialog-appearance.js'))
  );
  const id = '11111111-1111-4111-8111-111111111111';
  ipcMain.handle('vault-reauth:context', () => ({
    operation: 'folder-save',
    slots: {
      formatVersion: 1,
      vaultId: id,
      encrypted: true,
      slots: [{ id: randomUUID(), kind: 'password', preset: 'kdf-v1' }],
    },
  }));
  ipcMain.handle('vault-vnc-password:context', () => ({
    binding: {
      workspaceId: id,
      nodeId: id,
      sessionId: id,
      requestId: id,
      host: 'desktop.example',
      port: 5900,
      protocol: 'vnc',
      epoch: 1,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    publicKey: Buffer.alloc(32, 7).toString('base64'),
  }));
  const previous = nativeTheme.themeSource;
  ipcMain.handle('vault-enrollment:begin', demoEnrollment);
  nativeTheme.themeSource = 'dark';
  try {
    for (const [documentName, theme, screenshot] of [
      ['vault-reauth', 'oled', 'reauth-dialog.png'],
      ['vault-vnc-password', 'light', 'vnc-password-ui.png'],
      ['vault-create', 'system', 'create-setup.png'],
    ]) {
      const window = createVaultDialogWindow(
        {
          width: 510,
          height: 410,
          parent,
          show: false,
          autoHideMenuBar: true,
          webPreferences: {
            sandbox: true,
            contextIsolation: true,
            nodeIntegration: false,
            preload: join(compiled, documentName + '-preload.cjs'),
            partition: randomUUID(),
            offscreen: true,
            backgroundThrottling: false,
          },
        },
        theme,
        join(compiled, 'vault-dialog-appearance-preload.cjs'),
        (options) => new BrowserWindow(options),
      );
      try {
        const page = window.webContents;
        await window.loadFile(join(root, 'dist', documentName + '.html'));
        const view = await page.executeJavaScript(`(async () => {
          await document.fonts.ready;
          const input = document.querySelector('input[type=password]');
          const deadline = performance.now() + 5000;
          while (input?.disabled && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
          const actions = [...document.querySelectorAll('button')].filter(button => button.checkVisibility());
          await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
          return {
            dark: document.documentElement.classList.contains('dark'),
            oled: document.documentElement.classList.contains('oled'),
            geist: [...document.fonts].some(f => f.family.includes('Geist') && f.status === 'loaded'),
            visible: actions.length === 2 && actions.every(button => button.getBoundingClientRect().bottom <= innerHeight),
            empty: !!input && !input.disabled && !input.value,
            isolated: window.wormhole === undefined,
          };
        })()`);
        assert.deepEqual(
          view,
          {
            dark: theme !== 'light',
            oled: theme === 'oled',
            geist: true,
            visible: true,
            empty: true,
            isolated: true,
          },
          documentName,
        );
        await writeFile(
          join(output, screenshot),
          (await page.capturePage(undefined, { stayHidden: true, stayAwake: true })).toPNG(),
        );
        if (documentName === 'vault-create') {
          const recovery = await page.executeJavaScript(`(async () => {
            for (const field of document.querySelectorAll('input[autocomplete=new-password]')) {
              field.value = 'Demo workspace'; field.dispatchEvent(new Event('input'));
            }
            document.querySelector('form').requestSubmit();
            const code = document.querySelector('pre'), deadline = performance.now() + 5000;
            while (code.hidden && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve,20));
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
            return code.textContent;
          })()`);
          assert.equal(recovery, demoRecovery);
          await writeFile(
            join(output, 'create-recovery.png'),
            (await page.capturePage(undefined, { stayHidden: true, stayAwake: true })).toPNG(),
          );
          assert.equal(
            await page.executeJavaScript(`(() => {
            document.querySelector('.vault-dialog-actions button:not([hidden])').click();
            return document.querySelector('pre').textContent === '' &&
              document.querySelector('[type=submit]').form === document.querySelector('form') &&
              document.querySelector('[type=submit]').checkVisibility();
          })()`),
            true,
          );
        }
      } finally {
        window.destroy();
      }
    }
  } finally {
    nativeTheme.themeSource = previous;
    ipcMain.removeHandler('vault-reauth:context');
    ipcMain.removeHandler('vault-vnc-password:context');
    ipcMain.removeHandler('vault-enrollment:begin');
  }
};
