const assert = require('node:assert/strict');
const { writeFile } = require('node:fs/promises');
const { join, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');
const { BrowserWindow, ipcMain } = require('electron');

// Exercise the shipped document, sandboxed preload and dialog lifecycle. Only
// the empty workspace catalogue is supplied by the fixture.
module.exports = async function checkTunnelDocument(parent) {
  const root = resolve(__dirname, '../..');
  const compiled = join(root, 'dist-electron');
  const { VaultTunnelDialog } = await import(
    pathToFileURL(join(compiled, 'vault-tunnel-dialog.js'))
  );
  let child;
  let appearance = 'dark';
  const dialog = new VaultTunnelDialog({
    host: {
      unlockedWorkspaceId: '11111111-1111-4111-8111-111111111111',
      workspace: async () => ({ tree: [], tunnels: [], credentialOptions: { ssh: [] } }),
    },
    ipc: ipcMain,
    colorScheme: () => appearance,
    capabilities: async () => ({ openVpn: false }),
    preload: join(compiled, 'vault-tunnel-preload.cjs'),
    url: pathToFileURL(join(root, 'dist/vault-tunnel.html')).href,
    createWindow(options) {
      child = new BrowserWindow({
        ...options,
        webPreferences: { ...options.webPreferences, offscreen: true, backgroundThrottling: false },
      });
      child.show = () => {};
      return child;
    },
  });
  for (const theme of ['dark', 'light']) {
    appearance = theme;
    const outcome = dialog.open(parent, () => true, null);
    try {
      if (theme === 'light') child.setContentSize(430, 580);
      const page = child.webContents;
      const deadline = Date.now() + 8000;
      while (
        !(await page
          .executeJavaScript('!!document.querySelector("fieldset:enabled [name=PeerEndpoint]")')
          .catch(() => false))
      ) {
        assert.ok(Date.now() < deadline, 'Tunnel editor did not become ready');
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      const layout = await page.executeJavaScript(`(async () => {
        const field = (name) => document.querySelector('[name="' + name + '"]');
        field('name').value = 'Operations VPN';
        field('InterfaceAddress').value = '192.0.2.10/32';
        field('PeerEndpoint').value = 'vpn.example.com:51820';
        field('AllowedIps').value = '192.0.2.0/24';
        field('name').blur();
        await document.fonts.ready;
        const save = document.querySelector('[type=submit]');
        const footer = save.getBoundingClientRect();
        const scroller = document.querySelector('.vault-tunnel-scroll');
        scroller.scrollTop = scroller.scrollHeight;
        const fixed = footer.top === save.getBoundingClientRect().top;
        scroller.scrollTop = 0;
        await new Promise(resolve => requestAnimationFrame(()=>requestAnimationFrame(resolve)));
        return {
          dark: document.documentElement.classList.contains('dark'),
          geist: [...document.fonts].some(face => face.family.includes('Geist') && face.status === 'loaded'),
          footer: fixed && footer.bottom <= innerHeight && footer.top > 0 && !save.disabled,
          geometry: [footer.top, footer.bottom, innerHeight, fixed, save.disabled, scroller.clientHeight, scroller.scrollHeight],
          fits: document.documentElement.scrollWidth <= innerWidth && scroller.scrollWidth <= scroller.clientWidth,
        };
      })()`);
      const { geometry, ...appearanceChecks } = layout;
      assert.deepEqual(
        appearanceChecks,
        { dark: theme === 'dark', geist: true, footer: true, fits: true },
        JSON.stringify(geometry),
      );
      const image = await page.capturePage(undefined, { stayHidden: true, stayAwake: true });
      const name = theme === 'dark' ? 'tunnel-screen.png' : 'tunnel-fields.png';
      await writeFile(join(root, 'artifacts/vault', name), image.toPNG());
    } finally {
      await dialog.cancel();
      assert.equal(await outcome, null);
    }
  }
};
