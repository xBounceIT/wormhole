import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createRequire, stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { coverageThreshold } from '../scripts/test-coverage.ts';

const require = createRequire(import.meta.url);
test('vault unlock screen clears inputs and handles password, recovery, retries and disposal', async (context) => {
  const source = stripTypeScriptTypes(
    readFileSync(new URL('../src/vault-unlock-screen.ts', import.meta.url), 'utf8'),
  ).replace(/^export /gm, '');
  const directory = mkdtempSync(join(tmpdir(), 'wormhole-vault-screen-'));
  const css = readFileSync(new URL('../src/startup.css', import.meta.url), 'utf8');
  const renderer = `${source}
    (async () => {
      const check = (value, message) => { if (!value) throw Error(message); };
      const tick = () => new Promise(resolve => setTimeout(resolve, 0));
      const slots = [
        { id: 'recovery1', kind: 'recovery' }, { id: 'password1', kind: 'password', preset: 'kdf-v1' },
        { id: 'password2', kind: 'password', preset: 'kdf-v1' }, { id: 'recovery2', kind: 'recovery' },
      ];
      const ack = { unlocked: true, lockedMemory: true };
      const setup = (unlock, loaded = async () => {}, values = slots, hello, platform = 'win32') => {
        const card = document.createElement('section'); document.body.append(card);
        const formatVersion = values.some(slot => slot.kind === 'touch-id') ? 6 : 5;
        const dispose = mountVaultUnlockScreen(card, { formatVersion, vaultId: 'vault', encrypted: false, slots: values }, { platform, unlockVault: unlock, unlockVaultPresence: hello }, loaded);
        const input = card.querySelector('input'), select = card.querySelector('select'), form = card.querySelector('form'), button = card.querySelector('button'), status = card.querySelector('[role=status]');
        return { card, dispose, input, select, form, button, status, hello: card.querySelector('button[type=button]'),
          fill(value) { input.value = value; input.dispatchEvent(new Event('input')); },
          submit() { form.dispatchEvent(new SubmitEvent('submit', { cancelable: true })); },
          method(id) { select.value = id; select.dispatchEvent(new Event('change')); },
          close() { dispose(); card.remove(); },
        };
      };
      let resolveUnlock, calls = 0, loads = 0, borrowed;
      const f = setup(input => { calls++; borrowed = input.factor; check([...borrowed].join(',') === '112,97,115,115', 'wrong factor'); return new Promise(resolve => { resolveUnlock = resolve; }); }, async () => { loads++; });
      check(f.select.value === 'password1', 'password was not preferred');
      check(f.select.options[2].text === 'Password 2' && f.select.options[3].text === 'Recovery code 2', 'duplicate method labels');
      f.submit(); check(calls === 0 && f.button.disabled, 'empty submit');
      f.fill('pass'); check(!f.button.disabled, 'input did not enable submit');
      f.submit(); check(f.input.value === '' && borrowed.every(byte => byte === 0), 'factor retained');
      check(f.input.disabled && f.select.disabled && f.button.disabled, 'busy controls');
      f.submit(); check(calls === 1, 'double submit');
      resolveUnlock(ack); await tick(); check(loads === 1, 'workspace not loaded'); f.close();

      const pageable = setup(async () => ({ unlocked: true, lockedMemory: false }), async () => { loads++; });
      pageable.fill('pass'); pageable.submit(); await tick();
      check(loads === 2, 'optional memory-lock failure prevented loading the workspace'); pageable.close();

      let retryCalls = 0, retryLoads = 0;
      const retry = setup(async () => { retryCalls++; return ack; }, async () => { if (++retryLoads === 1) throw Error('private load diagnostic'); });
      retry.fill('pass'); retry.submit(); await tick();
      check(retry.status.textContent.includes('vault is unlocked') && !retry.status.textContent.includes('private'), 'wrong load failure');
      check(retry.button.textContent === 'Load workspace' && !retry.button.disabled && retry.input.disabled, 'missing load retry');
      retry.submit(); await tick(); check(retryCalls === 1 && retryLoads === 2, 'load retry repeated authentication'); retry.close();

      for (const mode of ['reject', 'throw', 'bad-result']) {
        const fail = setup(() => { if (mode === 'throw') throw Error('private secret diagnostic'); if (mode === 'reject') return Promise.reject(Error('private secret diagnostic')); return Promise.resolve({ unlocked: false, lockedMemory: false }); });
        fail.fill('pass'); fail.submit(); await tick();
        check(fail.input.value === '' && !fail.input.disabled && fail.button.disabled, 'failed input retained');
        check(fail.status.textContent.includes("couldn't unlock") && !fail.status.textContent.includes('private'), 'diagnostic exposed'); fail.close();
      }

      let recoveryCalls = 0;
      const recovery = setup(async input => { recoveryCalls++; check(input.kind === 'recovery-code' && input.factor.length === 76, 'recovery not passed natively'); return ack; });
      recovery.fill('previous-password'); recovery.method('recovery1');
      check(recovery.input.value === '' && recovery.input.autocomplete === 'off' && recovery.input.type === 'password', 'method switch retained input');
      recovery.fill('A'.repeat(75)); recovery.submit(); await tick(); check(recoveryCalls === 0, 'short recovery forwarded');
      recovery.fill('A'.repeat(76)); recovery.submit(); await tick(); check(recoveryCalls === 1, 'recovery not forwarded'); recovery.close();

      let oversizeCalls = 0;
      const oversize = setup(async () => { oversizeCalls++; return ack; });
      oversize.fill('界'.repeat(400)); oversize.submit(); await tick(); check(oversizeCalls === 0 && oversize.input.value === '', 'UTF8 bound missing');
      oversize.method('missing'); oversize.fill('pass'); oversize.submit(); check(oversizeCalls === 0, 'missing slot accepted'); oversize.close();

      for (const outcome of ['success', 'failure']) {
        let finish, disposedLoads = 0;
        const gone = setup(() => new Promise((resolve, reject) => { finish = outcome === 'success' ? () => resolve(ack) : () => reject(Error('private')); }), async () => { disposedLoads++; });
        gone.fill('pass'); gone.submit(); gone.dispose(); gone.dispose(); finish(); await tick();
        check(disposedLoads === 0 && gone.input.disabled && gone.input.value === '', 'disposed owner completed'); gone.close();
      }
      const hidden = setup(async () => ack); hidden.fill('unfinished'); window.dispatchEvent(new Event('pagehide'));
      check(hidden.input.value === '' && hidden.input.disabled, 'pagehide did not clear input'); hidden.close();
      const empty = setup(async () => ack, async () => {}, []); check(empty.button.disabled, 'empty descriptors enabled unlock'); empty.close();
      const onlyRecovery = setup(async () => ack, async () => {}, [slots[0]]); check(onlyRecovery.select.value === 'recovery1', 'recovery-only descriptor'); onlyRecovery.close();

      const helloSlots = [...slots, { id: 'native-slot', kind: 'hello' }];
      for (const [failure, message] of [['canceled', 'was canceled'], ['remote-desktop', 'Remote Desktop'], ['unavailable', 'unavailable'], ['rejected', "couldn't unlock"]]) {
        let calls = 0, loads = 0, passwordCalls = 0;
        const native = setup(async () => { passwordCalls++; return ack; }, async () => { loads++; }, helloSlots, async (selection) => {
          calls++;
          check(JSON.stringify(selection) === '{"vaultId":"vault","slotId":"native-slot"}', 'non-metadata native request');
          if (failure === 'rejected') throw Error('private native diagnostic');
          return { status: failure };
        });
        check(!native.hello.hidden && native.select.options.length === slots.length, 'Hello masked software methods');
        native.fill('not passed to native'); native.hello.click();
        check(native.hello.disabled && native.input.value === '', 'native request did not clear and disable controls');
        native.hello.dispatchEvent(new Event('click')); native.submit(); await tick();
        check(calls === 1 && loads === 0 && !native.input.disabled && !native.hello.disabled, 'native cancellation blocked fallback');
        check(native.status.textContent.includes(message) && !native.status.textContent.includes('private'), 'invalid native fallback message');
        native.fill('pass'); native.submit(); await tick();
        check(passwordCalls === 1 && loads === 1 && native.hello.hidden, 'software fallback failed'); native.close();
      }
      let nativeLoads = 0;
      const ready = setup(() => { throw Error('unexpected password IPC'); }, async () => { nativeLoads++; }, helloSlots, async () => ack);
      ready.hello.click(); await tick();
      check(nativeLoads === 1 && ready.hello.hidden && ready.input.disabled, 'native acknowledgement did not load the workspace'); ready.close();
      const unsupported = setup(async () => ack, async () => {}, helloSlots, async () => ack, 'linux');
      check(unsupported.hello.hidden && getComputedStyle(unsupported.hello).display === 'none', 'native method shown on another OS'); unsupported.close();
      let v6Calls = 0;
      const restored = setup(async () => { v6Calls++; return ack; }, async () => {}, [...helloSlots, { id: 'touch-slot', kind: 'touch-id' }], undefined, 'darwin');
      check(restored.select.options.length === slots.length && restored.select.value === 'password1', 'v6 platform slots hid software factors');
      restored.fill('pass'); restored.submit(); await tick();
      check(v6Calls === 1, 'v6 descriptor did not allow the software fallback'); restored.close();
      let touchCalls = 0, touchLoads = 0;
      const touch = setup(async () => { throw Error('unexpected password IPC'); }, async () => { touchLoads++; }, [...helloSlots, { id: 'touch-slot', kind: 'touch-id' }], async selection => {
        check(JSON.stringify(selection) === '{"vaultId":"vault","slotId":"touch-slot"}', 'macOS sent a slot for another provider');
        return ++touchCalls === 1 ? { status: 'unavailable' } : ack;
      }, 'darwin');
      check(!touch.hello.hidden && touch.hello.textContent === 'Unlock with Touch ID', 'Touch ID button is unavailable on macOS');
      touch.hello.click(); await tick();
      check(touchLoads === 0 && touch.status.textContent.includes('Touch ID is unavailable') && !touch.input.disabled, 'Touch ID denied access to fallback');
      touch.hello.click(); await tick();
      check(touchLoads === 1 && touch.hello.hidden, 'Touch ID acknowledgement failed to load the workspace'); touch.close();
    })();
    //# sourceURL=wormhole-vault-unlock-screen.js
  `;
  try {
    const harness = join(directory, 'main.cjs');
    writeFileSync(
      harness,
      `
      const { app, BrowserWindow } = require('electron');
      const assert = require('node:assert/strict');
      const { writeFileSync } = require('node:fs');
      app.disableHardwareAcceleration();
      app.setPath('userData', ${JSON.stringify(directory)});
      app.setPath('sessionData', ${JSON.stringify(directory)});
      app.whenReady().then(async () => {
        const window = new BrowserWindow({ show: false, width: 800, height: 650, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, backgroundThrottling: false, offscreen: true } });
        try {
          await window.loadURL('data:text/html,<html><body></body></html>');
          await window.webContents.executeJavaScript('const style = document.createElement("style"); style.textContent = ' + ${JSON.stringify(JSON.stringify(css))} + '; document.head.append(style)');
          const debug = window.webContents.debugger; debug.attach('1.3');
          await debug.sendCommand('Profiler.enable');
          await debug.sendCommand('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
          await window.webContents.executeJavaScript(${JSON.stringify(renderer)});
          const report = await debug.sendCommand('Profiler.takePreciseCoverage');
          const script = report.result.find(script => script.url === 'wormhole-vault-unlock-screen.js'); assert.ok(script);
          const fn = script.functions.find(fn => fn.functionName === 'mountVaultUnlockScreen'); assert.ok(fn);
          const extent = fn.ranges[0];
          const ranges = script.functions.filter(fn => fn.ranges[0].startOffset >= extent.startOffset && fn.ranges[0].endOffset <= extent.endOffset).flatMap(fn => fn.ranges);
          const coverage = 100 * ranges.filter(range => range.count > 0).length / ranges.length;
          console.log('Vault unlock screen: V8 block coverage ' + coverage.toFixed(2) + '%');
          assert.ok(coverage >= ${coverageThreshold});
          if (process.env.WORMHOLE_VAULT_SCREENSHOT) {
            await window.webContents.executeJavaScript('document.documentElement.classList.add("dark"); const previewShell = document.createElement("main"); previewShell.className = "startup-shell"; const previewCard = document.createElement("section"); previewCard.className = "startup-card"; previewShell.append(previewCard); document.body.replaceChildren(previewShell); mountVaultUnlockScreen(previewCard, { vaultId: "11111111-1111-4111-8111-111111111111", slots: [{id:"password",kind:"password",preset:"kdf-v1"},{id:"recovery",kind:"recovery"}] }, { unlockVault: async () => ({unlocked:true,lockedMemory:true}) }, async () => {}); undefined');
            await new Promise(resolve => setTimeout(resolve, 80));
            writeFileSync(process.env.WORMHOLE_VAULT_SCREENSHOT, (await window.webContents.capturePage()).toPNG());
          }
        } finally { window.destroy(); }
        app.quit();
      }).catch(error => { console.error(error); app.exit(1); });
    `,
    );
    const { ELECTRON_RUN_AS_NODE: _runAsNode, ...env } = process.env;
    const electron = require('electron') as string;
    const headless = process.platform === 'linux' && !env.DISPLAY;
    const { stdout, stderr } = await promisify(execFile)(
      headless ? 'xvfb-run' : electron,
      headless ? ['--auto-servernum', electron, '--no-sandbox', harness] : [harness],
      { env: { ...env, NODE_ENV: 'test' }, timeout: 30_000, windowsHide: true },
    );
    if (stdout.trim()) context.diagnostic(stdout.trim());
    if (stderr.trim()) context.diagnostic(stderr.trim());
  } finally {
    assert.equal(resolve(directory, '..'), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
