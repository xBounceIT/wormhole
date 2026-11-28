import { app, BrowserWindow, session } from 'electron';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { VaultVPNBrowserSession } from '../../electron/vault-vpn-browser-session.ts';
import { VaultVPNBrowserRecipient } from '../../electron/vault-vpn-browser.ts';
import { VaultVPNStorageDriver } from '../../electron/vault-vpn-storage-driver.ts';
import { VaultBackendClient } from '../../electron/vault-client.ts';
import { beginNativeVPNSSO } from '../../electron/vault-vpn-sso.ts';

app.disableHardwareAcceleration();
app.on('window-all-closed', () => {});
app.setPath('userData', process.env.WORMHOLE_STORAGE_DIRECTORY!);
app.setPath('sessionData', process.env.WORMHOLE_STORAGE_DIRECTORY!);
let phase = 'startup';
setTimeout(() => {
  console.error('Native session deadline:', phase);
  app.exit(1);
}, 60000).unref();
const executable = process.env.WORMHOLE_STORAGE_BACKEND!;
function launch(mode: string) {
  return spawn(executable, ['-test.run=^TestVPNBrowserInteropProcess$', '-test.timeout=90s'], {
    windowsHide: true,
    stdio: 'pipe',
    env: {
      ...process.env,
      TEMP: process.env.WORMHOLE_STORAGE_DIRECTORY,
      TMP: process.env.WORMHOLE_STORAGE_DIRECTORY,
      TMPDIR: process.env.WORMHOLE_STORAGE_DIRECTORY,
      WORMHOLE_TEST_VPN_BROWSER: mode,
    },
  });
}
app
  .whenReady()
  .then(async () => {
    const ipsec = process.env.WORMHOLE_STORAGE_KIND?.endsWith('ipsec'),
      shared = process.env.WORMHOLE_STORAGE_KIND?.startsWith('shared-'),
      fallback = process.env.WORMHOLE_STORAGE_KIND?.endsWith('fallback');
    const root = launch(
      fallback
        ? shared
          ? 'vault-shared-fallback'
          : 'vault-fallback'
        : shared
          ? ipsec
            ? 'vault-shared-ipsec'
            : 'vault-shared'
          : ipsec
            ? 'vault-ipsec'
            : 'vault',
    );
    root.stderr.resume();
    const lines = createInterface({ input: root.stdout });
    const info = await new Promise<any>((resolve, reject) => {
      lines.once('line', (line) => {
        try {
          resolve(JSON.parse(line));
        } catch (error) {
          reject(error);
        }
      });
      root.once('error', reject);
    });
    lines.close();
    const client = new VaultBackendClient(
      { executable, databasePath: 'native-fixture', heartbeatMs: 10000 },
      () => {
        queueMicrotask(() => {
          root.emit('spawn');
          root.stdout.resume();
        });
        return root;
      },
    );
    const helpers: ReturnType<typeof launch>[] = [];
    const attempts: {
      window: BrowserWindow;
      session: VaultVPNBrowserSession;
      abort: AbortController;
      ses: Electron.Session;
    }[] = [];
    const request = {
      ...info.request,
      workspaceId: info.binding.workspaceId,
      epoch: Number(info.request.epoch),
    };
    const open = async () => {
      const attemptIndex = attempts.length;
      const attemptRequest = {
        ...request,
        sessionId: randomUUID(),
        requestId: randomUUID(),
        epoch: request.epoch + attemptIndex,
      };
      const primary = await client.tunnelPlan(attemptRequest);
      const pair = fallback
        ? await client.tunnelFallbackPlan({
            ...attemptRequest,
            primary,
            fallbackRequestId: randomUUID(),
          })
        : undefined;
      const binding = pair?.fallback ?? primary;
      const ses = session.fromPartition('native-full-sso-' + randomUUID());
      const window = new BrowserWindow({
        show: false,
        webPreferences: {
          session: ses,
          sandbox: true,
          contextIsolation: true,
          nodeIntegration: false,
          offscreen: true,
          backgroundThrottling: false,
        },
      });
      const abort = new AbortController();
      const custody = new VaultVPNBrowserSession(
        {
          window,
          signal: abort.signal,
          current: () => !window.isDestroyed(),
          executable,
          request: attemptRequest,
          ...(pair ? { fallback: pair } : {}),
          context: {
            binding,
            challengeId: randomUUID(),
            publicKey: Buffer.alloc(32, 7).toString('base64'),
            startURL: fallback
              ? info.startURL
              : ipsec
                ? 'https://vpn.test:1001/saml?request=fixture-' + attemptIndex
                : 'https://vpn.test:443/remote/saml/start?realm=staff',
            ignoreCertificateErrors: false,
            ...(ipsec
              ? { callbackURL: 'http://127.0.0.1:' + (12345 + attemptIndex) + '/' }
              : { cookieName: 'SVPNCOOKIE' as const }),
          },
          authority: {
            security: () => client.security(),
            begin: async (q, reserved) => {
              const capability = await beginNativeVPNSSO(
                client,
                shared ? { ...q, custody: info.custody } : q,
                () => !window.isDestroyed(),
                reserved,
                () => client.lock(),
              );
              assert.equal(capability.offer.context.sourceRevision, String(attemptIndex));
              return capability;
            },
          },
        },
        {
          storage: (q, reserved) => VaultVPNStorageDriver.open(q, reserved),
          recipient: (q, reserved) =>
            VaultVPNBrowserRecipient.open(
              q,
              () => {
                const child = launch('recipient');
                helpers.push(child);
                return child;
              },
              reserved,
            ),
        },
      );
      attempts.push({ window, session: custody, abort, ses });
      ses.webRequest.onBeforeRequest((details, callback) =>
        callback({
          cancel: !custody.permitsRequest(
            details.url,
            details.webContentsId ?? -1,
            details.resourceType,
          ),
        }),
      );
      await custody.restore();
      assert.equal(custody.isOffline, false);
      ses.protocol.handle(
        'https',
        () =>
          new Response('<!doctype html><title>Native IdP fixture</title>', {
            headers: { 'Content-Type': 'text/html' },
          }),
      );
      await window.loadURL('https://idp.test/');
      return attempts.at(-1)!;
    };
    try {
      phase = 'first native attempt';
      const first = await open();
      await first.window.webContents.executeJavaScript(`(async()=>{
      localStorage.setItem('identity','vault-protected-native');sessionStorage.setItem('session','same-namespace');
      const q=indexedDB.open('native-identity',4);q.onupgradeneeded=()=>q.result.createObjectStore('accounts');
      const db=await new Promise((r,j)=>{q.onsuccess=()=>r(q.result);q.onerror=j;});const tx=db.transaction('accounts','readwrite');
      tx.objectStore('accounts').put({id:'native-account',token:'fixture-token'},1);await new Promise((r,j)=>{tx.oncomplete=r;tx.onerror=j;});db.close();return true;
    })()`);
      await first.ses.cookies.set({
        url: 'https://idp.test/',
        name: 'identity-cookie',
        value: 'private-native-fixture',
        secure: true,
        httpOnly: true,
      });
      await first.ses.cookies.set({
        url: 'https://vpn.test/',
        name: 'SVPNCOOKIE',
        value: 'fresh-only',
        secure: true,
        httpOnly: true,
      });
      first.ses.protocol.unhandle('https');
      await first.session.capture();
      first.window.destroy();
      first.abort.abort();
      await first.session.close();
      await first.ses.clearStorageData();
      phase = 'second native attempt';
      const second = await open();
      assert.equal(
        await second.window.webContents.executeJavaScript("localStorage.getItem('identity')"),
        'vault-protected-native',
      );
      assert.equal(
        await second.window.webContents.executeJavaScript("sessionStorage.getItem('session')"),
        'same-namespace',
      );
      assert.deepEqual(
        await second.window.webContents.executeJavaScript(`(async()=>{
      const q=indexedDB.open('native-identity');const db=await new Promise((r,j)=>{q.onsuccess=()=>r(q.result);q.onerror=j;});
      const tx=db.transaction('accounts');const qv=tx.objectStore('accounts').get(1);const value=await new Promise((r,j)=>{qv.onsuccess=()=>r(qv.result);qv.onerror=j;});
      db.close();return value;
    })()`),
        { id: 'native-account', token: 'fixture-token' },
      );
      const cookies = await second.ses.cookies.get({});
      assert.ok(cookies.some((c) => c.name === 'identity-cookie' && c.httpOnly));
      assert.equal(
        cookies.some((c) => c.name === 'SVPNCOOKIE'),
        false,
      );
      second.ses.protocol.unhandle('https');
      await second.session.capture();
      phase = 'original vault exit during login';
      const interrupted = await open();
      await client.lock();
      interrupted.window.destroy();
      interrupted.abort.abort();
      await interrupted.session.close();
    } finally {
      phase = 'joined native cleanup';
      for (const attempt of attempts) {
        if (!attempt.window.isDestroyed()) attempt.window.destroy();
        attempt.abort.abort();
        await attempt.session.close();
        await attempt.ses.clearStorageData();
      }
      await client.lock();
      for (const helper of helpers)
        assert.ok(helper.exitCode !== null || helper.signalCode !== null);
      assert.ok(root.exitCode !== null || root.signalCode !== null);
    }
    console.log(JSON.stringify({ ok: true }));
    app.quit();
  })
  .catch((error) => {
    console.error(phase, error?.name, error?.message);
    app.exit(1);
  });
