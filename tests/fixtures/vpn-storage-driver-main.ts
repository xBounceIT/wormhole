import { app, BrowserWindow, session } from 'electron';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Session } from 'node:inspector';
import { readFileSync } from 'node:fs';
import { VaultVPNStorageDriver } from '../../electron/vault-vpn-storage-driver.ts';

app.disableHardwareAcceleration();
app.on('window-all-closed', () => {});
app.setPath('userData', process.env.WORMHOLE_STORAGE_DIRECTORY!);
app.setPath('sessionData', process.env.WORMHOLE_STORAGE_DIRECTORY!);
const owned: {
  window: BrowserWindow;
  driver?: VaultVPNStorageDriver;
  session: Electron.Session;
}[] = [];
let phase = 'startup';
const watchdog = setInterval(() => console.error('Native fixture phase:', phase), 10000);
watchdog.unref();
setTimeout(() => {
  console.error('Native fixture deadline:', phase);
  app.exit(1);
}, 45000).unref();
async function nativeWindow(current = () => true, invalidated?: () => void) {
  const ses = session.fromPartition('vpn-storage-driver-' + randomUUID());
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
  const holder = { window, session: ses, driver: undefined as VaultVPNStorageDriver | undefined };
  owned.push(holder);
  ses.webRequest.onBeforeRequest((details, callback) =>
    callback({
      cancel: !holder.driver?.permitsRequest(
        details.url,
        details.webContentsId,
        details.resourceType,
      ),
    }),
  );
  holder.driver = await VaultVPNStorageDriver.open({
    window,
    current,
    attemptCookie: 'SVPNCOOKIE',
    invalidated,
  });
  return { window, ses, driver: holder.driver };
}
function fixtureNetwork(ses: Electron.Session) {
  ses.protocol.handle(
    'https',
    () =>
      new Response('<!doctype html><meta charset="utf-8"><title>Test identity provider</title>', {
        headers: { 'Content-Type': 'text/html' },
      }),
  );
}
async function liveFrame(window: BrowserWindow, top: string, child?: string) {
  await window.loadURL(top + '/sign-in');
  if (!child) return window.webContents.mainFrame;
  await window.webContents.executeJavaScript(
    `new Promise((resolve,reject)=>{const f=document.createElement('iframe');f.onload=()=>resolve(true);f.onerror=reject;f.src=${JSON.stringify(child + '/sign-in')};document.body.append(f);})`,
  );
  const frame = window.webContents.mainFrame.frames.find((f) => f.url === child + '/sign-in');
  assert.ok(frame);
  return frame;
}
async function seedFrame(frame: Electron.WebFrameMain, label: string) {
  assert.equal(
    await frame.executeJavaScript(`(async()=>{
    localStorage.setItem('identity',${JSON.stringify(label)});
    sessionStorage.setItem('session','session-value');
    const q=indexedDB.open('identity',3);q.onupgradeneeded=()=>q.result.createObjectStore('accounts');
    const db=await new Promise((r,j)=>{q.onsuccess=()=>r(q.result);q.onerror=j;});
    const tx=db.transaction('accounts','readwrite');tx.objectStore('accounts').put({value:${JSON.stringify(label)}},'account');
    await new Promise((r,j)=>{tx.oncomplete=r;tx.onerror=j;});db.close();return true;
  })()`),
    true,
  );
}
app
  .whenReady()
  .then(async () => {
    const profiler = new Session();
    profiler.connect();
    const profile = (method: string, parameters: any = {}) =>
      new Promise<any>((resolve, reject) =>
        profiler.post(method as any, parameters, (error, result) =>
          error ? reject(error) : resolve(result),
        ),
      );
    await profile('Profiler.enable');
    await profile('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
    phase = 'first session';
    const first = await nativeWindow();
    assert.equal(first.driver.isOffline, true);
    assert.equal(
      first.driver.permitsRequest(
        'https://idp.test/blocked',
        first.window.webContents.id,
        'mainFrame',
      ),
      false,
    );
    assert.equal(first.driver.permitsRequest('https://idp.test/blocked', -1, 'subFrame'), false);
    await assert.rejects(first.ses.fetch('https://idp.test/blocked'));
    phase = 'apply empty';
    await first.driver.apply(Buffer.alloc(0));
    await first.driver.publish();
    assert.equal(first.driver.isOffline, false);
    fixtureNetwork(first.ses);
    phase = 'seed first-party';
    await seedFrame(await liveFrame(first.window, 'https://idp.test'), 'first-party');
    phase = 'seed embedded';
    await seedFrame(
      await liveFrame(first.window, 'https://vpn.test', 'https://idp.test'),
      'vpn-party',
    );
    await seedFrame(
      await liveFrame(first.window, 'https://other.test', 'https://idp.test'),
      'other-party',
    );
    await liveFrame(first.window, 'https://vpn.test', 'https://middle.test');
    const middle = first.window.webContents.mainFrame.frames[0];
    await middle.executeJavaScript(
      "new Promise(resolve=>{const f=document.createElement('iframe');f.onload=()=>resolve(true);f.src='https://idp.test/nested';document.body.append(f);})",
    );
    const nested = middle.frames[0];
    assert.ok(nested);
    await seedFrame(nested, 'nested-party');
    await first.ses.cookies.set({
      url: 'https://idp.test/',
      name: 'identity-cookie',
      value: 'native-cookie',
      secure: true,
      httpOnly: true,
      sameSite: 'no_restriction',
    });
    await first.ses.cookies.set({
      url: 'https://idp.test/scoped',
      domain: '.idp.test',
      path: '/scoped',
      name: 'domain-cookie',
      value: 'domain-value',
      secure: true,
      httpOnly: true,
      sameSite: 'strict',
      expirationDate: Math.floor(Date.now() / 1000) + 3600,
    });
    await first.ses.cookies.set({
      url: 'https://vpn.test/',
      name: 'SVPNCOOKIE',
      value: 'fresh-only',
      secure: true,
      httpOnly: true,
    });
    await first.window.webContents.debugger.sendCommand('Network.setCookies', {
      cookies: [
        {
          url: 'https://idp.test/',
          name: 'partitioned',
          value: 'vpn-cookie',
          secure: true,
          httpOnly: true,
          sameSite: 'None',
          partitionKey: { topLevelSite: 'https://vpn.test', hasCrossSiteAncestor: true },
        },
        {
          url: 'https://idp.test/',
          name: 'partitioned',
          value: 'other-cookie',
          secure: true,
          httpOnly: true,
          sameSite: 'None',
          partitionKey: { topLevelSite: 'https://other.test', hasCrossSiteAncestor: true },
        },
      ],
    });
    first.ses.protocol.unhandle('https');
    phase = 'capture first';
    const archive = await first.driver.capture();
    const original = JSON.parse(archive.toString());
    assert.ok(
      original.contexts.some(
        (c: any) => c.origin === 'https://idp.test' && c.ancestors[0] === 'https://vpn.test',
      ),
    );
    assert.equal(
      original.cookies.some((c: any) => c.name === 'SVPNCOOKIE'),
      false,
    );
    assert.equal(original.cookies.filter((c: any) => c.name === 'partitioned').length, 2);
    phase = 'restore second';
    const second = await nativeWindow();
    const expiredSnapshot = {
      ...original,
      cookies: [
        ...original.cookies,
        {
          ...original.cookies[0],
          name: 'expired-cookie',
          session: false,
          expires: Date.now() / 1000 - 60,
        },
      ],
    };
    const ownedImport = Buffer.from(JSON.stringify(expiredSnapshot));
    await second.driver.apply(ownedImport);
    assert.ok(ownedImport.every((byte) => byte === 0));
    archive.fill(0);
    assert.ok(archive.every((byte) => byte === 0));
    assert.equal(second.driver.isOffline, true);
    await second.driver.publish();
    fixtureNetwork(second.ses);
    phase = 'verify second';
    for (const c of original.contexts.filter((c: any) => c.origin === 'https://idp.test')) {
      let frame = await liveFrame(
        second.window,
        c.ancestors[0] ?? c.origin,
        c.ancestors.length ? (c.ancestors[1] ?? c.origin) : undefined,
      );
      if (c.ancestors.length === 2) {
        await frame.executeJavaScript(
          "new Promise(resolve=>{const f=document.createElement('iframe');f.onload=()=>resolve(true);f.src='https://idp.test/nested';document.body.append(f);})",
        );
        frame = frame.frames[0];
        assert.ok(frame);
      }
      const state = await frame.executeJavaScript(`(async()=>{
      const q=indexedDB.open('identity');const db=await new Promise((r,j)=>{q.onsuccess=()=>r(q.result);q.onerror=j;});
      const tx=db.transaction('accounts');const read=tx.objectStore('accounts').get('account');
      const record=await new Promise((r,j)=>{read.onsuccess=()=>r(read.result);read.onerror=j;});db.close();
      return {local:localStorage.getItem('identity'),session:sessionStorage.getItem('session'),record};
    })()`);
      const expected = c.state.local.find(([key]: string[]) => key === 'identity')[1];
      assert.deepEqual(state, {
        local: expected,
        session: 'session-value',
        record: { value: expected },
      });
    }
    const restoredCookies = (
      await second.window.webContents.debugger.sendCommand('Network.getAllCookies')
    ).cookies;
    assert.equal(
      restoredCookies.some((c: any) => c.name === 'SVPNCOOKIE'),
      false,
    );
    assert.equal(restoredCookies.filter((c: any) => c.name === 'partitioned').length, 2);
    assert.equal(
      restoredCookies.some((c: any) => c.name === 'expired-cookie'),
      false,
    );
    assert.ok(
      restoredCookies.some(
        (c: any) => c.name === 'identity-cookie' && c.domain === 'idp.test' && c.httpOnly,
      ),
    );
    phase = 'second capture';
    second.ses.protocol.unhandle('https');
    const recaptured = await second.driver.capture();
    assert.equal(JSON.parse(recaptured.toString()).cookies.length, original.cookies.length);
    recaptured.fill(0);
    await assert.rejects(second.driver.capture());
    phase = 'invalid archive';
    for (const mutate of [
      (a: any) => {
        a.formatVersion = 2;
      },
      (a: any) => {
        a.contexts.push(a.contexts[0]);
      },
      (a: any) => {
        a.contexts[0].storageKey = 'https://foreign.test/';
      },
      (a: any) => {
        a.contexts[0].ancestors = ['http://unsafe.test'];
      },
      (a: any) => {
        a.cookies[0].name = 'SVPNCOOKIE';
      },
      (a: any) => {
        a.cookies[0].partitionKeyOpaque = true;
      },
      (a: any) => {
        a.cookies[0].unknown = true;
      },
      (a: any) => {
        a.cookies.push(a.cookies[0]);
      },
      (a: any) => {
        a.cookies[0].partitionKey = {
          topLevelSite: 'https://vpn.test',
          hasCrossSiteAncestor: 'invalid',
        };
      },
      (a: any) => {
        a.cookies[0].domain = 'idp.test@foreign.test';
      },
      (a: any) => {
        a.cookies[0].name = '__Host-refused';
        a.cookies[0].domain = '.idp.test';
        a.cookies[0].path = '/scoped';
      },
      (a: any) => {
        a.contexts[0].storageKey += 'unrecreatable-key';
      },
      (a: any) => {
        a.contexts[0].ancestors = ['https://vpn.test', 'https://middle.test'];
      },
    ]) {
      const rejected = await nativeWindow();
      const changed = structuredClone(original);
      mutate(changed);
      const raw = Buffer.from(JSON.stringify(changed));
      await assert.rejects(rejected.driver.apply(raw));
      assert.ok(raw.every((byte) => byte === 0));
      await assert.rejects(rejected.driver.publish());
      assert.equal(rejected.driver.isOffline, true);
      rejected.window.destroy();
      await rejected.driver.close();
    }
    phase = 'revocation';
    let current = true;
    const revoked = await nativeWindow(() => current);
    current = false;
    const raw = Buffer.from('not-retained');
    await assert.rejects(revoked.driver.apply(raw));
    assert.ok(raw.every((byte) => byte === 0));
    revoked.window.destroy();
    await revoked.driver.close();
    await revoked.driver.close();
    phase = 'admission and unsupported writers';
    await assert.rejects(
      VaultVPNStorageDriver.open({
        window: first.window,
        current: () => true,
        attemptCookie: 'SVPNCOOKIE',
      }),
    );
    assert.equal(first.window.webContents.debugger.isAttached(), true);
    for (const [initial, operation] of [
      ["caches.open('unsupported-cache')", 'cache'],
      [
        "globalThis.worker=new Worker(URL.createObjectURL(new Blob(['setInterval(()=>{},1000)'],{type:'text/javascript'})));true",
        'worker',
      ],
      [
        "new Promise(resolve=>{const f=document.createElement('iframe');f.sandbox='';f.onload=()=>resolve(true);f.src='https://opaque.test/';document.body.append(f);})",
        'opaque',
      ],
    ]) {
      phase = 'refuse ' + operation;
      let invalidations = 0;
      const unsupported = await nativeWindow(
        () => true,
        () => {
          invalidations++;
        },
      );
      await unsupported.driver.apply(Buffer.alloc(0));
      await unsupported.driver.publish();
      fixtureNetwork(unsupported.ses);
      await liveFrame(unsupported.window, 'https://idp.test');
      await unsupported.window.webContents.executeJavaScript(initial);
      unsupported.ses.protocol.unhandle('https');
      await assert.rejects(unsupported.driver.capture());
      if (operation !== 'cache') assert.equal(invalidations, 1);
      assert.equal(unsupported.driver.isOffline, true);
      unsupported.window.destroy();
      await unsupported.driver.close();
    }
    phase = 'joined cancellation and retry';
    const redirected = await nativeWindow();
    await redirected.driver.apply(Buffer.alloc(0));
    await redirected.driver.publish();
    redirected.ses.protocol.handle(
      'https',
      (request) =>
        new Response(
          request.url === 'https://fast.test/start'
            ? "<!doctype html><script>localStorage.setItem('fast','kept');location.replace('https://done.test/final');</script>"
            : '<!doctype html><title>Done</title>',
          { headers: { 'Content-Type': 'text/html' } },
        ),
    );
    const finished = new Promise<void>((resolve) => {
      const listener = () => {
        if (redirected.window.webContents.getURL() === 'https://done.test/final') {
          redirected.window.webContents.removeListener('did-finish-load', listener);
          resolve();
        }
      };
      redirected.window.webContents.on('did-finish-load', listener);
    });
    await redirected.window.loadURL('https://fast.test/start').catch(() => {});
    await finished;
    redirected.ses.protocol.unhandle('https');
    const redirectArchive = await redirected.driver.capture();
    assert.ok(
      JSON.parse(redirectArchive.toString()).contexts.some(
        (c: any) =>
          c.origin === 'https://fast.test' &&
          c.state.local.some(([k, v]: string[]) => k === 'fast' && v === 'kept'),
      ),
    );
    redirectArchive.fill(0);
    redirected.window.destroy();
    await redirected.driver.close();
    const interrupted = await nativeWindow();
    const importing = interrupted.driver.apply(Buffer.from(JSON.stringify(original)));
    const duplicate = Buffer.from('owned-on-refusal');
    await assert.rejects(interrupted.driver.apply(duplicate));
    assert.ok(duplicate.every((b) => b === 0));
    interrupted.window.destroy();
    await assert.rejects(importing);
    await interrupted.driver.close();
    const retry = await nativeWindow();
    const nativeUnhandle = retry.ses.protocol.unhandle.bind(retry.ses.protocol);
    let cleanupFails = true;
    retry.ses.protocol.unhandle = (scheme: string) => {
      if (cleanupFails) {
        cleanupFails = false;
        throw Error('Fixture cleanup failure.');
      }
      nativeUnhandle(scheme);
    };
    retry.window.destroy();
    await assert.rejects(retry.driver.close());
    await retry.driver.close();
    phase = 'pre-publish admission';
    const notImported = await nativeWindow();
    await assert.rejects(notImported.driver.publish());
    notImported.window.destroy();
    await notImported.driver.close();
    const malformed = await nativeWindow();
    const invalidUTF8 = Buffer.from([0xff]);
    await assert.rejects(malformed.driver.apply(invalidUTF8));
    assert.equal(invalidUTF8[0], 0);
    malformed.window.destroy();
    await malformed.driver.close();
    const persistentSession = session.fromPartition('persist:fixture-refusal-' + randomUUID());
    const persistentWindow = new BrowserWindow({
      show: false,
      webPreferences: { session: persistentSession },
    });
    owned.push({ window: persistentWindow, session: persistentSession });
    await assert.rejects(
      VaultVPNStorageDriver.open({
        window: persistentWindow,
        current: () => true,
        attemptCookie: 'SVPNCOOKIE',
      }),
    );
    persistentWindow.destroy();
    phase = 'aggregate archive limit';
    const oversized = await nativeWindow();
    await oversized.driver.apply(Buffer.alloc(0));
    await oversized.driver.publish();
    fixtureNetwork(oversized.ses);
    for (const host of ['large-first.test', 'large-second.test']) {
      await liveFrame(oversized.window, 'https://' + host);
      await oversized.window.webContents.executeJavaScript(`(async()=>{
        const q=indexedDB.open('large',1);q.onupgradeneeded=()=>q.result.createObjectStore('binary');
        const db=await new Promise((r,j)=>{q.onsuccess=()=>r(q.result);q.onerror=j;});const tx=db.transaction('binary','readwrite');
        tx.objectStore('binary').put(new ArrayBuffer(26*1024*1024),1);await new Promise((r,j)=>{tx.oncomplete=r;tx.onerror=j;});db.close();return true;
      })()`);
    }
    oversized.ses.protocol.unhandle('https');
    await assert.rejects(oversized.driver.capture());
    assert.equal(oversized.driver.isOffline, true);
    oversized.window.destroy();
    await oversized.driver.close();
    phase = 'cleanup';
    for (const item of owned) {
      if (!item.window.isDestroyed()) item.window.destroy();
      await item.driver?.close();
      await item.session.clearStorageData();
      await item.session.clearCache();
    }
    const report = await profile('Profiler.takePreciseCoverage');
    const source = readFileSync(__filename, 'utf8');
    const start = source.indexOf('// electron/vault-vpn-storage-driver.ts');
    const end = source.indexOf('// tests/fixtures/vpn-storage-driver-main.ts');
    assert.ok(start >= 0 && end > start);
    const script = report.result.find(
      (s: any) => s.url.endsWith('/main.cjs') || s.url.endsWith('\\main.cjs'),
    );
    assert.ok(script);
    const blocks = script.functions
      .filter((f: any) => f.ranges[0].startOffset >= start && f.ranges[0].endOffset <= end)
      .flatMap((f: any) => f.ranges);
    assert.ok(blocks.length > 30);
    const coverage = (100 * blocks.filter((r: any) => r.count > 0).length) / blocks.length;
    profiler.disconnect();
    console.log(JSON.stringify({ ok: true, coverage }));
    app.quit();
  })
  .catch((error) => {
    console.error(phase, error?.name, error?.message);
    app.exit(1);
  });
