import { app, BrowserWindow, session } from 'electron';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { vpnStorageDocument } from '../../electron/vault-vpn-storage-document.ts';

app.disableHardwareAcceleration();
app.setPath('userData', process.env.WORMHOLE_STORAGE_DIRECTORY!);
app.setPath('sessionData', process.env.WORMHOLE_STORAGE_DIRECTORY!);
const windows: BrowserWindow[] = [];
let phase = 'startup';
async function windowForOrigin() {
  const ses = session.fromPartition('vpn-storage-fixture-' + randomUUID());
  ses.protocol.handle(
    'https',
    () =>
      new Response('<!doctype html><meta charset="utf-8"><title>Offline storage</title>', {
        headers: {
          'Content-Type': 'text/html',
          'Content-Security-Policy': "default-src 'none'; frame-src https:",
        },
      }),
  );
  const win = new BrowserWindow({
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
  windows.push(win);
  await win.loadURL('https://idp.test/');
  win.webContents.debugger.attach('1.3');
  await win.webContents.debugger.sendCommand('Profiler.enable');
  await win.webContents.debugger.sendCommand('Profiler.startPreciseCoverage', {
    callCount: true,
    detailed: true,
  });
  await win.webContents.executeJavaScriptInIsolatedWorld(1501, [
    {
      code: `globalThis.vpnStorageDocument = (${vpnStorageDocument.toString()});true;\n//# sourceURL=wormhole-vpn-storage-document.js`,
    },
  ]);
  return win;
}
async function evaluate(win: BrowserWindow, request: any) {
  const value = await win.webContents.executeJavaScriptInIsolatedWorld(1501, [
    {
      code: `(async()=>{try{return await globalThis.vpnStorageDocument(JSON.parse(${JSON.stringify(JSON.stringify(request))}));}catch(e){return JSON.stringify({nativeError:String(e?.name)+': '+String(e?.message)});}})()`,
      url: 'wormhole-vpn-storage-fixture.js',
    },
  ]);
  const decoded = JSON.parse(value);
  if (decoded.nativeError) throw Error(decoded.nativeError);
  return decoded;
}

async function seed() {
  localStorage.setItem('opaque-token', 'local-native-fixture');
  sessionStorage.setItem('session-token', 'session-native-fixture');
  const q = indexedDB.open('identity-store', 7);
  q.onupgradeneeded = () => {
    const inline = q.result.createObjectStore('inline', {
      keyPath: 'meta.id',
      autoIncrement: true,
    });
    inline.createIndex('email', 'email', { unique: true });
    inline.createIndex('compound', ['email', 'zone']);
    inline.createIndex('tags', 'tags', { multiEntry: true });
    q.result.createObjectStore('out', { autoIncrement: true });
    q.result.createObjectStore('fresh', { autoIncrement: true });
    q.result.createObjectStore('exhausted', { autoIncrement: true });
    q.result.createObjectStore('penultimate', { autoIncrement: true });
    q.result.createObjectStore('compound', { keyPath: ['account', 'zone'] });
  };
  const db = await new Promise<IDBDatabase>((r, j) => {
    q.onsuccess = () => r(q.result);
    q.onerror = j;
  });
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, true, [
    'encrypt',
    'decrypt',
  ]);
  const tx = db.transaction([...db.objectStoreNames], 'readwrite');
  const done = new Promise<void>((r, j) => {
    tx.oncomplete = () => r();
    tx.onerror = j;
  });
  const buffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer;
  const sparse: any = new Array(3);
  sparse[2] = 'last';
  sparse.extra = 'kept';
  const value: any = {
    meta: {},
    email: 'ada@test',
    zone: 'eu',
    tags: ['sso', 'native'],
    array: sparse,
    date: new Date(1700000000000),
    invalidDate: new Date(NaN),
    pattern: /auth/giu,
    binary: buffer,
    view: new Uint16Array(buffer, 2, 2),
    data: new DataView(buffer, 1, 3),
    big: 9223372036854775807n,
    notANumber: NaN,
    infinity: Infinity,
    negativeInfinity: -Infinity,
    negativeZero: -0,
    empty: undefined,
    nil: null,
    bool: true,
    key,
    blob: new Blob(['blob-fixture'], { type: 'text/plain' }),
    file: new File(['file-fixture'], 'identity.bin', {
      type: 'application/octet-stream',
      lastModified: 123456,
    }),
  };
  value.self = value;
  value.map = new Map([[value, 'same-object']]);
  value.set = new Set([value]);
  Object.defineProperty(value, '__proto__', { value: 'literal-property', enumerable: true });
  const inline = tx.objectStore('inline');
  inline.add(value);
  inline.add({ meta: { id: 400 }, email: 'deleted@test' });
  inline.delete(400);
  const out = tx.objectStore('out');
  out.add({ token: 'out-of-line' });
  out.add({}, 100);
  out.delete(100);
  const exhausted = tx.objectStore('exhausted');
  exhausted.add({}, 9007199254740992);
  exhausted.delete(9007199254740992);
  const penultimate = tx.objectStore('penultimate');
  penultimate.add({}, 9007199254740991);
  penultimate.delete(9007199254740991);
  tx.objectStore('compound').add({ account: 'ada', zone: 'eu', token: 'compound-fixture' });
  await done;
  db.close();
  const empty = indexedDB.open('empty-store', 3);
  await new Promise<void>((r, j) => {
    empty.onsuccess = () => {
      empty.result.close();
      r();
    };
    empty.onerror = j;
  });
  return true;
}
async function verify() {
  const check = (v: unknown) => {
    if (!v) throw Error('Native IDB round trip mismatch.');
  };
  check(localStorage.getItem('opaque-token') === 'local-native-fixture');
  check(sessionStorage.getItem('session-token') === 'session-native-fixture');
  const q = indexedDB.open('identity-store');
  const db = await new Promise<IDBDatabase>((r, j) => {
    q.onsuccess = () => r(q.result);
    q.onerror = j;
  });
  check(db.version === 7);
  const tx = db.transaction([...db.objectStoreNames], 'readwrite');
  const done = new Promise<void>((r, j) => {
    tx.oncomplete = () => r();
    tx.onerror = j;
  });
  const read = tx.objectStore('inline').get(1);
  const v: any = await new Promise((r, j) => {
    read.onsuccess = () => r(read.result);
    read.onerror = j;
  });
  check(v.meta.id === 1 && v.self === v && v.map.get(v) === 'same-object' && v.set.has(v));
  check(
    v.array.length === 3 && !(0 in v.array) && v.array[2] === 'last' && v.array.extra === 'kept',
  );
  check(
    v.date.getTime() === 1700000000000 &&
      Number.isNaN(v.invalidDate.getTime()) &&
      v.pattern.source === 'auth' &&
      v.pattern.flags === 'giu',
  );
  check(v.view.buffer === v.binary && v.view.byteOffset === 2 && v.view.byteLength === 4);
  check(v.data.buffer === v.binary && v.data.byteOffset === 1 && v.data.byteLength === 3);
  check(
    v.big === 9223372036854775807n &&
      Number.isNaN(v.notANumber) &&
      v.infinity === Infinity &&
      v.negativeInfinity === -Infinity &&
      Object.is(v.negativeZero, -0),
  );
  check(
    v.empty === undefined &&
      v.nil === null &&
      v.bool === true &&
      Object.getOwnPropertyDescriptor(v, '__proto__')?.value === 'literal-property',
  );
  // Queue IDB work before awaiting Blob/WebCrypto promises (which would close tx).
  const generated = tx.objectStore('inline').add({ meta: {}, email: 'new@test' });
  const out = tx.objectStore('out').add({ token: 'new' });
  const exhausted = tx.objectStore('exhausted').add({});
  const penultimate = tx.objectStore('penultimate').add({});
  const result = new Promise<void>((r, j) => {
    let left = 4;
    const finish = () => {
      if (--left === 0) r();
    };
    generated.onsuccess = () => {
      try {
        check(generated.result === 401);
        finish();
      } catch (e) {
        j(e);
      }
    };
    out.onsuccess = () => {
      try {
        check(out.result === 101);
        finish();
      } catch (e) {
        j(e);
      }
    };
    penultimate.onsuccess = () => {
      try {
        check(penultimate.result === 9007199254740992);
        finish();
      } catch (e) {
        j(e);
      }
    };
    exhausted.onerror = (event) => {
      event.preventDefault();
      event.stopPropagation();
      try {
        check(exhausted.error?.name === 'ConstraintError');
        finish();
      } catch (e) {
        j(e);
      }
    };
  });
  await result;
  await done;
  db.close();
  check((await v.blob.text()) === 'blob-fixture' && v.blob.type === 'text/plain');
  check(
    (await v.file.text()) === 'file-fixture' &&
      v.file.name === 'identity.bin' &&
      v.file.lastModified === 123456,
  );
  check(v.key instanceof CryptoKey && v.key.extractable && v.key.usages.includes('decrypt'));
  const jwk = await crypto.subtle.exportKey('jwk', v.key);
  check(typeof jwk.k === 'string');
  return true;
}

async function negativeSnapshots(win: BrowserWindow) {
  const primitive = (root: any) => ({ root, nodes: [] });
  const node = (n: any) => ({ root: ['ref', 0], nodes: [n] });
  const invalid = [
    null,
    {},
    { root: [], nodes: null },
    primitive(['literal', {}]),
    primitive(['number', '01']),
    primitive(['bigint', '01']),
    primitive(['undefined', 0]),
    primitive(['ref', 0]),
    node(null),
    node(['unknown']),
    node(['array', -1, []]),
    node(['array', 1, [['length', ['number', '1']]]]),
    node(['array', 1, [['2', ['number', '1']]]]),
    node(['object', [['x']]]),
    node([
      'object',
      [
        ['x', ['literal', true]],
        ['x', ['literal', false]],
      ],
    ]),
    node(['object', [[1, ['literal', true]]]]),
    node(['map', {}]),
    node(['set', {}]),
    node(['date', 'invalid']),
    node(['regexp', 'x', 'invalid']),
    node(['buffer', 'AA=']),
    node(['buffer', 'AB==']),
    node(['blob', '', 0]),
    node(['file', '', '', 'x', null]),
    node(['crypto', null, {}, []]),
    node(['crypto', {}, { name: 'unsupported' }, []]),
    node(['view', 'Function', ['ref', 1], 0, 0]),
    node(['view', 'DataView', ['ref', 0], 0, 0]),
    {
      root: ['ref', 0],
      nodes: [
        ['view', 'Uint32Array', ['ref', 1], 0, 1],
        ['buffer', 'AAAAAA=='],
      ],
    },
  ];
  const state = (graph: any) => ({
    origin: 'https://idp.test',
    local: [],
    session: [],
    databases: [
      {
        name: 'bad',
        version: 1,
        stores: [
          {
            name: 'store',
            keyPath: null,
            autoIncrement: false,
            next: null,
            indexes: [],
            records: [{ key: primitive(['number', '1']), value: graph }],
          },
        ],
      },
    ],
  });
  for (const graph of invalid)
    await assert.rejects(
      evaluate(win, { operation: 'restore', origin: 'https://idp.test', state: state(graph) }),
    );
  const valid = state(primitive(['literal', true]));
  for (const mutate of [
    (s: any) => {
      const store = s.databases[0].stores[0];
      store.keyPath = 'id';
      store.records[0].value = node(['object', [['id', ['number', '2']]]]);
    },
    (s: any) => {
      const store = s.databases[0].stores[0];
      store.keyPath = 'id';
      store.records[0].key = primitive(['literal', true]);
      store.records[0].value = node(['object', [['id', ['number', '2']]]]);
    },
    (s: any) => {
      const store = s.databases[0].stores[0];
      store.autoIncrement = true;
      store.next = 1;
      store.records[0].key = primitive(['number', '100']);
    },
    (s: any) => {
      s.extra = true;
    },
    (s: any) => {
      s.origin = 'https://other.test';
    },
    (s: any) => {
      s.databases = null;
    },
    (s: any) => {
      s.databases[0].version = 0;
    },
    (s: any) => {
      s.databases.push(s.databases[0]);
    },
    (s: any) => {
      s.databases[0].stores = null;
    },
    (s: any) => {
      s.databases[0].stores[0].keyPath = 0;
    },
    (s: any) => {
      s.databases[0].stores[0].autoIncrement = true;
    },
    (s: any) => {
      s.databases[0].stores[0].indexes = [
        { name: 'x', keyPath: null, unique: true, multiEntry: false },
      ];
    },
    (s: any) => {
      s.databases[0].stores[0].records = [{}];
    },
    (s: any) => {
      s.databases = [];
      s.local = [
        ['duplicate', 'x'],
        ['duplicate', 'y'],
      ];
    },
    (s: any) => {
      s.databases = [];
      s.session = [[0, 'x']];
    },
  ]) {
    const bad = structuredClone(valid);
    mutate(bad);
    await assert.rejects(
      evaluate(win, { operation: 'restore', origin: 'https://idp.test', state: bad }),
    );
    await win.webContents.session.clearStorageData({ storages: ['indexdb', 'localstorage'] });
  }
  await assert.rejects(evaluate(win, { operation: 'bad', origin: 'https://idp.test' }));
}

async function cookieIsolation(first: BrowserWindow, second: BrowserWindow) {
  await first.webContents.session.cookies.set({
    url: 'https://idp.test/',
    name: 'first-context',
    value: 'first-fixture',
    secure: true,
    httpOnly: true,
    sameSite: 'no_restriction',
  });
  await second.webContents.session.cookies.set({
    url: 'https://idp.test/',
    name: 'second-context',
    value: 'second-fixture',
    secure: true,
    httpOnly: true,
    sameSite: 'no_restriction',
  });
  const cookies = async (win: BrowserWindow) =>
    (await win.webContents.debugger.sendCommand('Network.getAllCookies')).cookies;
  let initial = await cookies(first);
  assert.ok(
    initial.some((c: any) => c.name === 'first-context' && c.httpOnly && c.domain === 'idp.test'),
  );
  assert.equal(
    initial.some((c: any) => c.name === 'second-context'),
    false,
  );
  assert.equal(
    (await cookies(second)).some((c: any) => c.name === 'first-context'),
    false,
  );
  await first.webContents.debugger.sendCommand('Network.setCookies', {
    cookies: [
      {
        name: 'partitioned-fixture',
        value: 'vpn-context',
        url: 'https://idp.test/',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'None',
        partitionKey: { topLevelSite: 'https://vpn.test', hasCrossSiteAncestor: true },
      },
      {
        name: 'partitioned-fixture',
        value: 'other-context',
        url: 'https://idp.test/',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'None',
        partitionKey: { topLevelSite: 'https://other.test', hasCrossSiteAncestor: true },
      },
    ],
  });
  initial = await cookies(first);
  const partitioned = initial.filter((c: any) => c.name === 'partitioned-fixture');
  assert.equal(partitioned.length, 2);
  assert.ok(
    partitioned.some(
      (c: any) => c.value === 'vpn-context' && c.partitionKey.topLevelSite === 'https://vpn.test',
    ),
  );
  assert.ok(
    partitioned.some(
      (c: any) =>
        c.value === 'other-context' && c.partitionKey.topLevelSite === 'https://other.test',
    ),
  );
  assert.equal(
    (await cookies(second)).some((c: any) => c.name === 'partitioned-fixture'),
    false,
  );
}

async function storageKeyIsolation(win: BrowserWindow) {
  const attached = new Set<string>();
  const listener = (_event: unknown, method: string, params: any) => {
    if (method === 'Target.attachedToTarget' && params.targetInfo.type === 'iframe')
      attached.add(params.sessionId);
    if (method === 'Target.detachedFromTarget') attached.delete(params.sessionId);
  };
  win.webContents.debugger.on('message', listener);
  await win.webContents.debugger.sendCommand('Target.setAutoAttach', {
    autoAttach: true,
    waitForDebuggerOnStart: false,
    flatten: true,
  });
  const context = async (topOrigin: string) => {
    attached.clear();
    await win.loadURL(topOrigin + '/native-storage-key');
    await win.webContents.executeJavaScript(`new Promise((resolve,reject)=>{
      const frame=document.createElement('iframe');frame.onload=()=>resolve(true);frame.onerror=reject;
      frame.src='https://idp.test/native-storage-key';document.body.append(frame);
    })`);
    const tree = (await win.webContents.debugger.sendCommand('Page.getFrameTree')).frameTree;
    let id: string, targetSession: string | undefined;
    if (tree.childFrames?.length) id = tree.childFrames[0].frame.id;
    else {
      assert.equal(attached.size, 1);
      targetSession = [...attached][0];
      const child = await win.webContents.debugger.sendCommand(
        'Page.getFrameTree',
        {},
        targetSession,
      );
      assert.equal(new URL(child.frameTree.frame.url).origin, 'https://idp.test');
      id = child.frameTree.frame.id;
    }
    const key = (
      await win.webContents.debugger.sendCommand(
        'Storage.getStorageKeyForFrame',
        { frameId: id },
        targetSession,
      )
    ).storageKey;
    const executionContextId = (
      await win.webContents.debugger.sendCommand(
        'Page.createIsolatedWorld',
        {
          frameId: id,
          worldName: 'native-vpn-storage-proof',
        },
        targetSession,
      )
    ).executionContextId;
    assert.equal(typeof key, 'string');
    const evaluate = async (expression: string) => {
      const response = await win.webContents.debugger.sendCommand(
        'Runtime.evaluate',
        {
          contextId: executionContextId,
          expression,
          returnByValue: true,
          awaitPromise: true,
        },
        targetSession,
      );
      assert.equal(response.exceptionDetails, undefined);
      return response.result.value;
    };
    assert.equal(await evaluate('location.origin'), 'https://idp.test');
    return { key, evaluate };
  };
  const first = await context('https://vpn.test');
  await first.evaluate("localStorage.setItem('storage-key-proof','vpn-state');true");
  const request = { operation: 'capture', origin: 'https://idp.test' };
  const snapshot = JSON.parse(
    await first.evaluate(
      `(${vpnStorageDocument.toString()})(JSON.parse(${JSON.stringify(JSON.stringify(request))}))`,
    ),
  );
  assert.ok(
    snapshot.local.some(
      ([key, value]: string[]) => key === 'storage-key-proof' && value === 'vpn-state',
    ),
  );
  const second = await context('https://other.test');
  assert.equal(
    await second.evaluate("localStorage.getItem('storage-key-proof')"),
    second.key === first.key ? 'vpn-state' : null,
  );
  await second.evaluate("localStorage.setItem('storage-key-proof','other-state');true");
  const restored = await context('https://vpn.test');
  assert.equal(restored.key, first.key);
  assert.equal(
    await restored.evaluate("localStorage.getItem('storage-key-proof')"),
    second.key === first.key ? 'other-state' : 'vpn-state',
  );
  win.webContents.debugger.removeListener('message', listener);
}

app
  .whenReady()
  .then(async () => {
    const first = await windowForOrigin(),
      second = await windowForOrigin();
    phase = 'cookie partition isolation';
    await cookieIsolation(first, second);
    phase = 'seed';
    assert.equal(await first.webContents.executeJavaScript(`(${seed.toString()})()`), true);
    phase = 'capture';
    const state = await evaluate(first, { operation: 'capture', origin: 'https://idp.test' });
    assert.equal(state.databases.length, 2);
    phase = 'restore';
    assert.deepEqual(
      await evaluate(second, { operation: 'restore', origin: 'https://idp.test', state }),
      { restored: true },
    );
    phase = 'verify';
    assert.equal(await second.webContents.executeJavaScript(`(${verify.toString()})()`), true);
    await assert.rejects(
      evaluate(second, { operation: 'restore', origin: 'https://idp.test', state }),
    );
    await assert.rejects(
      evaluate(second, { operation: 'capture', origin: 'https://foreign.test' }),
    );
    await first.webContents.executeJavaScript(`caches.open('unsupported-cache')`);
    await assert.rejects(evaluate(first, { operation: 'capture', origin: 'https://idp.test' }));
    await first.webContents.executeJavaScript(`caches.delete('unsupported-cache')`);
    phase = 'negative snapshots';
    await negativeSnapshots(first);
    await first.webContents.session.clearStorageData({ storages: ['indexdb', 'localstorage'] });
    await first.webContents.executeJavaScript('sessionStorage.clear()');
    assert.deepEqual(
      await evaluate(first, { operation: 'restore', origin: 'https://idp.test', state }),
      { restored: true },
    );
    assert.equal(await first.webContents.executeJavaScript(`(${verify.toString()})()`), true);
    await first.webContents.executeJavaScript(`(async()=>{
      const q=indexedDB.open('identity-store');const db=await new Promise((r,j)=>{q.onsuccess=()=>r(q.result);q.onerror=j;});
      const key=await crypto.subtle.generateKey({name:'AES-GCM',length:128},false,['encrypt']);
      const tx=db.transaction('out','readwrite');tx.objectStore('out').put({key},9);
      await new Promise((r,j)=>{tx.oncomplete=r;tx.onerror=j;});db.close();return true;
    })()`);
    await assert.rejects(evaluate(first, { operation: 'capture', origin: 'https://idp.test' }));
    const report = await first.webContents.debugger.sendCommand('Profiler.takePreciseCoverage');
    const script = report.result.find((script: any) =>
      script.url.endsWith('wormhole-vpn-storage-document.js'),
    );
    assert.ok(script);
    const fn = script.functions.find((fn: any) => fn.functionName === 'vpnStorageDocument');
    assert.ok(fn);
    const extent = fn.ranges[0];
    const blocks = script.functions
      .filter(
        (f: any) =>
          f.ranges[0].startOffset >= extent.startOffset &&
          f.ranges[0].endOffset <= extent.endOffset,
      )
      .flatMap((f: any) => f.ranges);
    const percent = (100 * blocks.filter((r: any) => r.count > 0).length) / blocks.length;
    phase = 'native storage keys';
    await storageKeyIsolation(first);
    console.log(JSON.stringify({ ok: true, coverage: percent }));
    for (const win of windows) {
      const ses = win.webContents.session;
      win.destroy();
      await ses.clearStorageData();
    }
    app.quit();
  })
  .catch((error) => {
    console.error(phase, error?.name, error?.message, error?.target?.error?.name);
    app.exit(1);
  });
