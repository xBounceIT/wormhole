// Executed only in an isolated world of an offline, native-owned HTTPS document.
// Keep this function self-contained: its compiled source is the injected asset.
// There is no preload, page bridge, private key or arbitrary evaluation request.
export async function vpnStorageDocument(request: {
  operation: 'capture' | 'restore';
  origin: string;
  state?: unknown;
}): Promise<string> {
  const fail = () => {
    throw Error('Unsupported VPN browser storage.');
  };
  const maxBytes = 64 * 1024 * 1024 - 48,
    maxEntries = 100000;
  if (
    !isSecureContext ||
    location.origin !== request.origin ||
    typeof (globalThis as any).process !== 'undefined' ||
    typeof (globalThis as any).require !== 'undefined' ||
    typeof (globalThis as any).wormhole !== 'undefined'
  )
    fail();
  const deadline = Date.now() + 30000;
  const check = () => {
    if (Date.now() >= deadline) fail();
  };
  const fields = (v: any, names: string[]) =>
    v &&
    typeof v === 'object' &&
    !Array.isArray(v) &&
    Object.keys(v).length === names.length &&
    names.every((name) => Object.hasOwn(v, name));
  const text = (v: any, max = 16384) => typeof v === 'string' && v.length <= max;
  const integer = (v: any, min: number, max: number) => Number.isInteger(v) && v >= min && v <= max;
  const b64 = (raw: ArrayBuffer) => {
    if (raw.byteLength > maxBytes) fail();
    const bytes = new Uint8Array(raw);
    let out = '';
    for (let i = 0; i < bytes.length; i += 16384)
      out += String.fromCharCode(...bytes.subarray(i, i + 16384));
    return btoa(out);
  };
  const unb64 = (raw: any) => {
    if (!text(raw, maxBytes * 2) || raw.length % 4 !== 0) return fail();
    const binary = atob(raw);
    if (binary.length > maxBytes || btoa(binary) !== raw) return fail();
    return Uint8Array.from(binary, (c) => c.charCodeAt(0)).buffer;
  };
  const views: Record<string, any> = {
    Int8Array,
    Uint8Array,
    Uint8ClampedArray,
    Int16Array,
    Uint16Array,
    Int32Array,
    Uint32Array,
    Float32Array,
    Float64Array,
    BigInt64Array,
    BigUint64Array,
    DataView,
  };
  const encode = async (root: any) => {
    const nodes: any[] = [],
      seen = new Map<object, number>();
    const value = async (v: any, depth = 0): Promise<any> => {
      check();
      if (depth > 128) return fail();
      if (v === null || typeof v === 'string' || typeof v === 'boolean') return ['literal', v];
      if (typeof v === 'number') return ['number', Object.is(v, -0) ? '-0' : String(v)];
      if (typeof v === 'undefined') return ['undefined'];
      if (typeof v === 'bigint') {
        const raw = String(v);
        if (!text(raw)) return fail();
        return ['bigint', raw];
      }
      if (typeof v !== 'object') return fail();
      const old = seen.get(v);
      if (old !== undefined) return ['ref', old];
      if (nodes.length >= maxEntries) return fail();
      const index = nodes.length;
      seen.set(v, index);
      nodes.push(null);
      const child = (x: any) => value(x, depth + 1);
      if (Array.isArray(v)) {
        if (v.length > maxEntries || Object.keys(v).length > maxEntries) return fail();
        const values: any[] = [];
        for (const key of Object.keys(v)) {
          if (!text(key)) return fail();
          values.push([key, await child(v[key as any])]);
        }
        nodes[index] = ['array', v.length, values];
      } else if (v instanceof Date) nodes[index] = ['date', String(v.getTime())];
      else if (v instanceof RegExp) {
        if (!text(v.source)) return fail();
        nodes[index] = ['regexp', v.source, v.flags];
      } else if (v instanceof ArrayBuffer) nodes[index] = ['buffer', b64(v)];
      else if (ArrayBuffer.isView(v)) {
        const name = v.constructor.name;
        if (!Object.hasOwn(views, name)) return fail();
        nodes[index] = ['view', name, await child(v.buffer), v.byteOffset, v.byteLength];
      } else if (v instanceof Map) {
        if (v.size > maxEntries) return fail();
        const entries: any[] = [];
        for (const [k, item] of v) entries.push([await child(k), await child(item)]);
        nodes[index] = ['map', entries];
      } else if (v instanceof Set) {
        if (v.size > maxEntries) return fail();
        const entries: any[] = [];
        for (const item of v) entries.push(await child(item));
        nodes[index] = ['set', entries];
      } else if (v instanceof Blob) {
        if (!text(v.type, 1024) || (v instanceof File && !text(v.name))) return fail();
        const data = b64(await v.arrayBuffer());
        nodes[index] =
          v instanceof File
            ? ['file', data, v.type, v.name, v.lastModified]
            : ['blob', data, v.type];
      } else if (v instanceof CryptoKey) {
        if (!v.extractable) return fail();
        nodes[index] = [
          'crypto',
          await crypto.subtle.exportKey('jwk', v),
          v.algorithm,
          [...v.usages],
        ];
      } else {
        const prototype = Object.getPrototypeOf(v);
        if (prototype !== Object.prototype && prototype !== null) return fail();
        const entries: any[] = [];
        if (Object.keys(v).length > maxEntries) return fail();
        for (const k of Object.keys(v)) {
          if (!text(k)) return fail();
          entries.push([k, await child(v[k])]);
        }
        nodes[index] = ['object', entries];
      }
      return ['ref', index];
    };
    return { root: await value(root), nodes };
  };
  const decode = async (g: any) => {
    if (!fields(g, ['root', 'nodes']) || !Array.isArray(g.nodes) || g.nodes.length > maxEntries)
      return fail();
    const objects: any[] = new Array(g.nodes.length);
    const primitive = (v: any): any => {
      if (!Array.isArray(v)) return fail();
      if (v[0] === 'ref' && v.length === 2 && integer(v[1], 0, objects.length - 1))
        return objects[v[1]];
      if (
        v[0] === 'literal' &&
        v.length === 2 &&
        (v[1] === null || typeof v[1] === 'string' || typeof v[1] === 'boolean')
      )
        return v[1];
      if (v[0] === 'undefined' && v.length === 1) return undefined;
      if (
        v[0] === 'number' &&
        v.length === 2 &&
        text(v[1], 64) &&
        (['NaN', 'Infinity', '-Infinity', '-0'].includes(v[1]) || String(Number(v[1])) === v[1])
      )
        return Number(v[1]);
      if (v[0] === 'bigint' && v.length === 2 && text(v[1]) && /^-?(0|[1-9][0-9]*)$/.test(v[1]))
        return BigInt(v[1]);
      return fail();
    };
    for (let i = 0; i < g.nodes.length; i++) {
      check();
      const n = g.nodes[i];
      if (!Array.isArray(n)) return fail();
      switch (n[0]) {
        case 'array':
          if (
            n.length !== 3 ||
            !integer(n[1], 0, maxEntries) ||
            !Array.isArray(n[2]) ||
            n[2].length > maxEntries
          )
            return fail();
          objects[i] = new Array(n[1]);
          break;
        case 'object':
          if (n.length !== 2 || !Array.isArray(n[1]) || n[1].length > maxEntries) return fail();
          objects[i] = {};
          break;
        case 'map':
          if (n.length !== 2 || !Array.isArray(n[1]) || n[1].length > maxEntries) return fail();
          objects[i] = new Map();
          break;
        case 'set':
          if (n.length !== 2 || !Array.isArray(n[1]) || n[1].length > maxEntries) return fail();
          objects[i] = new Set();
          break;
        case 'date':
          if (
            n.length !== 2 ||
            !text(n[1], 64) ||
            (n[1] !== 'NaN' && String(Number(n[1])) !== n[1])
          )
            return fail();
          objects[i] = new Date(Number(n[1]));
          break;
        case 'regexp':
          if (n.length !== 3 || !text(n[1]) || !text(n[2], 16)) return fail();
          objects[i] = new RegExp(n[1], n[2]);
          break;
        case 'buffer':
          if (n.length !== 2) return fail();
          objects[i] = unb64(n[1]);
          break;
        case 'blob':
          if (n.length !== 3 || !text(n[2], 1024)) return fail();
          objects[i] = new Blob([unb64(n[1])], { type: n[2] });
          break;
        case 'file':
          if (n.length !== 5 || !text(n[2], 1024) || !text(n[3]) || !Number.isFinite(n[4]))
            return fail();
          objects[i] = new File([unb64(n[1])], n[3], { type: n[2], lastModified: n[4] });
          break;
        case 'crypto':
          if (
            n.length !== 4 ||
            !n[1] ||
            typeof n[1] !== 'object' ||
            !n[2] ||
            typeof n[2] !== 'object' ||
            !Array.isArray(n[3])
          )
            return fail();
          objects[i] = await crypto.subtle.importKey('jwk', n[1], n[2], true, n[3]);
          break;
        case 'view':
          if (
            n.length !== 5 ||
            !Object.hasOwn(views, n[1]) ||
            !integer(n[3], 0, maxBytes) ||
            !integer(n[4], 0, maxBytes)
          )
            return fail();
          break;
        default:
          return fail();
      }
    }
    for (let i = 0; i < g.nodes.length; i++) {
      const n = g.nodes[i];
      if (n[0] !== 'view') continue;
      const buffer = primitive(n[2]),
        View = views[n[1]];
      if (!(buffer instanceof ArrayBuffer)) return fail();
      objects[i] =
        n[1] === 'DataView'
          ? new DataView(buffer, n[3], n[4])
          : new View(buffer, n[3], n[4] / View.BYTES_PER_ELEMENT);
      if (objects[i].byteLength !== n[4]) return fail();
    }
    for (let i = 0; i < g.nodes.length; i++) {
      check();
      const n = g.nodes[i],
        target = objects[i];
      if (n[0] === 'set')
        for (const v of n[1]) {
          target.add(primitive(v));
        }
      if (n[0] === 'object' || n[0] === 'map' || n[0] === 'array') {
        const seen = new Set<string>();
        for (const pair of n[n[0] === 'array' ? 2 : 1]) {
          if (!Array.isArray(pair) || pair.length !== 2) return fail();
          if (n[0] === 'map') target.set(primitive(pair[0]), primitive(pair[1]));
          else {
            if (!text(pair[0]) || seen.has(pair[0]) || (n[0] === 'array' && pair[0] === 'length'))
              return fail();
            seen.add(pair[0]);
            Object.defineProperty(target, pair[0], {
              value: primitive(pair[1]),
              enumerable: true,
              writable: true,
              configurable: true,
            });
          }
        }
        if (n[0] === 'array' && target.length !== n[1]) return fail();
      }
    }
    return primitive(g.root);
  };
  const result = <T>(q: IDBRequest<T>) =>
    new Promise<T>((resolve, reject) => {
      q.onsuccess = () => resolve(q.result);
      q.onerror = () => reject(Error('VPN browser database operation failed.'));
    });
  const complete = (tx: IDBTransaction) =>
    new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = tx.onerror = () => reject(Error('VPN browser transaction failed.'));
    });
  const keyPath = (v: any) =>
    v === null || text(v) || (Array.isArray(v) && v.length <= 64 && v.every((p: any) => text(p)));
  const probe = (path: string | string[] | null, key?: number) => {
    const value: any = {};
    if (path !== null) {
      if (typeof path !== 'string' || !path) return fail();
      const parts = path.split('.');
      let current = value;
      for (let i = 0; i < parts.length; i++) {
        const child = i === parts.length - 1 ? key : {};
        if (child !== undefined)
          Object.defineProperty(current, parts[i], {
            value: child,
            enumerable: true,
            writable: true,
            configurable: true,
          });
        current = child;
      }
    }
    return value;
  };
  const generator = (db: IDBDatabase, name: string) =>
    new Promise<number | 'exhausted'>((resolve, reject) => {
      const tx = db.transaction(name, 'readwrite'),
        store = tx.objectStore(name);
      let next: number | 'exhausted' | undefined;
      tx.onabort = () =>
        next === undefined ? reject(Error('VPN key generator is unavailable.')) : resolve(next);
      tx.onerror = () => {};
      const q = store.add(probe(store.keyPath));
      q.onsuccess = () => {
        next = q.result as number;
        tx.abort();
      };
      q.onerror = (event) => {
        if (q.error?.name === 'ConstraintError') {
          event.preventDefault();
          next = 'exhausted';
        }
        tx.abort();
      };
    });
  const readStrings = (store: Storage) => {
    if (store.length > maxEntries) return fail();
    const entries: string[][] = [];
    for (let i = 0; i < store.length; i++) {
      const name = store.key(i);
      if (name === null) return fail();
      entries.push([name, store.getItem(name)!]);
    }
    return entries;
  };
  const writeStrings = (store: Storage, entries: any) => {
    if (!Array.isArray(entries) || entries.length > maxEntries) return fail();
    const seen = new Set<string>();
    for (const pair of entries) {
      if (
        !Array.isArray(pair) ||
        pair.length !== 2 ||
        !text(pair[0], maxBytes) ||
        !text(pair[1], maxBytes) ||
        seen.has(pair[0])
      )
        return fail();
      seen.add(pair[0]);
    }
    store.clear();
    for (const [k, v] of entries) store.setItem(k, v);
  };
  // Workers and caches require their own native snapshot/quiescence adapters.
  // Refuse such state explicitly rather than silently publishing a partial copy.
  if ((await navigator.serviceWorker.getRegistrations()).length || (await caches.keys()).length)
    fail();
  if (request.operation === 'capture') {
    const databases: any[] = [],
      names = await indexedDB.databases();
    if (names.length > 128) return fail();
    for (const info of names) {
      check();
      if (!text(info.name) || !integer(info.version, 1, Number.MAX_SAFE_INTEGER)) return fail();
      const db = await result(indexedDB.open(info.name!, info.version));
      try {
        const stores: any[] = [];
        if (db.objectStoreNames.length > 256) return fail();
        for (const name of db.objectStoreNames) {
          const tx = db.transaction(name, 'readonly'),
            done = complete(tx),
            store = tx.objectStore(name);
          if (!text(name) || !keyPath(store.keyPath) || store.indexNames.length > 256)
            return fail();
          const indexes = [...store.indexNames].map((name) => {
            const i = store.index(name);
            if (!text(name) || !keyPath(i.keyPath)) return fail();
            return { name, keyPath: i.keyPath, unique: i.unique, multiEntry: i.multiEntry };
          });
          const [keys, values] = await Promise.all([
            result(store.getAllKeys(undefined, maxEntries + 1)),
            result(store.getAll(undefined, maxEntries + 1)),
          ]);
          await done;
          if (keys.length !== values.length || keys.length > maxEntries) return fail();
          const records: any[] = [];
          for (let i = 0; i < keys.length; i++)
            records.push({ key: await encode(keys[i]), value: await encode(values[i]) });
          stores.push({
            name,
            keyPath: store.keyPath,
            autoIncrement: store.autoIncrement,
            next: store.autoIncrement ? await generator(db, name) : null,
            indexes,
            records,
          });
        }
        databases.push({ name: info.name, version: info.version, stores });
      } finally {
        db.close();
      }
    }
    const out = JSON.stringify({
      origin: request.origin,
      local: readStrings(localStorage),
      session: readStrings(sessionStorage),
      databases,
    });
    if (new TextEncoder().encode(out).length > maxBytes) return fail();
    return out;
  }
  if (request.operation !== 'restore') return fail();
  const state: any = request.state;
  if (
    !fields(state, ['origin', 'local', 'session', 'databases']) ||
    state.origin !== request.origin ||
    !Array.isArray(state.databases) ||
    state.databases.length > 128 ||
    new TextEncoder().encode(JSON.stringify(state)).length > maxBytes
  )
    return fail();
  const seenDB = new Set<string>();
  for (const spec of state.databases) {
    check();
    if (
      !fields(spec, ['name', 'version', 'stores']) ||
      !text(spec.name) ||
      seenDB.has(spec.name) ||
      !integer(spec.version, 1, Number.MAX_SAFE_INTEGER) ||
      !Array.isArray(spec.stores) ||
      spec.stores.length > 256
    )
      return fail();
    seenDB.add(spec.name);
    const decoded: any[] = [],
      seenStores = new Set<string>();
    for (const s of spec.stores) {
      if (
        !fields(s, ['name', 'keyPath', 'autoIncrement', 'next', 'indexes', 'records']) ||
        !text(s.name) ||
        seenStores.has(s.name) ||
        !keyPath(s.keyPath) ||
        typeof s.autoIncrement !== 'boolean' ||
        (s.autoIncrement
          ? s.next !== 'exhausted' && !integer(s.next, 1, 9007199254740992)
          : s.next !== null) ||
        !Array.isArray(s.indexes) ||
        s.indexes.length > 256 ||
        !Array.isArray(s.records) ||
        s.records.length > maxEntries
      )
        return fail();
      seenStores.add(s.name);
      const records: any[] = [],
        seenIndexes = new Set<string>();
      for (const i of s.indexes) {
        if (
          !fields(i, ['name', 'keyPath', 'unique', 'multiEntry']) ||
          !text(i.name) ||
          seenIndexes.has(i.name) ||
          i.keyPath === null ||
          !keyPath(i.keyPath) ||
          typeof i.unique !== 'boolean' ||
          typeof i.multiEntry !== 'boolean'
        )
          return fail();
        seenIndexes.add(i.name);
      }
      for (const r of s.records) {
        if (!fields(r, ['key', 'value'])) return fail();
        records.push({ key: await decode(r.key), value: await decode(r.value) });
      }
      decoded.push({ ...s, records });
    }
    // A fresh volatile profile is required. Never merge an archive into unknown
    // live databases or replay an upgrade callback into a remote page.
    if ((await indexedDB.databases()).some((d) => d.name === spec.name)) return fail();
    const open = indexedDB.open(spec.name, spec.version);
    open.onupgradeneeded = () => {
      for (const s of decoded) {
        const store = open.result.createObjectStore(s.name, {
          keyPath: s.keyPath,
          autoIncrement: s.autoIncrement,
        });
        for (const i of s.indexes)
          store.createIndex(i.name, i.keyPath, { unique: i.unique, multiEntry: i.multiEntry });
      }
    };
    const db = await result(open);
    try {
      for (const s of decoded) {
        const tx = db.transaction(s.name, 'readwrite'),
          done = complete(tx),
          store = tx.objectStore(s.name);
        try {
          for (const r of s.records) {
            if (s.keyPath === null) store.add(r.value, r.key);
            else {
              const inserted = store.add(r.value);
              inserted.onsuccess = () => {
                try {
                  if (indexedDB.cmp(inserted.result, r.key) !== 0) tx.abort();
                } catch {
                  tx.abort();
                }
              };
            }
          }
          if (s.autoIncrement && s.next !== 1) {
            const target = s.next === 'exhausted' ? 9007199254740992 : s.next - 1;
            // Existing records already advanced the generator if target exists.
            const q = store.count(target);
            q.onsuccess = () => {
              if (q.result) return;
              const value = probe(s.keyPath, target);
              if (s.keyPath === null) store.add(value, target);
              else store.add(value);
              store.delete(target);
            };
          }
        } catch (error) {
          tx.abort();
          await done.catch(() => {});
          throw error;
        }
        await done;
        if (s.autoIncrement && (await generator(db, s.name)) !== s.next) return fail();
      }
    } finally {
      db.close();
    }
  }
  writeStrings(localStorage, state.local);
  writeStrings(sessionStorage, state.session);
  return JSON.stringify({ restored: true });
}
