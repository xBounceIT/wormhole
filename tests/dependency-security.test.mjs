import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';
import { createRequire } from 'node:module';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const require = createRequire(import.meta.url);
const braces = require('braces');
const CachePolicy = require('http-cache-semantics');

test('transitive consumers resolve the security backports', () => {
  for (const [consumer, dependency, fork] of [
    ['micromatch', 'braces', '@wormhole/braces'],
    ['cacheable-request', 'http-cache-semantics', '@wormhole/http-cache-semantics'],
  ]) {
    const consumerRequire = createRequire(require.resolve(consumer));
    assert.equal(consumerRequire(dependency), require(dependency));
    assert.equal(consumerRequire(`${dependency}/package.json`).name, fork);
  }

  const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
  for (const [location, metadata] of Object.entries(lock.packages)) {
    for (const dependency of ['braces', 'http-cache-semantics']) {
      if (
        location.endsWith(`/node_modules/${dependency}`) ||
        location === `node_modules/${dependency}`
      ) {
        assert.equal(metadata.resolved, `vendor/${dependency}`, location);
        assert.equal(metadata.link, true, location);
      }
    }
  }
});

const nested = (depth, open = '{', close = '}') => open.repeat(depth) + 'a' + close.repeat(depth);

for (const method of ['parse', 'compile', 'expand', 'stringify']) {
  test(`braces.${method} bounds string nesting before recursive processing`, () => {
    for (const [open, close] of [
      ['{', '}'],
      ['(', ')'],
    ]) {
      assert.doesNotThrow(() => braces[method](nested(100, open, close)));
      for (const depth of [101, 3500]) {
        assert.throws(() => braces[method](nested(depth, open, close)), /exceeds max depth/);
      }
      assert.throws(
        () => braces[method](nested(101, open, close), { maxDepth: Infinity }),
        /exceeds max depth/,
      );
      assert.throws(
        () => braces[method](nested(101, open, close), { maxDepth: 10000 }),
        /exceeds max depth/,
      );
      assert.doesNotThrow(() => braces[method](nested(1, open, close), { maxDepth: 1.5 }));
      assert.throws(
        () => braces[method](nested(2, open, close), { maxDepth: 1.5 }),
        /exceeds max depth/,
      );
      assert.throws(
        () => braces[method](nested(1, open, close), { maxDepth: 0 }),
        /exceeds max depth/,
      );
    }
    assert.doesNotThrow(() => braces[method]('{a}(b){c}(d)', { maxDepth: 1 }));
    assert.throws(() => braces[method]('{(a)}', { maxDepth: 1 }), /exceeds max depth/);
  });
}

function nestedAst(depth) {
  let ast = { type: 'text', value: 'a' };
  for (let index = 0; index < depth; index++) ast = { type: 'brace', nodes: [ast] };
  return { type: 'root', nodes: [ast] };
}

for (const method of ['compile', 'expand', 'stringify']) {
  test(`braces.${method} bounds caller-supplied ASTs and cycles`, () => {
    assert.doesNotThrow(() => braces[method](nestedAst(100)));
    assert.throws(() => braces[method](nestedAst(101)), /exceeds max depth/);
    assert.throws(() => braces[method](nestedAst(2), { maxDepth: 1.5 }), /exceeds max depth/);
    assert.throws(() => braces[method](nestedAst(101), { maxDepth: 10000 }), /exceeds max depth/);
    const ast = { type: 'root', nodes: [] };
    ast.nodes.push(ast);
    assert.throws(() => braces[method](ast), /exceeds max depth/);
  });
}

test('braces expansion rejects parent cycles without hanging', () => {
  for (const multipleNodes of [false, true]) {
    const ast = { type: 'paren', nodes: [{ type: 'text', value: 'a' }] };
    const parent = multipleNodes ? { type: 'paren', parent: ast } : ast;
    ast.parent = parent;
    assert.throws(
      () => runInNewContext('braces.expand(ast)', { braces, ast }, { timeout: 1000 }),
      /AST parent chain contains a cycle/,
    );
  }
});

test('brace backport preserves ordinary glob and expansion behavior', () => {
  assert.deepEqual(braces('src/{a,b}.ts'), ['src/(a|b).ts']);
  assert.deepEqual(braces.expand('file-{1..3}'), ['file-1', 'file-2', 'file-3']);
  assert.deepEqual(braces.expand('foo/({a,b})'), ['foo/(a)', 'foo/(b)']);
  assert.deepEqual(require('micromatch')(['a.ts', 'b.ts', 'c.js'], '{a,b}.ts'), ['a.ts', 'b.ts']);
  assert.throws(() => braces(nested(3500)), /exceeds max depth/);
  assert.throws(() => braces(nested(3500), { expand: true }), /exceeds max depth/);
});

test('bounded brace stringification honors escapeInvalid on containing and nested braces', () => {
  for (const [pattern, escaped] of [
    ['{a}', '\\{a\\}'],
    ['{{a}}', '\\{\\{a\\}\\}'],
    ['{a,{b}}', '{a,\\{b\\}}'],
    ['{{x}y}', '\\{\\{x\\}y\\}'],
    ['{a,{b,{c}}', '{a,{b,\\{c\\}}'],
    ['{}{a}', '\\{\\}\\{a\\}'],
    ['{a,b}', '{a,b}'],
    ['file-{1..3}', 'file-{1..3}'],
    ['{1..3,a}', '{1..3,a}'],
  ]) {
    assert.equal(braces.stringify(braces.parse(pattern)), pattern);
    assert.equal(braces.stringify(braces.parse(pattern), { escapeInvalid: true }), escaped);
    assert.equal(braces.stringify(pattern, { escapeInvalid: true }), escaped);
  }
  assert.throws(
    () => braces.stringify(braces.parse(nested(2)), { escapeInvalid: true, maxDepth: 1 }),
    /exceeds max depth/,
  );
});

test('brace compilation never writes AST contents to stdout', () => {
  const output = execFileSync(
    process.execPath,
    [
      '-e',
      `
    const braces = require(${JSON.stringify(require.resolve('braces'))});
    const ast = { type: 'close', isClose: true, value: 'private-pattern' };
    if (braces.compile(ast) !== 'private-pattern') process.exit(1);
    if (braces.compile(ast, { escapeInvalid: true }) !== '\\\\private-pattern') process.exit(1);
  `,
    ],
    { encoding: 'utf8' },
  );
  assert.equal(output, '');
});

const request = {
  url: 'https://example.test/account',
  method: 'GET',
  headers: { host: 'example.test' },
};

function cachePolicy(headers, options = {}, requestHeaders = {}) {
  const policy = new CachePolicy(
    { ...request, headers: { ...request.headers, ...requestHeaders } },
    { status: 200, headers },
    options,
  );
  const storedAt = policy.now();
  policy.now = () => storedAt + 120000;
  return policy;
}

function assertCacheMiss(policy, directive) {
  const incoming = { ...request, headers: { ...request.headers, 'cache-control': directive } };
  assert.equal(policy.satisfiesWithoutRevalidation(incoming), false);
  const result = policy.evaluateRequest(incoming);
  assert.equal(result.response, undefined);
  assert.equal(result.revalidation.synchronous, true);
}

for (const [label, headers, options, requestHeaders] of [
  ['shared session cookies', { 'set-cookie': ['session=user-a'], 'cache-control': 'max-age=60' }],
  ['proxy revalidation', { 'cache-control': 'max-age=60, proxy-revalidate' }],
  ['no-cache', { 'cache-control': 'no-cache, max-age=60' }],
  ['no-store', { 'cache-control': 'no-store, max-age=60' }],
  ['private response in shared cache', { 'cache-control': 'private, max-age=60' }],
  ['must-revalidate', { 'cache-control': 'must-revalidate, max-age=60' }],
  [
    'authenticated response without opt-in',
    { 'cache-control': 'max-age=60' },
    {},
    { authorization: 'test-user' },
  ],
  [
    'cookies with stale-while-revalidate',
    { 'set-cookie': 'session=user-a', 'cache-control': 'max-age=60, stale-while-revalidate=3600' },
  ],
]) {
  test(`max-stale cannot bypass ${label}`, () => {
    const policy = cachePolicy(headers, options, requestHeaders);
    for (const directive of ['max-stale', 'max-stale=999999', 'max-stale=0']) {
      assertCacheMiss(policy, directive);
      const restored = CachePolicy.fromObject(policy.toObject());
      restored.now = policy.now;
      assertCacheMiss(restored, directive);
    }
  });
}

test('ordinary expired responses retain max-stale support', () => {
  const policy = cachePolicy({ 'cache-control': 'max-age=60' });
  assertCacheMiss(policy, 'max-stale=30');
  for (const directive of ['max-stale', 'max-stale=120']) {
    assert.equal(
      policy.satisfiesWithoutRevalidation({
        ...request,
        headers: { ...request.headers, 'cache-control': directive },
      }),
      true,
    );
  }
});

test('revalidation directives allow fresh hits and prohibit stale reuse in their cache scope', () => {
  for (const directive of [
    'must-revalidate',
    'proxy-revalidate',
    'MUST-REVALIDATE',
    'PROXY-REVALIDATE',
  ]) {
    for (const shared of [true, false]) {
      const policy = cachePolicy(
        {
          'cache-control': `max-age=60, ${directive}, stale-while-revalidate=3600, stale-if-error=3600`,
        },
        { shared },
      );
      for (const candidate of [policy, CachePolicy.fromObject(policy.toObject())]) {
        const storedAt = candidate.toObject().t;
        candidate.now = () => storedAt + 59000;
        assert.equal(candidate.maxAge(), 60);
        assert.equal(candidate.stale(), false);
        for (const cacheControl of ['', 'max-stale=999999']) {
          const incoming = {
            ...request,
            headers: { ...request.headers, 'cache-control': cacheControl },
          };
          assert.equal(candidate.satisfiesWithoutRevalidation(incoming), true);
          const result = candidate.evaluateRequest(incoming);
          assert.ok(result.response);
          assert.equal(result.revalidation, undefined);
        }
        candidate.now = () => storedAt + 60000;
        assert.equal(candidate.stale(), true);
        const restricted = shared || directive.toLowerCase() === 'must-revalidate';
        if (restricted) assertCacheMiss(candidate, 'max-stale=999999');
        else assert.ok(candidate.evaluateRequest(request).response);
        assert.equal(candidate.useStaleWhileRevalidate(), !restricted);
        assert.equal(
          candidate.revalidatedPolicy(request, { status: 500, headers: {} }).modified,
          restricted,
        );
      }
    }
  }
});

test('explicit cookie opt-ins and private caches preserve reuse', () => {
  for (const [cacheControl, options] of [
    ['public, max-age=60', {}],
    ['immutable, max-age=60', {}],
    ['max-age=60', { shared: false }],
    ['proxy-revalidate, max-age=60', { shared: false }],
  ]) {
    const policy = cachePolicy(
      { 'set-cookie': 'session=user-a', 'cache-control': cacheControl },
      options,
    );
    assert.equal(
      policy.satisfiesWithoutRevalidation({
        ...request,
        headers: { ...request.headers, 'cache-control': 'max-stale=120' },
      }),
      true,
    );
  }
});

for (const [label, headers, requestHeaders] of [
  ['shared session cookies', { 'set-cookie': 'session=user-a' }],
  ['no-store', { 'cache-control': 'no-store' }],
  ['no-cache', { 'cache-control': 'no-cache' }],
  ['private response', { 'cache-control': 'private' }],
  ['proxy revalidation', { 'cache-control': 'proxy-revalidate' }],
  ['mandatory revalidation', { 'cache-control': 'must-revalidate' }],
  ['authenticated response', {}, { authorization: 'test-user' }],
]) {
  test(`stale error and background revalidation cannot bypass ${label}`, () => {
    const policy = cachePolicy(
      {
        ...headers,
        'cache-control': `${headers['cache-control'] || ''}, max-age=60, stale-if-error=3600, stale-while-revalidate=3600`,
      },
      {},
      requestHeaders,
    );
    for (const candidate of [policy, CachePolicy.fromObject(policy.toObject())]) {
      candidate.now = policy.now;
      assert.equal(candidate.useStaleWhileRevalidate(), false);
      for (const status of [500, 502, 503, 504]) {
        const result = candidate.revalidatedPolicy(request, {
          status,
          headers: { 'cache-control': 'no-store' },
        });
        assert.notEqual(result.policy, candidate);
        assert.equal(result.modified, true);
        assert.equal(result.matches, false);
        assert.equal(result.policy.responseHeaders()['set-cookie'], undefined);
      }
      assert.throws(
        () => candidate.revalidatedPolicy(request, undefined),
        /Response headers missing/,
      );
    }
  });
}

test('ordinary stale-if-error and stale-while-revalidate retain their behavior', () => {
  const policy = cachePolicy({
    'cache-control': 'max-age=60, stale-if-error=3600, stale-while-revalidate=3600',
  });
  assert.equal(policy.useStaleWhileRevalidate(), true);
  const evaluated = policy.evaluateRequest(request);
  assert.ok(evaluated.response);
  assert.equal(evaluated.revalidation.synchronous, false);
  for (const response of [undefined, { status: 500, headers: {} }]) {
    const result = policy.revalidatedPolicy(request, response);
    assert.equal(result.policy, policy);
    assert.equal(result.modified, false);
    assert.equal(result.matches, true);
  }
  for (const mismatched of [
    { ...request, url: 'https://example.test/other-account' },
    { ...request, method: 'POST' },
    { ...request, headers: { host: 'other.test' } },
  ]) {
    const result = policy.revalidatedPolicy(mismatched, { status: 500, headers: {} });
    assert.notEqual(result.policy, policy);
    assert.equal(result.modified, true);
    assert.equal(result.matches, false);
  }
});

test('cache restrictions are case-insensitive, including previously serialized policies', () => {
  for (const directive of [
    'No-Cache',
    'No-Store',
    'PrIvAtE',
    'PrOxY-ReValidate',
    'MUST-REVALIDATE',
  ]) {
    const policy = cachePolicy({
      'cache-control': `${directive}, MAX-AGE=60, STALE-IF-ERROR=3600, STALE-WHILE-REVALIDATE=3600`,
    });
    const legacy = policy.toObject();
    legacy.rescc = {
      [directive]: true,
      'max-age': '60',
      'stale-if-error': '3600',
      'stale-while-revalidate': '3600',
    };
    for (const candidate of [policy, CachePolicy.fromObject(legacy)]) {
      candidate.now = policy.now;
      assertCacheMiss(candidate, 'MAX-STALE=999999');
      assert.equal(candidate.useStaleWhileRevalidate(), false);
      assert.equal(
        candidate.revalidatedPolicy(request, { status: 500, headers: {} }).modified,
        true,
      );
    }
  }
  const original = cachePolicy(
    { 'cache-control': 'max-age=60' },
    {},
    { 'cache-control': 'No-Store' },
  );
  const legacy = original.toObject();
  legacy.reqcc = { 'No-Store': true };
  assert.equal(original.storable(), false);
  assert.equal(CachePolicy.fromObject(legacy).storable(), false);
});

test('shared s-maxage responses require validation when stale and retain their freshness lifetime', () => {
  for (const shared of [true, false]) {
    const policy = cachePolicy(
      {
        'cache-control':
          'public, max-age=60, s-maxage=60, stale-if-error=3600, stale-while-revalidate=3600',
      },
      { shared },
    );
    assert.equal(policy.maxAge(), 60);
    assert.equal(policy.useStaleWhileRevalidate(), !shared);
    assert.equal(policy.revalidatedPolicy(request, { status: 500, headers: {} }).modified, shared);
    if (shared) assertCacheMiss(policy, 'max-stale=999999');
    else
      assert.equal(
        policy.satisfiesWithoutRevalidation({
          ...request,
          headers: { ...request.headers, 'cache-control': 'max-stale=999999' },
        }),
        true,
      );
    policy.now = () => policy.toObject().t;
    assert.equal(policy.satisfiesWithoutRevalidation(request), true);
  }
});

test('empty or duplicate directives cannot clear a cache reuse restriction', () => {
  for (const directive of [
    'no-cache',
    'no-store',
    'private',
    'proxy-revalidate',
    'must-revalidate',
  ]) {
    for (const restriction of [`${directive}=""`, `${directive}, ${directive.toUpperCase()}=""`]) {
      const policy = cachePolicy({
        'cache-control': `${restriction}, max-age=60, stale-if-error=3600, stale-while-revalidate=3600`,
      });
      assertCacheMiss(policy, 'max-stale=999999');
      assert.equal(policy.useStaleWhileRevalidate(), false);
      assert.equal(policy.revalidatedPolicy(request, { status: 500, headers: {} }).modified, true);
      const legacy = policy.toObject();
      legacy.rescc[directive] = '';
      const restored = CachePolicy.fromObject(legacy);
      restored.now = policy.now;
      assertCacheMiss(restored, 'max-stale=999999');
    }
  }
  assert.equal(
    cachePolicy(
      { 'cache-control': 'max-age=60' },
      {},
      {
        'cache-control': 'no-store, NO-STORE=""',
      },
    ).storable(),
    false,
  );
});

test('empty and duplicate freshness limits never fall back to a longer lifetime', () => {
  const expires = new Date(Date.now() + 86400000).toUTCString();
  for (const directive of ['max-age', 's-maxage']) {
    for (const values of [
      '0, MAX-AGE=""',
      '3600, MAX-AGE=0',
      '0, max-age=3600',
      '3600, max-age=60',
      '""',
      '0',
      '',
    ]) {
      const limit = values
        .replaceAll('MAX-AGE', directive.toUpperCase())
        .replaceAll('max-age', directive);
      const headers = { expires, 'cache-control': `${directive}=${limit}` };
      if (directive === 's-maxage') headers['cache-control'] += ', max-age=3600';
      const policy = cachePolicy(headers);
      for (const candidate of [policy, CachePolicy.fromObject(policy.toObject())]) {
        candidate.now = policy.now;
        assert.equal(candidate.maxAge(), 0, headers['cache-control']);
        assert.equal(candidate.stale(), true);
        assertCacheMiss(candidate, '');
      }
      const snapshot = policy.toObject();
      snapshot.rescc = { [directive]: '0', [directive.toUpperCase()]: '' };
      if (directive === 's-maxage') snapshot.rescc['max-age'] = '3600';
      const legacy = CachePolicy.fromObject(snapshot);
      legacy.now = policy.now;
      assert.equal(legacy.maxAge(), 0);
      assertCacheMiss(legacy, '');
    }
  }
  const privatePolicy = cachePolicy(
    { 'cache-control': 's-maxage=0, S-MAXAGE="", max-age=3600' },
    { shared: false },
  );
  assert.equal(privatePolicy.maxAge(), 3600);
  assert.equal(privatePolicy.satisfiesWithoutRevalidation(request), true);
  const ordinary = cachePolicy({ 'cache-control': 'max-age=3600', expires });
  assert.equal(ordinary.maxAge(), 3600);
  for (const maxAge of ['max-age=""', 'max-age=0, MAX-AGE=""', 'max-age=3600, max-age=0']) {
    assertCacheMiss(ordinary, maxAge);
  }
});

test('stale error fallback validates Vary and preserves explicit cookie opt-ins', () => {
  const varying = cachePolicy(
    {
      vary: 'accept-language',
      'cache-control': 'max-age=60, stale-if-error=3600',
    },
    {},
    { 'accept-language': 'it' },
  );
  assert.equal(
    varying.revalidatedPolicy(
      {
        ...request,
        headers: { ...request.headers, 'accept-language': 'en' },
      },
      { status: 500, headers: {} },
    ).modified,
    true,
  );
  for (const [optIn, options] of [
    ['public', {}],
    ['immutable', {}],
    ['private', { shared: false }],
  ]) {
    const policy = cachePolicy(
      {
        'set-cookie': 'session=user-a',
        'cache-control': `${optIn}, max-age=60, stale-if-error=3600, stale-while-revalidate=3600`,
      },
      options,
    );
    assert.equal(policy.useStaleWhileRevalidate(), true);
    assert.equal(policy.revalidatedPolicy(request, { status: 500, headers: {} }).policy, policy);
  }
});

test('comma header parsing preserves whitespace and matching semantics', () => {
  const policy = cachePolicy(
    {
      connection: ' x-remove \t, \t x-other ',
      'x-remove': 'hop-by-hop',
      'x-other': 'hop-by-hop',
      'x-keep': 'end-to-end',
      vary: ' Accept-Language \t, \t Accept-Encoding ',
      'cache-control': 'max-age=3600',
    },
    {},
    { 'accept-language': 'it', 'accept-encoding': 'gzip' },
  );
  const headers = policy.responseHeaders();
  assert.equal(headers.connection, undefined);
  assert.equal(headers['x-remove'], undefined);
  assert.equal(headers['x-other'], undefined);
  assert.equal(headers['x-keep'], 'end-to-end');
  for (const [language, encoding, matches] of [
    ['it', 'gzip', true],
    ['en', 'gzip', false],
    ['it', 'br', false],
  ]) {
    assert.equal(
      policy.satisfiesWithoutRevalidation({
        ...request,
        headers: { ...request.headers, 'accept-language': language, 'accept-encoding': encoding },
      }),
      matches,
    );
  }
});

test('Vary wildcards prohibit every stale reuse path, including direct methods', () => {
  for (const vary of ['*', ' * ', 'accept-language, *', '*, accept-language']) {
    const policy = cachePolicy({
      vary,
      'cache-control': 'max-age=0, stale-while-revalidate=3600, stale-if-error=3600',
    });
    for (const candidate of [policy, CachePolicy.fromObject(policy.toObject())]) {
      candidate.now = () => policy.toObject().t + 1000;
      assert.equal(candidate.maxAge(), 0);
      assert.equal(candidate.useStaleWhileRevalidate(), false);
      assertCacheMiss(candidate, 'max-stale=999999');
      const result = candidate.revalidatedPolicy(request, { status: 500, headers: {} });
      assert.notEqual(result.policy, candidate);
      assert.equal(result.modified, true);
      assert.equal(result.matches, false);
    }
  }
});

test('comma header parsing bounds work on long whitespace without a separator', () => {
  const token = `x-first${'\t'.repeat(80000)}x-last`;
  const policy = cachePolicy({
    connection: `${token}, x-remove`,
    'x-remove': 'hop-by-hop',
    'x-keep': 'end-to-end',
    vary: token,
    'cache-control': 'max-age=3600',
  });
  const headers = runInNewContext('policy.responseHeaders()', { policy }, { timeout: 1000 });
  assert.equal(headers['x-remove'], undefined);
  assert.equal(headers['x-keep'], 'end-to-end');
  assert.equal(
    runInNewContext(
      'policy.satisfiesWithoutRevalidation(request)',
      { policy, request },
      { timeout: 1000 },
    ),
    true,
  );
});

test(
  'cacheable-request never serves another user cookie after origin failure',
  { timeout: 10000 },
  async (t) => {
    let requests = 0;
    const server = createServer((_request, response) => {
      requests++;
      if (requests === 1) {
        response.writeHead(200, {
          'set-cookie': 'session=user-a',
          'cache-control': 'max-age=60, stale-if-error=3600',
          age: '120',
        });
        response.end('user-a account');
      } else {
        response.writeHead(500, { 'cache-control': 'no-store' });
        response.end('origin unavailable');
      }
    });
    t.after(
      () =>
        new Promise((resolve) => {
          server.closeAllConnections();
          server.close(resolve);
        }),
    );
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');

    let stored;
    const persisted = new Promise((resolve) => {
      stored = resolve;
    });
    class CacheStore extends Map {
      set(key, value) {
        super.set(key, value);
        stored();
        return this;
      }
    }
    const cacheableRequest = new (require('cacheable-request'))(httpRequest, new CacheStore());
    const port = server.address().port;
    const fetch = (headers = {}) =>
      new Promise((resolve, reject) => {
        const pending = cacheableRequest({
          protocol: 'http:',
          hostname: '127.0.0.1',
          port,
          path: '/account',
          headers: { host: `127.0.0.1:${port}`, ...headers },
        });
        pending.on('error', reject);
        pending.on('request', (request) => {
          request.on('error', reject);
          request.end();
        });
        pending.on('response', (response) => {
          (async () => {
            const chunks = [];
            for await (const chunk of response) chunks.push(chunk);
            return {
              status: response.statusCode,
              headers: response.headers,
              fromCache: response.fromCache,
              body: Buffer.concat(chunks).toString(),
            };
          })().then(resolve, reject);
        });
      });
    assert.equal((await fetch()).body, 'user-a account');
    await persisted;
    const failed = await fetch({ 'cache-control': 'max-stale=999999' });
    assert.equal(requests, 2);
    assert.equal(failed.status, 500);
    assert.equal(failed.fromCache, false);
    assert.equal(failed.headers['set-cookie'], undefined);
    assert.equal(failed.body, 'origin unavailable');
  },
);
