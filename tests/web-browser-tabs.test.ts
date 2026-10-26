import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter, getEventListeners } from 'node:events';
import {
  WebBrowserTabs,
  isAbortedWebNavigation,
  isWebBrowserRouteRequestAllowed,
  isWebBrowserCommand,
  resolveWebBrowserAddress,
  webBrowserTabLimit,
  webBrowserUrlLimit,
  isWebBrowserFavicon,
  readWebBrowserFavicon,
  fetchWebBrowserFavicon,
  webBrowserFaviconByteLimit,
  webBrowserFaviconUrlLimit,
} from '../electron/web-browser-tabs.ts';

test('browser snapshots show tunnel metadata only for the VPN route', () => {
  const tabs = new WebBrowserTabs<number>();
  tabs.add('page', 1, 'https://site.test/');
  const tunnel = { name: 'Office', kind: 'WireGuard' };
  assert.deepEqual(tabs.snapshot('vpn', undefined, tunnel).tunnel, tunnel);
  assert.equal(tabs.snapshot('direct', undefined, tunnel).tunnel, undefined);
  assert.equal(tabs.snapshot('vpn').tunnel, undefined);
});

test('favicon metadata accepts bounded image data only, never remote resources', () => {
  const image = 'data:image/png;base64,AQID';
  assert.equal(isWebBrowserFavicon(image), true);
  for (const value of [
    null,
    undefined,
    '',
    'https://site.test/icon.png',
    'data:text/html;base64,AQID',
    'data:image/png,unencoded',
    'data:image/png;base64,<>',
    `data:image/png;base64,${'A'.repeat(webBrowserFaviconUrlLimit)}`,
  ]) {
    assert.equal(isWebBrowserFavicon(value), false);
  }
  const tabs = new WebBrowserTabs<number>();
  tabs.add('page', 1, 'https://site.test/');
  tabs.update('page', { favicon: image });
  assert.equal(tabs.snapshot('direct').tabs[0].favicon, image);
  tabs.update('page', { favicon: 'https://site.test/icon.png' });
  assert.equal(tabs.snapshot('direct').tabs[0].favicon, undefined);
});

test('favicon reads accept image MIME types and stop invalid, empty and oversized bodies', async () => {
  const response = (body: BodyInit | null, headers = {}, status = 200) =>
    new Response(body, {
      headers: { 'content-type': 'image/png; charset=binary', ...headers },
      status,
    });
  assert.equal(
    await readWebBrowserFavicon(response(new Uint8Array([1, 2, 3]))),
    'data:image/png;base64,AQID',
  );
  for (const value of [
    response(null),
    response(''),
    response('not-found', {}, 404),
    response('html', { 'content-type': 'text/html' }),
    new Response('no-type', { headers: { 'content-type': '' } }),
    response('large', { 'content-length': String(webBrowserFaviconByteLimit + 1) }),
  ]) {
    assert.equal(await readWebBrowserFavicon(value), undefined);
  }
  let cancelled = false;
  const oversized = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(webBrowserFaviconByteLimit + 1));
    },
    cancel() {
      cancelled = true;
    },
  });
  assert.equal(
    await readWebBrowserFavicon(
      new Response(oversized, {
        headers: { 'content-type': 'image/x-icon' },
      }),
    ),
    undefined,
  );
  assert.equal(cancelled, true);
  const broken = new ReadableStream({
    start(controller) {
      controller.error(new Error('Read failed'));
    },
  });
  await assert.rejects(
    readWebBrowserFavicon(
      new Response(broken, {
        headers: { 'content-type': 'image/png' },
      }),
    ),
    /Read failed/,
  );
});

test('native favicon transport bounds response bytes and releases every request on completion or failure', async () => {
  const requests: any[] = [];
  let reply: any = {};
  const client = {
    fetchData: async (_url: string, _signal: AbortSignal) =>
      new Response(new Uint8Array([1, 2, 3]), { headers: { 'content-type': 'image/png' } }),
    request: (url: string, pageOrigin: string) => {
      const incoming: any = Object.assign(new EventEmitter(), {
        statusCode: reply.status ?? 200,
        headers:
          reply.mime === null
            ? {}
            : {
                'content-type': reply.arrays
                  ? [reply.mime ?? 'image/png']
                  : (reply.mime ?? 'image/png'),
                'content-length': reply.arrays
                  ? [String(reply.length ?? 3)]
                  : String(reply.length ?? 3),
              },
      });
      const request: any = Object.assign(new EventEmitter(), {
        url,
        pageOrigin,
        incoming,
        aborted: false,
        ended: false,
      });
      request.abort = () => {
        if (!request.aborted) {
          request.aborted = true;
          request.emit('abort');
          request.emit('close');
        }
      };
      request.end = () => {
        request.ended = true;
        request.emit('close');
        if (reply.beforeResponse) return;
        request.emit('response', incoming);
        if (reply.hold) return;
        for (const chunk of reply.chunks ?? [new Uint8Array([1, 2, 3])])
          incoming.emit('data', chunk);
        if (reply.event === 'request-error')
          request.emit('error', new Error('Private diagnostics'));
        else if (reply.event) incoming.emit(reply.event, new Error('Private diagnostics'));
        else incoming.emit('end');
      };
      requests.push(request);
      return request;
    },
  };
  const route = (url: string) => url;
  const load = (signal = new AbortController().signal, url = 'https://icons.test/icon') =>
    fetchWebBrowserFavicon(client, 'https://page.test/secret?token=synthetic', url, route, signal);
  assert.equal(await load(), 'data:image/png;base64,AQID');
  assert.equal(requests[0].pageOrigin, 'https://page.test');
  assert.equal(requests[0].aborted, true);
  for (const response of [
    { status: 404 },
    { status: 199 },
    { status: 304 },
    { mime: null },
    { mime: 'text/html' },
    { length: webBrowserFaviconByteLimit + 1 },
    { chunks: [new Uint8Array(40_000), new Uint8Array(30_000)] },
    { chunks: [] },
    { event: 'error' },
    { event: 'aborted' },
    { event: 'request-error' },
  ]) {
    reply = response;
    const controller = new AbortController();
    assert.equal(await load(controller.signal), undefined);
    assert.equal(requests.at(-1).aborted, true);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  }
  reply = {
    arrays: true,
    mime: 'IMAGE/PNG; charset=binary',
    chunks: [new Uint8Array([1]), new Uint8Array([2, 3])],
  };
  assert.equal(await load(), 'data:image/png;base64,AQID');
  const before = requests.length;
  assert.equal(await load(undefined, 'data:image/png;base64,AQID'), 'data:image/png;base64,AQID');
  const cancelled = new AbortController();
  cancelled.abort();
  assert.equal(await load(cancelled.signal), undefined);
  assert.equal(await load(undefined, 'x'.repeat(webBrowserFaviconUrlLimit + 1)), undefined);
  assert.equal(await load(undefined, 'file:///private'), undefined);
  assert.equal(
    await fetchWebBrowserFavicon(
      client,
      'https://page.test/',
      'https://outside.test/',
      () => undefined,
      new AbortController().signal,
    ),
    undefined,
  );
  assert.equal(requests.length, before);
  await assert.rejects(
    fetchWebBrowserFavicon(
      client,
      'invalid',
      'https://icons.test/',
      route,
      new AbortController().signal,
    ),
  );
  await assert.rejects(
    fetchWebBrowserFavicon(
      {
        ...client,
        request: () => {
          throw new Error('Unavailable');
        },
      },
      'https://page.test/',
      'https://icons.test/',
      route,
      new AbortController().signal,
    ),
  );
  for (const hold of [{ hold: true }, { beforeResponse: true }]) {
    reply = hold;
    const controller = new AbortController();
    const pending = load(controller.signal);
    const request = requests.at(-1);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 1);
    controller.abort();
    assert.equal(await pending, undefined);
    request.emit('response', request.incoming);
    request.incoming.emit('data', new Uint8Array(70_000));
    request.incoming.emit('end');
    request.emit('error', new Error('Late error'));
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  }
  const controller = new AbortController();
  const duringCreation = {
    ...client,
    request: (url: string, origin: string) => {
      controller.abort();
      return client.request(url, origin);
    },
  };
  assert.equal(
    await fetchWebBrowserFavicon(
      duringCreation,
      'https://page.test/',
      'https://icons.test/',
      route,
      controller.signal,
    ),
    undefined,
  );
  assert.equal(requests.at(-1).ended, false);
});

test('forwarder origin enforcement includes WebSockets and rejects malformed requests', () => {
  for (const [url, origin, allowed] of [
    ['wss://127.0.0.1:51000/live', 'https://127.0.0.1:51000', true],
    ['ws://127.0.0.1:51000/live', 'http://127.0.0.1:51000', true],
    ['https://127.0.0.1:51000/page', 'https://127.0.0.1:51000', true],
    ['https://outside.internal/page', 'https://127.0.0.1:51000', false],
    ['wss://127.0.0.1:51001/live', 'https://127.0.0.1:51000', false],
    ['chrome-extension://test/popup.html', 'https://127.0.0.1:51000', true],
    ['invalid-url', 'https://127.0.0.1:51000', false],
  ] as const)
    assert.equal(isWebBrowserRouteRequestAllowed(url, origin), allowed, url);
});

test('redirect cancellations do not become page failures', () => {
  for (const value of [{ code: 'ERR_ABORTED' }, { errno: -3 }])
    assert.equal(isAbortedWebNavigation(value), true);
  for (const value of [undefined, null, false, 'ERR_ABORTED', {}, { code: 'ERR_FAILED' }])
    assert.equal(isAbortedWebNavigation(value), false);
});

test('browser tabs select independently and closing a tab preserves its siblings', () => {
  const tabs = new WebBrowserTabs<object>();
  assert.equal(tabs.get(), undefined);
  assert.equal(tabs.adjacent(1), '');
  const first = {},
    second = {},
    third = {};
  tabs.add('first', first, 'https://router.test/');
  tabs.add('second', second, 'about:blank');
  tabs.add('third', third, 'https://switch.test/');
  assert.equal(tabs.size, 3);
  assert.deepEqual(tabs.all(), [first, second, third]);
  assert.equal(tabs.get(), third);
  assert.equal(tabs.adjacent(1), 'first');
  assert.equal(tabs.select('missing'), false);
  assert.equal(tabs.select('second'), true);
  assert.equal(tabs.adjacent(-1), 'first');
  assert.equal(tabs.remove('missing'), undefined);
  assert.equal(tabs.remove('first'), first);
  assert.equal(tabs.activeId, 'second');
  assert.equal(tabs.remove('second'), second);
  assert.equal(tabs.activeId, 'third');
  assert.equal(tabs.remove('third'), undefined, 'the final tab keeps its browser and tunnel alive');
  const left = new WebBrowserTabs<number>();
  left.add('a', 1, 'about:blank');
  left.add('b', 2, 'about:blank');
  left.remove('b');
  assert.equal(left.activeId, 'a');
});

test('metadata snapshots are bounded and cannot mutate native browser state', () => {
  const tabs = new WebBrowserTabs<number>();
  tabs.add('one', 1, 'about:blank');
  assert.equal(tabs.snapshot('direct').tabs[0].title, 'New tab');
  tabs.update('missing', { title: 'Ignored' });
  tabs.update('one', {
    title: 't'.repeat(300),
    url: 'u'.repeat(9000),
    error: 'e'.repeat(3000),
    canGoBack: true,
  });
  const state = tabs.snapshot('vpn', 'https://router.test');
  assert.equal(state.route, 'vpn');
  assert.equal(state.restrictedOrigin, 'https://router.test');
  assert.equal(state.tabs[0].title.length, 256);
  assert.equal(state.tabs[0].url.length, webBrowserUrlLimit);
  assert.equal(state.tabs[0].error?.length, 2048);
  assert.equal(state.tabs[0].canGoBack, true);
  state.tabs[0].title = 'Changed outside native browser';
  assert.notEqual(tabs.snapshot('direct').tabs[0].title, state.tabs[0].title);
  tabs.update('one', { error: undefined });
  assert.equal(tabs.snapshot('direct').tabs[0].error, undefined);
});

test('browser instances and resource limits are independent', () => {
  const first = new WebBrowserTabs<number>(),
    second = new WebBrowserTabs<number>();
  first.add('same', 1, 'https://a.test/');
  second.add('same', 2, 'https://b.test/');
  assert.equal(first.get(), 1);
  assert.equal(second.get(), 2);
  assert.throws(() => first.add('', 0, 'about:blank'));
  assert.throws(() => first.add('same', 0, 'about:blank'));
  for (let index = 1; index < webBrowserTabLimit; index++)
    first.add(`tab-${index}`, index, 'about:blank');
  assert.throws(() => first.add('excess', 0, 'about:blank'), /up to 32/);
  assert.equal(second.size, 1);
});

test('browser IPC validates operation-specific payloads before native actions', () => {
  for (const operation of ['back', 'forward', 'reload', 'stop', 'zoom-in', 'zoom-out', 'new-tab']) {
    assert.equal(isWebBrowserCommand({ sessionId: 'session-123', operation }), true);
  }
  for (const operation of ['select-tab', 'close-tab']) {
    assert.equal(
      isWebBrowserCommand({ sessionId: 'session-123', operation, tabId: 'tab-1' }),
      true,
    );
    for (const tabId of [undefined, '', 12, 'a'.repeat(129), ' tab ']) {
      assert.equal(isWebBrowserCommand({ sessionId: 's', operation, tabId }), false);
    }
  }
  assert.equal(
    isWebBrowserCommand({ sessionId: 's', operation: 'navigate', url: 'router.local' }),
    true,
  );
  for (const url of [undefined, 12, '', 'x'.repeat(webBrowserUrlLimit + 1)]) {
    assert.equal(isWebBrowserCommand({ sessionId: 's', operation: 'navigate', url }), false);
  }
  for (const value of [
    null,
    false,
    '',
    {},
    { sessionId: 123 },
    { sessionId: '' },
    { sessionId: ' x' },
    { sessionId: 'x'.repeat(129) },
    { sessionId: 's', operation: 'execute' },
    { sessionId: 's', operation: ['reload'] },
    { sessionId: 's', operation: new String('back') },
  ]) {
    assert.equal(isWebBrowserCommand(value), false);
  }
});

test('address entry defaults to HTTPS and rejects credentials and non-web schemes', () => {
  for (const [input, expected] of [
    [' router.internal/admin ', 'https://router.internal/admin'],
    ['router.internal:8443/path?q=1#tab', 'https://router.internal:8443/path?q=1#tab'],
    ['http://10.2.0.4/', 'http://10.2.0.4/'],
    ['https://[fd00::1]:8443/', 'https://[fd00::1]:8443/'],
    ['https://example.test/a%20b', 'https://example.test/a%20b'],
  ])
    assert.equal(resolveWebBrowserAddress(input), expected);
  for (const input of [
    '',
    ' ',
    'http://',
    'bad host',
    'bad\u0000host',
    'x'.repeat(webBrowserUrlLimit + 1),
    'file:///C:/secret',
    'javascript:alert(1)',
    'data:text/html,hello',
    'about:blank',
    'chrome://settings',
    'ftp://example.test/',
    'https://user:secret@example.test',
    'https://user@example.test',
  ]) {
    assert.equal(resolveWebBrowserAddress(input), undefined, input);
  }
});
