declare const React: typeof import('react');
declare const createRoot: typeof import('react-dom/client').createRoot;
declare const assert: typeof import('node:assert/strict');
declare const WebSurface: typeof import('../../src/components/WebSurface').WebSurface;
declare const BrowserSessionSurface: typeof WebSurface;
declare const resolveBrowser: () => void;

async function runWebBrowserTests() {
  const root = createRoot(document.getElementById('root')!);
  const commands: any[] = [],
    bounds: any[] = [],
    popups: any[] = [],
    reconnects: string[] = [];
  const listeners = new Set<(event: any) => void>();
  let rejectCommand = false;
  let reconnectCommand = async () => {};
  const previewImage =
    'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
  let capturePreview = async (): Promise<string | undefined> => previewImage;
  let nativeVisible = false;
  const acknowledgements: { id: string; decoded: boolean; paintedFrames: number }[] = [];
  let paintedFrames = 0;
  const preview = () =>
    document.querySelector<HTMLImageElement>('[aria-label="Web browser canvas"] > img');
  window.wormhole = {
    commandWebSession: async (request: any) => {
      commands.push(request);
      if (rejectCommand) throw new Error('This address cannot use the VPN route.');
      if (request.operation === 'reconnect-vpn') await reconnectCommand();
    },
    setWebSessionBounds: async (request: any) => {
      bounds.push(request);
      if (request.capturePreview) return capturePreview();
      if (request.previewId) {
        const image = preview();
        acknowledgements.push({
          id: request.previewId,
          decoded: Boolean(image?.complete && image.naturalWidth),
          paintedFrames,
        });
      }
      nativeVisible = request.visible;
    },
    onWebEvent: (listener: (event: any) => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    openBitwardenPopup: async (request: any) => {
      popups.push(request);
      return { open: true };
    },
    closeBitwardenPopup: async (sessionId: string) => {
      popups.push({ close: sessionId });
    },
  } as any;
  const first = {
    id: 'one',
    title: 'Gateway',
    url: 'https://gateway.internal/',
    isLoading: false,
    canGoBack: true,
    canGoForward: true,
    favicon: 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
  };
  const second = { ...first, id: 'two', title: 'Switch', url: 'http://switch.internal/' };
  const third = { ...first, id: 'three', title: 'Monitoring', url: 'https://monitor.internal/' };
  let session: any = {
    id: 'browser',
    protocol: 'https',
    host: 'gateway.internal',
    status: 'connected',
    webBrowser: {
      activeTabId: 'one',
      tabs: [first, second, third],
      route: 'vpn',
      tunnel: { name: 'Office', kind: 'WireGuard' },
    },
  };
  let props = { isActive: true, isAuthorized: true, isOccluded: false, bitwardenOpen: false };
  let hostHeight = '100vh';
  let hostWidth = '100%';
  const render = async (patch = {}, nextProps = {}) => {
    session = { ...session, ...patch };
    props = { ...props, ...nextProps };
    await React.act(async () => {
      root.render(
        <div style={{ height: hostHeight, width: hostWidth }}>
          <WebSurface session={session} {...props} onReconnect={(id) => reconnects.push(id)} />
        </div>,
      );
    });
    await new Promise(requestAnimationFrame);
  };
  const click = async (label: string) => {
    const button = document.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
    assert.ok(button, label);
    await React.act(async () => button.click());
  };
  const textClick = async (label: string) => {
    const button = [...document.querySelectorAll<HTMLButtonElement>('button')].find(
      (candidate) => candidate.textContent?.trim() === label,
    );
    assert.ok(button, label);
    await React.act(async () => button.click());
  };
  const key = async (target: Element, value: string, options = {}) => {
    const event = new KeyboardEvent('keydown', {
      bubbles: true,
      cancelable: true,
      key: value,
      ...options,
    });
    await React.act(async () => target.dispatchEvent(event));
    return event;
  };
  const assertNewTabPosition = () => {
    const list = document.querySelector('[role="tablist"]')!;
    const last = [...list.querySelectorAll('[role="tab"]')].at(-1)!.parentElement!;
    const add = document.querySelector<HTMLButtonElement>('[aria-label="New tab"]')!;
    const gap = add.getBoundingClientRect().left - last.getBoundingClientRect().right;
    assert.ok(gap >= 0 && gap <= 8, `New tab button is ${gap}px away from the final tab`);
    assert.ok(add.getBoundingClientRect().width >= 24, 'New tab button must remain usable');
  };
  await render();
  assert.equal(document.querySelectorAll('[role="tab"]').length, 3);
  assertNewTabPosition();
  const icon = document.querySelector<HTMLImageElement>('[role="tab"] img')!;
  assert.equal(icon.getAttribute('src'), first.favicon);
  await React.act(async () => icon.dispatchEvent(new Event('error')));
  assert.equal(document.querySelector('[role="tab"]')!.querySelector('img'), null);
  assert.ok(document.querySelectorAll('[role="tab"]')[1].querySelector('img'));
  assert.ok(document.body.textContent?.includes("Office's WireGuard ACTIVE"));
  assert.ok(
    document.querySelector(
      '[data-test-tooltip="Office\'s WireGuard ACTIVE. All tabs use this browser’s VPN tunnel"]',
    ),
  );
  const longName = 'Corporate VPN '.repeat(20);
  await render({
    webBrowser: { ...session.webBrowser, tunnel: { name: longName, kind: 'Cisco Secure Client' } },
  });
  const badge = document.querySelector<HTMLElement>(
    '[data-test-tooltip$="All tabs use this browser’s VPN tunnel"]',
  )!;
  const badgeText = badge.querySelector<HTMLElement>('.truncate')!;
  assert.ok(
    badge.getAttribute('data-test-tooltip')?.startsWith(`${longName}'s Cisco Secure Client ACTIVE`),
  );
  assert.ok(badgeText.scrollWidth > badgeText.clientWidth, 'Long VPN names must truncate');
  assertNewTabPosition();
  await render({
    webBrowser: { ...session.webBrowser, tunnel: { name: 'Office', kind: 'OpenVPN' } },
  });
  assert.ok(document.body.textContent?.includes("Office's OpenVPN ACTIVE"));
  await render({ webBrowser: { ...session.webBrowser, vpnStatus: 'disconnected' } });
  const recovery = document.querySelector<HTMLButtonElement>(
    'button[aria-label="VPN disconnected. Reconnect?"]',
  )!;
  assert.ok(recovery.classList.contains('bg-red-700'));
  assert.ok(recovery.classList.contains('text-white'));
  assert.equal(document.querySelectorAll('[role="tab"]').length, 3);
  assert.equal(nativeVisible, true);
  await click('VPN disconnected. Reconnect?');
  assert.deepEqual(commands.pop(), { sessionId: 'browser', operation: 'reconnect-vpn' });
  assert.equal(reconnects.length, 0);
  await render({ webBrowser: { ...session.webBrowser, vpnStatus: 'reconnecting' } });
  assert.equal(
    document.querySelector<HTMLButtonElement>('button[aria-label="Reconnecting VPN…"]')!.disabled,
    true,
  );
  assert.equal(nativeVisible, true);
  await render({ webBrowser: { ...session.webBrowser, vpnStatus: 'active' } });
  assert.ok(document.body.textContent?.includes("Office's OpenVPN ACTIVE"));
  assert.equal(document.querySelectorAll('[role="tab"]').length, 3);

  for (const interruption of ['lock', 'retry']) {
    await render({ webBrowser: { ...session.webBrowser, vpnStatus: 'disconnected' } });
    let rejectReconnect!: (error: Error) => void;
    reconnectCommand = () =>
      new Promise<void>((_resolve, reject) => {
        rejectReconnect = reject;
      });
    await click('VPN disconnected. Reconnect?');
    if (interruption === 'lock') {
      await render({}, { isAuthorized: false });
      await render({}, { isAuthorized: true });
    } else {
      reconnectCommand = async () => {};
      await click('VPN disconnected. Reconnect?');
      await render({ webBrowser: { ...session.webBrowser, vpnStatus: 'active' } });
    }
    await React.act(async () => rejectReconnect(new Error('The previous VPN attempt failed.')));
    assert.equal(document.querySelector('[role="alert"]')?.textContent, undefined);
  }

  await render({ webBrowser: { ...session.webBrowser, vpnStatus: 'disconnected' } });
  reconnectCommand = async () => {
    throw new Error('VPN authentication failed.');
  };
  await click('VPN disconnected. Reconnect?');
  assert.equal(document.querySelector('[role="alert"]')?.textContent, 'VPN authentication failed.');
  reconnectCommand = async () => {};
  await click('VPN disconnected. Reconnect?');
  await render({ webBrowser: { ...session.webBrowser, vpnStatus: 'active' } });

  await render({ status: 'failed' });
  assert.ok(!document.body.textContent?.includes('ACTIVE'));
  await render({ status: 'connected' });
  assert.equal(document.querySelector<HTMLInputElement>('input')!.value, first.url);
  assert.ok(bounds.some((value) => value.visible && value.height > 100));
  const frames = async (count = 1) => {
    for (let index = 0; index < count; index++) {
      await React.act(async () => {
        await new Promise(requestAnimationFrame);
      });
    }
  };
  const waitFor = async (predicate: () => boolean) => {
    const deadline = Date.now() + 5000;
    while (!predicate()) {
      assert.ok(Date.now() < deadline, 'Timed out waiting for browser presentation');
      await React.act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
      });
    }
  };
  const originalDecode = HTMLImageElement.prototype.decode;
  hostHeight = '32px';
  await render();
  await frames(2);
  assert.equal(
    document.querySelector('[aria-label="Web browser canvas"]')!.getBoundingClientRect().height,
    0,
  );
  assert.equal(
    nativeVisible,
    false,
    'A collapsed split must not leave native page pixels over its neighbours',
  );
  hostHeight = '100vh';
  await render();
  await frames();
  assert.equal(nativeVisible, true);
  hostWidth = '0px';
  await render({}, { isActive: false });
  assert.equal(
    nativeVisible,
    false,
    'An inactive zero-width pane must still hide its native content',
  );
  hostWidth = '100%';
  await render({}, { isActive: true });
  await frames();
  assert.equal(nativeVisible, true);
  const pendingDecodes: (() => void)[] = [];
  let delayDecode = true;
  HTMLImageElement.prototype.decode = function () {
    return originalDecode
      .call(this)
      .then(() =>
        delayDecode ? new Promise<void>((resolve) => pendingDecodes.push(resolve)) : undefined,
      );
  };
  let monitorFrames = true;
  const blackFrames: number[] = [];
  let monitorFrame = 0;
  const inspectFrame = () => {
    const image = preview();
    if (image?.complete && image.naturalWidth) paintedFrames++;
    if (!nativeVisible && !image?.naturalWidth) blackFrames.push(performance.now());
    if (monitorFrames) monitorFrame = requestAnimationFrame(inspectFrame);
  };
  monitorFrame = requestAnimationFrame(inspectFrame);
  const finishDecode = async () => {
    delayDecode = false;
    await React.act(async () => pendingDecodes.splice(0).forEach((resolve) => resolve()));
    await waitFor(() => Boolean(preview()?.naturalWidth));
  };
  try {
    await render({}, { isOccluded: true });
    await waitFor(() => pendingDecodes.length > 0);
    assert.equal(nativeVisible, true, 'A slow image decode must retain the native page');
    assert.equal(preview(), null);
    assert.equal(acknowledgements.length, 0);
    await finishDecode();
    assert.equal(preview()?.getAttribute('src'), previewImage);
    await frames(2);
    assert.equal(nativeVisible, false);
    assert.ok(acknowledgements.length > 0);
    assert.ok(acknowledgements.every((ack) => ack.decoded && ack.paintedFrames > 0));
    const firstPreviewId = acknowledgements.at(-1)!.id;

    // Selecting Edit closes the tree menu before the connection dialog opens.
    await render({}, { isOccluded: false });
    assert.equal(nativeVisible, true);
    assert.ok(preview(), 'Keep the painted preview beneath the live page during restoration');
    delayDecode = true;
    await render({}, { isOccluded: true });
    await waitFor(() => pendingDecodes.length > 0);
    assert.ok(preview(), 'Opening the editor must not clear the previous painted frame');
    assert.equal(nativeVisible, true);
    await finishDecode();
    await frames(2);
    assert.equal(nativeVisible, false);
    assert.notEqual(acknowledgements.at(-1)!.id, firstPreviewId);
    window.dispatchEvent(new Event('resize'));
    await frames(2);
    assert.ok(preview(), 'Resizing the dialog must retain its page preview');
    await render({}, { isOccluded: false });
    assert.ok(preview());
    await frames();
    assert.equal(preview(), null);
    assert.equal(nativeVisible, true);
    assert.deepEqual(
      blackFrames,
      [],
      'Every frame needs either the native page or a decoded preview',
    );
    monitorFrames = false;
    cancelAnimationFrame(monitorFrame);
    const acknowledgementsBeforeLock = acknowledgements.length;
    delayDecode = true;
    await render({}, { isOccluded: true });
    await waitFor(() => pendingDecodes.length > 0);
    await render({}, { isAuthorized: false });
    delayDecode = false;
    await React.act(async () => pendingDecodes.splice(0).forEach((resolve) => resolve()));
    await frames(2);
    assert.equal(preview(), null, 'An image finishing decoding after lock must stay private');
    assert.equal(acknowledgements.length, acknowledgementsBeforeLock);
    await render({}, { isAuthorized: true, isOccluded: false });
  } finally {
    monitorFrames = false;
    cancelAnimationFrame(monitorFrame);
    HTMLImageElement.prototype.decode = originalDecode;
  }
  const pendingCaptures: ((image: string) => void)[] = [];
  capturePreview = () => new Promise((resolve) => pendingCaptures.push(resolve));
  await render({}, { isOccluded: true });
  await render({}, { isAuthorized: false });
  await React.act(async () =>
    pendingCaptures.splice(0).forEach((resolve) => resolve(previewImage)),
  );
  assert.equal(preview(), null, 'A capture finishing after lock must not reveal page pixels');
  assert.equal(bounds.at(-1).capturePreview, false);
  await render({}, { isAuthorized: true });
  await render({}, { isOccluded: false });
  await React.act(async () =>
    pendingCaptures.splice(0).forEach((resolve) => resolve(previewImage)),
  );
  assert.equal(
    preview(),
    null,
    'A capture finishing after menu close must not replace the live page',
  );
  capturePreview = async () => {
    throw new Error('Capture unavailable');
  };
  await render({}, { isOccluded: true });
  assert.equal(preview(), null);
  await render({}, { isOccluded: false });
  capturePreview = async () => undefined;
  await render({}, { isOccluded: true });
  assert.equal(preview(), null);
  await render({}, { isOccluded: false });
  capturePreview = async () => previewImage;
  const decodeBeforeFailure = HTMLImageElement.prototype.decode;
  HTMLImageElement.prototype.decode = async () => {
    throw new Error('Image decode failed');
  };
  await render({}, { isOccluded: true });
  await waitFor(() => bounds.at(-1).capturePreview !== true);
  assert.equal(bounds.at(-1).visible, false, 'Decode failure must keep the menu accessible');
  HTMLImageElement.prototype.decode = decodeBeforeFailure;
  await render({}, { isOccluded: false });
  for (const label of ['Back', 'Forward', 'Reload', 'New tab', 'Close Switch']) await click(label);
  assert.deepEqual(
    commands.slice(-5).map((value) => value.operation),
    ['back', 'forward', 'reload', 'new-tab', 'close-tab'],
  );
  await React.act(async () =>
    (document.querySelectorAll('[role="tab"]')[1] as HTMLButtonElement).click(),
  );
  assert.equal(commands.at(-1).tabId, 'two');
  const section = document.querySelector('section')!;
  await click('Decrease text size');
  assert.equal(commands.at(-1).operation, 'zoom-out');
  await click('Increase text size');
  assert.equal(commands.at(-1).operation, 'zoom-in');
  for (const value of ['t', 'w', 'l', 'Tab'])
    assert.equal((await key(section, value, { ctrlKey: true })).defaultPrevented, true);
  await key(section, 'Tab', { ctrlKey: true, shiftKey: true });
  assert.equal(commands.at(-1).tabId, 'three');
  await key(section, 'q', { ctrlKey: true });
  await key(section, 't');
  const tabButton = document.getElementById('web-tab-one')!;
  for (const value of ['ArrowRight', 'ArrowLeft', 'Home', 'End', 'Enter'])
    await key(tabButton, value);
  const input = document.querySelector<HTMLInputElement>('input')!;
  assert.equal(document.activeElement?.id, 'web-tab-three');
  await React.act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(
      input,
      'router.internal:8443/settings',
    );
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await React.act(async () =>
    document
      .querySelector('form')!
      .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })),
  );
  assert.equal(commands.at(-1).url, 'router.internal:8443/settings');
  rejectCommand = true;
  await click('New tab');
  assert.match(document.querySelector('[role="alert"]')!.textContent!, /VPN route/);
  rejectCommand = false;
  await render({ webBrowser: { ...session.webBrowser, activeTabId: 'two' } });
  assert.equal(input.value, second.url);
  assert.equal(document.querySelector('[role="alert"]'), null);
  await render({
    webBrowser: {
      route: 'direct',
      tunnel: { name: 'Stale VPN', kind: 'WireGuard' },
      activeTabId: 'one',
      tabs: [{ ...first, isLoading: true, canGoBack: false, canGoForward: false }],
    },
  });
  assert.ok(document.body.textContent?.includes('No VPN'));
  assert.ok(!document.body.textContent?.includes('Stale VPN'));
  assertNewTabPosition();
  assert.ok(document.querySelector('[data-test-tooltip*="No VPN tunnel is attached"]'));
  await click('Stop loading');
  assert.equal(commands.at(-1).operation, 'stop');
  assert.equal(document.querySelector<HTMLButtonElement>('[aria-label="Back"]')!.disabled, true);
  assert.equal(
    document.querySelector<HTMLButtonElement>('[aria-label="Close Gateway"]')!.disabled,
    true,
  );
  await render({
    webBrowser: {
      route: 'vpn',
      restrictedOrigin: 'https://gateway.internal',
      tunnel: { name: 'Branch', kind: 'Fortinet' },
      activeTabId: 'blank',
      tabs: [{ ...first, id: 'blank', title: 'New tab', url: 'about:blank' }],
    },
  });
  assert.equal(input.value, '');
  assert.ok(
    document.querySelector(
      '[data-test-tooltip="Branch\'s Fortinet ACTIVE. VPN access is limited to https://gateway.internal"]',
    ),
  );
  assert.equal(document.activeElement, input);
  assert.match(document.body.textContent!, /Available host/);
  assert.equal(bounds.at(-1).visible, false);
  await render({
    webBrowser: {
      route: 'vpn',
      activeTabId: 'one',
      tabs: [{ ...first, error: 'Host unavailable' }],
    },
  });
  assert.match(document.body.textContent!, /This page could not load/);
  await textClick('Reload page');
  assert.equal(commands.at(-1).operation, 'reload');
  assert.equal(reconnects.length, 0);
  await render({
    webBrowser: { route: 'vpn', activeTabId: 'one', tabs: [first] },
    bitwardenPopupUrl: 'chrome-extension://test/popup.html',
  });
  assert.ok(document.body.textContent?.includes('VPN tunnel ACTIVE'));
  await click('Open Bitwarden');
  assert.equal(popups.at(-1).sessionId, 'browser');
  assert.ok(popups.at(-1).anchor.width > 0);
  await render({}, { bitwardenOpen: true });
  await click('Close Bitwarden');
  assert.equal(popups.at(-1).close, 'browser');
  await React.act(async () => {
    for (const listener of listeners) {
      listener({ sessionId: 'other', type: 'focus-address' });
      listener({ sessionId: 'browser', type: 'navigation' });
      listener({ sessionId: 'browser', type: 'focus-address' });
    }
  });
  assert.equal(document.activeElement, input);
  window.dispatchEvent(new Event('resize'));
  await render({}, { isAuthorized: false });
  assert.equal(bounds.at(-1).visible, false);
  const count = commands.length;
  await key(section, 't', { ctrlKey: true });
  assert.equal(commands.length, count);
  const loadingOverlay = () => document.querySelector<HTMLElement>('[data-connection-transition]');
  await render(
    { status: 'connecting', title: 'Lab gateway', port: 8443, tunnelProgress: null },
    { isAuthorized: true },
  );
  const loading = loadingOverlay()!;
  assert.equal(loading.dataset.connectionTransition, 'pending');
  assert.equal(loading.querySelector('h3')?.textContent, 'Lab gateway');
  assert.match(loading.textContent!, /gateway\.internal.*HTTPS.*Port 8443.*Opening browser/);
  assert.ok(loading.querySelector('.lucide-loader-circle'));
  assert.equal(nativeVisible, false);
  await render({ tunnelProgress: { phase: 'starting', detail: 'Starting VPN' } });
  assert.match(loading.textContent!, /Starting VPN/);
  assert.ok(loading.querySelector('.lucide-shield'));
  await render({ status: 'failed', error: 'Tunnel unavailable' });
  assert.equal(loadingOverlay(), null, 'failure must expose Retry immediately');
  await textClick('Retry');
  assert.deepEqual(reconnects, ['browser']);
  await render({ status: 'failed', error: undefined });
  await render({ status: 'closed' });
  await textClick('Reconnect');
  assert.deepEqual(reconnects, ['browser', 'browser']);
  await render({
    status: 'placeholder',
    webBrowser: undefined,
    webUrl: undefined,
    port: 8443,
    tunnelProgress: null,
  });
  await render({
    status: 'connected',
    webBrowser: {
      route: 'vpn',
      activeTabId: 'tab-31',
      tabs: Array.from({ length: 32 }, (_, index) => ({
        ...first,
        id: `tab-${index}`,
        title: `Browser tab ${index + 1}`,
      })),
    },
  });
  assert.equal(loadingOverlay()?.dataset.connectionTransition, 'exit');
  assert.equal(nativeVisible, false, 'native browser must stay below the fade');
  await React.act(async () =>
    loadingOverlay()?.dispatchEvent(new Event('animationend', { bubbles: true })),
  );
  assert.equal(loadingOverlay(), null);
  assert.equal(nativeVisible, true, 'the live browser is revealed after the fade');
  const crowdedList = document.querySelector('[role="tablist"]')!;
  assert.ok(crowdedList.scrollWidth > crowdedList.clientWidth);
  const assertSelectedTabVisible = () => {
    const activeTab = crowdedList.querySelector('[aria-selected="true"]')!.parentElement!;
    const selected = activeTab.getBoundingClientRect();
    const viewport = crowdedList.getBoundingClientRect();
    const leftCurve = parseFloat(getComputedStyle(activeTab, '::before').width);
    const rightCurve = parseFloat(getComputedStyle(activeTab, '::after').width);
    assert.ok(
      selected.left - leftCurve >= viewport.left - 1 &&
        selected.right + rightCurve <= viewport.right + 1,
      'Tab selection must reveal the selected tab and its curved base',
    );
    assert.ok(
      selected.top >= viewport.top + 3.5 &&
        selected.bottom <= viewport.top + crowdedList.clientHeight + 0.5,
      'The horizontal scrollbar must leave room for the full tab',
    );
  };
  assertSelectedTabVisible();
  await render({ webBrowser: { ...session.webBrowser, activeTabId: 'tab-0' } });
  assertSelectedTabVisible();
  await render({ webBrowser: { ...session.webBrowser, activeTabId: 'tab-18' } });
  assertSelectedTabVisible();
  hostWidth = '380px';
  await render();
  await new Promise(requestAnimationFrame);
  assertSelectedTabVisible();
  hostWidth = '100%';
  await render();
  await new Promise(requestAnimationFrame);
  assertSelectedTabVisible();
  await render({ webBrowser: { ...session.webBrowser, activeTabId: 'tab-31' } });
  assertSelectedTabVisible();
  crowdedList.scrollLeft = crowdedList.scrollWidth;
  await new Promise((resolve) => requestAnimationFrame(resolve));
  assertNewTabPosition();
  const addTab = document.querySelector<HTMLButtonElement>('[aria-label="New tab"]')!;
  assert.equal(addTab.disabled, true, 'the browser tab limit stays enforced');
  assert.ok(addTab.getBoundingClientRect().right < window.innerWidth);
  await render(
    {
      status: 'connected',
      webBrowser: { route: 'vpn', activeTabId: 'one', tabs: [first, second, third] },
    },
    { bitwardenOpen: false },
  );
  const addressForm = input.form!;
  const toolbar = input.closest('header')!;
  const canvas = section.querySelector('[role="tabpanel"]')!;
  const activeTab = section.querySelector('[role="tab"][aria-selected="true"]')!.parentElement!;
  assert.equal(getComputedStyle(activeTab).borderTopLeftRadius, '9px');
  assert.equal(getComputedStyle(activeTab).borderBottomLeftRadius, '0px');
  for (const side of ['::before', '::after']) {
    const curve = getComputedStyle(activeTab, side);
    assert.match(curve.backgroundImage, /^radial-gradient\(/);
    assert.equal(curve.bottom, '0px');
    assert.equal(curve.pointerEvents, 'none');
  }
  assert.ok(
    parseFloat(getComputedStyle(addressForm).borderTopLeftRadius) >= addressForm.offsetHeight / 2,
  );
  for (const theme of ['', 'dark', 'dark oled']) {
    document.documentElement.className = theme;
    const palette = getComputedStyle(section);
    const railColor = palette.getPropertyValue('--browser-rail').trim();
    assert.equal(railColor, palette.getPropertyValue(theme ? '--canvas' : '--muted').trim());
    assert.notEqual(railColor, palette.getPropertyValue('--sidebar').trim());
    assert.equal(
      getComputedStyle(activeTab).backgroundColor,
      getComputedStyle(toolbar).backgroundColor,
      'The selected tab and navigation must share a surface in every theme',
    );
  }
  document.documentElement.className = 'dark';

  hostWidth = '280px';
  await render();
  const toolbarBounds = toolbar.getBoundingClientRect();
  const addressBounds = addressForm.getBoundingClientRect();
  for (const button of toolbar.querySelectorAll('button')) {
    const controls = button.getBoundingClientRect();
    assert.ok(controls.right <= toolbarBounds.right && controls.bottom <= addressBounds.top);
  }
  assert.ok(
    addressBounds.width >= toolbarBounds.width - 24,
    'Narrow panes need a full address row',
  );
  const pageBounds = canvas.getBoundingClientRect();
  const browserBounds = section.getBoundingClientRect();
  assert.equal(pageBounds.top, toolbarBounds.bottom);
  assert.equal(pageBounds.left, browserBounds.left);
  assert.equal(pageBounds.right, browserBounds.right);
  assert.equal(pageBounds.bottom, browserBounds.bottom);
  assert.equal(bounds.at(-1).y, pageBounds.top);
  hostWidth = '100%';
  await render();
  assert.equal(document.documentElement.scrollWidth, window.innerWidth);

  const coldSession = { ...session, id: 'cold', title: 'Cold browser' };
  const renderCold = (status: 'connecting' | 'connected') =>
    React.act(async () =>
      root.render(
        <div style={{ height: '100vh' }}>
          <BrowserSessionSurface
            {...props}
            session={{ ...coldSession, status }}
            onReconnect={() => {}}
          />
        </div>,
      ),
    );
  await renderCold('connecting');
  assert.match(document.body.textContent!, /Cold browser.*Opening browser/);
  assert.equal(nativeVisible, false);
  await renderCold('connected');
  assert.equal(document.querySelector('[aria-label="Connection browser"]'), null);
  await React.act(async () => resolveBrowser());
  const coldExit = loadingOverlay()!;
  assert.equal(coldExit.dataset.connectionTransition, 'exit');
  assert.equal(
    nativeVisible,
    false,
    'a fast connection must keep the native view hidden through the fade',
  );
  await React.act(async () => coldExit.dispatchEvent(new Event('animationend', { bubbles: true })));
  assert.equal(nativeVisible, true);

  // Leave a representative browser state for visual inspection.
  (window as any).unmountWebBrowser = async () => {
    await React.act(async () => root.unmount());
    assert.equal(bounds.at(-1).visible, false);
  };
}

runWebBrowserTests();
