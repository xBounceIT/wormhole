import React, { act } from 'react';
import '../../src/index.css';
import { createRoot } from 'react-dom/client';
import { RdpSurface } from '../../src/components/RdpSurface';
import { VncSurface } from '../../src/components/VncSurface';

declare const assert: typeof import('node:assert/strict');

export async function runRdpCanvasTests() {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById('root')!);
  const listeners = new Set<(event: WormholeRdpBackendEvent) => void>();
  const inputs: { sessionId: string; lifecycleId: string; input: any }[] = [];
  const commands: any[] = [];
  const api = {
    onRdpEvent: (callback) => {
      listeners.add(callback);
      return () => listeners.delete(callback);
    },
    sendRdpInput: async (request) => {
      inputs.push(request);
    },
    resizeRdpSession: async (request) => {
      commands.push({ ...request, operation: 'resize' });
    },
    commandRdpSession: async (request) => {
      commands.push(request);
    },
  };
  Object.defineProperty(window, 'wormhole', { configurable: true, writable: true, value: api });
  const emit = (event: Partial<WormholeRdpBackendEvent>) => {
    for (const listener of listeners)
      listener({ type: 'frame', sessionId: 'rdp', lifecycleId: 'first', ...event });
  };
  const render = async (props = {}) => {
    await act(async () =>
      root.render(
        <RdpSurface
          sessionId="rdp"
          status="connected"
          isActive
          isAuthorized
          canOpenSystemClient={false}
          onConnect={() => {}}
          onRetry={() => {}}
          onOpenSystemClient={() => {}}
          {...props}
        />,
      ),
    );
  };
  await render();
  const canvas = document.querySelector('canvas')!;
  canvas.style.width = '200px';
  canvas.style.height = '100px';
  // Synthetic pointer events have no active native pointer to capture.
  canvas.setPointerCapture = () => {};
  emit({ type: 'connected' });
  const frame = {
    desktopWidth: 2,
    desktopHeight: 1,
    x: 0,
    y: 0,
    width: 1,
    height: 1,
    rgba: '/wAA/w==',
  };
  emit({ frame });
  const context = canvas.getContext('2d')!;
  assert.deepEqual([...context.getImageData(0, 0, 1, 1).data], [255, 0, 0, 255]);
  emit({ lifecycleId: 'stale', frame: { ...frame, rgba: 'AP8A/w==' } });
  emit({ sessionId: 'other', frame: { ...frame, rgba: 'AP8A/w==' } });
  emit({ frame: { ...frame, width: 500 } });
  assert.deepEqual([...context.getImageData(0, 0, 1, 1).data], [255, 0, 0, 255]);
  emit({ type: 'frameEnd', paintId: 1 });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(inputs.at(-1)?.input.kind, 'painted');
  canvas.focus();
  for (const type of ['pointerdown', 'pointermove', 'pointerup']) {
    canvas.dispatchEvent(
      new PointerEvent(type, {
        bubbles: true,
        cancelable: true,
        button: 0,
        clientX: 100,
        clientY: 40,
      }),
    );
  }
  canvas.dispatchEvent(new PointerEvent('pointerdown', { button: 4 }));
  canvas.dispatchEvent(
    new KeyboardEvent('keydown', { code: 'KeyA', bubbles: true, cancelable: true }),
  );
  canvas.dispatchEvent(
    new KeyboardEvent('keyup', { code: 'KeyA', bubbles: true, cancelable: true }),
  );
  canvas.dispatchEvent(new KeyboardEvent('keydown', { code: 'Unidentified' }));
  canvas.dispatchEvent(new KeyboardEvent('keydown', { code: 'KeyA', isComposing: true }));
  canvas.dispatchEvent(new WheelEvent('wheel', { deltaY: 10 }));
  canvas.dispatchEvent(new WheelEvent('wheel', { deltaY: -10 }));
  canvas.dispatchEvent(new WheelEvent('wheel', { deltaY: 0 }));
  canvas.dispatchEvent(new CompositionEvent('compositionend', { data: 'é' }));
  canvas.dispatchEvent(new MouseEvent('contextmenu', { cancelable: true }));
  await new Promise((resolve) => setTimeout(resolve, 0));
  canvas.dispatchEvent(new Event('pointercancel'));
  canvas.dispatchEvent(new Event('blur'));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.ok(
    inputs.some((item) => item.input.kind === 'key' && item.input.code === 0x1e && item.input.down),
  );
  assert.ok(
    inputs.some(
      (item) => item.input.kind === 'key' && item.input.code === 0x1e && !item.input.down,
    ),
  );
  assert.ok(inputs.some((item) => item.input.kind === 'pointer' && item.input.flags === 0x9000));
  assert.ok(inputs.some((item) => item.input.kind === 'pointer' && item.input.flags === 0x1000));
  assert.ok(inputs.some((item) => item.input.kind === 'unicode' && item.input.code === 233));
  assert.ok(inputs.every((item) => item.sessionId === 'rdp' && item.lifecycleId === 'first'));
  await render({ isActive: false });
  assert.equal(canvas.style.visibility, 'hidden');
  assert.ok(commands.some((item) => item.operation === 'hide'));
  const count = inputs.length;
  canvas.dispatchEvent(new KeyboardEvent('keydown', { code: 'KeyA' }));
  emit({ frame: { ...frame, rgba: 'AP8A/w==' } });
  assert.equal(inputs.length, count);
  await render();
  emit({ type: 'connected', lifecycleId: 'second' });
  emit({ lifecycleId: 'second', frame: { ...frame, rgba: 'AP8A/w==' } });
  assert.deepEqual([...context.getImageData(0, 0, 1, 1).data], [0, 255, 0, 255]);
  await render({ isAuthorized: false });
  assert.equal(canvas.style.visibility, 'hidden');
  await render({ backend: 'freerdp', status: 'starting' });
  await render({ backend: 'freerdp' });
  const loading = document.querySelector<HTMLElement>('[data-connection-transition]')!;
  assert.equal(loading.dataset.connectionTransition, 'pending');
  assert.match(loading.textContent!, /Waiting for the remote desktop/);
  assert.equal(commands.at(-1).operation, 'show', 'FreeRDP must send pixels during loading');
  assert.equal(canvas.tabIndex, -1);
  await act(async () => {
    emit({ type: 'connected', lifecycleId: 'third' });
    emit({ type: 'frameEnd', lifecycleId: 'third', paintId: 1 });
    emit({ lifecycleId: 'third', frame });
  });
  assert.equal(loading.dataset.connectionTransition, 'pending', 'wait for a complete frame');
  await act(async () => emit({ type: 'frameEnd', lifecycleId: 'third', paintId: 2 }));
  assert.equal(loading.dataset.connectionTransition, 'exit');
  assert.deepEqual([...context.getImageData(0, 0, 1, 1).data], [255, 0, 0, 255]);
  const beforeInput = inputs.length;
  canvas.dispatchEvent(new KeyboardEvent('keydown', { code: 'KeyA', bubbles: true }));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(
    inputs.length,
    beforeInput,
    'the remote desktop must not receive input during the fade',
  );
  await act(async () => loading.dispatchEvent(new Event('animationend', { bubbles: true })));
  assert.equal(canvas.tabIndex, 0);
  await act(async () => root.unmount());
  assert.equal(listeners.size, 0);
  Object.defineProperty(window, 'wormhole', {
    configurable: true,
    writable: true,
    value: undefined,
  });
  await runRdpSurfaceTests();
  await runVncSurfaceTests();
}

async function runRdpSurfaceTests() {
  const container = document.getElementById('root');
  const originalStyle = container.style.cssText;
  const originalApi = window.wormhole;
  container.style.cssText = 'position:fixed;left:32px;top:64px;width:800px;height:500px';
  const root = createRoot(container);
  const commands: Array<{ operation: string; bounds?: unknown }> = [];
  const sizes: unknown[] = [];
  const actions: string[] = [];
  let rdpSubscriptions = 0;
  let rejectCommands = false;
  const api = {
    onRdpEvent: () => {
      rdpSubscriptions++;
      return () => {
        rdpSubscriptions--;
      };
    },
    sendRdpInput: async () => {},
    commandRdpSession: async (request) => {
      commands.push(request);
      if (rejectCommands) throw new Error('Native host unavailable');
    },
    resizeRdpSession: async ({ bounds }) => {
      sizes.push(bounds);
      if (rejectCommands) throw new Error('Native host unavailable');
    },
  } as typeof window.wormhole;
  window.wormhole = api;
  const mount = async (props: Partial<Parameters<typeof RdpSurface>[0]> = {}) => {
    await React.act(async () =>
      root.render(
        <RdpSurface
          sessionId="rdp-layout"
          isActive
          isAuthorized
          status="connected"
          canOpenSystemClient={false}
          onConnect={() => actions.push('connect')}
          onRetry={() => actions.push('retry')}
          onOpenSystemClient={() => actions.push('system')}
          {...props}
        />,
      ),
    );
  };
  const settleLayout = async () => {
    await React.act(async () => {
      await new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      );
    });
  };
  const assertFullBounds = () => {
    const surface = container.querySelector('[data-rdp-native-surface-region]');
    const rect = surface.getBoundingClientRect();
    const parent = container.getBoundingClientRect();
    const expected = { x: parent.x, y: parent.y, width: parent.width, height: parent.height };
    assert.deepEqual({ x: rect.x, y: rect.y, width: rect.width, height: rect.height }, expected);
    assert.deepEqual(sizes.at(-1), expected);
    assert.ok(surface.querySelector('canvas'));
    assert.equal(
      surface.querySelector('button'),
      null,
      'embedded desktop must have no overlay controls',
    );
    return expected;
  };
  const press = async (label: string) => {
    const button = [...container.querySelectorAll('button')].find(
      (candidate) => candidate.textContent === label,
    );
    assert.ok(button, `missing ${label}`);
    await React.act(async () => button.click());
  };
  try {
    await mount();
    await settleLayout();
    assert.deepEqual(commands.at(-1), {
      sessionId: 'rdp-layout',
      operation: 'show',
      bounds: assertFullBounds(),
    });
    await mount({ canOpenSystemClient: true });
    assertFullBounds();
    assert.equal(container.querySelector('button'), null);
    const beforeResize = commands.length;
    container.style.width = '640px';
    container.style.height = '360px';
    window.dispatchEvent(new Event('resize'));
    assertFullBounds();
    await settleLayout();
    assertFullBounds();
    assert.equal(commands.length, beforeResize, 'resizing must not show the surface twice');
    const beforeDuplicate = sizes.length;
    window.dispatchEvent(new Event('resize'));
    assert.equal(sizes.length, beforeDuplicate, 'unchanged bounds must be deduplicated');
    container.style.height = '0px';
    await settleLayout();
    assert.equal(
      commands.at(-1).operation,
      'hide',
      'Collapsing a visible pane must hide native RDP',
    );
    const afterCollapse = commands.length;
    window.dispatchEvent(new Event('resize'));
    assert.equal(
      commands.length,
      afterCollapse,
      'Collapse reports must not repeat the hide command',
    );
    container.style.height = '360px';
    await settleLayout();
    assert.deepEqual(commands.at(-1), {
      sessionId: 'rdp-layout',
      operation: 'show',
      bounds: assertFullBounds(),
    });
    for (const props of [{ isActive: false }, { isAuthorized: false }]) {
      await mount(props);
      assert.equal(commands.at(-1).operation, 'hide');
      const beforeInactive = sizes.length;
      window.dispatchEvent(new Event('resize'));
      assert.equal(sizes.length, beforeInactive);
      await mount();
      assert.equal(commands.at(-1).operation, 'show');
    }
    await mount({ external: true });
    assert.equal(commands.at(-1).operation, 'hide');
    assert.match(container.textContent, /System Remote Desktop is running/);
    assert.equal(container.querySelector('button'), null);
    const beforeExternal = commands.length;
    window.dispatchEvent(new Event('resize'));
    assert.equal(
      commands.length,
      beforeExternal,
      'external clients must never show a native surface',
    );
    for (const status of ['idle', 'disconnected'] as const) {
      await mount({ status, canOpenSystemClient: true });
      assert.match(container.textContent, /RDP session is disconnected/);
      await press('Connect');
      await press('Open in System Remote Desktop');
    }
    await mount({ status: 'failed', error: 'Connection refused' });
    assert.match(container.textContent, /Connection refused/);
    await press('Retry connection');
    assert.deepEqual(actions, ['connect', 'system', 'connect', 'system', 'retry']);
    const metadata = { name: 'Lab desktop', destination: 'desktop.internal', port: 3390 };
    const transition = () => container.querySelector<HTMLElement>('[data-connection-transition]');
    await mount({ status: 'starting', ...metadata });
    const loading = transition();
    assert.equal(loading?.dataset.connectionTransition, 'pending');
    assert.equal(loading?.querySelector('h3')?.textContent, 'Lab desktop');
    assert.match(loading.textContent, /desktop\.internal.*RDP.*Port 3390.*Connecting to RDP/);
    assert.ok(loading.querySelector('.lucide-loader-circle'));
    assert.equal(container.querySelector('button'), null);
    await mount({ status: 'starting', ...metadata, tunnelProgress: { phase: 'authenticating' } });
    assert.match(loading.textContent, /Authenticating with the VPN gateway/);
    assert.ok(loading.querySelector('.lucide-key-round'));
    assert.equal(container.querySelector('button'), null);
    const beforeFade = commands.length;
    await mount();
    assert.equal(transition(), loading);
    assert.equal(loading.dataset.connectionTransition, 'exit');
    assert.equal(commands.length, beforeFade, 'native RDP cannot cover the loading fade');
    await act(async () => loading.dispatchEvent(new Event('animationend', { bubbles: true })));
    assert.equal(transition(), null);
    assert.equal(commands.at(-1).operation, 'show');
    await mount({ status: 'starting' });
    assert.equal(commands.at(-1).operation, 'hide');
    const beforeZero = commands.length;
    container.style.height = '0px';
    await mount();
    await act(async () =>
      transition()?.dispatchEvent(new Event('animationend', { bubbles: true })),
    );
    await settleLayout();
    window.dispatchEvent(new Event('resize'));
    assert.equal(commands.length, beforeZero, 'zero-size surfaces must not be shown');
    container.style.height = '360px';
    rejectCommands = true;
    await settleLayout();
    assertFullBounds();
    await mount({ isAuthorized: false });
    window.wormhole = undefined;
    const beforeMissingApi = commands.length;
    await mount();
    window.dispatchEvent(new Event('resize'));
    assert.equal(commands.length, beforeMissingApi);
    window.wormhole = api;
    await mount({ sessionId: 'rdp-restored' });
    assert.equal(commands.at(-1).operation, 'show');
  } finally {
    await React.act(async () => root.unmount());
    assert.equal(rdpSubscriptions, 0, 'unmount must remove canvas subscriptions');
    assert.equal(commands.at(-1).operation, 'hide');
    const afterUnmount = sizes.length;
    window.dispatchEvent(new Event('resize'));
    await settleLayout();
    assert.equal(sizes.length, afterUnmount, 'unmount must remove resize subscriptions');
    container.style.cssText = originalStyle;
    window.wormhole = originalApi;
  }
}

async function runVncSurfaceTests() {
  const container = document.getElementById('root')!;
  const root = createRoot(container);
  const listeners = new Set<(event: WormholeBackendEvent) => void>();
  const commands: WormholeVncCommand[] = [];
  window.wormhole = {
    onBackendEvent: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    sendVncCommand: async (command) => {
      commands.push(command);
      return { ok: true };
    },
  } as Pick<
    NonNullable<Window['wormhole']>,
    'onBackendEvent' | 'sendVncCommand'
  > as Window['wormhole'];
  const session = { id: 'vnc-layout', title: 'Lab monitor', host: 'monitor.internal', port: 5901 };
  const render = (connectionGeneration: number) =>
    act(async () =>
      root.render(
        <VncSurface
          bitwardenUnlockPending={false}
          connectionGeneration={connectionGeneration}
          disconnected={false}
          isAuthorized
          session={session}
        />,
      ),
    );
  const emit = (event: Omit<WormholeBackendEvent, 'sessionId'>) =>
    act(async () => {
      for (const listener of listeners) listener({ ...event, sessionId: session.id });
    });
  const transition = () => container.querySelector<HTMLElement>('[data-connection-transition]');

  try {
    await render(0);
    const loading = transition()!;
    assert.equal(loading.dataset.connectionTransition, 'pending');
    assert.match(
      loading.textContent!,
      /Lab monitor.*monitor\.internal.*VNC.*Port 5901.*Connecting to VNC/,
    );
    await emit({ type: 'tunnel.progress', phase: 'ready' });
    assert.ok(loading.querySelector('.lucide-shield-check'));
    await emit({ type: 'vnc.status', status: 'connected' });
    assert.equal(loading.dataset.connectionTransition, 'pending');
    assert.match(loading.textContent!, /Waiting for the remote desktop/);
    const desktop = container.querySelector<HTMLElement>('[role="application"]')!;
    const pressKey = () =>
      desktop.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'a', code: 'KeyA', bubbles: true }),
      );
    assert.equal(desktop.tabIndex, -1);
    await act(async () => pressKey());
    assert.equal(commands.filter((command) => command.action === 'vnc.key').length, 0);
    await emit({
      type: 'vnc.frame',
      image: 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
      width: 1,
      height: 1,
    });
    const image = container.querySelector('img')!;
    await act(async () => {
      await image.decode();
    });
    await act(async () => {
      await new Promise(requestAnimationFrame);
    });
    assert.equal(loading.dataset.connectionTransition, 'exit');
    assert.equal(image.naturalWidth, 1);
    await act(async () => loading.dispatchEvent(new Event('animationend', { bubbles: true })));
    assert.equal(transition(), null);
    assert.equal(desktop.tabIndex, 0);
    await act(async () => pressKey());
    assert.equal(commands.at(-1)?.action, 'vnc.key');
    await render(1);
    assert.equal(transition()?.dataset.connectionTransition, 'pending');
    await emit({ type: 'vnc.status', status: 'failed', message: 'Server unreachable' });
    assert.equal(transition(), null);
    assert.match(container.textContent!, /Server unreachable/);
    const failure = desktop.querySelector<HTMLElement>('.absolute.inset-0')!;
    const probe = document.createElement('div');
    probe.className = 'bg-canvas text-foreground';
    container.append(probe);
    const themeClasses = document.documentElement.className;
    try {
      for (const theme of ['', 'dark', 'dark oled']) {
        document.documentElement.className = theme;
        assert.equal(
          getComputedStyle(failure).backgroundColor,
          getComputedStyle(probe).backgroundColor,
        );
        assert.equal(getComputedStyle(failure).color, getComputedStyle(probe).color);
      }
    } finally {
      document.documentElement.className = themeClasses;
      probe.remove();
    }
  } finally {
    await act(async () => root.unmount());
    window.wormhole = undefined;
  }
}
