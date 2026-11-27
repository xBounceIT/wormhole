import * as React from 'react';
import { createRoot } from 'react-dom/client';
import { VncSurface } from '../../src/components/VncSurface';
declare const assert: typeof import('node:assert/strict');
export async function runVncSurfaceTests() {
  (globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById('root')!),
    original = window.wormhole;
  const requests: WormholeVncCommand[] = [],
    listeners = new Set<(event: WormholeBackendEvent) => void>();
  let reply: () => Promise<any> = async () => ({ id: '', ok: true }),
    unlocks = 0,
    unlockFails = false,
    reconnected = 0;
  const retries: (() => void)[] = [],
    statuses: string[] = [];
  const api = {
    sendVncCommand: async (command: WormholeVncCommand) => {
      requests.push(structuredClone(command));
      return reply();
    },
    onBackendEvent: (listener: (event: WormholeBackendEvent) => void) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    unlockBitwardenCli: async () => {
      unlocks++;
      if (unlockFails) throw Error('Bitwarden vault is locked');
    },
  };
  window.wormhole = api as any;
  let props: any = {
    vault: true,
    isAuthorized: true,
    connectionGeneration: 0,
    disconnected: false,
    bitwardenUnlockPending: false,
    session: {
      id: '11111111-1111-4111-8111-111111111111',
      nodeId: '22222222-2222-4222-8222-222222222222',
      credentialId: '33333333-3333-4333-8333-333333333333',
      host: 'renderer-override.invalid',
      port: 1,
      tunnelConfigId: '44444444-4444-4444-8444-444444444444',
    },
    onStatusChange: (v: string, manualPassword?: boolean) => {
      statuses.push(v);
      if (manualPassword !== undefined)
        props = { ...props, session: { ...props.session, manualPassword } };
    },
    onReconnect: () => reconnected++,
    onBitwardenUnlockRequired: (_reason: string, retry: () => void) => retries.push(retry),
  };
  const tick = () =>
    React.act(async () => {
      await new Promise((r) => setTimeout(r, 10));
    });
  const waitForInput = async (surface: HTMLElement) => {
    for (let i = 0; i < 200 && surface.tabIndex !== 0; i++) await tick();
    assert.equal(surface.tabIndex, 0, 'VNC input stays disabled until the first frame is visible');
  };
  const render = async (change: any = {}) => {
    props = { ...props, ...change };
    await React.act(async () => {
      root.render(<VncSurface {...props} />);
    });
    await tick();
  };
  const emit = async (fields: any) => {
    await React.act(async () => {
      for (const listener of listeners) listener({ sessionId: props.session.id, ...fields } as any);
    });
    await tick();
  };
  const click = async (text: string) => {
    const button = [...document.querySelectorAll('button')].find(
      (b) => b.textContent?.trim() === text,
    );
    assert.ok(button, text);
    await React.act(async () => button.click());
    await tick();
  };
  const submit = async (password: string) => {
    const input = document.querySelector('input')!;
    assert.ok(input);
    await React.act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(
        input,
        password,
      );
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await React.act(async () => {
      document
        .querySelector('form')!
        .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });
    await tick();
  };
  try {
    await render();
    assert.deepEqual(requests.at(-1), {
      action: 'vnc.connect',
      sessionId: props.session.id,
      nodeId: props.session.nodeId,
      credentialId: props.session.credentialId,
    });
    const opens = requests.filter((q) => q.action === 'vnc.connect').length;
    await render({
      session: { ...props.session, tunnelProgress: { phase: 'auth', detail: 'progress' } },
    });
    assert.equal(
      requests.filter((q) => q.action === 'vnc.connect').length,
      opens,
      'metadata-only rerender must not reconnect',
    );
    await emit({
      type: 'vnc.status',
      status: 'failed',
      passwordRequired: true,
      message: 'VNC connection failed',
    });
    assert.equal(document.querySelector('input'), null);
    assert.match(document.body.textContent!, /Enter password securely/);
    await click('Enter password securely');
    assert.deepEqual(requests.at(-1), {
      action: 'vnc.connect',
      sessionId: props.session.id,
      nodeId: props.session.nodeId,
      credentialId: props.session.credentialId,
      manualPassword: true,
    });
    assert.equal(document.querySelector('input'), null);
    await emit({
      type: 'vnc.status',
      status: 'failed',
      passwordRequired: true,
      message: 'VNC connection failed',
    });
    await click('Reconnect');
    assert.equal(requests.at(-1)!.action, 'vnc.connect');
    assert.equal(
      (requests.at(-1) as any).manualPassword,
      true,
      'manual retry must not fall back to saved credentials',
    );
    assert.equal(props.session.manualPassword, true);
    await React.act(async () => root.render(null));
    await render({ session: { ...props.session } });
    assert.equal(
      (requests.at(-1) as any).manualPassword,
      true,
      'public manual intent must survive a surface remount',
    );

    await emit({ type: 'vnc.status', status: 'connected' });
    await emit({
      type: 'vnc.frame',
      width: 100,
      height: 100,
      image:
        'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGNgAAAAAgABSK+kcQAAAABJRU5ErkJggg==',
    });
    const surface = document.querySelector('[role="application"]') as HTMLElement,
      image = document.querySelector('img')!;
    await waitForInput(surface);
    image.getBoundingClientRect = () => ({
      left: 0,
      top: 0,
      right: 100,
      bottom: 100,
      width: 100,
      height: 100,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });
    const captures = new Set<number>();
    surface.setPointerCapture = (id) => {
      captures.add(id);
    };
    surface.hasPointerCapture = (id) => captures.has(id);
    surface.releasePointerCapture = (id) => {
      captures.delete(id);
    };
    for (const [type, buttons] of [
      ['pointerdown', 1],
      ['pointermove', 1],
      ['pointermove', 1],
      ['pointerup', 0],
      ['pointercancel', 0],
    ] as const) {
      await React.act(async () => {
        surface.dispatchEvent(
          new PointerEvent(type, {
            bubbles: true,
            pointerId: 1,
            buttons,
            clientX: 50,
            clientY: 50,
          }),
        );
      });
      await tick();
    }
    assert.ok(requests.some((q) => q.action === 'vnc.pointer' && q.x === 50 && q.y === 50));
    assert.equal(captures.size, 0);
    for (const [deltaX, deltaY] of [
      [0, -1],
      [0, 1],
      [1, 0],
      [-1, 0],
      [0, 0],
    ])
      await React.act(async () => {
        surface.dispatchEvent(
          new WheelEvent('wheel', {
            bubbles: true,
            cancelable: true,
            clientX: 50,
            clientY: 50,
            deltaX,
            deltaY,
          }),
        );
      });
    for (const [key, code] of [
      ['a', 'KeyA'],
      ['Enter', 'Enter'],
      ['Shift', 'ShiftLeft'],
      ['😀', 'Unidentified'],
    ]) {
      for (const type of ['keydown', 'keyup'])
        await React.act(async () => {
          surface.dispatchEvent(
            new KeyboardEvent(type, { bubbles: true, cancelable: true, key, code }),
          );
        });
    }
    await React.act(async () => {
      surface.dispatchEvent(
        new KeyboardEvent('keydown', { bubbles: true, key: 'Control', code: 'ControlLeft' }),
      );
      surface.dispatchEvent(new FocusEvent('focusout', { bubbles: true }));
    });
    await emit({ type: 'tunnel.progress', phase: 'auth', detail: 'Authenticating' });
    await emit({ type: 'ignored' });
    await emit({ type: 'vnc.status' });
    await emit({ type: 'vnc.status', sessionId: 'foreign', status: 'failed' });
    await render({ disconnected: true });
    assert.equal(document.querySelector('img'), null);
    await click('Reconnect');
    assert.equal(reconnected, 1);
    await render({ disconnected: false, session: { ...props.session, nodeId: undefined } });
    assert.match(document.body.textContent!, /protected VNC target is invalid/);
    await render({
      session: {
        ...props.session,
        quickTarget: {
          protocol: 'vnc',
          host: 'quick.example',
          port: 5900,
          credentialId: '',
          tunnelId: '',
          sshAutoSudo: false,
          httpPath: '',
          ignoreCertificateErrors: false,
          rdp: null,
        },
      },
    });
    assert.equal((requests.at(-1) as any).quickTarget.host, 'quick.example');
    assert.equal('nodeId' in requests.at(-1)!, false);
    assert.equal('password' in requests.at(-1)!, false);
    assert.equal((requests.at(-1) as any).manualPassword, true);
    assert.equal(document.querySelector('input'), null);
    const quickOpens = requests.filter((q) => q.action === 'vnc.connect').length;
    await render({ session: { ...props.session, quickTarget: { ...props.session.quickTarget } } });
    assert.equal(requests.filter((q) => q.action === 'vnc.connect').length, quickOpens);
    // Equal public metadata may be reconstructed by the parent; it must not open another native attempt.
    await render({
      session: {
        ...props.session,
        id: '55555555-5555-4555-8555-555555555555',
        nodeId: '22222222-2222-4222-8222-222222222222',
        quickTarget: undefined,
        manualPassword: undefined,
      },
    });
    assert.equal(
      'manualPassword' in requests.at(-1)!,
      false,
      'a different session cannot inherit the previous surface mode',
    );

    await render({
      vault: false,
      session: {
        ...props.session,
        quickTarget: undefined,
        nodeId: '22222222-2222-4222-8222-222222222222',
      },
    });
    assert.equal((requests.at(-1) as any).host, 'renderer-override.invalid');
    reply = async () => ({ id: '', ok: false, error: 'VNC password is required' });
    await clickAfterFailure();
    async function clickAfterFailure() {
      await emit({
        type: 'vnc.status',
        status: 'failed',
        passwordRequired: true,
        message: 'VNC password is required',
      });
      assert.ok(document.querySelector('input'));
      await submit('legacy-password');
      assert.equal((requests.at(-1) as any).password, 'legacy-password');
    }
    reply = async () => ({ id: '', ok: true });
    await emit({ type: 'vnc.status', status: 'failed', message: 'Bitwarden vault is locked' });
    assert.ok(retries.length);
    await submit('master');
    assert.equal(unlocks, 1);
    unlockFails = true;
    await emit({ type: 'vnc.status', status: 'failed', message: 'Bitwarden vault is locked' });
    await submit('bad-master');
    assert.equal(unlocks, 2);
    assert.ok(retries.length >= 2);
    await render({ bitwardenUnlockPending: true });
    assert.equal(document.querySelector('form'), null);
    assert.match(document.body.textContent!, /shared prompt/);
    await render({ isAuthorized: false, bitwardenUnlockPending: false });
    assert.equal(document.querySelector('input'), null);
    await render({ isAuthorized: true });
    await emit({ type: 'vnc.status', status: 'failed', message: 'network failed' });
    reply = async () => {
      throw Error('network failed');
    };
    await click('Reconnect');
    assert.match(document.body.textContent!, /network failed/);
    reply = async () => ({ id: '', ok: true });
    window.wormhole = undefined;
    await render({ connectionGeneration: 1 });
    assert.match(document.body.textContent!, /unavailable/);
    window.wormhole = api as any;
    await render({ connectionGeneration: 2, vault: true });
    assert.equal(document.querySelector('input'), null);
    let complete!: (value: any) => void;
    reply = () =>
      new Promise((resolve) => {
        complete = resolve;
      });
    await render({ vault: true, connectionGeneration: 3 });
    await emit({
      type: 'vnc.status',
      status: 'failed',
      passwordRequired: true,
      message: 'VNC connection failed',
    });
    complete({ id: '', ok: false, error: 'VNC connection could not be completed.' });
    await tick();
    assert.equal(document.querySelector('input'), null);
    assert.match(document.body.textContent!, /Enter password securely/);
    assert.ok(statuses.includes('connected'));
    assert.ok(statuses.includes('failed'));
    // Shared tabs own opening and confirmed cleanup; the surface only renders
    // frames/controls after its subscriber is attached.
    reply = async () => ({ id: '', ok: true });
    let ready = 0,
      manualReconnects = 0;
    const managed = {
      status: 'opening',
      error: undefined as string | undefined,
      canReconnect: false,
      active: false,
      label: 'Managed desktop',
      passwordRequired: true,
      manualReconnect: () => {
        manualReconnects++;
      },
      ready: () => {
        ready++;
      },
    };
    const beforeManaged = requests.filter((command) => command.action === 'vnc.connect').length;
    await render({
      managed,
      connectionGeneration: 4,
      vault: true,
      isAuthorized: true,
      disconnected: false,
    });
    assert.equal(ready, 1);
    assert.equal(
      requests.filter((command) => command.action === 'vnc.connect').length,
      beforeManaged,
    );
    assert.match(document.body.textContent!, /Connecting to VNC/);
    assert.match(document.body.textContent!, /Managed desktop/);
    await render({ managed: { ...managed, status: 'connected', active: true } });
    await emit({ type: 'vnc.status', status: 'connected' });
    await emit({
      type: 'vnc.frame',
      width: 100,
      height: 100,
      image:
        'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGNgAAAAAgABSK+kcQAAAABJRU5ErkJggg==',
    });
    const controlledSurface = document.querySelector('[role=application]') as HTMLElement;
    await waitForInput(controlledSurface);
    const controlledImage = document.querySelector('img')!;
    controlledImage.getBoundingClientRect = image.getBoundingClientRect;
    await React.act(async () => {
      controlledSurface.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'x', code: 'KeyX', bubbles: true, cancelable: true }),
      );
      controlledSurface.dispatchEvent(
        new PointerEvent('pointerdown', {
          pointerId: 3,
          clientX: 20,
          clientY: 20,
          buttons: 1,
          bubbles: true,
        }),
      );
    });
    await tick();
    const pressed = requests.length;
    await render({
      managed: { ...managed, status: 'connected', active: false },
      isAuthorized: false,
    });
    assert.ok(
      requests
        .slice(pressed)
        .some((command) => command.action === 'vnc.key' && command.down === false),
    );
    assert.ok(
      requests
        .slice(pressed)
        .some((command) => command.action === 'vnc.pointer' && command.buttons === 0),
    );
    const inactive = requests.length;
    await React.act(async () =>
      controlledSurface.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'y', code: 'KeyY', bubbles: true, cancelable: true }),
      ),
    );
    await tick();
    assert.equal(requests.length, inactive);
    await render({
      managed: { ...managed, status: 'failed', error: 'Controlled connection failed' },
    });
    assert.match(document.body.textContent!, /Controlled connection failed/);
    assert.equal(document.querySelector('input'), null);
    assert.equal(
      (
        Array.from(document.querySelectorAll('button')).find(
          (button) => button.textContent?.trim() === 'Enter password securely',
        ) as HTMLButtonElement
      ).disabled,
      true,
    );
    const reconnect = [...document.querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Reconnect',
    )!;
    assert.equal(reconnect.disabled, true);
    await render({
      managed: { ...managed, status: 'failed', canReconnect: true, active: true },
      isAuthorized: true,
    });
    const beforeReconnect = reconnected;
    await click('Enter password securely');
    assert.equal(manualReconnects, 1);
    await click('Reconnect');
    assert.equal(reconnected, beforeReconnect + 1);
    assert.equal(
      requests.filter((command) => command.action === 'vnc.connect').length,
      beforeManaged,
    );
    await render({ managed: { ...managed, status: 'closing' } });
    assert.match(document.body.textContent!, /VNC disconnected/);
  } finally {
    await React.act(async () => root.unmount());
    window.wormhole = original;
  }
}
