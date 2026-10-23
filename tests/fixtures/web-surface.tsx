import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { WebSurface } from '../../src/components/WebSurface';

declare const assert: typeof import('node:assert/strict');
declare const runWebCommand: NonNullable<Window['wormhole']>['commandWebSession'];
declare function readWebZoom(): Promise<{
  pageFactor: number;
  workspaceFactor: number;
  navigationCount: number;
}>;

export async function runWebSurfaceTests() {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById('root'));
  const commands: { sessionId: string; operation: string }[] = [];
  const pending: Promise<void>[] = [];
  const popupCommands: string[] = [];
  const api = {
    commandWebSession: (request) => {
      commands.push(request);
      const operation = runWebCommand(request);
      pending.push(operation);
      return operation;
    },
    setWebSessionBounds: async () => {},
    closeBitwardenPopup: async () => {
      popupCommands.push('close');
    },
    openBitwardenPopup: async () => {
      popupCommands.push('open');
      return { open: true };
    },
  } as Pick<
    NonNullable<Window['wormhole']>,
    'commandWebSession' | 'setWebSessionBounds' | 'closeBitwardenPopup' | 'openBitwardenPopup'
  >;
  Object.defineProperty(window, 'wormhole', { configurable: true, value: api });
  const session = {
    id: 'session',
    protocol: 'https' as const,
    host: 'appliance.local',
    status: 'connected' as const,
  };
  const render = async (props = {}) => {
    await act(async () => {
      root.render(
        <WebSurface
          session={session}
          isActive
          isAuthorized
          bitwardenOpen={false}
          onReconnect={() => {}}
          {...props}
        />,
      );
    });
  };
  const button = (label: string) =>
    document.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`);
  const click = async (label: string) => {
    const target = button(label);
    assert.ok(target, `Missing toolbar button: ${label}`);
    await act(async () => target.click());
    await Promise.all(pending.splice(0));
  };

  await render();
  assert.equal(button('Decrease text size').disabled, false);
  assert.equal(button('Increase text size').disabled, false);
  await click('Decrease text size');
  assert.equal((await readWebZoom()).pageFactor, 0.9);
  await click('Increase text size');
  assert.equal((await readWebZoom()).pageFactor, 1);
  await click('Increase text size');
  assert.deepEqual(await readWebZoom(), {
    pageFactor: 1.1,
    workspaceFactor: 1,
    navigationCount: 0,
  });
  assert.deepEqual(commands, [
    { sessionId: 'session', operation: 'zoom-out' },
    { sessionId: 'session', operation: 'zoom-in' },
    { sessionId: 'session', operation: 'zoom-in' },
  ]);

  for (const props of [
    { isActive: false },
    { isAuthorized: false },
    ...(['connecting', 'failed', 'closed', 'placeholder'] as const).map((status) => ({
      session: { ...session, status },
    })),
  ]) {
    await render(props);
    assert.equal(button('Decrease text size').disabled, true);
    assert.equal(button('Increase text size').disabled, true);
    await click('Decrease text size');
    await click('Increase text size');
  }
  assert.equal(commands.length, 3, 'disabled controls must not send zoom commands');

  await render({ session: { ...session, protocol: 'http' } });
  assert.equal(button('Decrease text size'), null);
  assert.equal(button('Increase text size'), null);
  assert.ok(button('Reload'), 'existing HTTP navigation remains available');

  await render({
    session: { ...session, bitwardenPopupUrl: 'chrome-extension://test/popup.html' },
  });
  await click('Open Bitwarden');
  assert.equal(popupCommands.at(-1), 'open');
  await render({
    session: { ...session, bitwardenPopupUrl: 'chrome-extension://test/popup.html' },
    bitwardenOpen: true,
  });
  await click('Close Bitwarden');
  assert.equal(popupCommands.at(-1), 'close');
  assert.equal((await readWebZoom()).pageFactor, 1.1, 'rerendering preserves page zoom');

  await act(async () => root.unmount());
}
