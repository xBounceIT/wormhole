import { act, StrictMode, useState } from 'react';
import { createRoot } from 'react-dom/client';
import '../../src/index.css';
import { WebSurface } from '../../src/components/WebSurface';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuOverlayProvider,
  ContextMenuTrigger,
  useContextMenuOverlayOpen,
} from '../../src/components/ui/context-menu';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogTitle,
  DialogTrigger,
} from '../../src/components/ui/dialog';

declare const assert: typeof import('node:assert/strict');
declare const runWebCommand: NonNullable<Window['wormhole']>['commandWebSession'];
declare function readWebZoom(): Promise<{
  pageFactor: number;
  workspaceFactor: number;
  navigationCount: number;
}>;
declare const setNativeBounds: NonNullable<Window['wormhole']>['setWebSessionBounds'];
declare function readNativeVisibility(): Promise<boolean>;
declare function setNativeCaptureMode(mode: 'success' | 'failed' | 'delayed'): Promise<void>;
declare function finishNativeCaptures(): Promise<void>;

export async function runWebSurfaceTests() {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById('root'));
  const commands: { sessionId: string; operation: string }[] = [];
  const pending: Promise<void>[] = [];
  const popupCommands: string[] = [];
  let rejectCommand = false;
  const api = {
    commandWebSession: (request) => {
      commands.push(request);
      const operation = rejectCommand
        ? Promise.reject(new Error('Browser command unavailable'))
        : runWebCommand(request);
      pending.push(operation.catch(() => undefined));
      return operation;
    },
    setWebSessionBounds: async () => {},
    onWebEvent: () => () => {},
    closeBitwardenPopup: async () => {
      popupCommands.push('close');
    },
    openBitwardenPopup: async () => {
      popupCommands.push('open');
      return { open: true };
    },
  } as Pick<
    NonNullable<Window['wormhole']>,
    | 'commandWebSession'
    | 'setWebSessionBounds'
    | 'onWebEvent'
    | 'closeBitwardenPopup'
    | 'openBitwardenPopup'
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
  await act(async () => {
    document
      .querySelector('[data-connection-transition="exit"]')
      ?.dispatchEvent(new Event('animationend', { bubbles: true }));
  });
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
  rejectCommand = true;
  await click('Increase text size');
  assert.match(document.querySelector('[role="alert"]').textContent, /Browser command unavailable/);
  assert.equal((await readWebZoom()).pageFactor, 1.1, 'failed commands preserve native zoom');

  await act(async () => root.unmount());
}

function DialogOverlayHarness({ mounted = true, revision = 0 }) {
  const occluded = useContextMenuOverlayOpen();
  const [open, setOpen] = useState(false);
  const [closePending, setClosePending] = useState(false);
  return (
    <>
      <ContextMenuOverlayProvider>
        <button id="direct-delete" onClick={() => setOpen(true)}>
          Delete directly
        </button>
        <button id="close-browser" onClick={() => setClosePending(true)}>
          Close browser
        </button>
        <ContextMenu>
          <ContextMenuTrigger id="connection-menu">Connection</ContextMenuTrigger>
          <ContextMenuContent>
            <ContextMenuItem onSelect={() => setOpen(true)}>Delete connection</ContextMenuItem>
            <ContextMenuItem onSelect={() => setClosePending(true)}>
              Close browser from menu
            </ContextMenuItem>
          </ContextMenuContent>
        </ContextMenu>
        {mounted && (
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogContent>
              <DialogTitle>Delete connection</DialogTitle>
              <DialogDescription>Delete this saved connection?</DialogDescription>
              <DialogClose>Cancel</DialogClose>
              <Dialog>
                <DialogTrigger>Another confirmation</DialogTrigger>
                <DialogContent>
                  <DialogTitle>Nested confirmation</DialogTitle>
                  <DialogDescription>Keep the session hidden.</DialogDescription>
                  <DialogClose>Close nested confirmation</DialogClose>
                </DialogContent>
              </Dialog>
            </DialogContent>
          </Dialog>
        )}
        <Dialog open={closePending} onOpenChange={setClosePending}>
          <DialogContent role="alertdialog" showCloseButton={false}>
            <DialogTitle>Disconnect active connection?</DialogTitle>
            <DialogDescription>Close this browser session?</DialogDescription>
            <DialogClose>Keep browser open</DialogClose>
          </DialogContent>
        </Dialog>
      </ContextMenuOverlayProvider>
      <div style={{ height: 400, width: 700 + revision }}>
        <WebSurface
          session={{
            id: 'session',
            protocol: 'https',
            host: 'appliance.local',
            status: 'connected',
          }}
          isActive
          isAuthorized
          isOccluded={occluded || closePending}
          captureWhenOccluded={!closePending}
          bitwardenOpen={false}
          onReconnect={() => {}}
        />
      </div>
    </>
  );
}

export async function runDialogOverlayTests() {
  const root = createRoot(document.getElementById('root'));
  const boundsRequests: Parameters<typeof setNativeBounds>[0][] = [];
  window.wormhole.setWebSessionBounds = (request) => {
    boundsRequests.push(request);
    return setNativeBounds(request);
  };
  const render = async (props = {}) => {
    await act(async () => {
      root.render(
        <StrictMode>
          <ContextMenuOverlayProvider>
            <DialogOverlayHarness {...props} />
          </ContextMenuOverlayProvider>
        </StrictMode>,
      );
    });
  };
  const settle = async () => {
    await act(async () => new Promise((resolve) => setTimeout(resolve, 150)));
  };
  const expectVisibility = async (expected: boolean, message: string) => {
    const deadline = Date.now() + 3000;
    while ((await readNativeVisibility()) !== expected && Date.now() < deadline) {
      await act(async () => new Promise((resolve) => setTimeout(resolve, 20)));
    }
    assert.equal(await readNativeVisibility(), expected, message);
  };
  const click = async (text: string) => {
    const target = [...document.querySelectorAll<HTMLElement>('button, [role="menuitem"]')].find(
      (item) => item.textContent === text,
    );
    assert.ok(target, `Missing control: ${text}`);
    await act(async () => target.click());
    await settle();
  };
  const openConnectionMenu = async () => {
    await act(async () => {
      document
        .getElementById('connection-menu')
        .dispatchEvent(
          new MouseEvent('contextmenu', { bubbles: true, button: 2, clientX: 20, clientY: 20 }),
        );
    });
    await settle();
    await expectVisibility(false, 'the context menu hides the native session');
  };
  const preview = () => document.querySelector('[aria-label="Web browser canvas"] img');
  const requestDelete = async (expectPreview = true) => {
    await openConnectionMenu();
    if (expectPreview) {
      assert.ok(preview(), 'the production preview must replace the native page');
    }
    boundsRequests.length = 0;
    await click('Delete connection');
    assert.ok(document.querySelector('[role="dialog"]'));
    assert.equal(
      await readNativeVisibility(),
      false,
      'closing the context menu must not put the native page over the delete confirmation',
    );
    assert.ok(
      !boundsRequests.some((request) => request.visible),
      'the native page must stay hidden throughout the menu-to-dialog handoff',
    );
  };

  await render();
  await settle();
  assert.equal(await readNativeVisibility(), true);
  await requestDelete();
  for (let revision = 1; revision <= 3; revision++) {
    await render({ revision });
    const canvas = document.querySelector('[aria-label="Web browser canvas"]');
    assert.equal(canvas.getBoundingClientRect().width, 700 + revision);
    // Hidden test windows can defer ResizeObserver notifications. Also exercise the resize event
    // so the coalesced bounds callback runs before the next change.
    await act(async () => {
      window.dispatchEvent(new Event('resize'));
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    });
    assert.equal(await readNativeVisibility(), false, 'resizing must preserve modal occlusion');
  }
  assert.ok(
    !boundsRequests.some((request) => request.capturePreview),
    'Resizing an occluded canvas must not request the captured image again',
  );
  await click('Another confirmation');
  assert.equal(await readNativeVisibility(), false);
  await click('Close nested confirmation');
  assert.equal(await readNativeVisibility(), false, 'the outer confirmation is still open');
  await click('Cancel');
  assert.equal(await readNativeVisibility(), true, 'Cancel restores the session');
  assert.equal(boundsRequests.at(-1)?.width, 703, 'Restored bounds match the resized canvas');

  await requestDelete();
  await render({ mounted: false });
  await settle();
  assert.equal(await readNativeVisibility(), true, 'unmounting a dialog releases occlusion');
  await render();
  await click('Cancel');
  await setNativeCaptureMode('failed');
  await requestDelete(false);
  await click('Cancel');
  assert.equal(await readNativeVisibility(), true, 'a failed preview does not strand the session');

  await setNativeCaptureMode('delayed');
  await click('Delete directly');
  assert.ok(document.querySelector('[role="dialog"]'));
  await expectVisibility(false, 'a stalled capture must not keep the native page over the dialog');
  await click('Cancel');
  assert.equal(await readNativeVisibility(), true);
  await act(async () => finishNativeCaptures());
  await settle();
  assert.equal(await readNativeVisibility(), true, 'a late capture cannot hide the restored page');

  // Closing the browser must reveal the dialog without waiting for a capture.
  boundsRequests.length = 0;
  await act(async () => document.getElementById('close-browser').click());
  assert.ok(document.querySelector('[role="alertdialog"]'));
  assert.equal(await readNativeVisibility(), false);
  assert.ok(!boundsRequests.some((request) => request.capturePreview));
  assert.equal(preview(), null);
  await click('Keep browser open');
  assert.equal(await readNativeVisibility(), true);

  await setNativeCaptureMode('success');
  await openConnectionMenu();
  assert.ok(preview(), 'the menu fixture supplies an opaque white preview');
  boundsRequests.length = 0;
  await click('Close browser from menu');
  assert.ok(document.querySelector('[role="alertdialog"]'));
  assert.equal(await readNativeVisibility(), false);
  assert.ok(!boundsRequests.some((request) => request.visible || request.capturePreview));
  assert.equal(preview(), null, 'the close dialog must discard the menu snapshot');
  await click('Keep browser open');
  assert.equal(await readNativeVisibility(), true);
  await act(async () => root.unmount());
}
