import * as React from 'react';
import { createRoot } from 'react-dom/client';
import App from '../../src/App';
import { SidebarLayout, SidebarPinButton } from '../../src/components/SidebarLayout';
import { SidebarNavigation, type SidebarPage } from '../../src/components/SidebarNavigation';
import { UpdateNotification } from '../../src/components/UpdateNotification';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuOverlayProvider,
  ContextMenuTrigger,
  useContextMenuOverlayOpen,
} from '../../src/components/ui/context-menu';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../../src/components/ui/dropdown-menu';
import { Sidebar, SidebarProvider } from '../../src/components/ui/sidebar';
import { TooltipProvider } from '../../src/components/ui/tooltip';
import '../../src/index.css';

declare global {
  interface Window {
    sidebarAssert: typeof import('node:assert/strict');
    sidebarInput: (event: Record<string, unknown>) => Promise<void>;
    sidebarReducedMotion: (reduce: boolean) => Promise<void>;
    sidebarObserve: (stage: string) => Promise<void>;
    runSidebarTests: (handleOnly?: boolean) => Promise<void>;
  }
}

const writes: number[] = [];
const saves: boolean[] = [];
const pending: { resolve: () => void; reject: (error: Error) => void }[] = [];

function Harness({
  pinned,
  width,
  notification = false,
  rejectImmediately = false,
}: {
  pinned: boolean;
  width: number;
  notification?: boolean;
  rejectImmediately?: boolean;
}) {
  const menuOpen = useContextMenuOverlayOpen();
  const [dropdownOpen, setDropdownOpen] = React.useState(false);
  const [overlayOpen, setOverlayOpen] = React.useState(false);
  const [activePage, setActivePage] = React.useState<SidebarPage>('sessions');
  return (
    <div className="flex h-full flex-col">
      <SidebarLayout
        header={
          <>
            <header className="flex h-12 shrink-0 items-center border-b px-1 [-webkit-app-region:drag]">
              <div className="flex items-center gap-2.5 [-webkit-app-region:no-drag]">
                <SidebarPinButton />
                <span id="wormhole-title">Wormhole</span>
              </div>
            </header>
            {notification ? (
              <UpdateNotification
                version="9.9.9"
                busy={false}
                status=""
                downloadProgress={null}
                onDismiss={() => {}}
                onUpdate={() => {}}
                onViewChanges={() => {}}
              />
            ) : null}
          </>
        }
        navigation={(collapsed) => (
          <SidebarNavigation
            activePage={activePage}
            onNavigate={setActivePage}
            sessionCount={2}
            collapsed={collapsed}
          />
        )}
        initialPinned={pinned}
        initialWidth={width}
        keepOpen={dropdownOpen}
        onPinnedChange={(value) => {
          saves.push(value);
          if (rejectImmediately) return Promise.reject(new Error('disk unavailable'));
          return new Promise<void>((resolve, reject) => pending.push({ resolve, reject }));
        }}
        onWidthChange={(value) => writes.push(value)}
        onOverlayOpenChange={setOverlayOpen}
        sidebar={
          <SidebarProvider
            className="h-full min-h-0"
            style={{ '--sidebar-width': '100%' } as React.CSSProperties}
          >
            <Sidebar collapsible="none">
              <div className="flex items-center justify-between p-3">Connections</div>
              <input aria-label="Search connections" className="m-3 border p-2" />
              <DropdownMenu onOpenChange={setDropdownOpen}>
                <DropdownMenuTrigger className="m-3 border p-2">
                  Import connections
                </DropdownMenuTrigger>
                <DropdownMenuContent side="right">
                  <DropdownMenuItem>Import from mRemoteNG</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
              <ContextMenu>
                <ContextMenuTrigger id="tree" className="m-3 flex-1 border p-3">
                  Connection tree
                </ContextMenuTrigger>
                <ContextMenuContent>
                  <ContextMenuItem>New connection</ContextMenuItem>
                </ContextMenuContent>
              </ContextMenu>
            </Sidebar>
          </SidebarProvider>
        }
      >
        <main id="content" className="h-full bg-background p-8">
          <ContextMenu>
            <ContextMenuTrigger asChild>
              <button id="outside">Session content</button>
            </ContextMenuTrigger>
            <ContextMenuContent>
              <ContextMenuItem>Session action</ContextMenuItem>
            </ContextMenuContent>
          </ContextMenu>
          <output id="native-visible">{String(!overlayOpen && !menuOpen)}</output>
          <output id="page">{activePage}</output>
        </main>
      </SidebarLayout>
    </div>
  );
}

window.runSidebarTests = async (handleOnly = false) => {
  if (handleOnly) return runAppIntegrationTests(true);
  const assert = window.sidebarAssert;
  const root = createRoot(document.getElementById('root')!);
  let key = 0;
  const mount = async (
    pinned = true,
    width = 320,
    options: { notification?: boolean; rejectImmediately?: boolean } = {},
  ) => {
    await React.act(async () =>
      root.render(
        <React.StrictMode>
          <TooltipProvider>
            <ContextMenuOverlayProvider>
              <Harness key={++key} pinned={pinned} width={width} {...options} />
            </ContextMenuOverlayProvider>
          </TooltipProvider>
        </React.StrictMode>,
      ),
    );
    await tick();
  };
  const tick = () => React.act(async () => new Promise((resolve) => setTimeout(resolve, 30)));
  const waitFor = async (condition: () => boolean, message: string) => {
    const deadline = performance.now() + 5000;
    while (!condition()) {
      assert.ok(
        performance.now() < deadline,
        message +
          ': ' +
          JSON.stringify({
            writes,
            left: left(),
            width: aside().getBoundingClientRect().width,
            state: layout().dataset,
            transitions: aside()
              .getAnimations()
              .map((animation) => ({
                property: (animation as CSSTransition).transitionProperty,
                state: animation.playState,
              })),
          }),
      );
      await tick();
    }
  };
  const query = (selector: string) => document.querySelector<HTMLElement>(selector)!;
  const layout = () => query('[data-sidebar-layout]');
  const aside = () => query('aside');
  const sidebarContent = () => query('[data-sidebar-content]');
  const pin = () => query('[data-sidebar-pin]') as HTMLButtonElement;
  const rail = () => query('[aria-label="Show sidebar"]');
  const left = () => query('#content').getBoundingClientRect().left;
  const shown = async (expected: boolean) => {
    await waitFor(
      () =>
        layout().dataset.revealed === String(expected) &&
        aside().getAnimations().length === 0 &&
        (expected
          ? aside().getBoundingClientRect().left === 0
          : aside().getBoundingClientRect().right === 40),
      'Sidebar visibility did not settle',
    );
    assert.equal(
      layout().dataset.revealed,
      String(expected),
      JSON.stringify({
        state: layout().dataset,
        active: document.activeElement?.tagName,
        hover: aside().matches(':hover'),
      }),
    );
    assert.equal(sidebarContent().inert, !expected);
    assert.equal(sidebarContent().getAttribute('aria-hidden'), String(!expected));
  };
  const move = async (x: number, y = 450) => {
    await React.act(async () => window.sidebarInput({ type: 'mouseMove', x, y }));
    await tick();
    if (x === 6) await shown(true);
  };
  const click = async (element: HTMLElement) => {
    const bounds = element.getBoundingClientRect();
    const x = Math.round(bounds.x + bounds.width / 2),
      y = Math.round(bounds.y + bounds.height / 2);
    await move(x, y);
    await waitFor(
      () => element.contains(document.elementFromPoint(x, y)),
      'Click target is covered: ' +
        JSON.stringify({
          target: element.getAttribute('aria-label'),
          hit: document.elementFromPoint(x, y)?.outerHTML.slice(0, 250),
          state: layout().dataset,
          x,
          y,
          disabled: (element as HTMLButtonElement).disabled,
          pointerEvents: getComputedStyle(element).pointerEvents,
          bounds: element.getBoundingClientRect().toJSON(),
        }),
    );
    await React.act(async () => {
      await window.sidebarInput({ type: 'mouseDown', button: 'left', x, y, clickCount: 1 });
      await window.sidebarInput({ type: 'mouseUp', button: 'left', x, y, clickCount: 1 });
    });
    await tick();
  };
  const keypress = async (keyCode: string) => {
    await React.act(async () => {
      await window.sidebarInput({ type: 'keyDown', keyCode });
      await window.sidebarInput({ type: 'keyUp', keyCode });
    });
    await tick();
  };
  const settle = async (fail = false) => {
    await waitFor(
      () => pending.length > 0,
      'Preference write did not start, saves ' + JSON.stringify(saves),
    );
    const save = pending.shift();
    assert.ok(save, 'Expected a pending sidebar preference write');
    await React.act(async () =>
      fail ? save.reject(new Error('disk unavailable')) : save.resolve(),
    );
    await tick();
    await waitFor(
      () =>
        layout().dataset.pinned === 'true'
          ? left() >= aside().getBoundingClientRect().right
          : Math.abs(left() - 40) <= 1,
      'Pin layout did not settle',
    );
  };

  // Keep interaction regressions fast; exercise actual motion separately below.
  await React.act(async () => window.sidebarReducedMotion(true));
  await mount();
  await shown(true);
  const navigation = query('nav[aria-label="Main navigation"]');
  const navigationButtons = [...navigation.querySelectorAll('button')];
  const assertBadgeAligned = () => {
    const sessionsBounds = navigationButtons[0].getBoundingClientRect();
    const badgeBounds = query('[data-slot="sidebar-menu-badge"]').getBoundingClientRect();
    assert.ok(
      badgeBounds.top >= sessionsBounds.top &&
        badgeBounds.bottom <= sessionsBounds.bottom &&
        Math.abs(
          badgeBounds.top + badgeBounds.height / 2 - sessionsBounds.top - sessionsBounds.height / 2,
        ) <= 1,
      'The session count badge must stay centered inside the Sessions button',
    );
  };
  const assertResizeHandleCentered = () => {
    const separator = query('[data-slot="resizable-handle"]');
    const separatorBounds = separator.getBoundingClientRect();
    const gripBounds = separator.firstElementChild!.getBoundingClientRect();
    const surface = query('[data-sidebar-surface]');
    const dividerLeft =
      surface.getBoundingClientRect().right -
      parseFloat(getComputedStyle(surface).borderRightWidth);
    assert.ok(
      Math.abs(
        gripBounds.left + gripBounds.width / 2 - (dividerLeft + separatorBounds.right) / 2,
      ) <= 0.25,
      'The resize grip must stay centered across both visible divider borders',
    );
    assert.ok(
      Math.abs(
        gripBounds.top + gripBounds.height / 2 - (separatorBounds.top + separatorBounds.height / 2),
      ) <= 0.5,
      'The resize grip must stay vertically centered on the separator',
    );
    for (const x of [gripBounds.left + 0.5, gripBounds.right - 0.5]) {
      assert.ok(
        separator.contains(document.elementFromPoint(x, gripBounds.top + gripBounds.height / 2)),
        'Both sides of the resize grip must remain above the sidebar surface',
      );
    }
  };
  assertBadgeAligned();
  assertResizeHandleCentered();
  assert.equal(pin().getAttribute('aria-label'), 'Unpin sidebar');
  assert.equal(pin().getAttribute('aria-pressed'), 'true');
  assert.ok(
    pin().querySelector('svg.lucide-panel-left'),
    'Titlebar toggle must use the sidebar icon',
  );
  const pinnedColumn = pin().querySelector('svg path[fill="currentColor"]');
  assert.ok(pinnedColumn, 'Pinned sidebar icon must have a solid left column');
  assert.equal(
    getComputedStyle(pinnedColumn).fill,
    getComputedStyle(pin().querySelector('svg')!).stroke,
  );
  assert.equal(pin().querySelector('svg')!.getAttribute('aria-hidden'), 'true');
  assert.ok(
    query('aside nav [aria-current="page"]').querySelector('svg.lucide-terminal'),
    'Expanded Sessions button must use the SSH icon',
  );
  assert.ok(
    [...document.querySelectorAll('aside nav button')]
      .find((button) => button.textContent === 'Settings')
      ?.querySelector('svg.lucide-settings'),
    'Expanded Settings button must use the gear icon',
  );
  assert.ok(Math.abs(left() - 321) <= 1);
  const content = query('#content');
  const search = query('input') as HTMLInputElement;
  search.value = 'saved query';

  // Use the existing accessible resize handle, then retain that width across pin changes.
  await React.act(
    async () =>
      new Promise<void>((resolve) => {
        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
      }),
  );
  await React.act(async () => query('[role="separator"]').focus());
  await waitFor(
    () => query('[role="separator"]').getAttribute('aria-valuenow') !== null,
    'Resize handle was not initialized',
  );
  await React.act(async () =>
    query('[role="separator"]').dispatchEvent(
      new KeyboardEvent('keydown', {
        key: 'ArrowRight',
        bubbles: true,
        cancelable: true,
      }),
    ),
  );
  await tick();
  await waitFor(
    () => writes.length > 0 && aside().getBoundingClientRect().width > 320,
    'Resize did not update the sidebar',
  );
  assert.ok(writes.length > 0);
  const keyboardWidth = aside().getBoundingClientRect().width;
  const gripBounds = query('[data-slot="resizable-handle"] > div').getBoundingClientRect();
  const dragX = Math.ceil(gripBounds.left + 0.5);
  const dragY = Math.round(gripBounds.top + gripBounds.height / 2);
  await move(dragX, dragY);
  await React.act(async () =>
    window.sidebarInput({ type: 'mouseDown', button: 'left', x: dragX, y: dragY, clickCount: 1 }),
  );
  await tick();
  await React.act(async () =>
    window.sidebarInput({
      type: 'mouseMove',
      modifiers: ['leftbuttondown'],
      x: dragX + 30,
      y: dragY,
    }),
  );
  await tick();
  await React.act(async () =>
    window.sidebarInput({
      type: 'mouseUp',
      button: 'left',
      x: dragX + 30,
      y: dragY,
      clickCount: 1,
    }),
  );
  await waitFor(
    () => aside().getBoundingClientRect().width > keyboardWidth,
    'Pointer resize did not update the sidebar',
  );
  const resizedWidth = aside().getBoundingClientRect().width;
  assert.ok(resizedWidth > 320, JSON.stringify({ resizedWidth, writes, left: left() }));
  assertResizeHandleCentered();

  await click(pin());
  assert.equal(layout().dataset.pinned, 'false');
  assert.equal(pin().querySelector('svg path[fill="currentColor"]'), null);
  assert.equal(pin().getAttribute('aria-disabled'), 'true');
  assert.equal(pin().getAttribute('aria-busy'), 'true');
  await React.act(async () => pin().click());
  assert.deepEqual(saves, [false]);
  await settle();
  await shown(false);
  assert.equal(getComputedStyle(query('[data-slot="resizable-handle"]')).display, 'none');
  assert.equal(document.querySelector('[data-slot="sidebar-menu-badge"]'), null);
  assert.equal(
    document.querySelectorAll('nav[aria-label="Main navigation"]').length,
    1,
    'Collapsing the sidebar duplicated its navigation',
  );
  assert.ok(query('nav[aria-label="Main navigation"]') === navigation);
  assert.ok(
    [...navigation.querySelectorAll('button')].every(
      (button, index) => button === navigationButtons[index],
    ),
    'Collapsing replaced the navigation buttons',
  );
  await move(1000);
  await shown(false);
  assert.ok(Math.abs(left() - 40) <= 1);
  assert.equal(query('#native-visible').textContent, 'true');
  assert.equal(document.activeElement === search, false);

  await move(6);
  await shown(true);
  assertBadgeAligned();
  assert.equal(document.querySelectorAll('nav[aria-label="Main navigation"]').length, 1);
  assert.ok(query('nav[aria-label="Main navigation"]') === navigation);
  assert.ok(
    [...navigation.querySelectorAll('button')].every(
      (button, index) => button === navigationButtons[index],
    ),
  );
  assert.ok(Math.abs(left() - 40) <= 1, 'Hovering must not move the session');
  assert.equal(query('#native-visible').textContent, 'false');
  assert.ok(query('#content') === content, 'Pin changes remounted the session content');
  assert.equal((query('input') as HTMLInputElement).value, 'saved query');
  assert.equal(aside().getBoundingClientRect().width, resizedWidth);
  await move(1000);
  await shown(false);

  // Keyboard focus opens the rail, remains usable within the panel, and Escape closes it.
  await keypress('Tab');
  await React.act(async () => rail().focus());
  await tick();
  await shown(true);
  await keypress('Tab');
  assert.ok(document.activeElement === search, 'Tab did not reach the connection search');
  await move(1000);
  await shown(true);
  await keypress('Escape');
  await shown(false);
  assert.ok(document.activeElement === rail(), 'Escape did not return focus to the reveal button');
  await React.act(async () => query('#outside').focus());

  // Both types of portaled menus keep their sidebar visible beyond its bounds.
  await move(6);
  await click(query('[data-slot="dropdown-menu-trigger"]'));
  await waitFor(() => document.querySelector('[role="menu"]') !== null, 'Import menu did not open');
  assert.ok(document.querySelector('[role="menu"]'));
  await move(700);
  await shown(true);
  await keypress('Escape');
  await move(6);
  const treeBounds = query('#tree').getBoundingClientRect();
  await React.act(async () =>
    query('#tree').dispatchEvent(
      new MouseEvent('contextmenu', {
        bubbles: true,
        cancelable: true,
        button: 2,
        clientX: 310,
        clientY: treeBounds.y + 20,
      }),
    ),
  );
  await tick();
  await waitFor(
    () => document.querySelector('[role="menu"]') !== null,
    'Context menu did not open',
  );
  assert.ok(document.querySelector('[role="menu"]'));
  await move(700);
  await shown(true);
  await keypress('Escape');
  await move(6);
  await click(pin());
  await settle();
  await shown(true);
  assert.equal(layout().dataset.pinned, 'true');
  assert.ok(pin().querySelector('svg path[fill="currentColor"]'));
  await move(1000);
  await shown(true);
  await waitFor(
    () => Math.abs(left() - resizedWidth - 1) <= 1,
    'Pinned sidebar did not restore its previous width',
  );
  assertResizeHandleCentered();
  assert.equal(query('#native-visible').textContent, 'true');
  assert.ok(
    writes.every((width) => width >= 256),
    'Collapsing must not overwrite the saved width',
  );

  // Failed persistence rolls back either direction and offers a successful retry.
  await click(pin());
  await settle(true);
  assert.equal(layout().dataset.pinned, 'true');
  assert.match(query('[role="alert"]').textContent!, /couldn't save the sidebar preference/);
  assert.equal(pin().getAttribute('aria-disabled'), 'false');
  await click(pin());
  await settle();
  assert.equal(document.querySelector('[role="alert"]'), null);
  await click(pin());
  await settle(true);
  assert.equal(layout().dataset.pinned, 'false');
  await click(pin());
  await settle();

  // Restore the unpinned preference on startup; unrelated menus cannot reveal a hidden sidebar.
  await move(1000);
  await mount(false, 420);
  await shown(false);
  assert.ok(Math.abs(left() - 40) <= 1);
  await React.act(async () =>
    query('#outside').dispatchEvent(
      new MouseEvent('contextmenu', {
        bubbles: true,
        cancelable: true,
        button: 2,
        clientX: 700,
        clientY: 40,
      }),
    ),
  );
  await waitFor(
    () => document.querySelector('[role="menu"]') !== null,
    'Session menu did not open',
  );
  await shown(false);
  await keypress('Escape');
  await React.act(async () => rail().click());
  await shown(true);
  assert.equal(aside().getBoundingClientRect().width, 420);
  await move(6);
  await click(pin());
  await settle();
  assert.equal(aside().getBoundingClientRect().width, 420);
  await React.act(async () => query('#outside').focus());
  await keypress('Escape');
  await shown(true);

  const reviewFailures: string[] = [];
  const reviewCase = async (name: string, run: () => Promise<void>) => {
    try {
      await run();
    } catch (error) {
      reviewFailures.push(name + ': ' + (error as Error).message);
    }
  };
  await reviewCase('an update notification cannot latch the auto-hide sidebar open', async () => {
    await move(1000);
    await mount(false, 420, { notification: true });
    await shown(false);
    await move(6);
    await shown(true);
    await move(900, 300);
    await shown(false);
    assert.ok(document.getElementById('update-notification-title'));
    assert.equal(
      query('#native-visible').textContent,
      'false',
      'The notification must still hide native surfaces',
    );
  });
  await reviewCase(
    'scoped sidebar menus hide native surfaces and release them on close or unmount',
    async () => {
      await move(1000);
      await mount(true, 420);
      const openMenu = async () => {
        const bounds = query('#tree').getBoundingClientRect();
        await React.act(async () =>
          query('#tree').dispatchEvent(
            new MouseEvent('contextmenu', {
              bubbles: true,
              cancelable: true,
              button: 2,
              clientX: bounds.x + 20,
              clientY: bounds.y + 20,
            }),
          ),
        );
        await waitFor(
          () => query('#native-visible').textContent === 'false',
          'The scoped menu did not hide native surfaces',
        );
      };
      await openMenu();
      await keypress('Escape');
      await waitFor(
        () => query('#native-visible').textContent === 'true',
        'Closing the scoped menu left native surfaces hidden',
      );
      await openMenu();
      await mount(true, 420);
      await waitFor(
        () => query('#native-visible').textContent === 'true',
        'Unmounting the scoped menu left native surfaces hidden',
      );
    },
  );
  await reviewCase('keyboard save failure keeps its error accessible', async () => {
    await move(1000);
    await mount(false, 420);
    await keypress('Tab');
    await React.act(async () => rail().focus());
    await shown(true);
    await waitFor(
      () => getComputedStyle(pin()).visibility === 'visible',
      'Pin button remained hidden',
    );
    await React.act(async () => pin().focus());
    assert.ok(document.activeElement === pin(), 'Keyboard focus did not reach the pin button');
    await React.act(async () => pin().click());
    assert.ok(document.activeElement === pin(), 'Saving the pin preference dropped keyboard focus');
    await settle(true);
    assert.equal(layout().dataset.pinned, 'false');
    assert.equal(getComputedStyle(query('[role="alert"]')).visibility, 'visible');
    assert.equal(query('[role="alert"]').closest('[inert]'), null);
    assert.match(query('[role="alert"]').textContent!, /couldn't save the sidebar preference/);
    await React.act(async () => query('#outside').focus());
    await tick();
    assert.equal(
      layout().dataset.revealed,
      'false',
      'The failed pin left stale focus ownership after leaving the sidebar',
    );
  });
  await reviewCase('immediate unpin failure releases native occlusion after rollback', async () => {
    await move(1000);
    await mount(true, 420, { rejectImmediately: true });
    await React.act(async () => pin().click());
    await waitFor(
      () =>
        layout().dataset.pinned === 'true' &&
        pin().getAttribute('aria-busy') === 'false' &&
        query('#native-visible').textContent === 'true',
      'An immediate failed unpin left native surfaces hidden',
    );
    assert.ok(left() >= aside().getBoundingClientRect().right);
    assert.match(query('[role="alert"]').textContent!, /couldn't save/);
  });
  await reviewCase('deferred pin protects native surfaces on success and rollback', async () => {
    for (const fail of [false, true]) {
      await move(1000);
      await mount(false, 420);
      await move(6);
      const originalRequest = window.requestAnimationFrame;
      const originalCancel = window.cancelAnimationFrame;
      const frames = new Map<number, FrameRequestCallback>();
      let frameId = 1_000_000;
      window.requestAnimationFrame = (callback) => {
        frames.set(++frameId, callback);
        return frameId;
      };
      window.cancelAnimationFrame = (id) => {
        frames.delete(id);
      };
      try {
        await React.act(async () => pin().click());
        await waitFor(
          () => left() >= 256,
          'Pin constraints did not apply before the deferred frame',
        );
        await tick();
        const reserved = left();
        const sidebarRight = aside().getBoundingClientRect().right;
        const nativeProtected =
          query('#native-visible').textContent === 'false' || sidebarRight <= reserved;
        const save = pending.shift();
        assert.ok(save);
        await React.act(async () =>
          fail ? save.reject(new Error('disk unavailable')) : save.resolve(),
        );
        assert.ok(
          nativeProtected,
          'Pinning restored native surfaces before the sidebar reserved its full width: ' +
            JSON.stringify({ left: reserved, sidebarRight }),
        );
        await tick();
        assert.equal(layout().dataset.pinned, String(!fail));
        assert.equal(
          aside().getBoundingClientRect().width,
          420,
          'The deferred pin replaced the saved width with the transient minimum',
        );
      } finally {
        window.requestAnimationFrame = originalRequest;
        window.cancelAnimationFrame = originalCancel;
        for (const callback of frames.values()) originalRequest(callback);
      }
      await waitFor(
        () =>
          fail
            ? Math.abs(left() - 40) <= 1
            : left() >= aside().getBoundingClientRect().right &&
              query('#native-visible').textContent === 'true',
        'Deferred pin layout and native visibility did not settle',
      );
    }
  });
  await reviewCase('keyboard reopening after Escape closes when focus leaves', async () => {
    await move(1000);
    await mount(false, 420);
    await keypress('Tab');
    await React.act(async () => rail().focus());
    await shown(true);
    await React.act(async () =>
      rail().dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }),
      ),
    );
    await shown(false);
    assert.ok(document.activeElement === rail(), 'Escape did not focus the reveal button');
    await React.act(async () => rail().click());
    await shown(true);
    await React.act(async () => query('#outside').focus());
    await tick();
    assert.equal(
      layout().dataset.revealed,
      'false',
      'The explicit reopen remained latched after focus left',
    );
  });
  await reviewCase('mouse movement inside the rail recovers after Escape', async () => {
    await move(1000);
    await mount(false, 420);
    await keypress('Tab');
    await React.act(async () => rail().focus());
    await move(6);
    await shown(true);
    await keypress('Escape');
    await shown(false);
    await move(20);
    await shown(true);
    await move(1000);
    await React.act(async () => query('#outside').focus());
    await shown(false);
  });
  assert.deepEqual(reviewFailures, []);

  // One persistent titlebar control precedes the app name and works while the sidebar is hidden.
  await move(1000);
  await mount(false, 420);
  await shown(false);
  const titlebarPin = pin();
  const pinBounds = titlebarPin.getBoundingClientRect();
  assert.equal(document.querySelectorAll('[data-sidebar-pin]').length, 1);
  assert.ok(query('header').contains(titlebarPin));
  assert.ok(pinBounds.right < query('#wormhole-title').getBoundingClientRect().left);
  assert.equal(query('header').querySelector('img'), null);
  assert.equal(getComputedStyle(titlebarPin).getPropertyValue('-webkit-app-region'), 'no-drag');
  assert.equal(titlebarPin.getAttribute('aria-label'), 'Pin sidebar');
  assert.equal(titlebarPin.getAttribute('aria-pressed'), 'false');
  assert.equal(getComputedStyle(titlebarPin).visibility, 'visible');
  assert.equal(titlebarPin.closest('[inert]'), null);
  assert.ok(titlebarPin.querySelector('svg.lucide-panel-left'));
  assert.equal(titlebarPin.querySelector('svg path[fill="currentColor"]'), null);
  assert.equal(titlebarPin.querySelector('svg')!.getAttribute('aria-hidden'), 'true');
  assert.ok(pinBounds.width >= 32 && pinBounds.height >= 32);
  assert.equal(rail().children.length, 0, 'The removed vertical grip returned');
  const nav = query('[data-sidebar-navigation] nav');
  assert.ok(
    nav.querySelector('[aria-label="Sessions"] svg.lucide-terminal'),
    'Collapsed Sessions button must use the SSH icon',
  );
  assert.ok(
    nav.querySelector('[aria-label="Settings"] svg.lucide-settings'),
    'Collapsed Settings button must use the gear icon',
  );
  assert.deepEqual(
    [...nav.querySelectorAll('button')].map((button) => button.getAttribute('aria-label')),
    ['Sessions', 'Credentials', 'Tunnels', 'Settings'],
  );
  for (const button of nav.querySelectorAll('button')) {
    assert.ok(button.querySelector('svg'));
    assert.equal(getComputedStyle(button).visibility, 'visible');
    assert.ok(button.getBoundingClientRect().right <= aside().getBoundingClientRect().right);
    await click(button);
    assert.equal(button.getAttribute('aria-current'), 'page');
    assert.equal(query('#page').textContent, button.getAttribute('aria-label')!.toLowerCase());
  }
  await move(1000);
  await React.act(async () => query('#outside').focus());
  await shown(false);
  const saveCount = saves.length;
  await move(Math.round(pinBounds.x + pinBounds.width / 2), Math.round(pinBounds.y + 16));
  await shown(false);
  assert.equal(query('#native-visible').textContent, 'true');
  await click(titlebarPin);
  assert.equal(saves.length, saveCount + 1);
  assert.equal(saves.at(-1), true);
  assert.equal(layout().dataset.pinned, 'true');
  assert.ok(pin() === titlebarPin, 'Pinning replaced the titlebar control');
  assert.ok(document.activeElement === titlebarPin, 'Pinning from the titlebar lost focus');
  assert.equal(pin().getAttribute('aria-busy'), 'true');
  await React.act(async () => pin().click());
  assert.equal(saves.length, saveCount + 1, 'A pending titlebar pin was submitted twice');
  await settle(true);
  await shown(false);
  assert.equal(layout().dataset.pinned, 'false');
  assert.match(query('[role="alert"]').textContent!, /couldn't save the sidebar preference/);
  assert.ok(document.activeElement === pin(), 'Failed titlebar pin lost its retry control');
  assert.equal(query('[role="alert"]').closest('aside'), null);
  await move(1000);
  await React.act(async () => query('#outside').focus());
  await shown(false);

  await keypress('Tab');
  await React.act(async () => pin().focus());
  await shown(false);
  await keypress('Space');
  assert.equal(layout().dataset.pinned, 'true');
  assert.ok(document.activeElement === pin(), 'Keyboard titlebar pin did not retain focus');
  await settle();
  await shown(true);
  assert.equal(document.querySelectorAll('[data-sidebar-pin]').length, 1);
  assert.equal(aside().getBoundingClientRect().width, 420);
  assert.equal(query('#native-visible').textContent, 'true');

  await move(1000);
  await React.act(async () => window.sidebarReducedMotion(false));
  await mount(false, 420);
  await shown(false);
  assert.equal(aside().getBoundingClientRect().right, 40);
  const animatedSurface = aside();
  const session = query('#content');
  // Pause real CSS transitions so intermediate positions and reversals are deterministic.
  const beginSlide = async (x: number, y = 450) => {
    await React.act(async () => window.sidebarInput({ type: 'mouseMove', x, y }));
    const slide = () =>
      animatedSurface
        .getAnimations()
        .find(
          (animation) =>
            animation instanceof CSSTransition && animation.transitionProperty === 'width',
        );
    await waitFor(
      () => layout().dataset.revealed === String(x < 40) && Boolean(slide()),
      'Sidebar slide transition did not start',
    );
    for (const animation of animatedSurface.getAnimations()) animation.pause();
    return slide()!;
  };
  const halfway = async (animation: Animation) => {
    await React.act(async () => {
      animation.currentTime = Number(animation.effect!.getComputedTiming().activeDuration) / 2;
    });
    const bounds = animatedSurface.getBoundingClientRect();
    assert.equal(bounds.left, 0, 'The existing sidebar moved instead of expanding');
    assert.ok(
      bounds.width > 40 && bounds.width < 420,
      'Sidebar did not pass through an intermediate width',
    );
    assert.equal(document.querySelectorAll('nav[aria-label="Main navigation"]').length, 1);
    assert.equal(left(), 40, 'Sliding the sidebar moved the session');
    assert.ok(query('#content') === session, 'Sliding remounted the session');
  };
  const finishSlide = async () => {
    await React.act(async () => {
      for (const animation of animatedSurface.getAnimations()) animation.finish();
    });
    await tick();
  };
  try {
    const entering = await beginSlide(20, 68);
    assert.equal(entering.effect!.getComputedTiming().activeDuration, 200);
    await halfway(entering);
    assert.equal(query('#native-visible').textContent, 'false');
    await finishSlide();
    await shown(true);
    assert.equal(animatedSurface.getBoundingClientRect().left, 0);

    await halfway(await beginSlide(1000));
    assert.equal(getComputedStyle(pin()).visibility, 'visible');
    assert.ok(pin() === titlebarPin || query('header').contains(pin()));
    assert.equal(sidebarContent().inert, true);
    assert.equal(getComputedStyle(sidebarContent()).pointerEvents, 'none');
    assert.equal(getComputedStyle(animatedSurface).visibility, 'visible');
    assert.equal(query('#native-visible').textContent, 'false');
    assert.ok(!sidebarContent().contains(document.elementFromPoint(20, 450)));

    // Reenter before exit completes: cancellation must not expose native surfaces.
    await halfway(await beginSlide(6));
    await tick();
    assert.equal(sidebarContent().inert, false);
    assert.equal(query('#native-visible').textContent, 'false');
    await finishSlide();
    await shown(true);
    assert.equal(query('#native-visible').textContent, 'false');

    await halfway(await beginSlide(1000));
    await finishSlide();
    await shown(false);
    assert.equal(animatedSurface.getBoundingClientRect().right, 40);
    assert.equal(query('#native-visible').textContent, 'true');

    // Changing the system preference during an exit cancels motion and releases the overlay.
    await beginSlide(6);
    await finishSlide();
    await shown(true);
    await halfway(await beginSlide(1000));
    await React.act(async () => window.sidebarReducedMotion(true));
    await shown(false);
    await waitFor(
      () => query('#native-visible').textContent === 'true',
      'Cancelling sidebar motion did not restore native surfaces',
    );
    assert.equal(query('#native-visible').textContent, 'true');
    assert.equal(getComputedStyle(animatedSurface).transitionProperty, 'none');
    await move(6);
    await shown(true);
    assert.equal(animatedSurface.getBoundingClientRect().left, 0);
    assert.equal(query('#native-visible').textContent, 'false');
    await move(1000);
    await shown(false);
    assert.equal(query('#native-visible').textContent, 'true');
  } finally {
    await React.act(async () => window.sidebarReducedMotion(false));
  }
  await React.act(async () => root.unmount());
  await runAppIntegrationTests();
};

async function runAppIntegrationTests(handleOnly = false) {
  const assert = window.sidebarAssert;
  const root = createRoot(document.getElementById('root')!);
  const query = (selector: string) => document.querySelector<HTMLElement>(selector)!;
  const tick = () => React.act(async () => new Promise((resolve) => setTimeout(resolve, 30)));
  const waitFor = async (condition: () => boolean, message: string) => {
    const deadline = performance.now() + 5000;
    while (!condition()) {
      assert.ok(performance.now() < deadline, message);
      await tick();
    }
  };
  const move = async (x: number, y: number) => {
    await React.act(async () => window.sidebarInput({ type: 'mouseMove', x, y }));
    await tick();
  };
  const click = async (element: HTMLElement) => {
    const bounds = element.getBoundingClientRect();
    const x = Math.round(bounds.x + bounds.width / 2);
    const y = Math.round(bounds.y + bounds.height / 2);
    await move(x, y);
    await React.act(async () => {
      await window.sidebarInput({ type: 'mouseDown', x, y, button: 'left', clickCount: 1 });
      await window.sidebarInput({ type: 'mouseUp', x, y, button: 'left', clickCount: 1 });
    });
    await tick();
  };
  const shown = async (expected: boolean) => {
    await waitFor(() => {
      const surface = query('[data-sidebar-surface]');
      // Flush computed layout even while a hidden Chromium window still reports an animation.
      const bounds = surface.getBoundingClientRect();
      return (
        query('[data-sidebar-layout]').dataset.revealed === String(expected) &&
        surface.getAnimations().length === 0 &&
        (expected ? bounds.left === 0 : bounds.right === 40)
      );
    }, 'Full App sidebar did not settle: ' + expected);
  };
  let appKey = 0;
  const mount = async (
    tree: WormholeWorkspaceNode[],
    width = 320,
    pinned = false,
    theme: 'dark' | 'light' = 'dark',
  ) => {
    await React.act(async () =>
      root.render(
        <React.StrictMode key={++appKey}>
          <ContextMenuOverlayProvider>
            <App
              initialAuthState={{
                mode: 'disabled',
                fallback: 'pin',
                idleTimeoutMinutes: null,
                hasPin: false,
                hasPassword: false,
                isCorrupted: false,
                configured: false,
                windowsHello: { available: false, message: '' },
              }}
              initialWorkspace={{
                tree,
                credentials: [],
                credentialOptions: { ssh: [], rdp: [], vnc: [] },
                tunnels: [],
              }}
              initialSettings={{
                theme,
                promptBeforeTunnelConnect: true,
                autoCopyOnSelect: false,
                confirmOnTabClose: true,
                confirmOnWindowClose: true,
                sidebarWidth: width,
                sidebarPinned: pinned,
                connectionTreeExpansion: null,
                autoCheckForUpdates: false,
                lastUpdateCheck: null,
                skippedUpdateVersion: null,
              }}
            />
            <UpdateNotification
              version="9.9.9"
              busy={false}
              status=""
              downloadProgress={null}
              onDismiss={() => {}}
              onUpdate={() => {}}
              onViewChanges={() => {}}
            />
          </ContextMenuOverlayProvider>
        </React.StrictMode>,
      ),
    );
    await tick();
  };
  const checkPinnedHandle = async () => {
    for (const theme of ['dark', 'light'] as const) {
      await mount([], 294, true, theme);
      await window.sidebarObserve('pinned-' + theme);
    }
  };
  const originalBridge = window.wormhole;
  // Mount the real App; native services are outside this UI test.
  window.wormhole = undefined;
  try {
    // Keep the full App's focus/layout checks deterministic in a hidden profiled window.
    // The component cases above exercise both animated and reduced-motion transitions.
    await React.act(async () => window.sidebarReducedMotion(true));
    if (handleOnly) {
      await checkPinnedHandle();
      return;
    }
    await window.sidebarObserve('mount');
    await mount([
      {
        id: 'tree-folder',
        kind: 'folder',
        name: 'DD LAB',
        children: [
          {
            id: 'tree-child-folder',
            kind: 'folder',
            name: 'Nested folder',
            children: [
              {
                id: 'tree-child-connection',
                kind: 'connection',
                name: 'k3s-cp-01',
                protocol: 'ssh',
              },
            ],
          },
        ],
      },
      ...Array.from({ length: 40 }, (_, index) => ({
        id: `tree-connection-${index}`,
        kind: 'connection' as const,
        name: index === 0 ? 'Long connection name '.repeat(8) : `Server ${index}`,
        protocol: 'ssh' as const,
      })),
    ]);
    await move(1000, 400);
    await shown(false);
    const pin = query('[data-sidebar-pin]');
    assert.equal(document.querySelectorAll('[data-sidebar-pin]').length, 1);
    assert.ok(query('header').contains(pin));
    assert.equal(query('header').querySelector('img'), null);
    assert.equal(query('header span').textContent, 'Wormhole');
    assert.ok(
      pin.getBoundingClientRect().right < query('header span').getBoundingClientRect().left,
    );
    assert.equal(getComputedStyle(pin).getPropertyValue('-webkit-app-region'), 'no-drag');
    assert.equal(query('[aria-label="Show sidebar"]').children.length, 0);
    const nav = query('[data-sidebar-navigation] nav');
    const buttons = [...nav.querySelectorAll<HTMLButtonElement>('button')];
    const iconCenter = (element: Element) => {
      const bounds = element.querySelector('svg')!.getBoundingClientRect();
      return bounds.x + bounds.width / 2;
    };
    assert.deepEqual(
      buttons.map((button) => button.getAttribute('aria-label')),
      ['Sessions', 'Credentials', 'Tunnels', 'Settings'],
    );
    for (const button of buttons) {
      await window.sidebarObserve(button.getAttribute('aria-label')!);
      assert.ok(button.querySelector('svg'));
      assert.ok(
        Math.abs(iconCenter(pin) - iconCenter(button)) <= 1,
        'Titlebar toggle is not aligned with the collapsed navigation icons',
      );
      const bounds = button.getBoundingClientRect();
      assert.ok(bounds.left >= 0 && bounds.right <= 40 && bounds.bottom <= innerHeight);
      await click(button);
      await shown(true);
      assert.ok(
        Math.abs(iconCenter(pin) - iconCenter(button)) <= 1,
        'Expanding the sidebar moved its navigation icons out of alignment',
      );
      assert.equal(document.querySelectorAll('nav[aria-label="Main navigation"]').length, 1);
      assert.ok(query('nav[aria-label="Main navigation"]') === nav);
      assert.ok(
        [...nav.querySelectorAll('button')].every((current, index) => current === buttons[index]),
        'Expanding remounted navigation buttons',
      );
      assert.equal(button.getAttribute('aria-current'), 'page');
      const label = button.getAttribute('aria-label')!;
      assert.match(
        query('[data-slot="sidebar-inset"]').textContent!,
        new RegExp(label === 'Sessions' ? 'No active sessions' : label, 'i'),
      );
      await move(1000, 400);
      await shown(false);
    }
    const bodyTop = query('[data-sidebar-layout]').getBoundingClientRect().top;
    await window.sidebarObserve('collapsed');
    await move(20, bodyTop + 100);
    await shown(true);
    assert.equal(query('[data-sidebar-surface]').getBoundingClientRect().left, 0);
    const quickConnect = query('aside [aria-keyshortcuts="Control+K Meta+K"]');
    assert.equal(getComputedStyle(quickConnect).visibility, 'visible');
    const quickBounds = quickConnect.getBoundingClientRect();
    assert.ok(
      quickConnect.contains(
        document.elementFromPoint(
          quickBounds.x + quickBounds.width / 2,
          quickBounds.y + quickBounds.height / 2,
        ),
      ),
      'Opening the sidebar left its actions hidden',
    );
    await window.sidebarObserve('hover');
    // App's style-only JSX is outside Node loaded-module coverage. Exercise the changed
    // layout through Chromium's computed styles and geometry, including focus and drop rings.
    const tree = query('[data-connection-tree]');
    const viewport = query('[data-connection-tree] [data-slot="scroll-area-viewport"]');
    await move(
      viewport.getBoundingClientRect().left + 20,
      viewport.getBoundingClientRect().top + 16,
    );
    await waitFor(
      () =>
        query('[data-connection-tree] [data-slot="scroll-area-scrollbar"]')?.dataset.state ===
        'visible',
      'Tree scrollbar did not appear',
    );
    const scrollbar = query('[data-connection-tree] [data-slot="scroll-area-scrollbar"]');
    assert.ok(
      viewport.scrollHeight > viewport.clientHeight,
      'Tree fixture must overflow vertically',
    );
    assert.equal(
      viewport.scrollWidth,
      viewport.clientWidth,
      'Long names must stay within the tree',
    );
    const rows = [...tree.querySelectorAll<HTMLButtonElement>('button[draggable]')];
    assert.equal(rows.length, 43);
    for (const row of rows) {
      const bounds = row.getBoundingClientRect();
      assert.ok(
        bounds.left >= viewport.getBoundingClientRect().left + 4,
        'Tree highlight has no inset from the left viewport edge',
      );
      assert.ok(
        bounds.right <= scrollbar.getBoundingClientRect().left - 2,
        'Tree highlight overlaps the scrollbar',
      );
    }
    await React.act(async () => {
      await window.sidebarInput({ type: 'keyDown', keyCode: 'Tab' });
      await window.sidebarInput({ type: 'keyUp', keyCode: 'Tab' });
    });
    // Cover the shared row style on root/nested folders and connections, including the last row.
    for (const row of [rows[0], rows[1], rows[2], rows[3], rows.at(-1)!]) {
      await React.act(async () => row.focus());
      await tick();
      assert.ok(row.matches(':focus-visible'), 'Tree keyboard focus must remain visible');
      assert.match(
        getComputedStyle(row).boxShadow,
        /\binset\b/,
        'Tree focus ring must stay inside its row',
      );
    }
    await React.act(async () => {
      rows[3].focus();
      viewport.scrollTop = 0;
    });
    await tick();
    const dragData = new DataTransfer();
    await React.act(async () =>
      rows[3].dispatchEvent(new DragEvent('dragstart', { bubbles: true, dataTransfer: dragData })),
    );
    const folder = rows[0];
    const folderBounds = folder.getBoundingClientRect();
    assert.ok(
      folderBounds.top >= viewport.getBoundingClientRect().top,
      'Drop target must be visible',
    );
    assert.ok(!folder.matches(':focus-visible'), 'The drop assertion must not match a focus ring');
    await React.act(async () =>
      folder.dispatchEvent(
        new DragEvent('dragover', {
          bubbles: true,
          cancelable: true,
          clientY: folderBounds.top + folderBounds.height / 2,
          dataTransfer: dragData,
        }),
      ),
    );
    assert.match(
      getComputedStyle(folder).boxShadow,
      /\binset\b/,
      'Tree drop ring must stay inside its row',
    );
    await React.act(async () => {
      rows[3].dispatchEvent(new DragEvent('dragend', { bubbles: true, dataTransfer: dragData }));
      folder.focus();
    });
    await tick();
    await window.sidebarObserve('tree-highlight');
    await React.act(async () => {
      query('[aria-label="Show sidebar"]').focus();
      query('[aria-label="Show sidebar"]').dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }),
      );
    });
    await shown(false);
    await move(21, bodyTop + 101);
    await shown(true);
    await move(1000, 400);
    await React.act(async () => pin.focus());
    await shown(false);
    assert.ok(document.activeElement === pin);
    await window.sidebarObserve('complete');

    // Cover viewport-dependent indentation using real row and guide bounds, not just scrollWidth:
    // nested Collapsible overflow can hide oversized rows from the viewport's scroll metrics.
    for (const width of [256, 320, 600]) {
      for (const depth of [0, 2, 8, 16]) {
        let node: WormholeWorkspaceNode = {
          id: 'boundary-connection',
          kind: 'connection',
          name: '服务器 🔒 Long connection '.repeat(8),
          protocol: 'ssh',
        };
        for (let level = depth - 1; level >= 0; level--) {
          node = {
            id: `boundary-folder-${level}`,
            kind: 'folder',
            name: `Folder ${level}`,
            children: [node],
          };
        }
        await mount([node], width, true, width === 256 ? 'light' : 'dark');
        const viewport = query('[data-connection-tree] [data-slot="scroll-area-viewport"]');
        const rows = [
          ...document.querySelectorAll<HTMLButtonElement>(
            '[data-connection-tree] button[draggable]',
          ),
        ];
        assert.equal(rows.length, depth + 1);
        await React.act(async () => rows.at(-1)!.focus());
        await tick();
        assert.equal(
          viewport.scrollLeft,
          0,
          'Focusing a deep row must not shift the tree horizontally',
        );
        const viewportBounds = viewport.getBoundingClientRect();
        for (const [index, row] of rows.entries()) {
          const bounds = row.getBoundingClientRect();
          assert.ok(bounds.left >= viewportBounds.left + 4, 'Deep row lost its left inset');
          assert.ok(
            bounds.right <= viewportBounds.right - 12,
            'Deep row overlaps the scrollbar gutter',
          );
          assert.ok(
            row.lastElementChild!.getBoundingClientRect().width >= 31,
            'Deep row must retain a readable label',
          );
          if (index === 0) continue;
          const wrapper = row.parentElement!.parentElement!;
          const rail = wrapper
            .querySelector<HTMLElement>(':scope > span.w-px')!
            .getBoundingClientRect();
          const connector = wrapper
            .querySelector<HTMLElement>(':scope > span.h-px')!
            .getBoundingClientRect();
          const parentCheckbox = rows[index - 1]
            .querySelector('[role="checkbox"]')!
            .getBoundingClientRect();
          const checkbox = row.querySelector('[role="checkbox"]')!.getBoundingClientRect();
          assert.ok(
            Math.abs(rail.left - (parentCheckbox.left + parentCheckbox.width / 2)) <= 1,
            'Branch must stay aligned with the parent selection slot',
          );
          assert.ok(
            Math.abs(connector.left - Math.min(rail.right, checkbox.left - 1)) <= 1,
            'Connector must start at a visible slot',
          );
          assert.ok(
            Math.abs(connector.right - Math.max(rail.left, checkbox.left - 1)) <= 1,
            'Connector must terminate at the other slot',
          );
        }
      }
    }
    await mount([], 256, true);
    assert.match(query('[data-connection-tree]').textContent!, /Nothing here yet\./);
    assert.equal(document.querySelectorAll('[data-connection-tree] button[draggable]').length, 0);
    await window.sidebarObserve('tree-boundaries');
    await checkPinnedHandle();
  } finally {
    await React.act(async () => root.unmount());
    window.wormhole = originalBridge;
    await React.act(async () => window.sidebarReducedMotion(false));
  }
}
