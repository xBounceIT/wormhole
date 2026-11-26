import * as React from 'react';
import { createRoot } from 'react-dom/client';
import App from '../../src/App';
import { AppTitlebar } from '../../src/components/AppTitlebar';
import { SidebarLayout } from '../../src/components/SidebarLayout';
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
import { applyTheme } from '../../src/theme';
import '../../src/index.css';

declare global {
  interface Window {
    sidebarAssert: typeof import('node:assert/strict');
    sidebarInput: (event: Record<string, unknown>) => Promise<void>;
    sidebarHover: (selector: string, enabled: boolean) => Promise<void>;
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
  platform,
}: {
  pinned: boolean;
  width: number;
  notification?: boolean;
  rejectImmediately?: boolean;
  platform?: string;
}) {
  const menuOpen = useContextMenuOverlayOpen();
  const [dropdownOpen, setDropdownOpen] = React.useState(false);
  const [overlayOpen, setOverlayOpen] = React.useState(false);
  const [activePage, setActivePage] = React.useState<SidebarPage>('sessions');
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  return (
    <div className="flex h-full flex-col">
      <SidebarLayout
        header={
          <>
            <AppTitlebar platform={platform} />
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
        navigation={
          <SidebarNavigation
            activePage={activePage}
            onNavigate={setActivePage}
            onOpenSettings={() => setSettingsOpen(true)}
            sessionCount={2}
            settingsOpen={settingsOpen}
          />
        }
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
          <output id="settings-open">{String(settingsOpen)}</output>
        </main>
      </SidebarLayout>
    </div>
  );
}

const tick = () => React.act(async () => new Promise((resolve) => setTimeout(resolve, 30)));

async function keypress(keyCode: string) {
  await React.act(async () => {
    await window.sidebarInput({ type: 'keyDown', keyCode });
    await window.sidebarInput({ type: 'keyUp', keyCode });
  });
  await tick();
}

window.runSidebarTests = async (handleOnly = false) => {
  if (handleOnly) return runAppIntegrationTests(true);
  const assert = window.sidebarAssert;
  const root = createRoot(document.getElementById('root')!);
  let key = 0;
  const mount = async (
    pinned = true,
    width = 320,
    options: { notification?: boolean; rejectImmediately?: boolean; platform?: string } = {},
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
            focus: document.activeElement?.getAttribute('aria-label'),
            transitions: sidebarAnimations().map((animation) => ({
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
  const panel = () => query('[data-sidebar-panel]');
  const aside = () => query('aside');
  const sidebarAnimations = () => [...panel().getAnimations(), ...aside().getAnimations()];
  const sidebarContent = () => query('[data-sidebar-content]');
  const pin = () => query('[data-sidebar-pin]') as HTMLButtonElement;
  const left = () => query('[data-workspace-canvas] > div').getBoundingClientRect().left;
  const assertPreviewAlignment = () => {
    const canvas = query('[data-workspace-canvas] > div').getBoundingClientRect();
    assert.equal(canvas.left, aside().getBoundingClientRect().right);
    assert.equal(canvas.right, layout().getBoundingClientRect().right);
  };
  const shown = async (expected: boolean) => {
    await waitFor(
      () =>
        layout().dataset.revealed === String(expected) &&
        sidebarAnimations().length === 0 &&
        (expected
          ? aside().getBoundingClientRect().left === 0
          : aside().getBoundingClientRect().width === 0),
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
    assert.equal(aside().inert, !expected);
    assert.equal(aside().getAttribute('aria-hidden'), String(!expected));
    assert.equal(pin().getAttribute('aria-expanded'), String(expected));
    assert.equal(getComputedStyle(aside()).opacity, expected ? '1' : '0');
    if (layout().dataset.pinned === 'false') assertPreviewAlignment();
  };
  const move = async (x: number, y = 450) => {
    await React.act(async () => window.sidebarInput({ type: 'mouseMove', x, y }));
    await tick();
  };
  const pinPoint = () => {
    const bounds = pin().getBoundingClientRect();
    return [
      Math.round(bounds.x + bounds.width / 2),
      Math.round(bounds.y + bounds.height / 2),
    ] as const;
  };
  const hoverPin = async () => {
    await move(...pinPoint());
    await shown(true);
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
          ? panel().dataset.preview === 'false' && left() >= aside().getBoundingClientRect().right
          : left() === aside().getBoundingClientRect().right,
      'Pin layout did not settle',
    );
  };

  // Keep interaction regressions fast; exercise actual motion separately below.
  await React.act(async () => window.sidebarReducedMotion(true));
  // Exercise the real titlebar with each platform, including browser-preview fallback.
  for (const platform of ['darwin', 'win32', 'linux', undefined]) {
    for (const pinned of [true, false]) {
      await mount(pinned, 320, { platform });
      const header = query('header');
      const title = query('header span');
      const content = pin().parentElement!;
      const nativeTitlebarHeight = platform === 'darwin' ? 28 : 0;
      const headerBounds = header.getBoundingClientRect();
      const pinBounds = pin().getBoundingClientRect();
      const titleBounds = title.getBoundingClientRect();
      assert.equal(headerBounds.height, 48 + nativeTitlebarHeight);
      assert.equal(getComputedStyle(header).paddingTop, nativeTitlebarHeight + 'px');
      assert.equal(getComputedStyle(header).paddingLeft, '12px');
      assert.equal(content.getBoundingClientRect().left, 12);
      assert.equal(pinBounds.left, 12);
      assert.ok(pinBounds.top >= headerBounds.top + nativeTitlebarHeight);
      assert.ok(titleBounds.top >= headerBounds.top + nativeTitlebarHeight);
      assert.ok(titleBounds.left > pinBounds.right);
      assert.equal(layout().getBoundingClientRect().top, headerBounds.bottom);
      assert.ok(
        pin().contains(
          document.elementFromPoint(
            pinBounds.left + pinBounds.width / 2,
            pinBounds.top + pinBounds.height / 2,
          ),
        ),
        'The titlebar sidebar button must remain clickable below the native controls',
      );
      assert.equal(title.textContent, 'Wormhole');
      assert.equal(getComputedStyle(header).getPropertyValue('-webkit-app-region'), 'drag');
      assert.equal(getComputedStyle(content).getPropertyValue('-webkit-app-region'), 'no-drag');
      assert.equal(getComputedStyle(pin()).visibility, 'visible');
      if (platform === 'darwin') {
        // No renderer control or label can intercept the three native traffic lights.
        for (const x of [20, 44, 68]) {
          assert.equal(document.elementFromPoint(x, 20), header);
        }
      }
    }
  }
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
    assert.ok(
      Math.abs(
        gripBounds.left + gripBounds.width / 2 - (separatorBounds.left + separatorBounds.width / 2),
      ) <= 0.25,
      'The resize grip must stay centered on the sidebar seam',
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
  const gripCenterY = () => {
    const { top, height } = query('[data-sidebar-resize-handle] > div').getBoundingClientRect();
    return top + height / 2;
  };
  assertBadgeAligned();
  assertResizeHandleCentered();
  const {
    left: separatorX,
    top: separatorTop,
    bottom: separatorBottom,
  } = query('[data-sidebar-resize-handle]').getBoundingClientRect();
  const gripX = Math.round(separatorX);
  await window.sidebarReducedMotion(false);
  for (const y of [Math.round(separatorTop) + 56, Math.round(separatorBottom) - 56]) {
    await move(gripX, y);
    assert.ok(Math.abs(gripCenterY() - y) <= 0.5, 'The resize grip should follow hover');
  }
  await move(gripX, Math.ceil(separatorTop) + 1);
  assert.ok(Math.abs(gripCenterY() - (separatorTop + 12)) <= 0.5);
  await move(gripX, Math.floor(separatorBottom) - 1);
  assert.ok(Math.abs(gripCenterY() - (separatorBottom - 12)) <= 0.5);
  await window.sidebarReducedMotion(true);
  assertResizeHandleCentered();
  await move(1000, 400);
  assertResizeHandleCentered();
  assert.equal(pin().getAttribute('aria-label'), 'Unpin sidebar');
  assert.equal(pin().getAttribute('aria-pressed'), 'true');
  assert.equal(getComputedStyle(pin()).backgroundColor, 'rgba(0, 0, 0, 0)');
  assert.equal(getComputedStyle(pin()).boxShadow, 'none');
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
  assert.equal(
    left(),
    aside().getBoundingClientRect().right,
    'The resize handle must not add width',
  );
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
  assertResizeHandleCentered();
  await window.sidebarReducedMotion(false);
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
      y: dragY + 60,
    }),
  );
  await tick();
  assert.ok(Math.abs(gripCenterY() - (dragY + 60)) <= 0.5, 'The grip must follow the drag');
  await React.act(async () =>
    window.sidebarInput({
      type: 'mouseUp',
      button: 'left',
      x: dragX + 30,
      y: dragY + 60,
      clickCount: 1,
    }),
  );
  await waitFor(
    () => aside().getBoundingClientRect().width > keyboardWidth,
    'Pointer resize did not update the sidebar',
  );
  const resizedWidth = aside().getBoundingClientRect().width;
  const pinnedCanvasLeft = left();
  assert.ok(resizedWidth > 320, JSON.stringify({ resizedWidth, writes, left: pinnedCanvasLeft }));
  await move(1000, 400);
  assertResizeHandleCentered();
  await window.sidebarReducedMotion(true);

  await click(pin());
  assert.equal(layout().dataset.pinned, 'false');
  assert.equal(pin().querySelector('svg path[fill="currentColor"]'), null);
  assert.equal(pin().getAttribute('aria-disabled'), 'true');
  assert.equal(pin().getAttribute('aria-busy'), 'true');
  await React.act(async () => pin().click());
  assert.deepEqual(saves, [false]);
  await settle();
  await shown(true);
  await move(1000);
  await shown(false);
  assert.equal(getComputedStyle(query('[data-slot="resizable-handle"]')).display, 'none');
  assert.ok(navigation.closest('[inert]'));
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
  await move(6);
  await shown(false);
  assert.equal(left(), 0);
  assert.ok(content.contains(document.elementFromPoint(6, 450)));
  assert.equal(query('#native-visible').textContent, 'true');
  assert.equal(document.activeElement === search, false);

  await hoverPin();
  // Cross the titlebar padding and enter the sidebar away from its former rail.
  const bodyTop = layout().getBoundingClientRect().top;
  await move(pinPoint()[0], bodyTop - 2);
  await move(160, bodyTop + 80);
  await shown(true);
  assertBadgeAligned();
  assert.equal(document.querySelectorAll('nav[aria-label="Main navigation"]').length, 1);
  assert.ok(query('nav[aria-label="Main navigation"]') === navigation);
  assert.ok(
    [...navigation.querySelectorAll('button')].every(
      (button, index) => button === navigationButtons[index],
    ),
  );
  assert.ok(
    Math.abs(left() - pinnedCanvasLeft) <= 0.5,
    `The canvas begins at ${left()}px on hover and ${pinnedCanvasLeft}px when pinned`,
  );
  assert.deepEqual(saves, [false], 'Hovering must not save a pin preference');
  assert.equal(query('#native-visible').textContent, 'false');
  assert.ok(query('#content') === content, 'Pin changes remounted the session content');
  assert.equal((query('input') as HTMLInputElement).value, 'saved query');
  assert.ok(Math.abs(aside().getBoundingClientRect().width - resizedWidth) <= 1);
  await move(1000);
  await shown(false);

  // The titlebar button opens the sidebar for keyboard navigation, and Escape returns to it.
  await keypress('Tab');
  await React.act(async () => pin().focus());
  await tick();
  await shown(true);
  await keypress('Tab');
  assert.ok(document.activeElement === search, 'Tab did not reach the connection search');
  await move(1000);
  await shown(true);
  await keypress('Escape');
  await shown(false);
  assert.ok(document.activeElement === pin(), 'Escape did not return focus to the titlebar button');
  await React.act(async () => query('#outside').focus());

  // Both types of portaled menus keep their sidebar visible beyond its bounds.
  await hoverPin();
  await click(query('[data-slot="dropdown-menu-trigger"]'));
  await waitFor(() => document.querySelector('[role="menu"]') !== null, 'Import menu did not open');
  assert.ok(document.querySelector('[role="menu"]'));
  await move(700);
  await shown(true);
  await keypress('Escape');
  await hoverPin();
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
  await hoverPin();
  await click(pin());
  await settle();
  await shown(true);
  assert.equal(layout().dataset.pinned, 'true');
  assert.ok(pin().querySelector('svg path[fill="currentColor"]'));
  await move(1000);
  await shown(true);
  await waitFor(
    () => Math.abs(left() - pinnedCanvasLeft) <= 0.5,
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
  assert.equal(left(), 0);
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
  await hoverPin();
  assert.equal(aside().getBoundingClientRect().width, 420);
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
  await reviewCase('clicking search does not keep the hover preview open', async () => {
    await move(1000);
    await mount(false, 420);
    await hoverPin();
    const input = query('[aria-label="Search connections"]');
    await click(input);
    assert.equal(document.activeElement, input);
    await move(1000);
    await shown(false);
    assert.equal(query('#native-visible').textContent, 'true');
    await hoverPin();
    await click(input);
    await keypress('Tab');
    assert.equal(document.activeElement, query('[data-slot="dropdown-menu-trigger"]'));
    await move(1000);
    await shown(true);
    await keypress('Escape');
    await shown(false);
  });
  await reviewCase(
    'choosing a portaled menu item with the mouse releases the preview',
    async () => {
      await move(1000);
      await mount(false, 420);
      await hoverPin();
      await click(query('[data-slot="dropdown-menu-trigger"]'));
      await waitFor(
        () => document.querySelector('[role="menuitem"]') !== null,
        'Import menu did not open',
      );
      const item = query('[role="menuitem"]');
      const bounds = item.getBoundingClientRect();
      assert.ok(bounds.x + bounds.width / 2 > aside().getBoundingClientRect().right);
      await click(item);
      await shown(false);
      assert.equal(query('#native-visible').textContent, 'true');
    },
  );
  await reviewCase('an update notification cannot latch the auto-hide sidebar open', async () => {
    await move(1000);
    await mount(false, 420, { notification: true });
    await shown(false);
    await hoverPin();
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
    await React.act(async () => pin().focus());
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
  await reviewCase(
    'pinning a saved maximum width respects the current panel constraints',
    async () => {
      await move(1000);
      await mount(false, 600);
      await hoverPin();
      const previewWidth = aside().getBoundingClientRect().width;
      assert.ok(previewWidth < 600, 'The preview must respect the canvas minimum width');
      assert.equal(sidebarContent().getBoundingClientRect().width, previewWidth);
      await React.act(async () => pin().click());
      await settle();
      await shown(true);
      await waitFor(
        () => query('#native-visible').textContent === 'true',
        'Pin restoration did not finish',
      );
      const width = aside().getBoundingClientRect().width;
      assert.ok(
        width >= 256 && width < 600,
        'The narrow viewport must constrain the saved maximum width',
      );
      assert.ok(Math.abs(left() - previewWidth) <= 0.5, 'Pinning must preserve the preview edge');
      assert.equal(left(), aside().getBoundingClientRect().right);
    },
  );
  await reviewCase('deferred pin protects native surfaces on success and rollback', async () => {
    for (const fail of [false, true]) {
      await move(1000);
      await mount(false, 420);
      await hoverPin();
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
            ? left() === aside().getBoundingClientRect().right
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
    await React.act(async () => pin().focus());
    await shown(true);
    await keypress('Escape');
    await shown(false);
    assert.ok(document.activeElement === pin(), 'Escape did not focus the titlebar button');
    await keypress('Down');
    await shown(true);
    await React.act(async () => query('#outside').focus());
    await tick();
    assert.equal(
      layout().dataset.revealed,
      'false',
      'The explicit reopen remained latched after focus left',
    );
  });
  await reviewCase('mouse movement on the titlebar button recovers after Escape', async () => {
    await move(1000);
    await mount(false, 420);
    await keypress('Tab');
    await React.act(async () => pin().focus());
    await hoverPin();
    await keypress('Escape');
    await shown(false);
    const [x, y] = pinPoint();
    await move(x + 1, y);
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
  assert.ok(pinBounds.right < query('header span').getBoundingClientRect().left);
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
  assert.equal(pin().getAttribute('aria-controls'), aside().id);
  const nav = query('[data-sidebar-navigation] nav');
  assert.ok(nav.closest('[inert]'));
  await hoverPin();
  assert.ok(
    nav.querySelector('[aria-label="Sessions"] svg.lucide-terminal'),
    'Sessions button must use the SSH icon',
  );
  assert.ok(
    nav.querySelector('[aria-label="Settings"] svg.lucide-settings'),
    'Settings button must use the gear icon',
  );
  assert.deepEqual(
    [...nav.querySelectorAll('button')].map((button) => button.getAttribute('aria-label')),
    ['Sessions', 'Credentials', 'Tunnels', 'Settings'],
  );
  const navButtons = [...nav.querySelectorAll('button')];
  const credentialsBounds = navButtons[1].getBoundingClientRect();
  const credentialsX = Math.round(credentialsBounds.left + credentialsBounds.width / 2);
  const credentialsY = Math.round(credentialsBounds.top + credentialsBounds.height / 2);
  await move(credentialsX, credentialsY);
  await React.act(async () =>
    window.sidebarInput({
      type: 'mouseDown',
      button: 'left',
      x: credentialsX,
      y: credentialsY,
      clickCount: 1,
    }),
  );
  await move(1000, credentialsY);
  await React.act(async () =>
    window.sidebarInput({
      type: 'mouseUp',
      button: 'left',
      x: 1000,
      y: credentialsY,
      clickCount: 1,
    }),
  );
  assert.equal(query('#page').textContent, 'sessions', 'Dragging off cancels sidebar navigation');
  await hoverPin();
  for (const button of navButtons.slice(0, 3)) {
    assert.ok(button.querySelector('svg'));
    assert.equal(getComputedStyle(button).visibility, 'visible');
    assert.ok(button.getBoundingClientRect().right <= aside().getBoundingClientRect().right);
    await click(button);
    assert.equal(button.getAttribute('aria-current'), 'page');
    assert.equal(query('#page').textContent, button.getAttribute('aria-label')!.toLowerCase());
    await shown(true);
  }
  const settingsNavButton = navButtons[3];
  assert.ok(settingsNavButton.querySelector('svg'));
  assert.equal(getComputedStyle(settingsNavButton).visibility, 'visible');
  assert.ok(
    settingsNavButton.getBoundingClientRect().right <= aside().getBoundingClientRect().right,
  );
  await click(settingsNavButton);
  assert.equal(settingsNavButton.getAttribute('aria-haspopup'), 'dialog');
  assert.equal(settingsNavButton.getAttribute('aria-expanded'), 'true');
  assert.equal(settingsNavButton.getAttribute('aria-current'), null);
  assert.equal(query('#settings-open').textContent, 'true');
  assert.equal(query('#page').textContent, 'tunnels');
  await shown(true);
  await move(1000);
  await React.act(async () => query('#outside').focus());
  await shown(false);
  const saveCount = saves.length;
  await hoverPin();
  assert.equal(query('#native-visible').textContent, 'false');
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
  await shown(true);
  assert.equal(layout().dataset.pinned, 'false');
  assert.match(query('[role="alert"]').textContent!, /couldn't save the sidebar preference/);
  assert.ok(document.activeElement === pin(), 'Failed titlebar pin lost its retry control');
  assert.equal(query('[role="alert"]').closest('aside'), null);
  await move(1000);
  await React.act(async () => query('#outside').focus());
  await shown(false);

  await keypress('Tab');
  await React.act(async () => pin().focus());
  await shown(true);
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
  assert.equal(aside().getBoundingClientRect().width, 0);
  const animatedSurface = aside();
  const session = query('#content');
  // Pause real CSS transitions so intermediate positions and reversals are deterministic.
  const beginSlide = async (opening: boolean) => {
    const [x, y] = opening ? pinPoint() : [1000, 450];
    await React.act(async () => window.sidebarInput({ type: 'mouseMove', x, y }));
    const slide = () =>
      panel()
        .getAnimations()
        .find(
          (animation) =>
            animation instanceof CSSTransition && animation.transitionProperty === 'width',
        );
    await waitFor(
      () => layout().dataset.revealed === String(opening) && Boolean(slide()),
      'Sidebar slide transition did not start',
    );
    for (const animation of sidebarAnimations()) animation.pause();
    return slide()!;
  };
  const halfway = async (animation: Animation) => {
    await React.act(async () => {
      animation.currentTime = Number(animation.effect!.getComputedTiming().activeDuration) / 2;
    });
    const bounds = animatedSurface.getBoundingClientRect();
    assert.equal(bounds.left, 0, 'The existing sidebar moved instead of expanding');
    assert.ok(
      bounds.width > 0 && bounds.width < 420,
      'Sidebar did not pass through an intermediate width',
    );
    assert.equal(document.querySelectorAll('nav[aria-label="Main navigation"]').length, 1);
    assertPreviewAlignment();
    assert.ok(query('#content') === session, 'Sliding remounted the session');
  };
  const finishSlide = async () => {
    await React.act(async () => {
      for (const animation of sidebarAnimations()) animation.finish();
    });
    await tick();
  };
  try {
    const entering = await beginSlide(true);
    assert.equal(entering.effect!.getComputedTiming().activeDuration, 200);
    await halfway(entering);
    assert.equal(query('#native-visible').textContent, 'false');
    await finishSlide();
    await shown(true);
    assert.equal(animatedSurface.getBoundingClientRect().left, 0);

    await halfway(await beginSlide(false));
    assert.equal(getComputedStyle(pin()).visibility, 'visible');
    assert.ok(pin() === titlebarPin || query('header').contains(pin()));
    assert.equal(aside().inert, true);
    assert.equal(getComputedStyle(animatedSurface).visibility, 'visible');
    assert.equal(query('#native-visible').textContent, 'false');
    assert.ok(!sidebarContent().contains(document.elementFromPoint(20, 450)));

    // Reenter before exit completes: cancellation must not expose native surfaces.
    await halfway(await beginSlide(true));
    await tick();
    assert.equal(aside().inert, false);
    assert.equal(query('#native-visible').textContent, 'false');
    await finishSlide();
    await shown(true);
    assert.equal(query('#native-visible').textContent, 'false');

    await halfway(await beginSlide(false));
    await finishSlide();
    await shown(false);
    assert.equal(animatedSurface.getBoundingClientRect().width, 0);
    assert.equal(query('#native-visible').textContent, 'true');

    // Changing the system preference during an exit cancels motion and releases the overlay.
    await beginSlide(true);
    await finishSlide();
    await shown(true);
    await halfway(await beginSlide(false));
    await React.act(async () => window.sidebarReducedMotion(true));
    await shown(false);
    await waitFor(
      () => query('#native-visible').textContent === 'true',
      'Cancelling sidebar motion did not restore native surfaces',
    );
    assert.equal(query('#native-visible').textContent, 'true');
    assert.equal(getComputedStyle(panel()).transitionProperty, 'none');
    assert.equal(getComputedStyle(animatedSurface).transitionProperty, 'none');
    await hoverPin();
    assert.equal(animatedSurface.getBoundingClientRect().left, 0);
    assert.equal(query('#native-visible').textContent, 'false');
    await move(1000);
    await shown(false);
    assert.equal(query('#native-visible').textContent, 'true');

    await React.act(async () => window.sidebarReducedMotion(false));
    await halfway(await beginSlide(true));
    const previewWidth = aside().getBoundingClientRect().width;
    await React.act(async () => pin().click());
    await React.act(
      async () =>
        new Promise<void>((resolve) => {
          requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
        }),
    );
    assert.equal(layout().dataset.pinned, 'true');
    assert.equal(
      aside().getBoundingClientRect().width,
      previewWidth,
      'Pinning during the slide must allow the width transition to finish',
    );
    assert.equal(query('#native-visible').textContent, 'false');
    await settle(true);
    assert.equal(layout().dataset.pinned, 'false');
    assert.equal(aside().getBoundingClientRect().width, previewWidth);
    assertPreviewAlignment();
    await React.act(async () => pin().click());
    await finishSlide();
    await settle();
    await shown(true);
    await waitFor(
      () => query('#native-visible').textContent === 'true',
      'Pinning during the slide left native content hidden',
    );
    assertResizeHandleCentered();
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
  const connectionActions = () =>
    [
      'Expand all folders',
      'Collapse all folders',
      'Import connections',
      'New folder',
      'New connection',
    ].map((label) => query(`aside button[aria-label="${label}"]`));
  const connectionSearchIcon = () =>
    query('[aria-label="Search connections"]').parentElement!.querySelector('svg')!;
  const workspaceCanvas = () => query('[data-session-canvas], .workspace-page-canvas');
  function assertConnectionControlsAligned() {
    const centerX = (element: Element) => {
      const { left, width } = element.getBoundingClientRect();
      return left + width / 2;
    };
    const searchIcon = connectionSearchIcon();
    const firstActionIcon = connectionActions()[0].querySelector('svg')!;
    const checkbox = query('[data-connection-tree] [role="checkbox"]');
    assert.ok(
      Math.abs(centerX(firstActionIcon) - centerX(searchIcon)) <= 0.5,
      'The first toolbar icon must align with the search icon',
    );
    assert.ok(
      Math.abs(centerX(firstActionIcon) - centerX(checkbox)) <= 0.5,
      'The first toolbar icon must align with root connection checkboxes',
    );
  }
  function assertCanvasAlignedWithSearch() {
    const canvas = workspaceCanvas().getBoundingClientRect();
    const connectionSearch = query('[aria-label="Search connections"]').getBoundingClientRect();
    assert.equal(canvas.top, connectionSearch.top, 'Canvas and connection search must align');
  }
  async function assertTabSearchStartsAtCanvas() {
    await waitFor(() => {
      const popover = query('[data-session-tab-search]');
      return (
        popover &&
        Math.abs(
          popover.getBoundingClientRect().top - workspaceCanvas().getBoundingClientRect().top,
        ) <= 0.5
      );
    }, 'Tab search popover must start at the top of the canvas');
  }
  function workspaceStyles() {
    const search = getComputedStyle(query('[aria-label="Search connections"]'));
    const canvas = getComputedStyle(workspaceCanvas());
    return {
      titlebar: getComputedStyle(query('header')).backgroundColor,
      sidebar: getComputedStyle(query('[data-sidebar-surface]')).backgroundColor,
      searchBackground: search.backgroundColor,
      searchRadius: search.borderTopLeftRadius,
      quickConnect: getComputedStyle(query('[aria-label="Quick Connect"]')).backgroundColor,
      treeRadius: getComputedStyle(query('[data-connection-tree] button[draggable]'))
        .borderTopLeftRadius,
      navigationRadius: getComputedStyle(query('nav [aria-current="page"]')).borderTopLeftRadius,
      groupedActions: connectionActions().filter((action) => action.closest('[role="group"]'))
        .length,
      divider: getComputedStyle(query('[data-workspace-canvas] > div')).borderLeftWidth,
      canvasBackground: canvas.backgroundColor,
      canvasCorners: [
        canvas.borderTopLeftRadius,
        canvas.borderTopRightRadius,
        canvas.borderBottomLeftRadius,
        canvas.borderBottomRightRadius,
      ],
    };
  }
  const colorContext = document.createElement('canvas').getContext('2d', {
    willReadFrequently: true,
  })!;
  function luminance(color: string) {
    colorContext.clearRect(0, 0, 1, 1);
    colorContext.fillStyle = color;
    colorContext.fillRect(0, 0, 1, 1);
    const channels = Array.from(colorContext.getImageData(0, 0, 1, 1).data)
      .slice(0, 3)
      .map((value) => {
        const srgb = value / 255;
        return srgb <= 0.04045 ? srgb / 12.92 : ((srgb + 0.055) / 1.055) ** 2.4;
      });
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
  }
  function assertContrast(label: string, foreground: string, background: string, minimum = 4.5) {
    const first = luminance(foreground);
    const second = luminance(background);
    const ratio = (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
    assert.ok(
      ratio >= minimum,
      `${label} contrast is ${ratio.toFixed(2)}:1, expected ${minimum}:1 (${foreground} on ${background})`,
    );
  }
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
      const panel = query('[data-sidebar-panel]');
      // Flush computed layout even while a hidden Chromium window still reports an animation.
      const bounds = surface.getBoundingClientRect();
      return (
        query('[data-sidebar-layout]').dataset.revealed === String(expected) &&
        panel.getAnimations().length === 0 &&
        surface.getAnimations().length === 0 &&
        (expected ? bounds.left === 0 : bounds.width === 0)
      );
    }, 'Full App sidebar did not settle: ' + expected);
  };
  function NativeOverlayProbe() {
    return <output hidden data-native-overlay-open={useContextMenuOverlayOpen()} />;
  }
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
            <NativeOverlayProbe />
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
          </ContextMenuOverlayProvider>
        </React.StrictMode>,
      ),
    );
    await tick();
  };
  const checkSessionTabContextTooltip = async () => {
    await mount(
      [
        { id: 'menu-server', kind: 'connection', name: 'Menu server', protocol: 'https' },
        { id: 'touch-server', kind: 'connection', name: 'Touch server', protocol: 'https' },
      ],
      294,
      true,
    );
    await React.act(async () =>
      query('[data-connection-tree] button[draggable]').dispatchEvent(
        new MouseEvent('dblclick', { bubbles: true }),
      ),
    );
    const tab = query('[role="tab"][data-session-tab-id="session-menu-server"]');
    const { x, y, width, height } = tab.getBoundingClientRect();
    const centerX = Math.round(x + width / 2);
    const centerY = Math.round(y + height / 2);
    const tooltip = () =>
      [...document.querySelectorAll('[data-slot="tooltip-content"]')].find((content) =>
        content.textContent?.includes('Drag to another tab bar'),
      );
    const menu = () => query('[data-slot="context-menu-content"]');
    const openMenu = async () => {
      await React.act(async () =>
        tab.dispatchEvent(
          new MouseEvent('contextmenu', {
            bubbles: true,
            cancelable: true,
            button: 2,
            clientX: centerX,
            clientY: centerY,
          }),
        ),
      );
      await waitFor(() => Boolean(menu()), 'The session tab context menu must open');
      await waitFor(() => !tooltip(), 'Opening the menu must hide the tab tooltip');
    };

    await React.act(async () => tab.focus());
    await waitFor(() => Boolean(tooltip()), 'The tab tooltip must open on focus');
    await openMenu();
    const reconnect = [...menu().querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
      (item) => item.textContent?.trim() === 'Reconnect',
    )!;
    await click(reconnect);
    await waitFor(
      () => !menu() && document.activeElement === tab,
      'Selecting a command must close the menu and return focus to the tab',
    );
    assert.ok(!tooltip(), 'Menu selection must not reopen the tab tooltip on restored focus');

    await openMenu();
    await keypress('Escape');
    await waitFor(
      () => !menu() && document.activeElement === tab,
      'Escape must close the menu and return focus to the tab',
    );
    assert.ok(!tooltip(), 'Dismissing the menu must not reopen the tab tooltip on restored focus');

    await move(1000, 400);
    await move(centerX, centerY);
    await waitFor(() => Boolean(tooltip()), 'The tab tooltip must still open on the next hover');
    await move(1000, 400);
    await waitFor(() => !tooltip(), 'The tab tooltip must close when the pointer leaves');

    await React.act(async () => {
      document
        .querySelectorAll('[data-connection-tree] button[draggable]')[1]!
        .dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
      tab.blur();
      tab.focus();
    });
    await waitFor(() => Boolean(tooltip()), 'Refocusing the tab must still show its tooltip');
    const touchTab = query('[role="tab"][data-session-tab-id="session-touch-server"]');
    const touchBounds = touchTab.getBoundingClientRect();
    await React.act(async () =>
      touchTab.dispatchEvent(
        new PointerEvent('pointerdown', {
          bubbles: true,
          pointerType: 'touch',
          clientX: touchBounds.x + touchBounds.width / 2,
          clientY: touchBounds.y + touchBounds.height / 2,
        }),
      ),
    );
    await waitFor(() => Boolean(menu()), 'A long press must open the other tab’s context menu');
    await keypress('Escape');
    await waitFor(
      () => !menu() && document.activeElement === tab,
      'Closing the other tab’s menu must restore the previous focus',
    );
    assert.ok(!tooltip(), 'Restoring focus across tabs must not reopen the tab tooltip');
  };
  const checkPinnedHandle = async () => {
    for (const theme of ['dark', 'light'] as const) {
      await mount(
        [
          { id: 'preview-server', kind: 'connection', name: 'Preview server', protocol: 'https' },
          { id: 'another-server', kind: 'connection', name: 'Another server', protocol: 'https' },
          {
            id: 'icon-folder',
            kind: 'folder',
            name: 'Servers',
            children: [{ id: 'folder-ssh', kind: 'connection', name: 'Linux', protocol: 'ssh' }],
          },
          ...(['ssh', 'rdp', 'http', 'vnc', 'sftp', 'smb', 'serial'] as const).map((protocol) => ({
            id: `icon-${protocol}`,
            kind: 'connection' as const,
            name: protocol.toUpperCase(),
            protocol,
          })),
        ],
        294,
        true,
        theme,
      );
      const trigger = query('[aria-label="Search open tabs"]');
      const quickConnect = query('aside button[aria-label="Quick Connect"]');
      assert.equal(
        trigger.getBoundingClientRect().top,
        quickConnect.getBoundingClientRect().top,
        'Tab search and Quick Connect must share a row',
      );
      assertCanvasAlignedWithSearch();
      assertConnectionControlsAligned();
      if (!handleOnly) {
        const searchTooltip = () =>
          [...document.querySelectorAll<HTMLElement>('[data-slot="tooltip-content"]')].find(
            (content) => content.textContent?.includes('Search open tabs'),
          );
        await React.act(async () => {
          trigger.dispatchEvent(
            new PointerEvent('pointermove', { bubbles: true, pointerType: 'mouse' }),
          );
        });
        await waitFor(() => {
          const bounds = searchTooltip()?.getBoundingClientRect();
          return Boolean(
            bounds && bounds.width > 0 && bounds.left >= trigger.getBoundingClientRect().right,
          );
        }, 'The tab search button must show its Shadcn tooltip on hover');
        const tooltip = searchTooltip()!;
        assert.equal(tooltip.getAttribute('data-side'), 'right');
        const background = theme === 'dark' ? 'rgb(250, 250, 250)' : 'rgb(23, 23, 23)';
        assert.equal(getComputedStyle(tooltip).backgroundColor, background);
        if (theme === 'dark') {
          applyTheme('oled');
          assert.equal(getComputedStyle(tooltip).backgroundColor, background);
          assert.equal(getComputedStyle(tooltip).color, 'rgb(23, 23, 23)');
          applyTheme('dark');
        }
        assert.ok(
          tooltip.getBoundingClientRect().bottom <= workspaceCanvas().getBoundingClientRect().top,
        );
        await React.act(async () => trigger.click());
        assert.equal(trigger.getAttribute('aria-expanded'), 'true');
        await waitFor(
          () => !searchTooltip() || searchTooltip()!.dataset.state === 'closed',
          'The tooltip must dismiss when tab search opens',
        );
        await React.act(async () => trigger.click());
        await React.act(async () => trigger.blur());
      }
      const toolbarIcons = connectionActions().map((button) => button.querySelector('svg')!);
      const [firstActionIcon, ...otherActionIcons] = toolbarIcons;
      const { stroke, strokeWidth } = getComputedStyle(firstActionIcon);
      const iconWidth = firstActionIcon.getBoundingClientRect().width;
      for (const icon of [
        quickConnect.querySelector('svg')!,
        ...otherActionIcons,
        ...document.querySelectorAll('[data-connection-tree] button[draggable] svg'),
      ]) {
        const { stroke: color, strokeWidth: weight } = getComputedStyle(icon);
        assert.equal(
          color,
          stroke,
          `Inconsistent connection icon color in ${theme}: ${icon.classList}`,
        );
        assert.equal(weight, strokeWidth);
        assert.equal(icon.getBoundingClientRect().width, iconWidth);
      }
      if (theme === 'dark') {
        await React.act(async () => trigger.click());
        assert.match(
          query('[data-slot="popover-content"] [role="status"]').textContent!,
          /No open tabs/,
        );
        await React.act(async () => trigger.click());
      }
      const rowSelector = '[data-connection-tree] button[draggable]';
      const connection = query(rowSelector);
      await React.act(async () =>
        connection.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })),
      );
      const tab = query('[role="tab"][data-session-tab-id="session-preview-server"]');
      assert.ok(tab, 'Opening a connection must render its session tab');
      assert.equal(tab.getAttribute('aria-selected'), 'true');
      const titlebar = query('header');
      const sidebar = query('[data-sidebar-surface]');
      const separator = query('[data-slot="resizable-handle"]');
      const workspacePanel = query('[data-workspace-canvas] > div');
      const canvas = query('[data-session-canvas]');
      await waitFor(
        () => Boolean(query('[aria-label="Connection browser"]')),
        'Browser must mount',
      );
      const browser = query('[aria-label="Connection browser"]');
      const tablist = query('[aria-label="Pane tabs"]');
      const titlebarStyle = getComputedStyle(titlebar);
      const canvasStyle = getComputedStyle(canvas);
      assert.equal(titlebarStyle.backgroundColor, getComputedStyle(sidebar).backgroundColor);
      assert.equal(
        titlebarStyle.backgroundColor,
        getComputedStyle(titlebar.parentElement!).backgroundColor,
      );
      assert.equal(titlebarStyle.borderBottomWidth, '0px');
      assert.equal(getComputedStyle(sidebar).borderRightWidth, '0px');
      assert.equal(getComputedStyle(workspacePanel).borderLeftWidth, '0px');
      assert.notEqual(canvasStyle.backgroundColor, titlebarStyle.backgroundColor);
      assert.equal(canvasStyle.borderTopLeftRadius, '12px');
      assert.equal(canvasStyle.borderTopRightRadius, '12px');
      assert.equal(canvasStyle.borderBottomLeftRadius, '12px');
      assert.equal(canvasStyle.borderBottomRightRadius, '12px');
      assert.equal(getComputedStyle(connection).borderTopLeftRadius, '8px');
      assert.ok(parseFloat(getComputedStyle(tab.parentElement!).borderTopLeftRadius) >= 17);
      const bounds = canvas.getBoundingClientRect();
      const browserBounds = browser.getBoundingClientRect();
      assert.deepEqual(
        [browserBounds.left, browserBounds.top, browserBounds.right, browserBounds.bottom],
        [bounds.left, bounds.top, bounds.right, bounds.bottom],
        'The embedded browser must fill the connection canvas',
      );
      assertCanvasAlignedWithSearch();
      assert.ok(tablist.contains(tab));
      assert.ok(!canvas.contains(tab));
      assert.ok(tablist.getBoundingClientRect().bottom < bounds.top);
      assert.ok(bounds.right < innerWidth && bounds.bottom < innerHeight);
      await move(1000, 400);
      assert.equal(getComputedStyle(separator.firstElementChild!).opacity, '0');
      const activeNav = query('nav [aria-current="page"]');
      assert.equal(
        getComputedStyle(activeNav).backgroundColor,
        getComputedStyle(tab.parentElement!).backgroundColor,
        'Selected navigation and session tabs must use the same fill',
      );
      if (theme === 'light') {
        const noticeSlot = query('[data-sftp-recovery-notice]');
        const notice = document.createElement('div');
        notice.style.height = '36px';
        noticeSlot.append(notice);
        assertCanvasAlignedWithSearch();
        assert.ok(notice.getBoundingClientRect().top >= canvas.getBoundingClientRect().bottom);
        notice.remove();

        const connectionSearch = query('[aria-label="Search connections"]');
        // Begin from painted dark styles and check the first computed light frame.
        applyTheme('dark');
        void getComputedStyle(activeNav).backgroundColor;
        applyTheme('light');
        const sidebarBackground = getComputedStyle(sidebar).backgroundColor;
        for (const action of [...connectionActions(), query('nav [aria-label="Settings"]')]) {
          assertContrast(
            action.getAttribute('aria-label')!,
            getComputedStyle(action).color,
            sidebarBackground,
          );
        }
        assertContrast(
          'Connection search text',
          getComputedStyle(connectionSearch).color,
          getComputedStyle(connectionSearch).backgroundColor,
        );
        assertContrast(
          'Active navigation',
          getComputedStyle(activeNav).color,
          getComputedStyle(activeNav).backgroundColor,
        );
        assertContrast(
          'Active tab',
          getComputedStyle(tab).color,
          getComputedStyle(tab.parentElement!).backgroundColor,
        );
        assertContrast('Tab search button', getComputedStyle(trigger).color, sidebarBackground, 3);
      }
      await window.sidebarObserve('pinned-' + theme);

      const seam = separator.getBoundingClientRect();
      const seamX = Math.round(seam.left + seam.width / 2);
      const seamY = Math.round(seam.top + seam.height / 2);
      await move(seamX, seamY);
      assert.equal(getComputedStyle(separator.firstElementChild!).opacity, '1');
      await move(1000, 400);

      const tablistBounds = tablist.getBoundingClientRect();
      assert.equal(getComputedStyle(tablist, '::before').opacity, '0');
      assert.equal(getComputedStyle(tablist, '::after').opacity, '0');
      const dataTransfer = new DataTransfer();
      await window.sidebarObserve('session-drop-idle');
      const pill = tab.closest<HTMLElement>('[data-session-tab-index]')!;
      const pillTop = pill.getBoundingClientRect().top;
      tablist.style.maxWidth = '64px';
      const pillBounds = pill.getBoundingClientRect();
      assert.ok(pillBounds.right > tablist.getBoundingClientRect().right);
      assert.equal(pillBounds.top, pillTop, 'The scrollbar must not shift the pills vertically');
      assert.ok(
        pillBounds.top >= tablistBounds.top + 3.5,
        'The top edge of the pill must clear the strip',
      );
      assert.ok(
        pillBounds.bottom <= tablistBounds.top + tablist.clientHeight - 1.5,
        'The bottom edge of the pill must clear the horizontal scrollbar',
      );
      assert.equal(canvas.getBoundingClientRect().top, bounds.top);
      const clientX = Math.round(pillBounds.left + 16);
      const clientY = Math.round(pillBounds.top + 12);
      const snapshots: { image: HTMLElement; bounds: DOMRect; hotspot: number[] }[] = [];
      const setDragImage = dataTransfer.setDragImage.bind(dataTransfer);
      dataTransfer.setDragImage = (image, x, y) => {
        snapshots.push({ image, bounds: image.getBoundingClientRect(), hotspot: [x, y] });
        setDragImage(image, x, y);
      };
      await React.act(async () => {
        tab.dispatchEvent(
          new DragEvent('dragstart', { bubbles: true, clientX, clientY, dataTransfer }),
        );
      });
      tablist.style.maxWidth = '';
      assert.equal(snapshots.length, 1, 'Dragging must supply an image of the complete pill');
      const [{ image, bounds: imageBounds, hotspot }] = snapshots;
      assert.equal(imageBounds.width, pillBounds.width);
      assert.equal(imageBounds.height, pillBounds.height);
      assert.equal(image.textContent, pill.textContent);
      assert.equal(image.querySelectorAll('button').length, pill.querySelectorAll('button').length);
      assert.ok(image.inert && !tablist.contains(image));
      assert.deepEqual(hotspot, [
        Math.round(clientX - pillBounds.left),
        Math.round(clientY - pillBounds.top),
      ]);
      await waitFor(
        () => !image.isConnected,
        'The drag image element must be removed after capture',
      );
      const dragOver = new DragEvent('dragover', {
        bubbles: true,
        cancelable: true,
        clientX: tablistBounds.right - 16,
        clientY: tablistBounds.top + 8,
        // Chromium does not expose the drag payload during native dragover.
        dataTransfer: new DataTransfer(),
      });
      await React.act(async () => tablist.dispatchEvent(dragOver));
      assert.ok(dragOver.defaultPrevented, 'The tab bar must accept the ongoing session drag');
      await window.sidebarObserve('session-drop-hover');
      await React.act(async () => {
        tab.dispatchEvent(new DragEvent('dragend', { bubbles: true, dataTransfer }));
      });
      await window.sidebarObserve('session-drop-end');

      const quickIcon = quickConnect.querySelector('svg')!;
      assert.equal(getComputedStyle(quickConnect).backgroundColor, 'rgba(0, 0, 0, 0)');
      assert.equal(getComputedStyle(quickIcon).fill, 'none');
      await React.act(async () => quickConnect.focus());
      const tooltip = () => query('[data-slot="tooltip-content"]');
      await waitFor(
        () => tooltip()?.textContent?.includes('Quick Connect') === true,
        'Quick Connect must show its tooltip on keyboard focus',
      );
      const background = theme === 'dark' ? 'rgb(250, 250, 250)' : 'rgb(23, 23, 23)';
      const color = theme === 'dark' ? 'rgb(23, 23, 23)' : 'rgb(250, 250, 250)';
      assert.equal(getComputedStyle(tooltip()!).backgroundColor, background);
      assert.equal(getComputedStyle(tooltip()!).color, color);
      assert.equal(getComputedStyle(tooltip()!.querySelector('svg')!).fill, background);
      assert.equal(getComputedStyle(tooltip()!.querySelector('kbd')!).color, color);
      const tooltipBounds = tooltip().getBoundingClientRect();
      assert.ok(
        tooltipBounds.left >= sidebar.getBoundingClientRect().left &&
          tooltipBounds.right <= bounds.left,
        'Quick Connect tooltip must fit inside the sidebar, clear of native session surfaces',
      );
      await React.act(async () => quickConnect.blur());
      await waitFor(
        () => !tooltip()?.textContent?.includes('Quick Connect'),
        'Quick Connect tooltip must close on blur',
      );
      const quickBounds = quickConnect.getBoundingClientRect();
      await move(quickBounds.x + quickBounds.width / 2, quickBounds.y + quickBounds.height / 2);
      const assertQuickConnectHover = () => {
        const hoverBackground = getComputedStyle(quickConnect).backgroundColor;
        assert.notEqual(hoverBackground, 'rgba(0, 0, 0, 0)');
        assert.notEqual(hoverBackground, getComputedStyle(sidebar).backgroundColor);
        assert.equal(getComputedStyle(quickIcon).fill, 'none');
      };
      assertQuickConnectHover();
      if (theme === 'dark') {
        applyTheme('oled');
        assertQuickConnectHover();
        applyTheme('dark');
      }
      await move(1000, 400);
      assert.equal(getComputedStyle(quickConnect).backgroundColor, 'rgba(0, 0, 0, 0)');
      if (theme === 'light') {
        await click(trigger);
        await assertTabSearchStartsAtCanvas();
        const popover = query('[data-session-tab-search]');
        const heading = query('[data-session-tab-search] [id]');
        const input = query('[data-session-tab-search] [role="combobox"]');
        const result = query('[data-session-tab-search] [aria-selected="true"]');
        assertContrast(
          'Tab search heading',
          getComputedStyle(heading).color,
          getComputedStyle(popover).backgroundColor,
        );
        assertContrast(
          'Tab search placeholder',
          getComputedStyle(input, '::placeholder').color,
          getComputedStyle(input).backgroundColor,
        );
        assertContrast(
          'Highlighted search result',
          getComputedStyle(result).color,
          getComputedStyle(result).backgroundColor,
        );
        await window.sidebarObserve('tab-search-light');
        await click(trigger);
        const sessionStyles = workspaceStyles();
        for (const page of ['Credentials', 'Tunnels', 'Sessions']) {
          await click(query(`nav [aria-label="${page}"]`));
          assertCanvasAlignedWithSearch();
          assert.deepEqual(
            workspaceStyles(),
            sessionStyles,
            `Light workspace style changed in ${page}`,
          );
          if (page !== 'Sessions')
            await window.sidebarObserve(`workspace-${page.toLowerCase()}-light`);
        }
      }
      if (theme === 'dark') {
        await React.act(async () => {
          const rows = document.querySelectorAll('[data-connection-tree] button[draggable]');
          rows[1].dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
        });
        const another = query('[data-session-tab-id="session-another-server"]');
        const surface = workspaceCanvas();
        const transfer = new DataTransfer();
        const surfaceBounds = surface.getBoundingClientRect();
        await React.act(async () => {
          another.dispatchEvent(
            new DragEvent('dragstart', { bubbles: true, dataTransfer: transfer }),
          );
          surface.dispatchEvent(
            new DragEvent('dragover', {
              bubbles: true,
              cancelable: true,
              clientX: surfaceBounds.left + surfaceBounds.width / 2,
              clientY: surfaceBounds.top + 1,
              dataTransfer: transfer,
            }),
          );
        });
        const preview = query('[data-session-drop-preview]');
        assert.equal(preview.textContent?.trim(), 'Split top');
        const previewBounds = preview.getBoundingClientRect();
        assert.ok(previewBounds.top >= surfaceBounds.top, 'Split preview must stay below the tabs');
        assert.ok(
          previewBounds.bottom <= surfaceBounds.bottom,
          'Split preview must stay inside the canvas',
        );
        await React.act(async () =>
          another.dispatchEvent(
            new DragEvent('dragend', { bubbles: true, dataTransfer: transfer }),
          ),
        );
        const press = (target: HTMLElement, key: string, modifiers = {}) =>
          React.act(async () => {
            target.dispatchEvent(
              new KeyboardEvent('keydown', {
                key,
                bubbles: true,
                cancelable: true,
                ...modifiers,
              }),
            );
          });
        await press(another, 'ArrowRight', { altKey: true, shiftKey: true });
        assert.equal(document.querySelectorAll('[data-session-canvas]').length, 2);

        const nativeDialog = document.createElement('dialog');
        document.body.append(nativeDialog);
        try {
          nativeDialog.showModal();
          await press(nativeDialog, 'A', { ctrlKey: true, shiftKey: true });
          assert.equal(trigger.getAttribute('aria-expanded'), 'false');
          await press(nativeDialog, 'k', { ctrlKey: true });
          assert.equal(document.querySelector('[role="dialog"][data-state="open"]'), null);
        } finally {
          nativeDialog.close();
          nativeDialog.remove();
        }

        assert.ok(trigger.getBoundingClientRect().right <= tablist.getBoundingClientRect().left);
        assert.ok(query('[data-native-overlay-open="false"]'));
        await click(trigger);
        await assertTabSearchStartsAtCanvas();
        const input = query(
          '[role="combobox"][aria-label="Search open tabs by title"]',
        ) as HTMLInputElement;
        await waitFor(() => document.activeElement === input, 'Tab search did not focus its input');
        const connectionSearch = query('[aria-label="Search connections"]');
        assert.equal(
          input.getBoundingClientRect().height,
          connectionSearch.getBoundingClientRect().height,
        );
        assert.equal(
          getComputedStyle(input).borderTopLeftRadius,
          getComputedStyle(connectionSearch).borderTopLeftRadius,
        );
        assert.equal(trigger.getAttribute('aria-expanded'), 'true');
        assert.ok(
          query('[data-native-overlay-open="true"]'),
          'Tab search must occlude native views',
        );
        assert.match(query('[aria-label="Open tabs"]').textContent!, /Another serverActive/);
        await window.sidebarObserve('tab-search');

        const type = (value: string) =>
          React.act(async () => {
            Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(
              input,
              value,
            );
            input.dispatchEvent(new Event('input', { bubbles: true }));
          });
        await type('no-such-tab');
        assert.match(
          query('[data-slot="popover-content"] [role="status"]').textContent!,
          /No matching tabs/,
        );
        await click(query('[aria-label="Clear tab search"]'));
        assert.equal(input.value, '');
        assert.ok(document.activeElement === input);
        assert.equal(document.querySelectorAll('[role="option"]').length, 2);
        await type('  SERVER ');
        assert.equal(document.querySelectorAll('[role="option"]').length, 2);
        await press(input, 'ArrowDown');
        assert.match(query('[role="option"][aria-selected="true"]').textContent!, /Another server/);
        await press(input, 'ArrowUp');
        await press(input, 'Enter');
        await waitFor(
          () => trigger.getAttribute('aria-expanded') === 'false' && document.activeElement === tab,
          'Selecting a result must close the search and focus the tab in its pane',
        );
        await waitFor(
          () => Boolean(query('[data-native-overlay-open="false"]')),
          'Closing the tab search must let native views return',
        );

        await press(tab, 'A', { ctrlKey: true, shiftKey: true });
        const reopened = query('[aria-label="Search open tabs by title"]') as HTMLInputElement;
        assert.ok(reopened);
        assert.equal(reopened.value, '');
        await press(reopened, 'Escape', { isComposing: true });
        assert.equal(
          trigger.getAttribute('aria-expanded'),
          'true',
          'Escape during composition must leave tab search open',
        );
        await press(reopened, 'Escape');
        await waitFor(
          () => document.activeElement === trigger,
          'Escape must return focus to the search button',
        );
        await click(trigger);
        const secondResult = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(
          (option) => option.textContent?.includes('Another server'),
        );
        assert.ok(secondResult);
        await click(secondResult);
        await waitFor(
          () => document.activeElement === query('[data-session-tab-id="session-another-server"]'),
          'Clicking a result must focus the tab in the other pane',
        );
      }
      if (!handleOnly) {
        const connectionSelector = `${rowSelector}:has([aria-label="Select Another server"])`;
        const folderSelector = `${rowSelector}:has([aria-label="Select Servers"])`;
        const assertRoundedRow = (style: CSSStyleDeclaration) => {
          assert.deepEqual(
            [
              style.borderTopLeftRadius,
              style.borderTopRightRadius,
              style.borderBottomRightRadius,
              style.borderBottomLeftRadius,
            ],
            ['8px', '8px', '8px', '8px'],
          );
        };
        // Hidden windows can lose synthetic pointer moves after restoring focus.
        async function assertRowHover(selector: string, stage: string) {
          const row = query(selector);
          assert.ok(row, `Missing hover row for ${stage}`);
          const viewport = query('[data-connection-tree] [data-slot="scroll-area-viewport"]');
          const bounds = row.getBoundingClientRect();
          const viewportBounds = viewport.getBoundingClientRect();
          assert.ok(bounds.left > viewportBounds.left && bounds.right < viewportBounds.right);
          const style = getComputedStyle(row);
          const idleBackground = style.backgroundColor;
          assert.equal(style.borderTopLeftRadius, '0px');
          await window.sidebarHover(selector, true);
          try {
            assert.notEqual(style.backgroundColor, idleBackground);
            assertRoundedRow(style);
            const background = style.backgroundColor;
            await window.sidebarObserve(stage);
            return background;
          } finally {
            await window.sidebarHover(selector, false);
          }
        }
        const connectionBackground = await assertRowHover(
          connectionSelector,
          'workspace-tree-hover-' + theme,
        );
        const collapsedFolder = `${rowSelector}[aria-expanded="false"]`;
        const expandedFolder = `${rowSelector}[aria-expanded="true"]`;
        assert.equal(
          await assertRowHover(expandedFolder, 'workspace-tree-hover-expanded-folder-' + theme),
          connectionBackground,
        );
        await React.act(async () => connectionActions()[1].click());
        await waitFor(() => Boolean(query(collapsedFolder)), 'Folder did not collapse');
        assert.equal(
          await assertRowHover(collapsedFolder, 'workspace-tree-hover-folder-' + theme),
          connectionBackground,
        );

        async function selectRow(selector: string) {
          const row = query(selector);
          const idleBackground = getComputedStyle(row).backgroundColor;
          await React.act(async () => row.click());
          assert.deepEqual(
            [...document.querySelectorAll(`${rowSelector}[aria-current="true"]`)],
            [row],
          );
          const style = getComputedStyle(row);
          const appearance = {
            background: style.backgroundColor,
            color: style.color,
            shadow: style.boxShadow,
          };
          assert.notEqual(appearance.background, idleBackground);
          const checkbox = row.querySelector('[role="checkbox"]');
          assert.equal(checkbox?.getAttribute('aria-checked'), 'false');
          await window.sidebarHover(selector, true);
          try {
            assert.equal(style.backgroundColor, appearance.background);
          } finally {
            await window.sidebarHover(selector, false);
          }
          assertRoundedRow(style);
          return appearance;
        }

        const selectedConnection = await selectRow(connectionSelector);
        assert.deepEqual(await selectRow(folderSelector), selectedConnection);
        assert.deepEqual(await selectRow(connectionSelector), selectedConnection);
      }
    }
  };
  const checkOverflowingTabs = async () => {
    await mount(
      Array.from({ length: 12 }, (_, index): WormholeWorkspaceNode => ({
        id: `overflow-${index}`,
        kind: 'connection',
        name: `Overflow ${index} • Long workspace connection`,
        protocol: 'https',
      })),
      320,
      true,
    );
    const connections = [...document.querySelectorAll('[data-connection-tree] button[draggable]')];
    for (const connection of connections) {
      await React.act(async () =>
        connection.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })),
      );
    }
    const strip = query('[aria-label="Pane tabs"]');
    assert.ok(strip.scrollWidth > strip.clientWidth, 'Fixture must overflow the tab strip');
    assert.equal(strip.querySelectorAll('[role="tab"]').length, connections.length);
    assert.equal(getComputedStyle(strip, '::-webkit-scrollbar-track').marginRight, '8px');
    const visible = (tab: Element) => {
      const stripBounds = strip.getBoundingClientRect();
      const bounds = tab.parentElement!.getBoundingClientRect();
      return bounds.left >= stripBounds.left - 1 && bounds.right <= stripBounds.right + 1;
    };
    const activeTab = strip.querySelector('[role="tab"][aria-selected="true"]')!;
    assert.ok(
      visible(activeTab),
      'Opening an overflowing connection must reveal its title and actions',
    );
    const expectEdgeBlur = async (left: string, right: string) => {
      await waitFor(
        () =>
          getComputedStyle(strip, '::before').opacity === left &&
          getComputedStyle(strip, '::after').opacity === right,
        `The edge blur must follow the scroll direction at offset ${strip.scrollLeft}`,
      );
    };
    await expectEdgeBlur('1', '0');
    strip.scrollLeft = 0;
    await expectEdgeBlur('0', '1');
    strip.scrollLeft = (strip.scrollWidth - strip.clientWidth) / 2;
    await expectEdgeBlur('1', '1');
    await window.sidebarObserve('session-scroll-middle');
    strip.scrollLeft = strip.scrollWidth;
    await expectEdgeBlur('1', '0');
    const shell = query('[data-workspace-shell]');
    const initialWidth = strip.clientWidth;
    try {
      shell.style.width = '820px';
      await waitFor(
        () => strip.clientWidth < initialWidth && visible(activeTab),
        'Resizing the workspace must keep the active connection tab visible',
      );
    } finally {
      shell.style.removeProperty('width');
      await waitFor(
        () => strip.clientWidth === initialWidth,
        'The tab strip must return to its initial width',
      );
    }
    const firstTab = strip.querySelector('[role="tab"]')!;
    assert.ok(!visible(firstTab), 'The first tab must be outside the current strip viewport');
    const trigger = query('[aria-label="Search open tabs"]');
    await click(trigger);
    await click(query('[role="listbox"] [role="option"]'));
    await waitFor(
      () => document.activeElement === firstTab && visible(firstTab),
      'Search must reveal a matching tab that was outside the strip viewport',
    );

    await click(trigger);
    await waitFor(
      () => Boolean(query('[data-native-overlay-open="true"]')),
      'Open tab search must be counted as an overlay',
    );
    await click(query('nav [aria-label="Credentials"]'));
    await waitFor(
      () =>
        query('nav [aria-current="page"]').getAttribute('aria-label') === 'Credentials' &&
        !query('[data-session-tab-search]') &&
        Boolean(query('[data-native-overlay-open="false"]')),
      'Leaving Sessions must remove tab search and release native occlusion',
    );
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
    await checkSessionTabContextTooltip();
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
    const pinBounds = pin.getBoundingClientRect();
    const hoverPin = async () => {
      await move(pinBounds.x + pinBounds.width / 2, pinBounds.y + pinBounds.height / 2);
      await shown(true);
    };
    const nav = query('[data-sidebar-navigation] nav');
    assert.ok(nav.closest('[inert]'));
    assert.equal(getComputedStyle(query('[data-sidebar-surface]')).opacity, '0');
    const canvas = query('[data-workspace-canvas] > div');
    assert.equal(canvas.getBoundingClientRect().left, 0);
    assert.equal(getComputedStyle(query('[data-session-canvas]')).borderTopLeftRadius, '12px');
    const buttons = [...nav.querySelectorAll<HTMLButtonElement>('button')];
    const iconCenter = (element: Element) => {
      const bounds = element.querySelector('svg')!.getBoundingClientRect();
      return bounds.x + bounds.width / 2;
    };
    assert.deepEqual(
      buttons.map((button) => button.getAttribute('aria-label')),
      ['Sessions', 'Credentials', 'Tunnels', 'Settings'],
    );
    const sessionStyles = workspaceStyles();
    for (const button of buttons.slice(0, 3)) {
      await hoverPin();
      await window.sidebarObserve(button.getAttribute('aria-label')!);
      assert.ok(button.querySelector('svg'));
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
      assertCanvasAlignedWithSearch();
      assert.deepEqual(
        workspaceStyles(),
        sessionStyles,
        `Dark workspace style changed in ${label}`,
      );
      if (label !== 'Sessions')
        await window.sidebarObserve(`workspace-${label.toLowerCase()}-dark`);
      await move(1000, 400);
      await shown(false);
      const shellBounds = query('[data-workspace-shell]').getBoundingClientRect();
      const canvasBounds = workspaceCanvas().getBoundingClientRect();
      assert.equal(
        canvasBounds.left - shellBounds.left,
        shellBounds.right - canvasBounds.right,
        `${label} must have equal side margins when the sidebar is closed`,
      );
    }
    const settingsButton = buttons[3];
    await hoverPin();
    await window.sidebarObserve(settingsButton.getAttribute('aria-label')!);
    assert.ok(settingsButton.querySelector('svg'));
    assert.ok(
      Math.abs(iconCenter(pin) - iconCenter(settingsButton)) <= 1,
      'Expanding the sidebar moved its navigation icons out of alignment',
    );
    assert.equal(settingsButton.getAttribute('aria-haspopup'), 'dialog');
    assert.equal(settingsButton.getAttribute('aria-current'), null);
    await click(settingsButton);
    await waitFor(
      () => document.querySelector('[data-settings-dialog][data-state="open"]') !== null,
      'Settings overlay dialog did not open',
    );
    assert.match(query('[data-slot="sidebar-inset"]').textContent!, /Tunnels/i);
    await click(query('[aria-label="Close settings"]'));
    await waitFor(
      () => document.querySelector('[data-settings-dialog][data-state="open"]') === null,
      'Settings overlay dialog did not close',
    );
    await move(1000, 400);
    await shown(false);
    await window.sidebarObserve('collapsed');
    await hoverPin();
    const preview = query('[data-sidebar-surface]').getBoundingClientRect();
    assert.equal(preview.left, 0);
    assert.equal(canvas.getBoundingClientRect().left, preview.right);
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
    await keypress('Tab');
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
      folder.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }),
      );
    });
    await shown(false);
    await move(1000, 400);
    await hoverPin();
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
        if (depth === 0) {
          const title = query('aside h1').getBoundingClientRect();
          const quickConnect = query('aside [aria-keyshortcuts="Control+K Meta+K"]');
          const quick = quickConnect.getBoundingClientRect();
          const search = query('[aria-label="Search connections"]').getBoundingClientRect();
          assert.ok(title.right < quick.left, 'Quick Connect must sit to the right of Connections');
          assert.ok(
            Math.abs(title.top + title.height / 2 - (quick.top + quick.height / 2)) < 1,
            'Quick Connect and Connections must share a row',
          );
          assert.ok(quick.height < search.height && quick.width < search.width);
          assert.equal(quick.right, search.right);
          assert.ok(quick.bottom <= search.top);

          const actions = connectionActions();
          const actionBounds = actions.map((action) => action.getBoundingClientRect());
          const firstAction = actionBounds[0];
          assert.ok(actions.every((action) => !action.closest('[role="group"]')));
          assertConnectionControlsAligned();
          assert.ok(search.bottom <= firstAction.top);
          assert.ok(firstAction.bottom <= rows[0].getBoundingClientRect().top);
          for (const [index, action] of actionBounds.entries()) {
            assert.equal(action.top, firstAction.top);
            assert.ok(action.right <= search.right);
            assert.equal(action.width, 28);
            assert.equal(action.height, 28);
            if (index > 0) assert.equal(action.left - actionBounds[index - 1].right, 4);
          }
        }
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

    const headerQuickConnect = query('aside [aria-keyshortcuts="Control+K Meta+K"]');
    await React.act(async () => headerQuickConnect.focus());
    for (const control of [query('[aria-label="Search connections"]'), ...connectionActions()]) {
      await keypress('Tab');
      assert.ok(
        document.activeElement === control,
        `Expected Tab to focus ${control.getAttribute('aria-label')}`,
      );
    }

    await click(headerQuickConnect);
    const name = document.querySelector<HTMLInputElement>('#connection-name')!;
    assert.equal(name.required, false);
    assert.match(name.labels![0].textContent!, /optional/i);
    assert.ok(query('#connection-tunnel-route'), 'SSH should offer a VPN route');
    await click(query('#connection-protocol'));
    const serial = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(
      (option) => option.textContent?.trim() === 'Serial',
    );
    assert.ok(serial, 'Serial must be selectable in Quick Connect');
    await click(serial);
    assert.equal(query('label[for="connection-host"]').textContent, 'Serial line');
    assert.equal(query('#connection-tunnel-route'), null, 'Serial must omit the VPN route');
    const clickDialogButton = async (label: string) => {
      const button = [
        ...document.querySelectorAll<HTMLButtonElement>(
          '[role="dialog"][data-state="open"] button',
        ),
      ].find((item) => item.textContent?.trim() === label);
      assert.ok(button, 'Missing dialog action ' + label);
      await React.act(async () => button.click());
    };
    await clickDialogButton('Cancel');
    await waitFor(() => !query('#connection-name'), 'Quick Connect did not close');

    await React.act(async () => query('[aria-label="New connection"]').click());
    assert.equal(document.querySelector<HTMLInputElement>('#connection-name')?.required, true);
    await clickDialogButton('Cancel');
    await waitFor(() => !query('#connection-name'), 'The saved connection editor did not close');

    const importButton = query('[aria-label="Import connections"]');
    await React.act(async () => {
      importButton.focus();
      importButton.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: 'ArrowDown',
          bubbles: true,
          cancelable: true,
        }),
      );
    });
    const mremote = [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find((item) =>
      item.textContent?.includes('Import from mRemoteNG'),
    );
    assert.ok(mremote, 'the Connections menu must offer mRemoteNG import');
    await React.act(async () => mremote.click());
    assert.match(query('[role="dialog"]').textContent!, /mRemoteNG/i);
    const imported = {
      foldersCreated: 1,
      connectionsCreated: 0,
      credentialsCreated: 0,
      credentialsReused: 0,
      skippedUnsupported: 0,
      warnings: [],
      droppedWarnings: 0,
    } satisfies WormholeMRemoteImportResult;
    let completeImport!: (result: WormholeMRemoteImportResult) => void;
    window.wormhole = {
      hideTreeTooltip: () => {},
      clearMRemoteImport: () => {},
      onOperationProgress: () => () => {},
      selectMRemoteImport: async () => ({
        fileName: 'connections.xml',
        fileSize: 128,
        confVersion: '2.7',
        passwordRequired: false,
        fullFileEncrypted: false,
      }),
      analyzeMRemoteImport: async () => ({
        planToken: 'a'.repeat(64),
        folders: 1,
        connections: 0,
        credentials: 0,
        credentialsReused: 0,
        sharedCredentials: 0,
        sharedCredentialConnections: 0,
        skippedUnsupported: 0,
        skippedUnsupportedSamples: [],
        warnings: [],
        droppedWarnings: 0,
        preview: [],
        previewTruncated: false,
      }),
      commitMRemoteImport: () =>
        new Promise<WormholeMRemoteImportResult>((resolve) => {
          completeImport = resolve;
        }),
      loadWorkspace: async () => ({
        tree: [{ id: 'new-import', kind: 'folder', name: 'Imported servers' }],
        credentials: [],
        credentialOptions: { ssh: [], rdp: [], vnc: [] },
        tunnels: [],
      }),
    } as unknown as Window['wormhole'];
    await clickDialogButton('Choose file…');
    await clickDialogButton('Analyze file');
    await clickDialogButton('Import plan');
    assert.match(query('[data-connection-tree]').textContent!, /Nothing here yet/);
    await React.act(async () => completeImport(imported));
    await waitFor(
      () => query('[data-connection-tree]').textContent!.includes('Imported servers'),
      'The connection tree did not refresh after import',
    );
    await clickDialogButton('Close');
    window.wormhole = undefined;

    await checkPinnedHandle();
    await checkOverflowingTabs();
  } catch (error) {
    if (error instanceof AggregateError) throw new Error(error.errors.map(String).join(' / '));
    throw error;
  } finally {
    await React.act(async () => root.unmount());
    window.wormhole = originalBridge;
    await React.act(async () => window.sidebarReducedMotion(false));
  }
}
