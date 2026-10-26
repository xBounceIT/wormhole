import {
  createContext,
  useContext,
  useEffect,
  useEffectEvent,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type MouseEvent,
  type ReactNode,
} from 'react';
import { PanelLeft } from 'lucide-react';
import { usePanelRef } from 'react-resizable-panels';

import { maxSidebarWidth, minSidebarWidth, normalizeSidebarWidth } from '@/sidebar-settings';
import { Button } from '@/components/ui/button';
import { ContextMenuOverlayProvider } from '@/components/ui/context-menu';
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from '@/components/ui/resizable';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

const SidebarPinContext = createContext({ pinned: true, busy: false, toggle: () => {} });
const collapsedSidebarWidth = 40;

export function SidebarPinButton() {
  const { pinned, busy, toggle } = useContext(SidebarPinContext);
  const label = pinned ? 'Unpin sidebar' : 'Pin sidebar';
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          aria-busy={busy}
          aria-disabled={busy}
          aria-label={label}
          aria-pressed={pinned}
          className="transition aria-disabled:opacity-50 [-webkit-app-region:no-drag]"
          data-sidebar-pin=""
          onClick={toggle}
          size="icon"
          type="button"
          variant="ghost"
        >
          <PanelLeft aria-hidden="true">
            {pinned ? (
              <path
                d="M9 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h4Z"
                fill="currentColor"
                key="pinned-column"
                stroke="none"
              />
            ) : null}
          </PanelLeft>
        </Button>
      </TooltipTrigger>
      <TooltipContent side="bottom">{label}</TooltipContent>
    </Tooltip>
  );
}

export function SidebarLayout({
  header,
  navigation,
  initialPinned,
  initialWidth,
  keepOpen,
  onPinnedChange,
  onWidthChange,
  onOverlayOpenChange,
  sidebar,
  children,
}: {
  header: ReactNode;
  navigation: (collapsed: boolean) => ReactNode;
  initialPinned: boolean;
  initialWidth: number;
  keepOpen: boolean;
  onPinnedChange: (pinned: boolean) => Promise<unknown>;
  onWidthChange: (width: number) => void;
  onOverlayOpenChange: (open: boolean) => void;
  sidebar: ReactNode;
  children: ReactNode;
}) {
  const [pinned, setPinned] = useState(initialPinned);
  const [pinResizePending, setPinResizePending] = useState(false);
  const [busy, setBusy] = useState(false);
  const pinSavePending = useRef(false);
  const [error, setError] = useState('');
  const [width, setWidth] = useState(() => normalizeSidebarWidth(initialWidth));
  const [defaultSize] = useState(() =>
    initialPinned ? `${normalizeSidebarWidth(initialWidth)}px` : `${collapsedSidebarWidth}px`,
  );
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const panelRef = usePanelRef();
  const expandedWidth = useRef(normalizeSidebarWidth(initialWidth));
  const revealButton = useRef<HTMLButtonElement>(null);
  const sidebarSurface = useRef<HTMLElement>(null);
  const previousPinned = useRef(pinned);
  const sidebarId = useId();
  const visible = pinned || revealed;
  const shouldKeepOpen = keepOpen || menuOpen;

  // A portaled menu may extend beyond the sidebar. Keep its owning surface mounted and visible.
  useEffect(() => {
    setRevealed((current) => hovered || focused || (shouldKeepOpen && current));
  }, [hovered, focused, shouldKeepOpen]);

  function revealOnHover(event: MouseEvent<HTMLDivElement>) {
    // Portaled menus are outside this surface even though React events bubble through it.
    if (!event.currentTarget.contains(event.target as Node)) return;
    setHovered(true);
    // Recover on movement too, including when an entry event happened before mounting or closing.
    setRevealed(true);
  }

  const resizePanel = useEffectEvent(() => {
    if (pinned) panelRef.current?.resize(`${expandedWidth.current}px`);
    else panelRef.current?.collapse();
    setPinResizePending(false);
  });
  useEffect(() => {
    if (previousPinned.current === pinned && !pinResizePending) return;
    previousPinned.current = pinned;
    // The panel group registers changed collapse constraints in its own layout update.
    const frame = requestAnimationFrame(() => resizePanel());
    return () => cancelAnimationFrame(frame);
  }, [pinned, pinResizePending]);

  useLayoutEffect(() => {
    let active = true;
    const transitions = sidebarSurface.current!.getAnimations();
    // Native surfaces stay behind the sidebar through its exit and deferred pin resize.
    onOverlayOpenChange(pinResizePending || (!pinned && (visible || transitions.length > 0)));
    if (!visible && transitions.length > 0) {
      void Promise.allSettled(transitions.map((transition) => transition.finished)).then(() => {
        if (active) onOverlayOpenChange(false);
      });
    }
    return () => {
      active = false;
    };
  }, [onOverlayOpenChange, pinned, pinResizePending, visible]);

  useLayoutEffect(() => () => onOverlayOpenChange(false), [onOverlayOpenChange]);

  async function toggle() {
    if (pinSavePending.current) return;
    pinSavePending.current = true;
    const next = !pinned;
    if (pinned) expandedWidth.current = width;
    setBusy(true);
    setError('');
    setPinned(next);
    setPinResizePending(next);
    try {
      await onPinnedChange(next);
    } catch {
      setPinned(!next);
      setPinResizePending(!next);
      setError("Wormhole couldn't save the sidebar preference. Try again.");
    } finally {
      pinSavePending.current = false;
      setBusy(false);
    }
  }

  return (
    <SidebarPinContext.Provider value={{ pinned, busy, toggle }}>
      <div className="flex min-h-0 flex-1 flex-col">
        {header}
        {error ? (
          <p className="shrink-0 px-3 py-2 text-xs text-destructive" role="alert">
            {error}
          </p>
        ) : null}
        <div
          className="relative min-h-0 flex-1 overflow-hidden"
          data-sidebar-layout=""
          data-pinned={pinned}
          data-revealed={visible}
        >
          <ResizablePanelGroup className="h-full min-h-0" orientation="horizontal">
            <ResizablePanel
              collapsedSize={`${collapsedSidebarWidth}px`}
              collapsible={!pinned}
              defaultSize={defaultSize}
              groupResizeBehavior="preserve-pixel-size"
              maxSize={`${maxSidebarWidth}px`}
              minSize={`${minSidebarWidth}px`}
              onResize={(size, _id, previous) => {
                if (pinned && size.inPixels >= minSidebarWidth) {
                  const nextWidth = normalizeSidebarWidth(size.inPixels);
                  setWidth(nextWidth);
                  if (previous) onWidthChange(nextWidth);
                }
              }}
              panelRef={panelRef}
            />
            {/* Both 1px borders form the visible divider. */}
            <ResizableHandle
              className={
                pinned
                  ? 'z-40 [&>div]:absolute [&>div]:top-1/2 [&>div]:left-0 [&>div]:-translate-1/2'
                  : 'hidden'
              }
              disabled={!pinned}
              withHandle
            />
            <ResizablePanel className="min-h-0" minSize="54%">
              {children}
            </ResizablePanel>
          </ResizablePanelGroup>
          <div
            className="absolute inset-y-0 left-0 z-30"
            onBlur={(event) => {
              if (!event.currentTarget.contains(event.relatedTarget)) setFocused(false);
            }}
            onFocus={(event) => setFocused(event.target.matches(':focus-visible'))}
            onKeyDown={(event) => {
              if (event.key === 'Escape' && !pinned && !shouldKeepOpen) {
                event.preventDefault();
                revealButton.current?.focus();
                setFocused(false);
                setHovered(false);
                setRevealed(false);
              }
            }}
            onPointerDown={() => setFocused(false)}
            onMouseEnter={revealOnHover}
            onMouseMove={revealOnHover}
            onMouseLeave={() => setHovered(false)}
            style={{ width: visible ? width : collapsedSidebarWidth }}
          >
            <aside
              aria-label="Sidebar"
              className="absolute inset-y-0 left-0 flex flex-col overflow-hidden border-r border-sidebar-border bg-sidebar data-[overlay=true]:shadow-xl"
              data-expanded={visible}
              data-overlay={!pinned}
              data-sidebar-surface=""
              ref={sidebarSurface}
              style={{ width: visible ? width : collapsedSidebarWidth }}
            >
              {!pinned ? (
                <button
                  aria-controls={sidebarId}
                  aria-expanded={revealed}
                  aria-label="Show sidebar"
                  className="absolute inset-0 z-10 bg-transparent outline-none data-[expanded=true]:pointer-events-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-sidebar-ring"
                  data-expanded={visible}
                  onClick={(event) => {
                    setFocused(event.currentTarget.matches(':focus-visible'));
                    setRevealed(true);
                  }}
                  ref={revealButton}
                  tabIndex={visible ? -1 : 0}
                  type="button"
                />
              ) : null}
              <div
                aria-hidden={!visible}
                className="min-h-0 flex-1 aria-hidden:pointer-events-none"
                data-sidebar-content=""
                id={sidebarId}
                inert={!visible}
                style={{ width }}
              >
                <ContextMenuOverlayProvider onOpenChange={setMenuOpen}>
                  {sidebar}
                </ContextMenuOverlayProvider>
              </div>
              <div
                className="relative z-20 shrink-0 border-t border-sidebar-border p-1"
                data-sidebar-navigation=""
              >
                {navigation(!visible)}
              </div>
            </aside>
          </div>
        </div>
      </div>
    </SidebarPinContext.Provider>
  );
}
