import {
  createContext,
  useContext,
  useEffect,
  useEffectEvent,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type HTMLAttributes,
  type MouseEvent,
  type ReactNode,
  type Ref,
} from 'react';
import { PanelLeft } from 'lucide-react';
import { usePanelRef } from 'react-resizable-panels';

import { maxSidebarWidth, minSidebarWidth, normalizeSidebarWidth } from '@/sidebar-settings';
import { Button } from '@/components/ui/button';
import { ContextMenuOverlayProvider } from '@/components/ui/context-menu';
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from '@/components/ui/resizable';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

type SidebarInteractions = Pick<
  HTMLAttributes<HTMLElement>,
  | 'onBlur'
  | 'onFocus'
  | 'onKeyDown'
  | 'onMouseEnter'
  | 'onMouseLeave'
  | 'onMouseMove'
  | 'onPointerDown'
>;

const SidebarPinContext = createContext<{
  pinned: boolean;
  busy: boolean;
  toggle: () => void;
  visible?: boolean;
  sidebarId?: string;
  buttonRef?: Ref<HTMLButtonElement>;
  interactions?: SidebarInteractions;
}>({ pinned: true, busy: false, toggle: () => {} });
const sidebarHoverExitDelayMs = 120;
const canvasMinPercent = 54;

export function SidebarPinButton() {
  const { pinned, busy, toggle, visible, sidebarId, buttonRef, interactions } =
    useContext(SidebarPinContext);
  const label = pinned ? 'Unpin sidebar' : 'Pin sidebar';
  return (
    <Tooltip disableHoverableContent>
      <TooltipTrigger asChild>
        <Button
          {...interactions}
          aria-busy={busy}
          aria-controls={sidebarId}
          aria-disabled={busy}
          aria-expanded={visible}
          aria-keyshortcuts={pinned ? undefined : 'ArrowDown'}
          aria-label={label}
          aria-pressed={pinned}
          className="transition aria-disabled:opacity-50 [-webkit-app-region:no-drag]"
          data-sidebar-pin=""
          onClick={toggle}
          ref={buttonRef}
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
      <TooltipContent className="pointer-events-none" side="right" sideOffset={4}>
        {label}
      </TooltipContent>
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
  navigation: ReactNode;
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
    initialPinned ? `${normalizeSidebarWidth(initialWidth)}px` : '0px',
  );
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const panelRef = usePanelRef();
  const sidebarPanel = useRef<HTMLDivElement>(null);
  const expandedWidth = useRef(normalizeSidebarWidth(initialWidth));
  const pinButton = useRef<HTMLButtonElement>(null);
  const lastInputWasPointer = useRef(false);
  const hoverExit = useRef<number | undefined>(undefined);
  const sidebarSurface = useRef<HTMLElement>(null);
  const previousPinned = useRef(pinned);
  const sidebarId = useId();
  const visible = pinned || revealed;
  const shouldKeepOpen = keepOpen || menuOpen;

  // A portaled menu may extend beyond the sidebar. Keep its owning surface mounted and visible.
  useEffect(() => {
    setRevealed((current) => hovered || focused || (shouldKeepOpen && current));
  }, [hovered, focused, shouldKeepOpen]);
  useEffect(() => () => window.clearTimeout(hoverExit.current), []);
  useEffect(() => {
    // Chromium matches :focus-visible on text inputs even when the pointer focuses them.
    const markPointerInput = () => {
      lastInputWasPointer.current = true;
    };
    const markKeyboardInput = () => {
      lastInputWasPointer.current = false;
    };
    document.addEventListener('pointerdown', markPointerInput, true);
    document.addEventListener('keydown', markKeyboardInput, true);
    return () => {
      document.removeEventListener('pointerdown', markPointerInput, true);
      document.removeEventListener('keydown', markKeyboardInput, true);
    };
  }, []);

  function revealOnHover(event: MouseEvent<HTMLElement>) {
    // Portaled menus are outside this surface even though React events bubble through it.
    if (!event.currentTarget.contains(event.target as Node)) return;
    window.clearTimeout(hoverExit.current);
    setHovered(true);
    // Recover on movement too, including when an entry event happened before mounting or closing.
    setRevealed(true);
  }

  const interactions: SidebarInteractions = {
    onBlur(event) {
      if (
        event.relatedTarget !== pinButton.current &&
        !sidebarSurface.current?.contains(event.relatedTarget)
      ) {
        setFocused(false);
      }
    },
    onFocus(event) {
      setFocused(!lastInputWasPointer.current && event.target.matches(':focus-visible'));
    },
    onKeyDown(event) {
      if (pinned || !event.currentTarget.contains(event.target as Node)) return;
      if (event.key === 'ArrowDown' && event.target === pinButton.current) {
        event.preventDefault();
        setFocused(true);
        setRevealed(true);
      } else if (event.key === 'Escape' && !shouldKeepOpen && visible) {
        event.preventDefault();
        pinButton.current?.focus();
        setFocused(false);
        setHovered(false);
        setRevealed(false);
      }
    },
    onMouseEnter: revealOnHover,
    onMouseLeave() {
      window.clearTimeout(hoverExit.current);
      // Give the pointer time to cross the space below the titlebar button.
      hoverExit.current = window.setTimeout(() => setHovered(false), sidebarHoverExitDelayMs);
    },
    onMouseMove: revealOnHover,
    onPointerDown: () => setFocused(false),
  };

  const resizePanel = useEffectEvent(() => {
    if (pinned) panelRef.current?.resize(`${expandedWidth.current}px`);
    else panelRef.current?.collapse();
    setPinResizePending(false);
  });
  useEffect(() => {
    if (previousPinned.current === pinned && !pinResizePending) return;
    previousPinned.current = pinned;
    let active = true;
    // The panel group registers changed collapse constraints in its own layout update.
    let frame = requestAnimationFrame(resizeWhenSettled);
    function resizeWhenSettled() {
      const transition = pinned ? sidebarPanel.current?.getAnimations()[0] : undefined;
      if (!transition) {
        resizePanel();
        return;
      }
      const checkAgain = () => {
        if (active) frame = requestAnimationFrame(resizeWhenSettled);
      };
      void transition.finished.then(checkAgain, checkAgain);
    }
    return () => {
      active = false;
      cancelAnimationFrame(frame);
    };
  }, [pinned, pinResizePending]);

  useLayoutEffect(() => {
    let active = true;
    const transitions = [
      ...sidebarPanel.current!.getAnimations(),
      ...sidebarSurface.current!.getAnimations(),
    ];
    // Native surfaces stay hidden until the canvas has settled after an exit or pin resize.
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
    <SidebarPinContext.Provider
      value={{ pinned, busy, toggle, visible, sidebarId, buttonRef: pinButton, interactions }}
    >
      <div className="flex min-h-0 flex-1 flex-col bg-sidebar">
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
          style={
            {
              '--sidebar-preview-width': `min(${width}px, ${100 - canvasMinPercent}cqi)`,
            } as CSSProperties
          }
        >
          <ResizablePanelGroup className="h-full min-h-0" orientation="horizontal">
            <ResizablePanel
              className="relative"
              collapsedSize="0px"
              collapsible={!pinned}
              data-sidebar-panel=""
              data-preview={!pinned || pinResizePending}
              defaultSize={defaultSize}
              elementRef={sidebarPanel}
              groupResizeBehavior="preserve-pixel-size"
              maxSize={`${maxSidebarWidth}px`}
              minSize={`${minSidebarWidth}px`}
              onResize={(size, _id, previous) => {
                // Constraint updates briefly report the minimum before the saved width is restored.
                if (pinned && !pinResizePending && size.inPixels >= minSidebarWidth) {
                  const nextWidth = normalizeSidebarWidth(size.inPixels);
                  setWidth(nextWidth);
                  if (previous) onWidthChange(nextWidth);
                }
              }}
              panelRef={panelRef}
              style={{ overflow: 'hidden' }}
            >
              <aside
                {...interactions}
                aria-hidden={!visible}
                aria-label="Sidebar"
                className="absolute inset-0 flex flex-col overflow-hidden bg-sidebar"
                data-expanded={visible}
                data-overlay={!pinned}
                data-sidebar-surface=""
                id={sidebarId}
                inert={!visible}
                ref={sidebarSurface}
              >
                <div className="min-h-0 flex-1" data-sidebar-content="">
                  <ContextMenuOverlayProvider onOpenChange={setMenuOpen}>
                    {sidebar}
                  </ContextMenuOverlayProvider>
                </div>
                <div
                  className="relative z-20 mx-3 shrink-0 border-t border-sidebar-border py-2"
                  data-sidebar-navigation=""
                >
                  {navigation}
                </div>
              </aside>
            </ResizablePanel>
            {/* The canvas border is the divider. Center the grip on that border. */}
            <ResizableHandle
              className={
                pinned
                  ? 'z-40 bg-transparent [&>div]:absolute [&>div]:top-1/2 [&>div]:left-[calc(100%+0.5px)] [&>div]:-translate-1/2'
                  : 'hidden'
              }
              disabled={!pinned || pinResizePending}
              withHandle
            />
            <ResizablePanel
              className="min-h-0 rounded-tl-xl border-t border-l border-border bg-background"
              data-workspace-canvas=""
              minSize={`${canvasMinPercent}%`}
              style={{ overflow: 'hidden' }}
            >
              {children}
            </ResizablePanel>
          </ResizablePanelGroup>
        </div>
      </div>
    </SidebarPinContext.Provider>
  );
}
