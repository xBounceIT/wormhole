import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';
import { Popover } from 'radix-ui';

import { isWormholeShortcutSuppressed } from '@/app-shortcuts';
import { SearchField } from '@/components/SearchField';
import { Button } from '@/components/ui/button';
import { useNativeSurfaceOverlay } from '@/components/ui/context-menu';
import { Kbd } from '@/components/ui/kbd';
import { TextTooltip, Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { normalizeListSearch } from '@/list-search';

export function SessionTabSearch<T extends { id: string; title: string }>({
  tabs,
  activeTabId,
  onSelect,
  renderIcon,
}: {
  tabs: readonly T[];
  activeTabId?: string;
  onSelect: (id: string) => boolean;
  renderIcon: (tab: T) => ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [tooltipOpen, setTooltipOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [highlight, setHighlight] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const highlightedOption = useRef<HTMLDivElement>(null);
  const selectedTab = useRef<string | null>(null);
  const headingId = useId();
  const listId = useId();
  const normalizedQuery = open ? normalizeListSearch(query) : '';
  const matches = normalizedQuery
    ? tabs.filter(({ title }) => title.toLowerCase().includes(normalizedQuery))
    : tabs;
  const highlightedIndex = Math.min(highlight, matches.length - 1);
  const highlightedId = matches[highlightedIndex]?.id;
  useNativeSurfaceOverlay(open);

  function changeQuery(next: string) {
    setQuery(next);
    setHighlight(0);
  }

  function changeOpen(next: boolean) {
    if (next) {
      setTooltipOpen(false);
      changeQuery('');
    }
    setOpen(next);
  }

  useEffect(() => {
    function handleShortcut(event: KeyboardEvent) {
      if (
        event.defaultPrevented ||
        event.repeat ||
        event.isComposing ||
        event.altKey ||
        !event.shiftKey ||
        !(event.ctrlKey || event.metaKey) ||
        event.key.toLowerCase() !== 'a' ||
        isWormholeShortcutSuppressed(event)
      ) {
        return;
      }
      if (!open && document.querySelector('[role="dialog"], [role="alertdialog"], [role="menu"]')) {
        return;
      }
      event.preventDefault();
      changeOpen(!open);
    }
    window.addEventListener('keydown', handleShortcut);
    return () => window.removeEventListener('keydown', handleShortcut);
  }, [open]);

  useLayoutEffect(() => {
    if (open) highlightedOption.current?.scrollIntoView({ block: 'nearest' });
  }, [highlightedId, open, query]);

  function choose(id: string) {
    selectedTab.current = id;
    changeOpen(false);
  }

  return (
    <Popover.Root open={open} onOpenChange={changeOpen}>
      <Tooltip
        disableHoverableContent
        open={!open && tooltipOpen}
        onOpenChange={(next) => setTooltipOpen(!open && next)}
      >
        <Popover.Trigger asChild>
          <TooltipTrigger asChild>
            <Button
              aria-keyshortcuts="Control+Shift+A Meta+Shift+A"
              aria-label="Search open tabs"
              className="size-[30px] rounded-full text-muted-foreground data-active:selected-surface"
              data-active={open}
              size="icon-sm"
              type="button"
              variant="ghost"
            >
              <ChevronDown />
            </Button>
          </TooltipTrigger>
        </Popover.Trigger>
        <TooltipContent className="pointer-events-none" side="right" sideOffset={4}>
          Search open tabs
        </TooltipContent>
      </Tooltip>
      <Popover.Portal>
        <Popover.Content
          align="start"
          aria-labelledby={headingId}
          className="z-50 w-[min(330px,var(--radix-popover-content-available-width))] rounded-xl border border-border bg-popover p-2.5 text-xs text-popover-foreground shadow-xl"
          collisionPadding={8}
          data-session-tab-search=""
          data-slot="popover-content"
          onCloseAutoFocus={(event) => {
            const id = selectedTab.current;
            selectedTab.current = null;
            if (id && onSelect(id)) event.preventDefault();
          }}
          onOpenAutoFocus={(event) => {
            event.preventDefault();
            input.current?.focus();
          }}
          onEscapeKeyDown={(event) => {
            if (event.isComposing) event.preventDefault();
          }}
          sideOffset={13}
        >
          <div className="mb-2 flex items-center justify-between px-0.5 text-muted-foreground">
            <span className="font-medium" id={headingId}>
              Search open tabs
            </span>
            <Kbd className="h-5 rounded-sm border border-border bg-transparent text-[10px]">
              Esc
            </Kbd>
          </div>
          <SearchField
            aria-activedescendant={
              highlightedIndex >= 0 ? `${listId}-${highlightedIndex}` : undefined
            }
            aria-autocomplete="list"
            aria-controls={listId}
            aria-expanded="true"
            aria-label="Search open tabs by title"
            autoComplete="off"
            clearLabel="Clear tab search"
            onChange={(event) => changeQuery(event.target.value)}
            onClear={() => changeQuery('')}
            onKeyDown={(event) => {
              if (event.nativeEvent.isComposing || matches.length === 0) return;
              if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                event.preventDefault();
                const step = event.key === 'ArrowDown' ? 1 : -1;
                setHighlight((highlightedIndex + step + matches.length) % matches.length);
              } else if (event.key === 'Enter' && highlightedId) {
                event.preventDefault();
                choose(highlightedId);
              }
            }}
            placeholder="Search by title..."
            ref={input}
            role="combobox"
            value={query}
          />
          <div
            aria-label="Open tabs"
            className="mt-2 max-h-[min(240px,max(2rem,calc(var(--radix-popover-content-available-height)-5.5rem)))] overflow-auto"
            id={listId}
            role="listbox"
          >
            {matches.map((tab, index) => (
              <div
                aria-selected={index === highlightedIndex}
                className="flex h-9 cursor-pointer items-center gap-2 rounded-lg px-2 hover:bg-accent/70 aria-selected:selected-surface"
                id={`${listId}-${index}`}
                key={tab.id}
                onClick={() => choose(tab.id)}
                onPointerDown={(event) => event.preventDefault()}
                ref={index === highlightedIndex ? highlightedOption : undefined}
                role="option"
              >
                <span aria-hidden="true" className="shrink-0 text-muted-foreground">
                  {renderIcon(tab)}
                </span>
                <TextTooltip text={tab.title}>
                  <span className="min-w-0 flex-1 truncate">{tab.title}</span>
                </TextTooltip>
                {tab.id === activeTabId ? (
                  <span className="text-[10px] text-muted-foreground">Active</span>
                ) : null}
              </div>
            ))}
          </div>
          {matches.length === 0 ? (
            <p className="px-2 py-2 text-muted-foreground" role="status">
              {tabs.length === 0 ? 'No open tabs' : 'No matching tabs'}
            </p>
          ) : null}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
