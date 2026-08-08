import { useCallback, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';

import { ScrollArea } from '@/components/ui/scroll-area';
import {
  virtualGridColumnCount,
  virtualGridHeight,
  virtualGridRange,
  virtualGridScrollAnchor,
} from '../virtual-grid';

type VirtualCardGridProps<T> = {
  items: readonly T[];
  getKey: (item: T) => string;
  renderItem: (item: T) => ReactNode;
  minimumColumnWidth: number;
  rowHeight: number;
  gap: number;
  ariaLabel: string;
  className?: string;
  bottomPadding?: number;
  endPadding?: number;
  overscanRows?: number;
  resetKey?: string;
};

type VirtualGridViewport = {
  width: number;
  height: number;
  scrollTop: number;
};

export function VirtualCardGrid<T>({
  items,
  getKey,
  renderItem,
  minimumColumnWidth,
  rowHeight,
  gap,
  ariaLabel,
  className,
  bottomPadding = 0,
  endPadding = 0,
  overscanRows = 2,
  resetKey,
}: VirtualCardGridProps<T>) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const viewportStateRef = useRef<VirtualGridViewport>({ width: 0, height: 0, scrollTop: 0 });
  const [viewportState, setViewportState] = useState(viewportStateRef.current);

  const syncViewport = useCallback(
    (viewport: HTMLDivElement) => {
      const next = {
        width: viewport.clientWidth,
        height: viewport.clientHeight,
        scrollTop: virtualGridScrollAnchor(viewport.scrollTop, rowHeight, gap),
      };
      const current = viewportStateRef.current;
      if (
        current.width === next.width &&
        current.height === next.height &&
        current.scrollTop === next.scrollTop
      ) {
        return;
      }
      viewportStateRef.current = next;
      setViewportState(next);
    },
    [gap, rowHeight],
  );

  useLayoutEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    const sync = () => syncViewport(viewport);
    sync();
    const observer = new ResizeObserver(sync);
    observer.observe(viewport);
    return () => observer.disconnect();
  }, [syncViewport]);

  useLayoutEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    viewport.scrollTop = 0;
    syncViewport(viewport);
  }, [resetKey, syncViewport]);

  const availableWidth = Math.max(0, viewportState.width - endPadding);
  const columnCount = virtualGridColumnCount(availableWidth, minimumColumnWidth, gap);
  const contentHeight = virtualGridHeight(items.length, columnCount, rowHeight, gap);
  const range = virtualGridRange(
    items.length,
    columnCount,
    viewportState.scrollTop,
    viewportState.height,
    rowHeight,
    gap,
    overscanRows,
  );
  const visibleItems = useMemo(
    () => items.slice(range.startIndex, range.endIndex),
    [items, range.endIndex, range.startIndex],
  );

  useLayoutEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    const maximumScrollTop = Math.max(0, contentHeight + bottomPadding - viewport.clientHeight);
    if (viewport.scrollTop <= maximumScrollTop) return;
    viewport.scrollTop = maximumScrollTop;
    syncViewport(viewport);
  }, [bottomPadding, contentHeight, syncViewport]);

  return (
    <ScrollArea
      aria-label={ariaLabel}
      className={className}
      onViewportScroll={(event) => syncViewport(event.currentTarget)}
      role="list"
      viewportRef={viewportRef}
    >
      <div className="relative" style={{ height: contentHeight + bottomPadding }}>
        <div
          className="absolute left-0 top-0 grid"
          style={{
            right: endPadding,
            gap,
            gridAutoRows: rowHeight,
            gridTemplateColumns: `repeat(${columnCount}, minmax(0, 1fr))`,
            transform: `translateY(${range.startRow * (rowHeight + gap)}px)`,
            willChange: 'transform',
          }}
        >
          {visibleItems.map((item, offset) => {
            const itemIndex = range.startIndex + offset;
            return (
              <div
                aria-posinset={itemIndex + 1}
                aria-setsize={items.length}
                className="min-w-0"
                key={getKey(item)}
                role="listitem"
              >
                {renderItem(item)}
              </div>
            );
          })}
        </div>
      </div>
    </ScrollArea>
  );
}
