export type VirtualGridRange = {
  startRow: number;
  endRow: number;
  startIndex: number;
  endIndex: number;
  totalRows: number;
};

export function virtualGridColumnCount(
  viewportWidth: number,
  minimumColumnWidth: number,
  gap: number,
): number {
  const safeWidth = Math.max(0, viewportWidth);
  const safeMinimum = Math.max(1, minimumColumnWidth);
  const safeGap = Math.max(0, gap);
  return Math.max(1, Math.floor((safeWidth + safeGap) / (safeMinimum + safeGap)));
}

export function virtualGridScrollAnchor(scrollTop: number, rowHeight: number, gap: number): number {
  const stride = Math.max(1, rowHeight + Math.max(0, gap));
  return Math.floor(Math.max(0, scrollTop) / stride) * stride;
}

export function virtualGridHeight(
  itemCount: number,
  columnCount: number,
  rowHeight: number,
  gap: number,
): number {
  const safeCount = Math.max(0, Math.floor(itemCount));
  const safeColumns = Math.max(1, Math.floor(columnCount));
  const totalRows = Math.ceil(safeCount / safeColumns);
  if (totalRows === 0) return 0;
  return totalRows * Math.max(1, rowHeight) + (totalRows - 1) * Math.max(0, gap);
}

export function virtualGridRange(
  itemCount: number,
  columnCount: number,
  scrollTop: number,
  viewportHeight: number,
  rowHeight: number,
  gap: number,
  overscanRows = 2,
): VirtualGridRange {
  const safeCount = Math.max(0, Math.floor(itemCount));
  const safeColumns = Math.max(1, Math.floor(columnCount));
  const totalRows = Math.ceil(safeCount / safeColumns);
  if (totalRows === 0) {
    return { startRow: 0, endRow: 0, startIndex: 0, endIndex: 0, totalRows: 0 };
  }

  const safeRowHeight = Math.max(1, rowHeight);
  const safeGap = Math.max(0, gap);
  const stride = safeRowHeight + safeGap;
  const safeScrollTop = Math.max(0, scrollTop);
  const firstVisibleRow = Math.min(totalRows - 1, Math.floor(safeScrollTop / stride));
  const offsetWithinRow = safeScrollTop - firstVisibleRow * stride;
  const visibleRows = Math.max(
    1,
    Math.ceil((offsetWithinRow + Math.max(0, viewportHeight)) / stride),
  );
  const overscan = Math.max(0, Math.floor(overscanRows));
  const startRow = Math.max(0, firstVisibleRow - overscan);
  const endRow = Math.min(totalRows, firstVisibleRow + visibleRows + overscan);

  return {
    startRow,
    endRow,
    startIndex: startRow * safeColumns,
    endIndex: Math.min(safeCount, endRow * safeColumns),
    totalRows,
  };
}
