export function mergeTerminalScrollback<T>(
  previous:
    | { columns: number; rows: number; scrollback?: T[]; scrollbackStart?: number }
    | undefined,
  incoming: { columns: number; rows: number; scrollbackReset: boolean; scrollback?: T[] },
  limit: number,
): { scrollback: T[]; scrollbackStart: number } {
  if (
    incoming.scrollbackReset ||
    previous?.columns !== incoming.columns ||
    previous?.rows !== incoming.rows
  ) {
    return { scrollback: incoming.scrollback?.slice(-limit) ?? [], scrollbackStart: 0 };
  }
  const retained = previous.scrollback ?? [];
  const start = previous.scrollbackStart ?? 0;
  if (!incoming.scrollback?.length) return { scrollback: retained, scrollbackStart: start };
  const overflow = Math.max(0, retained.length + incoming.scrollback.length - limit);
  return {
    scrollback: retained.concat(incoming.scrollback).slice(-limit),
    scrollbackStart: start + overflow,
  };
}

export function terminalScrollbackChunks<T>(lines: T[], start: number, size: number) {
  const chunks: { start: number; lines: T[] }[] = [];
  for (let index = 0; index < lines.length;) {
    const length = Math.min(size - ((start + index) % size), lines.length - index);
    chunks.push({ start: start + index, lines: lines.slice(index, index + length) });
    index += length;
  }
  return chunks;
}

export function sameTerminalScrollbackChunk<T>(
  previous: { start: number; lines: T[] },
  incoming: { start: number; lines: T[] },
): boolean {
  return (
    previous.start === incoming.start &&
    previous.lines.length === incoming.lines.length &&
    previous.lines.every((line, index) => line === incoming.lines[index])
  );
}

export function terminalVisibleScrollback<T>(frame: {
  alternateScreen: boolean;
  scrollback?: T[];
}): T[] | undefined {
  return frame.alternateScreen ? undefined : frame.scrollback;
}

export function nextTerminalViewportResetSequence(
  previous: number | undefined,
  incoming: { sequence: number; viewportReset: boolean },
): number | undefined {
  return incoming.viewportReset ? incoming.sequence : previous;
}

export function terminalScrollEventKeepsBottomPin(
  scrollTop: number,
  atBottom: boolean,
  automaticScrollTop: number | undefined,
): boolean {
  if (atBottom) return true;
  return automaticScrollTop !== undefined && Math.abs(scrollTop - automaticScrollTop) <= 1;
}

export function scrollTerminalToBottom(surface: {
  scrollHeight: number;
  clientHeight: number;
  scrollTop: number;
}): number {
  surface.scrollTop = Math.max(0, surface.scrollHeight - surface.clientHeight);
  // Chromium can clamp or round the requested offset. Track the applied position.
  return surface.scrollTop;
}
