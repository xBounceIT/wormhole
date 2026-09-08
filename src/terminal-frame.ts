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
