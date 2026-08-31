export function terminalVisibleScrollback<T>(frame: {
  alternateScreen: boolean;
  scrollback?: T[];
}): T[] | undefined {
  return frame.alternateScreen ? undefined : frame.scrollback;
}
