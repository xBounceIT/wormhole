export type TerminalClipboardKeyEvent = {
  key: string;
  ctrlKey: boolean;
  metaKey: boolean;
  altKey: boolean;
};

export function normalizeTerminalPasteText(text: string): string {
  return text.replace(/\r?\n/g, '\r');
}

export function shouldUseTerminalClipboardShortcut(
  event: TerminalClipboardKeyEvent,
  hasSelection: boolean,
): boolean {
  if (event.altKey || (!event.ctrlKey && !event.metaKey)) return false;
  const key = event.key.toLowerCase();
  if (key === 'v') return true;
  return key === 'c' && hasSelection;
}

export function shouldAutoCopyTerminalSelection(enabled: boolean, mouseButton: number): boolean {
  return enabled && mouseButton === 0;
}
