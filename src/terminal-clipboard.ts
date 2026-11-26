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
  copyChordActive = false,
): boolean {
  const key = event.key.toLowerCase();
  if (copyChordActive && key === 'c') return true;
  if (event.altKey || (!event.ctrlKey && !event.metaKey)) return false;
  if (key === 'v') return true;
  return key === 'c' && hasSelection;
}

export function terminalCopyChordAfterKeyDown(
  event: TerminalClipboardKeyEvent,
  hasSelection: boolean,
  copyChordActive: boolean,
): boolean {
  if (copyChordActive) return true;
  return (
    event.key.toLowerCase() === 'c' &&
    !event.altKey &&
    (event.ctrlKey || event.metaKey) &&
    hasSelection
  );
}

export function terminalCopyChordAfterKeyUp(
  event: Pick<TerminalClipboardKeyEvent, 'key'>,
  copyChordActive: boolean,
): boolean {
  return copyChordActive && event.key.toLowerCase() !== 'c';
}

export function copyTerminalSelection(
  text: string,
  clipboardData: Pick<DataTransfer, 'setData'>,
): boolean {
  if (!text) return false;
  clipboardData.setData('text/plain', text);
  return true;
}

export function shouldAutoCopyTerminalSelection(enabled: boolean, mouseButton: number): boolean {
  return enabled && mouseButton === 0;
}
