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

export function copyAndClearTerminalSelection(
  text: string,
  clipboardData: Pick<DataTransfer, 'setData'>,
  clearSelection: () => void,
): boolean {
  if (!text) return false;
  clipboardData.setData('text/plain', text);
  clearSelection();
  return true;
}

type TerminalSelectionIdentity = Pick<
  Selection,
  'anchorNode' | 'anchorOffset' | 'focusNode' | 'focusOffset'
>;

export function clearTerminalSelectionIfUnchanged(
  currentSelection: (TerminalSelectionIdentity & Pick<Selection, 'removeAllRanges'>) | undefined,
  copiedSelection: TerminalSelectionIdentity,
): boolean {
  if (!currentSelection) return false;
  const sameDirection =
    currentSelection.anchorNode === copiedSelection.anchorNode &&
    currentSelection.anchorOffset === copiedSelection.anchorOffset &&
    currentSelection.focusNode === copiedSelection.focusNode &&
    currentSelection.focusOffset === copiedSelection.focusOffset;
  const reversedDirection =
    currentSelection.anchorNode === copiedSelection.focusNode &&
    currentSelection.anchorOffset === copiedSelection.focusOffset &&
    currentSelection.focusNode === copiedSelection.anchorNode &&
    currentSelection.focusOffset === copiedSelection.anchorOffset;
  if (!sameDirection && !reversedDirection) return false;
  currentSelection.removeAllRanges();
  return true;
}

export function shouldAutoCopyTerminalSelection(enabled: boolean, mouseButton: number): boolean {
  return enabled && mouseButton === 0;
}
