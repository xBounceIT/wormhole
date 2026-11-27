export async function writeClipboardText(
  value: string,
  writeText: ((value: string) => Promise<void>) | undefined,
  fallback: () => boolean,
): Promise<void> {
  if (writeText) {
    try {
      await writeText(value);
      return;
    } catch {
      // Chromium can expose the async clipboard API while denying a particular write.
    }
  }
  if (!fallback()) throw new Error('Clipboard access is unavailable.');
}

export async function copyTextToClipboard(value: string): Promise<void> {
  const asyncWrite = navigator.clipboard?.writeText.bind(navigator.clipboard);
  await writeClipboardText(value, asyncWrite, () => {
    const activeElement =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const selection = document.getSelection();
    const ranges = selection
      ? Array.from({ length: selection.rangeCount }, (_, index) =>
          selection.getRangeAt(index).cloneRange(),
        )
      : [];
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    try {
      textarea.select();
      return document.execCommand('copy');
    } finally {
      textarea.remove();
      activeElement?.focus({ preventScroll: true });
      if (selection && ranges.length > 0) {
        selection.removeAllRanges();
        for (const range of ranges) selection.addRange(range);
      }
    }
  });
}
