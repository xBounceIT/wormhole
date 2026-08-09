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
