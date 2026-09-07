const sshInputMaxBytes = 1024 * 1024;
// CRLF clipboard input can be twice as large before Go normalizes it.
const sshPasteMaxBytes = 2 * sshInputMaxBytes;
const canonicalBase64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function isEncodedSshInput(value: unknown, paste = false): value is string {
  const maxBytes = paste ? sshPasteMaxBytes : sshInputMaxBytes;
  if (
    typeof value !== 'string' ||
    value.length > Math.ceil(maxBytes / 3) * 4 ||
    !canonicalBase64Pattern.test(value)
  ) {
    return false;
  }
  return Buffer.byteLength(value, 'base64') <= maxBytes;
}

export function encodeTerminalClipboardText(text: string): string | undefined {
  if (!text) return undefined;
  const data = Buffer.from(text, 'utf8');
  if (data.byteLength > sshPasteMaxBytes) {
    throw new Error('Clipboard text is too large to paste.');
  }
  return data.toString('base64');
}
