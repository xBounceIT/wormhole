const sshInputMaxBytes = 1024 * 1024;
const sshInputMaxEncodedLength = Math.ceil(sshInputMaxBytes / 3) * 4;
const canonicalBase64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function normalizeTerminalPasteText(text: string): string {
  return text.replace(/\r?\n/g, '\r');
}

export function isEncodedSshInput(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length > sshInputMaxEncodedLength ||
    !canonicalBase64Pattern.test(value)
  ) {
    return false;
  }
  return Buffer.byteLength(value, 'base64') <= sshInputMaxBytes;
}

export function encodeTerminalClipboardText(text: string): string | undefined {
  if (!text) return undefined;
  const data = Buffer.from(normalizeTerminalPasteText(text), 'utf8');
  if (data.byteLength > sshInputMaxBytes) {
    throw new Error('Clipboard text is too large to paste.');
  }
  return data.toString('base64');
}
