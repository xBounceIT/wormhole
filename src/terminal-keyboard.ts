const terminalControlCharacters: Readonly<Record<string, string>> = {
  '@': '\u0000',
  '[': '\u001b',
  '\\': '\u001c',
  ']': '\u001d',
  '^': '\u001e',
  _: '\u001f',
};

export function terminalControlKeyData(key: string): string | undefined {
  if (key === ' ') return '\u0000';
  if (key.length !== 1) return undefined;
  const code = key.toUpperCase().charCodeAt(0);
  if (code >= 65 && code <= 90) return String.fromCharCode(code - 64);
  return terminalControlCharacters[key];
}
