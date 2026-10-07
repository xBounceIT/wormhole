export function parseTerminalLink(value: unknown): string {
  if (typeof value !== 'string' || value.length > 8192 || /[\s\p{Cc}]/u.test(value))
    throw new Error('The terminal link is invalid.');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('The terminal link is invalid.');
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.href.length > 8192
  )
    throw new Error('The terminal link is invalid.');
  return url.href;
}
