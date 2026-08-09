const aboutBlank = 'about:blank';

/**
 * Maps a browser new-window request back into its existing session. Forwarder-backed sessions may
 * only follow the original appliance origin, which is rewritten through the loopback endpoint;
 * allowing any other host here would silently bypass the selected tunnel route.
 */
export function getInSessionNavigationUrl(
  rawUrl: string | undefined,
  routedBaseUrl?: string,
  originalBaseUrl?: string,
): string | undefined {
  const candidate = rawUrl?.trim();
  if (!candidate || isAboutBlank(candidate)) return undefined;
  if (!routedBaseUrl || !originalBaseUrl) return candidate;

  let target: URL;
  let routedBase: URL;
  let originalBase: URL;
  try {
    target = new URL(candidate);
    routedBase = new URL(routedBaseUrl);
    originalBase = new URL(originalBaseUrl);
  } catch {
    return undefined;
  }
  if (target.origin === routedBase.origin) return candidate;
  if (target.origin !== originalBase.origin) return undefined;

  target.protocol = routedBase.protocol;
  target.hostname = routedBase.hostname;
  target.port = routedBase.port;
  return target.toString();
}

function isAboutBlank(url: string): boolean {
  if (!url.toLowerCase().startsWith(aboutBlank)) return false;
  return (
    url.length === aboutBlank.length ||
    url[aboutBlank.length] === '?' ||
    url[aboutBlank.length] === '#'
  );
}
