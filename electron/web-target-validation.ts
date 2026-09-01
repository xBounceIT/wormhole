type WebTargetEndpoint = {
  protocol: 'http' | 'https';
  host: string;
  port: number;
};

function canonicalWebTargetHostname(hostname: string): string | undefined {
  let value = hostname.toLowerCase();
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  if (!value || /[\\/?#@%]/.test(value) || /[\s\p{Cc}]/u.test(value)) {
    return undefined;
  }
  try {
    const parsed = new URL(`http://${value.includes(':') ? `[${value}]` : value}/`);
    const canonical = parsed.hostname.toLowerCase();
    if (canonical.startsWith('[') && canonical.endsWith(']')) return canonical.slice(1, -1);
    return canonical.endsWith('.') ? canonical.slice(0, -1) : canonical;
  } catch {
    return undefined;
  }
}

export function webTargetURLMatchesEndpoint(targetUrl: URL, endpoint: WebTargetEndpoint): boolean {
  const effectivePort =
    targetUrl.port === '' ? (targetUrl.protocol === 'https:' ? 443 : 80) : Number(targetUrl.port);
  return (
    targetUrl.protocol === `${endpoint.protocol}:` &&
    canonicalWebTargetHostname(targetUrl.hostname) === canonicalWebTargetHostname(endpoint.host) &&
    effectivePort === endpoint.port &&
    !targetUrl.username &&
    !targetUrl.password
  );
}
