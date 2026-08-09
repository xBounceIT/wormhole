import type { Cookie, CookiesSetDetails } from 'electron';
import { isIP } from 'node:net';

function normalizeCookieDomain(value: string | undefined): string {
  const normalized = (value ?? '').trim().replace(/^\.+/, '').replace(/\.+$/, '').toLowerCase();
  return normalized.startsWith('[') && normalized.endsWith(']')
    ? normalized.slice(1, -1)
    : normalized;
}

export function getBitwardenCookieHosts(targetUrl: string): ReadonlySet<string> {
  const hostname = normalizeCookieDomain(new URL(targetUrl).hostname);
  const hosts = new Set<string>();
  if (!hostname) return hosts;

  hosts.add(hostname);
  if (isIP(hostname) !== 0) return hosts;

  let dotIndex = hostname.indexOf('.');
  while (dotIndex > 0 && dotIndex < hostname.length - 1) {
    const parentDomain = hostname.slice(dotIndex + 1);
    if (!parentDomain.includes('.')) break;
    hosts.add(parentDomain);
    dotIndex = hostname.indexOf('.', dotIndex + 1);
  }
  return hosts;
}

export function selectBitwardenCookiesForTarget(
  cookies: readonly Cookie[],
  targetUrl: string,
): Cookie[] {
  const hosts = getBitwardenCookieHosts(targetUrl);
  return cookies.filter((cookie) => hosts.has(normalizeCookieDomain(cookie.domain)));
}

export function bitwardenCookieIdentity(cookie: Cookie): string {
  return `${normalizeCookieDomain(cookie.domain)}\0${cookie.path || '/'}\0${cookie.name}`;
}

export function buildBitwardenCookieRefreshPlan(
  destinationCookies: readonly Cookie[],
  sourceCookies: readonly Cookie[],
): { set: readonly Cookie[]; remove: readonly Cookie[] } {
  const sourceKeys = new Set(sourceCookies.map(bitwardenCookieIdentity));
  return {
    set: sourceCookies,
    remove: destinationCookies.filter((cookie) => !sourceKeys.has(bitwardenCookieIdentity(cookie))),
  };
}

export function buildBitwardenCookieSetDetails(
  cookie: Cookie,
  targetUrl: string,
): CookiesSetDetails {
  const url = new URL(targetUrl);
  url.pathname = cookie.path?.startsWith('/') ? cookie.path : '/';
  url.search = '';
  url.hash = '';
  const details: CookiesSetDetails = {
    url: url.toString(),
    name: cookie.name,
    value: cookie.value,
    path: cookie.path,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
  };
  if (!cookie.hostOnly && cookie.domain) details.domain = cookie.domain;
  if (!cookie.session && cookie.expirationDate !== undefined) {
    details.expirationDate = cookie.expirationDate;
  }
  return details;
}
