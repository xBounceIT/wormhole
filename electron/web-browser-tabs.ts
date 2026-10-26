import type { ClientRequest } from 'electron';

export const webBrowserTabLimit = 32;
export const webBrowserUrlLimit = 8192;
export const webBrowserFaviconByteLimit = 65_536;
export const webBrowserFaviconUrlLimit = Math.ceil(webBrowserFaviconByteLimit / 3) * 4 + 64;

const webBrowserFaviconTypes = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/x-icon',
  'image/vnd.microsoft.icon',
  'image/svg+xml',
  'image/avif',
  'image/bmp',
]);

export function isWebBrowserFavicon(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > webBrowserFaviconUrlLimit) return false;
  const match = /^data:([^;,]+);base64,([a-z\d+/]+={0,2})$/i.exec(value);
  return !!match && webBrowserFaviconTypes.has(match[1]);
}

/** Only bounded image bytes cross into the workspace; remote URLs stay in their browser session. */
export async function readWebBrowserFavicon(response: Response): Promise<string | undefined> {
  const mime = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();
  if (
    !response.ok ||
    !mime ||
    !webBrowserFaviconTypes.has(mime) ||
    Number(response.headers.get('content-length')) > webBrowserFaviconByteLimit ||
    !response.body
  ) {
    await response.body?.cancel();
    return undefined;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > webBrowserFaviconByteLimit) return undefined;
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return size ? `data:${mime};base64,${Buffer.concat(chunks).toString('base64')}` : undefined;
}

type WebBrowserFaviconClient = {
  fetchData: (url: string, signal: AbortSignal) => Promise<Response>;
  request: (url: string, pageOrigin: string) => ClientRequest;
};

/** A native request has no page initiator: never lend another origin its authenticated cookies. */
export async function fetchWebBrowserFavicon(
  client: WebBrowserFaviconClient,
  pageUrl: string,
  sourceUrl: string,
  routeUrl: (url: string) => string | undefined,
  signal: AbortSignal,
): Promise<string | undefined> {
  if (signal.aborted || sourceUrl.length > webBrowserFaviconUrlLimit) return;
  if (sourceUrl.startsWith('data:image/')) {
    return readWebBrowserFavicon(await client.fetchData(sourceUrl, signal));
  }
  const pageOrigin = new URL(pageUrl).origin;
  const url = routeUrl(sourceUrl);
  if (!url || !['http:', 'https:'].includes(new URL(url).protocol)) return;
  return new Promise<string | undefined>((resolve) => {
    const request = client.request(url, pageOrigin);
    let settled = false;
    const abort = () => finish();
    const finish = (value?: string) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', abort);
      resolve(value);
      request.abort();
    };
    request.once('response', (response) => {
      if (settled) return;
      const header = (name: string) => {
        const value = response.headers[name];
        return Array.isArray(value) ? value[0] : value;
      };
      const mime = header('content-type')?.split(';')[0].trim().toLowerCase();
      if (
        response.statusCode < 200 ||
        response.statusCode >= 300 ||
        !mime ||
        !webBrowserFaviconTypes.has(mime) ||
        Number(header('content-length')) > webBrowserFaviconByteLimit
      ) {
        finish();
        return;
      }
      const chunks: Uint8Array[] = [];
      let size = 0;
      response.on('data', (chunk) => {
        if (settled) return;
        size += chunk.byteLength;
        if (size > webBrowserFaviconByteLimit) finish();
        else chunks.push(chunk);
      });
      response.once('end', () =>
        finish(
          size ? `data:${mime};base64,${Buffer.concat(chunks).toString('base64')}` : undefined,
        ),
      );
      response.on('error', () => finish());
      response.once('aborted', () => finish());
    });
    request.on('error', () => finish());
    request.once('abort', () => finish());
    // Electron's writable stream may close after end(), before the response arrives.
    // Response completion/errors or the caller's deadline own request cleanup.
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) finish();
    else request.end();
  });
}

export function isAbortedWebNavigation(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const failure = error as { code?: unknown; errno?: unknown };
  return failure.code === 'ERR_ABORTED' || failure.errno === -3;
}

export type WebBrowserTabState = {
  id: string;
  title: string;
  url: string;
  isLoading: boolean;
  canGoBack: boolean;
  canGoForward: boolean;
  error?: string;
  favicon?: string;
};

export type WebBrowserState = {
  activeTabId: string;
  tabs: WebBrowserTabState[];
  route: 'direct' | 'vpn';
  tunnel?: { name: string; kind: string };
  restrictedOrigin?: string;
};

export type WebBrowserCommand = {
  sessionId: string;
  operation:
    | 'back'
    | 'forward'
    | 'reload'
    | 'stop'
    | 'zoom-in'
    | 'zoom-out'
    | 'new-tab'
    | 'close-tab'
    | 'select-tab'
    | 'navigate';
  tabId?: string;
  url?: string;
};

/** The native browser owns tab identity, selection and bounded public metadata. */
export class WebBrowserTabs<T> {
  private readonly entries = new Map<string, { surface: T; state: WebBrowserTabState }>();
  private selectedId = '';

  get activeId(): string {
    return this.selectedId;
  }

  get size(): number {
    return this.entries.size;
  }

  get(id = this.selectedId): T | undefined {
    return this.entries.get(id)?.surface;
  }

  all(): T[] {
    return [...this.entries.values()].map((entry) => entry.surface);
  }

  add(id: string, surface: T, url: string): void {
    if (!id || this.entries.has(id) || this.size >= webBrowserTabLimit) {
      throw new Error(`A browser can open up to ${webBrowserTabLimit} tabs.`);
    }
    this.entries.set(id, {
      surface,
      state: {
        id,
        title: url === 'about:blank' ? 'New tab' : 'Loading…',
        url: url.slice(0, webBrowserUrlLimit),
        isLoading: url !== 'about:blank',
        canGoBack: false,
        canGoForward: false,
      },
    });
    this.selectedId = id;
  }

  select(id: string): boolean {
    if (!this.entries.has(id)) return false;
    this.selectedId = id;
    return true;
  }

  adjacent(offset: number): string {
    const ids = [...this.entries.keys()];
    if (ids.length === 0) return '';
    return ids[(ids.indexOf(this.selectedId) + offset + ids.length) % ids.length];
  }

  update(id: string, values: Partial<Omit<WebBrowserTabState, 'id'>>): void {
    const entry = this.entries.get(id);
    if (!entry) return;
    entry.state = { ...entry.state, ...values };
    entry.state.url = entry.state.url.slice(0, webBrowserUrlLimit);
    entry.state.title = entry.state.title.slice(0, 256);
    entry.state.error = entry.state.error?.slice(0, 2048);
    if (!isWebBrowserFavicon(entry.state.favicon)) entry.state.favicon = undefined;
  }

  remove(id: string): T | undefined {
    if (this.size <= 1) return undefined;
    const entry = this.entries.get(id);
    if (!entry) return undefined;
    const ids = [...this.entries.keys()];
    const index = ids.indexOf(id);
    this.entries.delete(id);
    if (this.selectedId === id) this.selectedId = ids[index + 1] ?? ids[index - 1];
    return entry.surface;
  }

  snapshot(
    route: WebBrowserState['route'],
    restrictedOrigin?: string,
    tunnel?: WebBrowserState['tunnel'],
  ): WebBrowserState {
    return {
      activeTabId: this.selectedId,
      tabs: [...this.entries.values()].map(({ state }) => ({ ...state })),
      route,
      restrictedOrigin,
      tunnel: route === 'vpn' ? tunnel : undefined,
    };
  }
}

export function isWebBrowserCommand(value: unknown): value is WebBrowserCommand {
  if (!value || typeof value !== 'object') return false;
  const request = value as Record<string, unknown>;
  if (typeof request.sessionId !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(request.sessionId)) {
    return false;
  }
  if (request.operation === 'select-tab' || request.operation === 'close-tab') {
    return typeof request.tabId === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(request.tabId);
  }
  if (request.operation === 'navigate') {
    return (
      typeof request.url === 'string' &&
      request.url.length > 0 &&
      request.url.length <= webBrowserUrlLimit
    );
  }
  return (
    typeof request.operation === 'string' &&
    ['back', 'forward', 'reload', 'stop', 'zoom-in', 'zoom-out', 'new-tab'].includes(
      request.operation,
    )
  );
}

/** WebSocket handshakes use the same transport and endpoint as their HTTP(S) origin. */
export function isWebBrowserRouteRequestAllowed(value: string, routedOrigin: string): boolean {
  try {
    const target = new URL(value);
    if (target.protocol === 'ws:') target.protocol = 'http:';
    if (target.protocol === 'wss:') target.protocol = 'https:';
    return !['http:', 'https:'].includes(target.protocol) || target.origin === routedOrigin;
  } catch {
    return false;
  }
}

/** Address entry accepts web URLs only; credentials stay outside renderer/browser commands. */
export function resolveWebBrowserAddress(value: string): string | undefined {
  const address = value.trim();
  if (!address || address.length > webBrowserUrlLimit || /[\s\p{Cc}]/u.test(address))
    return undefined;
  try {
    const candidate =
      /^[a-z][a-z\d+.-]*:\/\//i.test(address) ||
      /^(?:about|file|javascript|data|chrome):/i.test(address)
        ? address
        : `https://${address}`;
    const url = new URL(candidate);
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      !url.hostname ||
      url.username ||
      url.password
    )
      return undefined;
    return url.toString();
  } catch {
    return undefined;
  }
}
