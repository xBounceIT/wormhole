import type { ProxyConfig, Session } from 'electron';

// A single unusable proxy and no implicit loopback bypass keep Chromium fail-closed.
export const blockedWebTunnelProxy = {
  mode: 'fixed_servers',
  proxyRules: 'socks5://127.0.0.1:0',
  proxyBypassRules: '<-loopback>',
} satisfies ProxyConfig;

export type WebTunnelEndpoint = {
  readonly port: number;
  connect(port: number): Promise<void>;
  disconnect(): Promise<void>;
  close(): Promise<void>;
};

type BrowserProxyState = {
  endpoint?: WebTunnelEndpoint;
  pending: Promise<void>;
  retired: Set<WebTunnelEndpoint>;
};

export class WebTunnelProxy {
  private readonly sessions = new WeakMap<Session, BrowserProxyState>();

  attach(session: Session, endpoint: WebTunnelEndpoint, config: ProxyConfig): Promise<void> {
    let state = this.sessions.get(session);
    if (!state) {
      state = { pending: Promise.resolve(), retired: new Set() };
      this.sessions.set(session, state);
    }
    return this.update(session, state, endpoint, config);
  }

  detach(session: Session, endpoint: WebTunnelEndpoint): Promise<void> {
    const state = this.sessions.get(session);
    if (state?.endpoint !== endpoint) return Promise.resolve();
    return this.update(session, state, undefined, blockedWebTunnelProxy);
  }

  private update(
    session: Session,
    state: BrowserProxyState,
    endpoint: WebTunnelEndpoint | undefined,
    config: ProxyConfig,
  ): Promise<void> {
    const previous = state.endpoint;
    state.endpoint = endpoint;
    // A background page can outlive its browser. Disconnect immediately and keep the old port
    // reserved until Chromium drops the obsolete proxy configuration and cached connections.
    const pending = Promise.all([
      state.pending.catch(() => undefined),
      previous?.disconnect(),
    ]).then(async () => {
      if (previous) state.retired.add(previous);
      await session.setProxy(config);
      if (!state.retired.size) return;
      await session.closeAllConnections();
      for (const retired of state.retired) {
        await retired.close();
        state.retired.delete(retired);
      }
    });
    state.pending = pending;
    return pending;
  }
}

export function parseWebTunnelSocksPort(endpoint: string): number {
  const match = /^127\.0\.0\.1:(\d{1,5})$/.exec(endpoint);
  const port = Number(match?.[1]);
  if (!port || port > 65535) throw new Error('The VPN returned an invalid SOCKS endpoint.');
  return port;
}
