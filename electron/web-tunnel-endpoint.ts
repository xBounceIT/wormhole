import { createConnection, createServer, type AddressInfo, type Socket } from 'node:net';
import type { ProxyConfig, Session } from 'electron';

// A single unusable proxy and no implicit loopback bypass keep Chromium fail-closed.
export const blockedWebTunnelProxy = {
  mode: 'fixed_servers',
  proxyRules: 'socks5://127.0.0.1:0',
  proxyBypassRules: '<-loopback>',
} satisfies ProxyConfig;

// Chromium keeps this loopback address for the browser's lifetime. In particular, changing the
// address of a TCP forwarder would change the page origin, including its storage and history.
export class WebTunnelEndpoint {
  private upstreamPort?: number;
  private readonly sockets = new Set<Socket>();
  private readonly server = createServer({ allowHalfOpen: true }, (client) => {
    if (this.upstreamPort === undefined) {
      client.destroy();
      return;
    }
    const upstream = createConnection({
      host: '127.0.0.1',
      port: this.upstreamPort,
      allowHalfOpen: true,
    });
    for (const [socket, peer] of [
      [client, upstream],
      [upstream, client],
    ]) {
      this.sockets.add(socket);
      socket.once('close', () => this.sockets.delete(socket));
      socket.on('error', () => peer.destroy());
      socket.pipe(peer);
    }
  });

  private constructor() {}

  static async listen(): Promise<WebTunnelEndpoint> {
    const endpoint = new WebTunnelEndpoint();
    await new Promise<void>((resolve, reject) => {
      endpoint.server.once('error', reject);
      endpoint.server.listen(0, '127.0.0.1', () => {
        endpoint.server.off('error', reject);
        endpoint.server.unref();
        resolve();
      });
    });
    return endpoint;
  }

  get port(): number {
    return (this.server.address() as AddressInfo).port;
  }

  connect(port: number): void {
    this.upstreamPort = port;
  }

  disconnect(): void {
    this.upstreamPort = undefined;
    for (const socket of this.sockets) socket.destroy();
  }

  close(): void {
    this.disconnect();
    this.server.close();
  }
}

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
    previous?.disconnect();
    const pending = state.pending
      .catch(() => undefined)
      .then(async () => {
        if (previous) state.retired.add(previous);
        await session.setProxy(config);
        if (!state.retired.size) return;
        await session.closeAllConnections();
        for (const retired of state.retired) retired.close();
        state.retired.clear();
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
