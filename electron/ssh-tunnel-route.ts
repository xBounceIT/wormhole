export type SshTunnelRoute = Readonly<{
  nodeId: string;
  socksEndpoint: string;
}>;

/** Keeps the established route available across the host-key trust boundary. */
export class SshTunnelRouteRegistry {
  private readonly routes = new Map<string, SshTunnelRoute>();

  remember(sessionId: string, nodeId: string, socksEndpoint: string): void {
    this.routes.set(sessionId, { nodeId, socksEndpoint });
  }

  retained(sessionId: string, nodeId: string): SshTunnelRoute | undefined {
    const route = this.routes.get(sessionId);
    return route?.nodeId === nodeId ? route : undefined;
  }

  sessionIds(): string[] {
    return [...this.routes.keys()];
  }

  forget(sessionId: string): void {
    this.routes.delete(sessionId);
  }

  clear(): void {
    this.routes.clear();
  }
}

export function isSshHostKeyMismatch(
  expected: string | undefined,
  received: string | undefined,
): boolean {
  return Boolean(expected && received && expected !== received);
}
