// An explicit Direct choice still belongs to the saved VPN configuration shown in its prompt.
export function assertTunnelRouteUnchanged(
  acquiredTunnelId: unknown,
  resolvedTunnelId: unknown,
): void {
  if (
    typeof acquiredTunnelId !== 'string' ||
    typeof resolvedTunnelId !== 'string' ||
    acquiredTunnelId !== resolvedTunnelId
  ) {
    throw new Error(
      'The VPN route no longer matches this connection. Reconnect to use its current settings.',
    );
  }
}
