export const tunnelClosedMessage =
  'The connection tunnel closed. The dependent session was disconnected.';

export class TunnelFailureRegistry {
  private readonly callbacks = new Map<string, () => void>();

  watch(leaseId: string, callback?: () => void): void {
    if (callback) this.callbacks.set(leaseId, callback);
  }

  forget(leaseId: string): void {
    this.callbacks.delete(leaseId);
  }

  fail(event: unknown): boolean {
    if (!event || typeof event !== 'object') return false;
    const value = event as Record<string, unknown>;
    if (
      value.type !== 'tunnel.failed' ||
      typeof value.sessionId !== 'string' ||
      !value.sessionId ||
      value.sessionId.length > 128 ||
      /\p{Cc}/u.test(value.sessionId)
    )
      return false;
    const callback = this.callbacks.get(value.sessionId);
    this.callbacks.delete(value.sessionId);
    try {
      callback?.();
    } catch {
      /* Continue processing other lease failures. */
    }
    return true;
  }

  failAll(): void {
    const callbacks = [...this.callbacks.values()];
    this.callbacks.clear();
    for (const callback of callbacks) {
      try {
        callback();
      } catch {
        /* One closed owner must not retain other routes. */
      }
    }
  }
}
