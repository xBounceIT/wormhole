/**
 * Invalidates asynchronous browser open work when a tab is closed or retried.
 *
 * The renderer and the native surface manager each keep an instance: they have
 * different lifecycles, but both need the same last-request-wins guarantee.
 */
export class WebSessionAttemptTracker {
  private readonly generations = new Map<string, number>();
  private sequence = 0;

  begin(sessionId: string): number {
    const generation = ++this.sequence;
    this.generations.set(sessionId, generation);
    return generation;
  }

  cancel(sessionId: string): void {
    this.generations.delete(sessionId);
  }

  cancelAll(): void {
    this.generations.clear();
  }

  isCurrent(sessionId: string, generation: number): boolean {
    return this.generations.get(sessionId) === generation;
  }
}
