/**
 * Invalidates asynchronous browser open work when a tab is closed or retried.
 *
 * The renderer and the native surface manager each keep an instance: they have
 * different lifecycles, but both need the same last-request-wins guarantee.
 */
export class WebSessionAttemptTracker {
  private readonly generations = new Map<string, number>();

  begin(sessionId: string): number {
    return this.advance(sessionId);
  }

  cancel(sessionId: string): void {
    this.advance(sessionId);
  }

  isCurrent(sessionId: string, generation: number): boolean {
    return this.generations.get(sessionId) === generation;
  }

  private advance(sessionId: string): number {
    const generation = (this.generations.get(sessionId) ?? 0) + 1;
    this.generations.set(sessionId, generation);
    return generation;
  }
}
