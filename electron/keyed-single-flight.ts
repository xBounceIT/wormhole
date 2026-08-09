export class KeyedSingleFlight<TKey, TDefaultResult = unknown> {
  private readonly pending = new Map<TKey, Promise<unknown>>();
  private readonly suspensions = new Map<TKey, number>();

  run<TResult = TDefaultResult>(key: TKey, operation: () => Promise<TResult>): Promise<TResult> {
    const existing = this.pending.get(key);
    if (existing) return existing as Promise<TResult>;

    let tracked!: Promise<TResult>;
    tracked = Promise.resolve()
      .then(operation)
      .finally(() => {
        if (this.pending.get(key) === tracked) this.pending.delete(key);
      });
    this.pending.set(key, tracked);
    return tracked;
  }

  runExclusive<TResult = TDefaultResult>(
    key: TKey,
    operation: () => Promise<TResult>,
    conflictMessage: string,
  ): Promise<TResult> {
    if (this.pending.has(key) || this.suspensions.has(key)) {
      return Promise.reject(new Error(conflictMessage));
    }
    return this.run(key, operation);
  }

  suspend(key: TKey): () => void {
    this.suspensions.set(key, (this.suspensions.get(key) ?? 0) + 1);
    let active = true;
    return () => {
      if (!active) return;
      active = false;
      const remaining = (this.suspensions.get(key) ?? 1) - 1;
      if (remaining > 0) this.suspensions.set(key, remaining);
      else this.suspensions.delete(key);
    };
  }

  async waitForIdle(key: TKey): Promise<void> {
    while (true) {
      const pending = this.pending.get(key);
      if (!pending) return;
      await pending.catch(() => undefined);
    }
  }
}
