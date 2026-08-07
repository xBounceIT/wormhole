export class KeyedSingleFlight<TKey, TResult> {
  private readonly pending = new Map<TKey, Promise<TResult>>();

  run(key: TKey, operation: () => Promise<TResult>): Promise<TResult> {
    const existing = this.pending.get(key);
    if (existing) return existing;

    let tracked!: Promise<TResult>;
    tracked = Promise.resolve()
      .then(operation)
      .finally(() => {
        if (this.pending.get(key) === tracked) this.pending.delete(key);
      });
    this.pending.set(key, tracked);
    return tracked;
  }
}
