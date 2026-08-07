export class KeyedTaskTracker<TKey> {
  private readonly pending = new Map<TKey, Set<Promise<unknown>>>();

  run<TResult>(key: TKey, operation: () => Promise<TResult>): Promise<TResult> {
    let tasks = this.pending.get(key);
    if (!tasks) {
      tasks = new Set();
      this.pending.set(key, tasks);
    }

    let tracked!: Promise<TResult>;
    tracked = Promise.resolve()
      .then(operation)
      .finally(() => {
        const current = this.pending.get(key);
        if (!current) return;
        current.delete(tracked);
        if (current.size === 0) this.pending.delete(key);
      });
    tasks.add(tracked);
    return tracked;
  }

  async waitForIdle(key: TKey): Promise<void> {
    while (true) {
      const tasks = this.pending.get(key);
      if (!tasks?.size) return;
      await Promise.allSettled([...tasks]);
    }
  }

  async waitForAllIdle(): Promise<void> {
    while (true) {
      const tasks = [...this.pending.values()].flatMap((pending) => [...pending]);
      if (tasks.length === 0) return;
      await Promise.allSettled(tasks);
    }
  }
}
