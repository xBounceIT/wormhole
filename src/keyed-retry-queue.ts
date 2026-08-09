export class KeyedRetryQueue<TKey> {
  private readonly retries = new Map<TKey, () => void>();

  get isEmpty(): boolean {
    return this.retries.size === 0;
  }

  upsert(key: TKey, retry: () => void): boolean {
    const wasEmpty = this.retries.size === 0;
    this.retries.set(key, retry);
    return wasEmpty;
  }

  remove(key: TKey): void {
    this.retries.delete(key);
  }

  clear(): void {
    this.retries.clear();
  }

  drain(): Array<() => void> {
    const pending = [...this.retries.values()];
    this.retries.clear();
    return pending;
  }
}
