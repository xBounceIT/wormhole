// One coordinator per mounted workspace, shared by every full-snapshot consumer.
export class WorkspaceRefreshCoordinator {
  private generation = 0;

  invalidate(): void {
    this.generation += 1;
  }

  async refresh<T>(load: () => Promise<T>, apply: (snapshot: T) => void): Promise<boolean> {
    const generation = ++this.generation;
    let snapshot: T;
    try {
      snapshot = await load();
    } catch (error) {
      // A superseded failure must not trigger a caller's stale local fallback either.
      if (generation !== this.generation) return false;
      throw error;
    }
    if (generation !== this.generation) return false;
    apply(snapshot);
    return true;
  }
}
