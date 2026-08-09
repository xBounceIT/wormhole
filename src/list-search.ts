export function normalizeListSearch(value: string): string {
  return value.trim().toLowerCase();
}

export function listSearchResultsArePending(input: string, deferred: string): boolean {
  return normalizeListSearch(input) !== normalizeListSearch(deferred);
}

export function filterListSearchIndex<T>(
  items: readonly T[],
  index: ReadonlyArray<{ item: T; text: string }>,
  normalizedQuery: string,
): readonly T[] {
  if (!normalizedQuery) return items;
  const matches: T[] = [];
  for (const entry of index) {
    if (entry.text.includes(normalizedQuery)) matches.push(entry.item);
  }
  return matches;
}
