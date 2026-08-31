export function drainSshBackendSessionIds(
  activeSessions: Set<string>,
  retainedMismatchSessions: Set<string>,
): string[] {
  const sessionIds = [...new Set([...activeSessions, ...retainedMismatchSessions])];
  activeSessions.clear();
  retainedMismatchSessions.clear();
  return sessionIds;
}
