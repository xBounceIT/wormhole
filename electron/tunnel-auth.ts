export function isMatchingOAuthRedirect(candidate: URL, expectedRaw: string): boolean {
  const expected = new URL(expectedRaw);
  return (
    candidate.protocol === expected.protocol &&
    candidate.hostname === expected.hostname &&
    candidate.port === expected.port &&
    candidate.pathname === expected.pathname &&
    !candidate.username &&
    !candidate.password
  );
}
