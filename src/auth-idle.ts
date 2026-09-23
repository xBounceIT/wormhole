export function authenticationIdleSeconds(
  systemIdleSeconds: number,
  lastActivityAt: number,
  lastUnlockedAt: number,
  now: number,
): number {
  // Biometric verification is activity even when Windows records no keyboard/mouse input.
  const sinceUnlock = Math.max(0, (now - lastUnlockedAt) / 1000);
  const localIdle = Math.max(0, (now - lastActivityAt) / 1000);
  return Math.min(sinceUnlock, Math.max(systemIdleSeconds, localIdle));
}
