export function newSessionToken(): string {
  return globalThis.crypto.randomUUID();
}
