export type SshReconnectingEvent = {
  attempt: number;
  maxAttempts: number;
  delaySeconds: number;
};

export type SshReconnectFailedEvent = {
  attempt: number;
  maxAttempts: number;
  error: string;
};

export function settlesSshHostKeyTrustAttempt(eventType: string): boolean {
  return (
    eventType === 'connected' ||
    eventType === 'error' ||
    eventType === 'closed' ||
    eventType === 'reconnect-failed'
  );
}

export function reconnectingSshState(event: SshReconnectingEvent) {
  const delay = `${event.delaySeconds} second${event.delaySeconds === 1 ? '' : 's'}`;
  return {
    status: 'connecting' as const,
    sftp: undefined,
    tunnelProgress: null,
    error: `Connection lost. Reconnecting in ${delay} (attempt ${event.attempt} of ${event.maxAttempts}).`,
  };
}

export function failedSshReconnectState(event: SshReconnectFailedEvent) {
  return {
    status: 'failed' as const,
    sftp: undefined,
    tunnelProgress: null,
    error: `Automatic reconnect failed after ${event.attempt} attempts. ${event.error}`,
  };
}
