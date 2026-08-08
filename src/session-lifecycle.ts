export type SessionLifecycleState = {
  protocol: string;
  status: string;
  rdpStatus?: string;
};

export function isSessionActive(session: SessionLifecycleState): boolean {
  if (session.protocol === 'rdp') {
    return session.rdpStatus === 'starting' || session.rdpStatus === 'connected';
  }
  return session.status === 'connecting' || session.status === 'connected';
}

export function shouldConfirmConnectedTabClose(
  enabled: boolean,
  sessions: readonly SessionLifecycleState[],
): boolean {
  return enabled && sessions.some(isSessionActive);
}

export function connectedTabCloseMessage(count: number): string {
  return count === 1
    ? 'This connection is still active. Close the tab and disconnect it?'
    : `${count} connections are still active. Close their tabs and disconnect them?`;
}

export class SessionCloseGate {
  private readonly active = new Set<string>();

  async run(sessionId: string, close: () => Promise<void>): Promise<boolean> {
    if (this.active.has(sessionId)) return false;
    this.active.add(sessionId);
    try {
      await close();
      return true;
    } finally {
      this.active.delete(sessionId);
    }
  }

  activeSessionIds(): ReadonlySet<string> {
    return new Set(this.active);
  }
}

export function nextSelectedSessionId(
  sessions: readonly { id: string }[],
  selectedId: string,
  isClosing: (id: string) => boolean,
): string {
  if (!isClosing(selectedId)) return selectedId;
  const selectedIndex = sessions.findIndex((session) => session.id === selectedId);
  for (let index = selectedIndex + 1; index < sessions.length; index += 1) {
    if (!isClosing(sessions[index].id)) return sessions[index].id;
  }
  for (let index = selectedIndex - 1; index >= 0; index -= 1) {
    if (!isClosing(sessions[index].id)) return sessions[index].id;
  }
  return '';
}
