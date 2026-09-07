type McpSession = {
  backendSessionId?: string;
  mcpAccessible?: boolean;
};

export function applySessionMcpAccess<T extends McpSession>(
  sessions: T[],
  event: { sessionId: string; accessible: boolean },
): T[] {
  return sessions.map((session) =>
    session.backendSessionId === event.sessionId
      ? { ...session, mcpAccessible: event.accessible }
      : session,
  );
}

export function sessionTabPresentation(
  session: { protocol: string; status: string; mcpAccessible?: boolean },
  active: boolean,
) {
  const aiAccessible =
    session.protocol === 'ssh' && session.status === 'connected' && session.mcpAccessible === true;
  return {
    aiAccessible,
    accessLabel: aiAccessible ? 'AI agent access via MCP. ' : '',
    className: aiAccessible
      ? active
        ? 'bg-yellow-200 text-yellow-950 dark:bg-yellow-400/25 dark:text-yellow-100'
        : 'bg-yellow-100 text-yellow-900 hover:bg-yellow-200 dark:bg-yellow-400/15 dark:text-yellow-200 dark:hover:bg-yellow-400/25'
      : active
        ? 'bg-card text-foreground'
        : 'text-muted-foreground hover:bg-muted/25',
  };
}
