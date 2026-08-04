export type RdpUiStatus = 'idle' | 'starting' | 'connected' | 'disconnected' | 'failed';
export type RdpBackendKind = 'activex' | 'freerdp';

export type RdpSessionState = {
  rdpStatus?: RdpUiStatus;
  rdpBackend?: RdpBackendKind;
  rdpError?: string;
};

export type RdpBackendEventForState = {
  type:
    | 'started'
    | 'ready'
    | 'connected'
    | 'loginComplete'
    | 'disconnected'
    | 'fatalError'
    | 'logonError'
    | 'autoReconnecting'
    | 'autoReconnected'
    | 'exited'
    | 'ack'
    | 'error';
  backend?: RdpBackendKind;
  code?: number;
  attempt?: number;
  max?: number;
  message?: string;
};

export function applyRdpBackendEvent<T extends RdpSessionState>(
  session: T,
  event: RdpBackendEventForState,
): T {
  const backend = event.backend ?? session.rdpBackend;

  if (
    event.type === 'started' ||
    event.type === 'autoReconnecting' ||
    (event.type === 'ready' && session.rdpStatus !== 'connected')
  ) {
    return { ...session, rdpStatus: 'starting', rdpBackend: backend, rdpError: undefined };
  }
  if (
    event.type === 'connected' ||
    event.type === 'loginComplete' ||
    event.type === 'autoReconnected'
  ) {
    return { ...session, rdpStatus: 'connected', rdpBackend: backend, rdpError: undefined };
  }
  if (event.type === 'logonError') {
    // ActiveX can report non-terminal logon notifications (including the -2 continue-logon
    // notification) before the eventual LoginComplete or Disconnected event. Do not mark the
    // process failed here: Retry must not race a still-live native session.
    return { ...session, rdpBackend: backend, rdpError: event.message || session.rdpError };
  }
  if (event.type === 'error' || event.type === 'fatalError') {
    return {
      ...session,
      rdpStatus: 'failed',
      rdpBackend: backend,
      rdpError: event.message || 'The RDP backend rejected the connection.',
    };
  }
  if (event.type === 'disconnected') {
    const failed = session.rdpStatus === 'failed' || (event.code ?? 0) !== 0;
    return {
      ...session,
      rdpStatus: failed ? 'failed' : 'disconnected',
      rdpBackend: backend,
      rdpError: failed ? event.message || session.rdpError : event.message,
    };
  }
  if (event.type === 'exited') {
    const failed = session.rdpStatus === 'failed' || (event.code ?? 0) !== 0;
    return {
      ...session,
      rdpStatus: failed ? 'failed' : 'disconnected',
      rdpBackend: backend,
      rdpError: failed
        ? event.code && event.code !== 0
          ? `The RDP client exited with code ${event.code}.`
          : session.rdpError
        : undefined,
    };
  }
  return session;
}
