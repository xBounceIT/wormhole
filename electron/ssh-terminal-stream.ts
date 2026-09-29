export interface SshTerminalOutput {
  type: 'terminal-output';
  sessionId: string;
  data: string;
  sequence: number;
  reset: boolean;
  columns: number;
  rows: number;
}

export function parseSshTerminalOutput(
  value: Record<string, unknown>,
): SshTerminalOutput | undefined {
  // encoding/json omits empty data on Go's reset packets.
  const data = value.data === undefined && value.reset === true ? '' : value.data;
  if (
    typeof value.session_id !== 'string' ||
    !/^[a-zA-Z0-9-]{1,128}$/.test(value.session_id) ||
    typeof data !== 'string' ||
    data.length > 21848 ||
    data.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data) ||
    typeof value.sequence !== 'number' ||
    !Number.isSafeInteger(value.sequence) ||
    value.sequence < 1 ||
    (value.reset !== undefined && typeof value.reset !== 'boolean')
  )
    return undefined;
  const reset = value.reset === true;
  const columns = value.columns ?? 0,
    rows = value.rows ?? 0;
  if (
    typeof columns !== 'number' ||
    typeof rows !== 'number' ||
    !Number.isInteger(columns) ||
    !Number.isInteger(rows) ||
    (reset ? columns < 1 || rows < 1 : columns !== 0 || rows !== 0) ||
    columns > 500 ||
    rows > 500 ||
    Buffer.from(data, 'base64').length > 16384
  )
    return undefined;
  return {
    type: 'terminal-output',
    sessionId: value.session_id,
    data,
    sequence: value.sequence,
    reset,
    columns,
    rows,
  };
}

// The Go credit window limits each session to 16 unacknowledged packets.
// Retain those packets while locked; never replay a lossy cell snapshot on unlock.
export class SshTerminalDelivery {
  private packets = new Map<string, Map<number, SshTerminalOutput>>();

  receive(packet: SshTerminalOutput): boolean {
    if (packet.reset) this.remove(packet.sessionId);
    const pending = this.packets.get(packet.sessionId) ?? new Map();
    if (pending.size >= 16 || pending.has(packet.sequence)) return false;
    pending.set(packet.sequence, packet);
    this.packets.set(packet.sessionId, pending);
    return true;
  }

  acknowledge(sessionId: string, sequence: number): boolean {
    const pending = this.packets.get(sessionId);
    if (!pending?.delete(sequence)) return false;
    if (pending.size === 0) this.packets.delete(sessionId);
    return true;
  }

  pending(): SshTerminalOutput[] {
    return [...this.packets.values()].flatMap((packets) => [...packets.values()]);
  }

  remove(sessionId: string): void {
    this.packets.delete(sessionId);
  }
  clear(): void {
    this.packets.clear();
  }
}
