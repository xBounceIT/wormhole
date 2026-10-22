type ConnectionEditValue = string | boolean | Record<string, string | number | boolean>;

// RDP tabs remain open after disconnecting. Saving their profile must not start a connection.
export function connectionEditCanRestartSession(
  session: { protocol: string; rdpStatus?: string } | undefined,
): boolean {
  return Boolean(
    session &&
    (session.protocol !== 'rdp' ||
      session.rdpStatus === 'starting' ||
      session.rdpStatus === 'connected'),
  );
}

export type ConnectionEditForm = {
  name: string;
  notes: string;
  inlinePassword: string;
  removeInlinePassword: boolean;
  [field: string]: ConnectionEditValue;
};

// Compare the editor's initial values, so inherited settings and displayed defaults
// do not turn a rename into a connection settings change.
export function connectionEditRequiresReconnect(
  initial: ConnectionEditForm | null,
  current: ConnectionEditForm,
): boolean {
  if (!initial) return true;
  return Object.keys(current).some((field) => {
    if (field === 'name' || field === 'notes') return false;
    const before = initial[field];
    const after = current[field];
    if (typeof before === 'object' && typeof after === 'object') {
      return (
        Object.keys(before).length !== Object.keys(after).length ||
        Object.keys(after).some((key) => before[key] !== after[key])
      );
    }
    return before !== after;
  });
}
