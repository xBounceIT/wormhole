export const workspaceNotesMaxLength = 16_384;
// JSON can escape each note character to six bytes; retain room for other node fields.
export const workspaceNodeWriteMaxRequestBytes = 256 * 1024;

// Undefined preserves existing notes when an older caller edits a connection.
export function parseWorkspaceNotes(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length > workspaceNotesMaxLength || value.includes('\0')) {
    throw new Error('Connection notes are invalid.');
  }
  return value;
}
