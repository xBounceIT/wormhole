export type ConnectionTreeExpansionSetting = {
  defaultExpanded: boolean;
  folderIds: string[];
};

export const maxConnectionTreeExpansionFolderIds = 25_000;
export const maxConnectionTreeExpansionFolderIdBytes = 128;
export const connectionTreeExpansionMaxRequestBytes = 4 * 1024 * 1024;

function isConnectionTreeFolderId(value: unknown): value is string {
  const hasControlCharacter =
    typeof value === 'string' &&
    [...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint < 0x20 || codePoint === 0x7f;
    });
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value, 'utf8') <= maxConnectionTreeExpansionFolderIdBytes &&
    value.trim() === value &&
    !hasControlCharacter
  );
}

export function parseConnectionTreeExpansionSetting(
  value: unknown,
): ConnectionTreeExpansionSetting {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('Connection tree expansion setting is invalid.');
  }
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.defaultExpanded !== 'boolean' ||
    !Array.isArray(candidate.folderIds) ||
    candidate.folderIds.length > maxConnectionTreeExpansionFolderIds
  ) {
    throw new Error('Connection tree expansion setting is invalid.');
  }
  const folderIds = Array.from(candidate.folderIds);
  if (!folderIds.every(isConnectionTreeFolderId)) {
    throw new Error('Connection tree expansion setting is invalid.');
  }
  return { defaultExpanded: candidate.defaultExpanded, folderIds: [...new Set(folderIds)] };
}
