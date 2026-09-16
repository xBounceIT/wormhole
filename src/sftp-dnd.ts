export const sftpDragDataType = 'application/x-wormhole-sftp-items';

export function hasSftpDragPayload(types: readonly string[]): boolean {
  return types.includes(sftpDragDataType) || types.includes('Files');
}

export type SftpTransferItem = {
  sourcePath: string;
  name: string;
  isDirectory: boolean;
  size: number;
};

export function externalSftpTransferItems(
  files: readonly File[],
  dataItems: readonly DataTransferItem[],
  getPathForFile: (file: File) => string,
): SftpTransferItem[] {
  const fileDataItems = dataItems.filter((item) => item.kind === 'file');
  return files.reduce<SftpTransferItem[]>((result, file, index) => {
    let sourcePath = '';
    try {
      sourcePath = getPathForFile(file);
    } catch {
      return result;
    }
    if (!sourcePath) return result;

    const fileSystemEntry = fileDataItems[index]?.webkitGetAsEntry?.();
    result.push({
      sourcePath,
      name: file.name,
      isDirectory: fileSystemEntry?.isDirectory === true,
      size: file.size,
    });
    return result;
  }, []);
}
