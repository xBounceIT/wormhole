import type {
  BrowserWindow,
  MessageBoxOptions,
  MessageBoxReturnValue,
  SaveDialogOptions,
  SaveDialogReturnValue,
} from 'electron';
import { realpath } from 'node:fs/promises';
import { dirname, isAbsolute, relative, sep } from 'node:path';

function looksSynchronized(folder: string): boolean {
  if (
    folder
      .split(sep)
      .some((name) =>
        /^(?:onedrive(?: - .+)?|dropbox(?: \(.+\))?|googledrive(?:-.+)?|google drive|icloud drive|cloudstorage|mobile documents)$/i.test(
          name,
        ),
      )
  )
    return true;
  return [process.env.OneDrive, process.env.OneDriveCommercial, process.env.OneDriveConsumer].some(
    (root) => {
      if (!root || !isAbsolute(root)) return false;
      const offset = relative(root, folder);
      return !offset || (!isAbsolute(offset) && offset !== '..' && !offset.startsWith(`..${sep}`));
    },
  );
}

export async function pickSharedBackupDestination(
  dialog: {
    showSaveDialog(
      window: BrowserWindow,
      options: SaveDialogOptions,
    ): Promise<SaveDialogReturnValue>;
    showMessageBox(
      window: BrowserWindow,
      options: MessageBoxOptions,
    ): Promise<MessageBoxReturnValue>;
  },
  window: BrowserWindow,
  accepted: () => boolean,
): Promise<string | null> {
  while (accepted()) {
    const choice = await dialog.showSaveDialog(window, {
      title: 'Save encrypted workspace recovery backup',
      defaultPath: 'wormhole-workspace-recovery.json',
      filters: [{ name: 'Wormhole recovery backup', extensions: ['json'] }],
    });
    if (!accepted() || choice.canceled || !choice.filePath) return null;
    const folder = dirname(choice.filePath);
    const resolved = await realpath(folder).catch(() => folder);
    if (!accepted()) return null;
    if (!looksSynchronized(folder) && !looksSynchronized(resolved)) return choice.filePath;
    const warning = await dialog.showMessageBox(window, {
      type: 'warning',
      message: 'This folder appears to sync to cloud storage.',
      detail:
        'Prefer an offline location. The backup is encrypted. Store its recovery password separately.',
      buttons: ['Choose another folder', 'Save here', 'Cancel'],
      defaultId: 0,
      cancelId: 2,
    });
    if (!accepted() || warning.response === 2) return null;
    if (warning.response === 1) return choice.filePath;
  }
  return null;
}
