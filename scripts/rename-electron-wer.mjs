import { rename } from 'node:fs/promises';
import path from 'node:path';

export async function renameElectronWerHelper(executablePath) {
  const directory = path.dirname(executablePath);
  const source = path.join(directory, 'electron_wer.dll');
  const name = path.basename(executablePath, path.extname(executablePath));
  const destination = path.join(directory, `${name}_wer.dll`);
  if (source === destination) return;
  try {
    await rename(source, destination);
  } catch (error) {
    // Older Electron runtimes do not ship a WER helper. Repeated staging is safe.
    if (error.code !== 'ENOENT') throw error;
  }
}
