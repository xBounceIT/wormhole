import { execFileSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { basename, dirname } from 'node:path';
import { appendBlockmap } from 'app-builder-lib/out/targets/differentialUpdateInfoBuilder.js';
import { valid } from 'semver';

// Patch the reserved ELF section in place: changing the ELF layout would move the SquashFS
// payload. Both supported static runtimes use ELF64 little-endian headers.
export function embedUpdateInformation(image, information) {
  if (
    image.length < 64 ||
    image.subarray(0, 6).toString('hex') !== '7f454c460201' ||
    image.subarray(8, 11).toString('hex') !== '414902'
  ) {
    throw new Error('Expected a little-endian ELF64 type-2 AppImage.');
  }
  const sectionTable = Number(image.readBigUInt64LE(40));
  const sectionSize = image.readUInt16LE(58);
  const sectionCount = image.readUInt16LE(60);
  const nameIndex = image.readUInt16LE(62);
  const checkRange = (offset, size) => {
    if (
      !Number.isSafeInteger(offset) ||
      !Number.isSafeInteger(size) ||
      size < 0 ||
      offset < 0 ||
      size > image.length - offset
    ) {
      throw new Error('AppImage ELF section is out of bounds.');
    }
  };
  if (sectionSize !== 64 || nameIndex >= sectionCount) {
    throw new Error('Invalid AppImage ELF section table.');
  }
  checkRange(sectionTable, sectionSize * sectionCount);
  const section = (index) => {
    const header = sectionTable + index * sectionSize;
    const offset = Number(image.readBigUInt64LE(header + 24));
    const size = Number(image.readBigUInt64LE(header + 32));
    checkRange(offset, size);
    return { offset, size };
  };
  const names = section(nameIndex);
  const nameTable = image.subarray(names.offset, names.offset + names.size);
  let updateIndex;
  for (let index = 0; index < sectionCount; index++) {
    const header = sectionTable + index * sectionSize;
    const nameOffset = image.readUInt32LE(header);
    const end = nameTable.indexOf(0, nameOffset);
    if (nameOffset >= nameTable.length || end < 0) {
      throw new Error('Invalid AppImage ELF section name.');
    }
    if (nameTable.subarray(nameOffset, end).toString('utf8') !== '.upd_info') continue;
    if (updateIndex !== undefined || image.readUInt32LE(header + 4) !== 1) {
      throw new Error('Invalid AppImage update information section.');
    }
    updateIndex = index;
  }
  if (updateIndex === undefined)
    throw new Error('AppImage runtime has no reserved update information section.');
  const { offset, size } = section(updateIndex);
  const overlaps = (start, length) =>
    length > 0 && offset < start + length && start < offset + size;
  const programTable = Number(image.readBigUInt64LE(32));
  const programTableSize = image.readUInt16LE(54) * image.readUInt16LE(56);
  checkRange(programTable, programTableSize);
  if (
    overlaps(0, 64) ||
    overlaps(programTable, programTableSize) ||
    overlaps(sectionTable, sectionSize * sectionCount)
  ) {
    throw new Error('AppImage update section overlaps ELF headers.');
  }
  for (let index = 0; index < sectionCount; index++) {
    const type = image.readUInt32LE(sectionTable + index * sectionSize + 4);
    // NULL and NOBITS sections have no file-backed contents.
    if (index === updateIndex || type === 0 || type === 8) continue;
    const other = section(index);
    if (overlaps(other.offset, other.size))
      throw new Error('AppImage update section overlaps another ELF section.');
  }
  const data = Buffer.from(information, 'utf8');
  if (data.length >= size || data.includes(0)) {
    throw new Error('AppImage update information does not fit its reserved section.');
  }
  image.fill(0, offset, offset + size);
  data.copy(image, offset);
}

export default async function finalizeAppImage({ file, updateInfo }, run = execFileSync) {
  if (!file?.endsWith('.AppImage')) return;
  const filename = basename(file);
  const match = /^Wormhole-(.+)-(x86_64|arm64)\.AppImage$/.exec(filename);
  if (!match || valid(match[1]) === null)
    throw new Error(`Unexpected AppImage filename: ${filename}`);
  const [, version, arch] = match;
  let image = await readFile(file);
  if (updateInfo) {
    const size = updateInfo.blockMapSize;
    if (
      !Number.isSafeInteger(size) ||
      size < 1 ||
      size + 64 + 4 > image.length ||
      image.readUInt32BE(image.length - 4) !== size
    ) {
      throw new Error('Invalid AppImage embedded blockmap.');
    }
    image = image.subarray(0, image.length - size - 4);
  }
  embedUpdateInformation(
    image,
    `gh-releases-zsync|xBounceIT|wormhole|latest|Wormhole-*-${arch}.AppImage.zsync`,
  );
  await writeFile(file, image);
  // electron-builder already calculated a blockmap and hash before invoking this hook.
  // Rebuild them after modifying the runtime so its update manifests remain consistent too.
  if (updateInfo) Object.assign(updateInfo, await appendBlockmap(file));
  // Run after the final bytes are written, before release SHA-256 sidecars are generated.
  // zsyncmake is a host tool, so an x64 runner can also finalize the arm64 AppImage.
  await run(
    'zsyncmake',
    [
      '-u',
      `https://github.com/xBounceIT/wormhole/releases/download/v${version}/${filename}`,
      '-o',
      `${filename}.zsync`,
      filename,
    ],
    { cwd: dirname(file), stdio: 'inherit' },
  );
  await readFile(`${file}.zsync`);
}
