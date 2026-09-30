import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { appendBlockmap } from 'app-builder-lib/out/targets/differentialUpdateInfoBuilder.js';
import finalizeAppImage, { embedUpdateInformation } from '../scripts/appimage-update-info.mjs';

function runtimeFixture() {
  const image = Buffer.alloc(1600);
  Buffer.from('7f454c4602010000414902', 'hex').copy(image);
  image.writeBigUInt64LE(64n, 40);
  image.writeUInt16LE(64, 58);
  image.writeUInt16LE(3, 60);
  image.writeUInt16LE(1, 62);
  const names = Buffer.from('\0.shstrtab\0.upd_info\0');
  image.writeBigUInt64LE(256n, 64 + 64 + 24);
  image.writeUInt32LE(3, 64 + 64 + 4);
  image.writeBigUInt64LE(BigInt(names.length), 64 + 64 + 32);
  names.copy(image, 256);
  image.writeUInt32LE(11, 64 + 128);
  image.writeUInt32LE(1, 64 + 128 + 4);
  image.writeBigUInt64LE(320n, 64 + 128 + 24);
  image.writeBigUInt64LE(1024n, 64 + 128 + 32);
  image.fill(0xff, 320, 1344);
  Buffer.from('hsqs-payload-and-blockmap').copy(image, 1400);
  return image;
}

test('update information changes only the reserved section and clears old contents', () => {
  const image = runtimeFixture();
  const original = Buffer.from(image);
  const information = 'gh-releases-zsync|owner|repo|latest|*.zsync';
  embedUpdateInformation(image, information);
  assert.equal(image.length, original.length);
  assert.deepEqual(image.subarray(0, 320), original.subarray(0, 320));
  assert.deepEqual(image.subarray(1344), original.subarray(1344));
  assert.equal(image.subarray(320, 320 + information.length).toString(), information);
  assert.ok(image.subarray(320 + information.length, 1344).every((byte) => byte === 0));
});

test('invalid runtimes and oversized metadata are rejected before modifying bytes', () => {
  const cases = [
    (image) => image.subarray(0, 63),
    (image) => {
      image[0] = 0;
      return image;
    },
    (image) => {
      image[5] = 2;
      return image;
    },
    (image) => {
      image[10] = 1;
      return image;
    },
    (image) => {
      image.writeUInt16LE(63, 58);
      return image;
    },
    (image) => {
      image.writeUInt16LE(3, 62);
      return image;
    },
    (image) => {
      image.writeBigUInt64LE(2n ** 60n, 40);
      return image;
    },
    (image) => {
      image.writeBigUInt64LE(1590n, 216);
      return image;
    },
    (image) => {
      image.writeUInt32LE(1000, 192);
      return image;
    },
    (image) => {
      image[276] = 1;
      return image;
    },
    (image) => {
      image[267] = 0xae;
      return image;
    },
    (image) => {
      image.writeUInt32LE(1, 192);
      return image;
    },
    (image) => {
      image.writeBigUInt64LE(0n, 216);
      return image;
    },
    (image) => {
      image.writeBigUInt64LE(64n, 216);
      return image;
    },
    (image) => {
      image.writeBigUInt64LE(256n, 216);
      return image;
    },
    (image) => {
      image.writeUInt32LE(8, 196);
      return image;
    },
    (image) => {
      image.writeBigUInt64LE(320n, 32);
      image.writeUInt16LE(56, 54);
      image.writeUInt16LE(1, 56);
      return image;
    },
    (image) => {
      image.writeBigUInt64LE(2n ** 60n, 32);
      return image;
    },
    (image) => {
      image.writeUInt32LE(11, 128);
      image.writeUInt32LE(1, 132);
      return image;
    },
  ];
  for (const mutate of cases) {
    const image = mutate(runtimeFixture());
    const original = Buffer.from(image);
    assert.throws(() => embedUpdateInformation(image, 'update'), /AppImage/);
    assert.deepEqual(image, original);
  }
  for (const information of ['x'.repeat(1024), 'nul\0byte']) {
    const image = runtimeFixture();
    assert.throws(() => embedUpdateInformation(image, information), /reserved section/);
  }
});

test('the packaging hook leaves other targets untouched', async () => {
  for (const file of [undefined, 'Wormhole.deb', 'Wormhole.rpm', 'Wormhole.dmg', 'Wormhole.exe']) {
    await finalizeAppImage({ file }, () => assert.fail('must not run zsyncmake'));
  }
  await assert.rejects(finalizeAppImage({ file: 'Other-2.1.0-x86_64.AppImage' }), /filename/);
  await assert.rejects(finalizeAppImage({ file: 'Wormhole-invalid-x86_64.AppImage' }), /filename/);
});

test('both architectures generate delta files from final bytes with distinct release selectors', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wormhole-appimage-'));
  try {
    for (const [arch, version] of [
      ['x86_64', '2.1.0'],
      ['arm64', '2.1.0'],
      ['x86_64', '2.2.0-beta.1'],
    ]) {
      const filename = `Wormhole-${version}-${arch}.AppImage`;
      const file = join(directory, filename);
      await writeFile(file, runtimeFixture());
      let called = false;
      await finalizeAppImage({ file }, async (command, args, options) => {
        called = true;
        assert.equal(command, 'zsyncmake');
        assert.deepEqual(args, [
          '-u',
          `https://github.com/xBounceIT/wormhole/releases/download/v${version}/${filename}`,
          '-o',
          `${filename}.zsync`,
          filename,
        ]);
        assert.equal(options.cwd, directory);
        const image = await readFile(file);
        assert.equal(
          image.subarray(320, image.indexOf(0, 320)).toString(),
          `gh-releases-zsync|xBounceIT|wormhole|latest|Wormhole-*-${arch}.AppImage.zsync`,
        );
        await writeFile(`${file}.zsync`, 'delta fixture');
      });
      assert.ok(called);
      assert.equal(basename(file), filename);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('packaging fails when the delta generator fails or produces no sidecar', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wormhole-appimage-'));
  const file = join(directory, 'Wormhole-2.1.0-x86_64.AppImage');
  try {
    await writeFile(file, runtimeFixture());
    await assert.rejects(
      finalizeAppImage({ file }, () => {
        throw new Error('zsync failed');
      }),
      /zsync failed/,
    );
    await assert.rejects(
      finalizeAppImage({ file }, () => {}),
      /ENOENT/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('the builder blockmap and manifest describe the final image before zsync generation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wormhole-appimage-'));
  const file = join(directory, 'Wormhole-2.1.0-x86_64.AppImage');
  try {
    await writeFile(file, runtimeFixture());
    const updateInfo = await appendBlockmap(file);
    const previousHash = updateInfo.sha512;
    await finalizeAppImage({ file, updateInfo }, async () => {
      const image = await readFile(file);
      assert.equal(updateInfo.sha512, createHash('sha512').update(image).digest('base64'));
      assert.notEqual(updateInfo.sha512, previousHash);
      assert.equal(updateInfo.size, image.length);
      assert.equal(image.readUInt32BE(image.length - 4), updateInfo.blockMapSize);
      const blockmap = JSON.parse(inflateRawSync(image.subarray(1600, -4)).toString());
      assert.equal(
        blockmap.files[0].sizes.reduce((sum, size) => sum + size, 0),
        1600,
      );
      await writeFile(`${file}.zsync`, 'delta fixture');
    });
    const original = await readFile(file);
    for (const blockMapSize of [undefined, 0, original.length, 1]) {
      await assert.rejects(finalizeAppImage({ file, updateInfo: { blockMapSize } }), /blockmap/);
      assert.deepEqual(await readFile(file), original);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
