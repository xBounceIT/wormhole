import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  renameSync,
  rmdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const freeRdpRevision = '5a10d7b6b79a2fbc62e8eba77085cd356dc303a6'; // 3.33.0

function runner(spawn, cwd, env = process.env) {
  return (command, args, capture = false) => {
    const result = spawn(command, args, {
      cwd,
      env,
      encoding: 'utf8',
      stdio: capture ? 'pipe' : 'inherit',
    });
    if (result.error) throw new Error(`Could not start ${command}: ${result.error.message}`);
    if (result.status !== 0) {
      throw new Error(`${command} failed (${result.status}): ${result.stderr || result.stdout}`);
    }
    return result.stdout;
  };
}

// Static third-party libraries keep the DMG independent of Homebrew and its install prefix.
// Inspect both slices: an ARM runner must not silently ship an Intel-only dependency.
export function verifyMacFreeRdp(resources, { spawn = spawnSync } = {}) {
  const binary = path.join(resources, 'freerdp', 'sdl-freerdp');
  if (!existsSync(binary)) throw new Error('The bundled macOS FreeRDP client is missing.');
  const run = runner(spawn, resources);
  run('lipo', [binary, '-verify_arch', 'x86_64', 'arm64']);
  for (const arch of ['x86_64', 'arm64']) {
    const output = run('otool', ['-arch', arch, '-L', binary], true);
    const dependencies = output
      .split('\n')
      .slice(1)
      .filter((line) => line.trim());
    if (!dependencies.length)
      throw new Error('FreeRDP dependency inspection returned no libraries.');
    for (const line of dependencies) {
      const dependency = line.trim().split(' (')[0];
      if (!dependency.startsWith('/usr/lib/') && !dependency.startsWith('/System/Library/')) {
        throw new Error(`FreeRDP depends on an unbundled library: ${dependency}`);
      }
    }
  }
  return binary;
}

export function buildMacFreeRdp({
  repoRoot,
  platform = process.platform,
  vcpkgRoot = process.env.WORMHOLE_RDP_VCPKG_ROOT,
  spawn = spawnSync,
}) {
  if (platform !== 'darwin') throw new Error('FreeRDP must be built on macOS.');
  repoRoot = path.resolve(repoRoot);
  const lock = path.join(repoRoot, 'obj', 'macos-freerdp-build.lock');
  mkdirSync(path.dirname(lock), { recursive: true });
  try {
    mkdirSync(lock);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    throw new Error(
      `FreeRDP build lock exists: ${lock}. Remove it only after confirming its owner process has stopped.`,
    );
  }
  const owner = path.join(lock, 'owner-pid');
  try {
    writeFileSync(owner, `${process.pid}\n`);
    // An overlapping invocation must not remove another build's output or workspace.
    rmSync(path.join(repoRoot, 'dist-electron', 'freerdp'), { recursive: true, force: true });
    return compileMacFreeRdp({ repoRoot, vcpkgRoot, spawn });
  } finally {
    rmSync(owner, { force: true });
    rmdirSync(lock);
  }
}

function compileMacFreeRdp({ repoRoot, vcpkgRoot, spawn }) {
  // Resolve before CMake changes the base directory for relative toolchain paths.
  vcpkgRoot = vcpkgRoot && path.resolve(vcpkgRoot);
  if (!vcpkgRoot || !existsSync(path.join(vcpkgRoot, 'scripts', 'buildsystems', 'vcpkg.cmake'))) {
    throw new Error('Set WORMHOLE_RDP_VCPKG_ROOT to the pinned, bootstrapped vcpkg checkout.');
  }
  const source = path.join(repoRoot, 'obj', 'freerdp-source');
  const work = path.join(repoRoot, 'obj', 'macos-freerdp');
  const staged = path.join(repoRoot, 'dist-electron', 'freerdp');
  const manifest = path.join(repoRoot, 'tools', 'macos-freerdp');
  const run = runner(spawn, repoRoot, { ...process.env, VCPKG_ROOT: vcpkgRoot });
  mkdirSync(work, { recursive: true });
  if (!existsSync(source)) {
    run('git', ['clone', '--no-checkout', 'https://github.com/FreeRDP/FreeRDP.git', source]);
  }
  run('git', ['-C', source, 'checkout', '--detach', freeRdpRevision]);
  if (run('git', ['-C', source, 'rev-parse', 'HEAD'], true).trim() !== freeRdpRevision) {
    throw new Error('Unexpected FreeRDP source revision.');
  }
  if (
    run('git', ['-C', source, 'status', '--porcelain', '--untracked-files=normal'], true).trim()
  ) {
    throw new Error(
      'FreeRDP source checkout has local changes; restore it before building the pinned client.',
    );
  }
  const slices = [];
  for (const [triplet, arch] of [
    ['x64-osx', 'x86_64'],
    ['arm64-osx', 'arm64'],
  ]) {
    console.log(`Building macOS FreeRDP (${arch})`);
    const build = path.join(work, triplet);
    // Manifest installs remove packages for other triplets in the same root.
    // Keep both SDKs available for the later canvas adapter build.
    const installed = path.join(work, 'installed', triplet);
    run(path.join(vcpkgRoot, 'vcpkg'), [
      'install',
      `--triplet=${triplet}`,
      `--x-manifest-root=${manifest}`,
      `--x-install-root=${installed}`,
      `--overlay-triplets=${path.join(manifest, 'triplets')}`,
    ]);
    run('cmake', [
      '-S',
      source,
      '-B',
      build,
      '-G',
      'Ninja',
      `-DCMAKE_TOOLCHAIN_FILE=${path.join(vcpkgRoot, 'scripts', 'buildsystems', 'vcpkg.cmake')}`,
      '-DVCPKG_MANIFEST_MODE=OFF',
      `-DVCPKG_INSTALLED_DIR=${installed}`,
      `-DVCPKG_TARGET_TRIPLET=${triplet}`,
      `-DCMAKE_OSX_ARCHITECTURES=${arch}`,
      '-DCMAKE_OSX_DEPLOYMENT_TARGET=12.0',
      '-DCMAKE_BUILD_TYPE=Release',
      '-DCMAKE_C_COMPILER=clang',
      '-DCMAKE_CXX_COMPILER=clang++',
      '-DBUILD_SHARED_LIBS=OFF',
      '-DOPENSSL_USE_STATIC_LIBS=TRUE',
      '-DWITH_SDL_LINK_SHARED=OFF',
      '-DWITH_BINARY_VERSIONING=OFF',
      '-DSDL_USE_COMPILED_RESOURCES=ON',
      '-DWITH_CLIENT_SDL=ON',
      '-DWITH_CLIENT_SDL3=ON',
      '-DWITH_CLIENT_SDL2=OFF',
      '-DWITH_CLIENT_SDL_VERSIONED=OFF',
      // The backend intentionally uses the FreeRDP 2/3 gateway and certificate switches.
      '-DWITH_FREERDP_DEPRECATED_COMMANDLINE=ON',
      '-DWITH_CLIENT_MAC=OFF',
      '-DWITH_X11=OFF',
      '-DWITH_SERVER=OFF',
      '-DWITH_SAMPLE=OFF',
      '-DWITH_MANPAGES=OFF',
      '-DBUILD_TESTING=OFF',
      '-DWITH_FFMPEG=OFF',
      '-DWITH_SWSCALE=OFF',
      '-DWITH_OPENH264=OFF',
      '-DWITH_WEBVIEW=OFF',
      '-DWITH_KRB5=OFF',
      '-DWITH_PKCS11=OFF',
      '-DCHANNEL_URBDRC=OFF',
      '-DWITH_UNICODE_BUILTIN=ON',
      '-DWITH_JANSSON_REQUIRED=ON',
      '-DWITH_URIPARSER=ON',
      '-DWITH_ABSOLUTE_PLUGIN_LOAD_PATHS=OFF',
      '-DWITH_VERBOSE_WINPR_ASSERT=OFF',
      '-DWITH_CCACHE=OFF',
      '-DWITH_CLANG_FORMAT=OFF',
    ]);
    run('cmake', ['--build', build, '--target', 'sdl3-freerdp', '--parallel', '4']);
    slices.push(path.join(build, 'client', 'SDL', 'SDL3', 'sdl-freerdp'));
  }
  const temporaryResources = path.join(work, 'resources');
  const temporary = path.join(temporaryResources, 'freerdp');
  rmSync(temporary, { recursive: true, force: true });
  mkdirSync(temporary, { recursive: true });
  const binary = path.join(temporary, 'sdl-freerdp');
  run('lipo', ['-create', ...slices, '-output', binary]);
  chmodSync(binary, 0o755);
  verifyMacFreeRdp(temporaryResources, { spawn });
  run('codesign', ['--force', '--sign', '-', binary]);
  // Carry the notices for every static dependency, including transitive dependencies.
  const licenses = path.join(temporary, 'licenses');
  mkdirSync(licenses);
  copyFileSync(path.join(source, 'LICENSE'), path.join(licenses, 'FreeRDP.txt'));
  copyFileSync(
    path.join(source, 'resources', 'font', 'OFL.txt'),
    path.join(licenses, 'OpenSans.txt'),
  );
  if (existsSync(path.join(source, 'NOTICE'))) {
    copyFileSync(path.join(source, 'NOTICE'), path.join(licenses, 'FreeRDP-NOTICE.txt'));
  }
  const share = path.join(work, 'installed', 'arm64-osx', 'arm64-osx', 'share');
  for (const entry of readdirSync(share, { withFileTypes: true })) {
    const copyright = path.join(share, entry.name, 'copyright');
    if (entry.isDirectory() && existsSync(copyright)) {
      copyFileSync(copyright, path.join(licenses, `${entry.name}.txt`));
    }
  }
  mkdirSync(path.dirname(staged), { recursive: true });
  renameSync(temporary, staged);
  return path.join(staged, 'sdl-freerdp');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildMacFreeRdp({ repoRoot: path.resolve(fileURLToPath(new URL('..', import.meta.url))) });
}
