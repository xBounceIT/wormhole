import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';

// macOS releases must link the real engine for each slice before lipo combines them.
// Keep process execution injectable so failure/cleanup paths can be tested on Windows too.
export function buildMacOvpnProxy({
  repoRoot,
  architecture,
  platform = process.platform,
  ...options
}) {
  if (platform !== 'darwin' || !['x64', 'arm64'].includes(architecture)) {
    throw new Error('OpenVPN macOS builds require macOS and architecture x64 or arm64.');
  }
  // The patched submodule and Go cache stamp are shared by both architectures.
  // Reject overlap before touching either sources or an existing staged binary.
  const lock = path.join(repoRoot, 'obj', 'macos-ovpn-build.lock');
  mkdirSync(path.dirname(lock), { recursive: true });
  try {
    mkdirSync(lock);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    throw new Error(
      `OpenVPN build lock exists: ${lock}. If a build was interrupted, remove this directory only after confirming its owner process has stopped.`,
    );
  }
  const temporary = path.join(lock, 'wormhole-ovpnproxy.building');
  const owner = path.join(lock, 'owner-pid');
  try {
    writeFileSync(owner, `${process.pid}\n`);
    return compileMacOvpnProxy({ ...options, repoRoot, architecture, temporary });
  } finally {
    rmSync(temporary, { force: true });
    rmSync(owner, { force: true });
    rmdirSync(lock);
  }
}

function compileMacOvpnProxy({
  repoRoot,
  architecture,
  temporary,
  hostArchitecture = process.arch,
  environment = process.env,
  spawn = spawnSync,
}) {
  const source = path.join(repoRoot, 'tools', 'wormhole-ovpnproxy');
  const shim = path.join(source, 'ovpn_shim');
  const build = path.join(shim, 'build', `darwin-${architecture}`);
  const output = path.join(repoRoot, 'dist-electron', 'wormhole-ovpnproxy');
  const openvpn = path.join(source, 'third_party', 'openvpn3');
  const applied = [];
  const env = {
    ...environment,
    GOOS: 'darwin',
    GOARCH: architecture === 'x64' ? 'amd64' : 'arm64',
    CGO_ENABLED: '1',
    CC: 'clang',
    CXX: 'clang++',
    MACOSX_DEPLOYMENT_TARGET: '12.0',
  };
  const execute = (command, args, options = {}) =>
    spawn(command, args, {
      cwd: repoRoot,
      env,
      encoding: 'utf8',
      stdio: 'inherit',
      ...options,
    });
  const run = (command, args, options) => {
    const result = execute(command, args, options);
    if (result.error) throw new Error(`Could not start ${command}: ${result.error.message}`);
    if (result.status !== 0)
      throw new Error(`${command} failed with exit ${result.status ?? 'unknown'}.`);
    return result;
  };

  mkdirSync(path.dirname(output), { recursive: true });
  rmSync(output, { force: true });
  let failure;
  const restorationFailures = [];
  try {
    const vcpkgRoot = environment.VCPKG_ROOT || environment.VCPKG_INSTALLATION_ROOT;
    const vcpkg = vcpkgRoot && path.resolve(vcpkgRoot);
    if (!vcpkg || !existsSync(path.join(vcpkg, 'scripts', 'buildsystems', 'vcpkg.cmake'))) {
      throw new Error(
        'Set VCPKG_ROOT to a bootstrapped vcpkg checkout to build the macOS OpenVPN engine.',
      );
    }
    env.VCPKG_ROOT = vcpkg;
    const headers = [
      path.join(openvpn, 'client', 'ovpncli.hpp'),
      path.join(source, 'third_party', 'mbedtls', 'include', 'mbedtls', 'ssl.h'),
      path.join(source, 'third_party', 'mbedtls', 'framework', 'CMakeLists.txt'),
    ];
    if (headers.some((header) => !existsSync(header))) {
      run('git', [
        'submodule',
        'update',
        '--init',
        '--recursive',
        '--',
        'tools/wormhole-ovpnproxy/third_party/openvpn3',
        'tools/wormhole-ovpnproxy/third_party/mbedtls',
      ]);
    }
    if (headers.some((header) => !existsSync(header)))
      throw new Error('Required OpenVPN3/mbedTLS sources are missing.');
    const sdk = run('xcrun', ['--sdk', 'macosx', '--show-sdk-path'], {
      stdio: 'pipe',
    }).stdout.trim();
    if (!sdk) throw new Error('Could not resolve the installed macOS SDK.');
    env.SDKROOT = sdk;
    const patches = readdirSync(path.join(source, 'patches'))
      .filter((name) => name.endsWith('.patch'))
      .sort();
    if (!patches.length) throw new Error('Required OpenVPN3 patches are missing.');
    for (const name of patches) {
      const patch = path.join(source, 'patches', name);
      const args = ['-C', openvpn, 'apply'];
      const alreadyApplied = execute('git', [...args, '--reverse', '--check', patch], {
        stdio: 'pipe',
      });
      if (!alreadyApplied.error && alreadyApplied.status === 0) continue;
      run('git', [...args, '--check', patch]);
      run('git', [...args, patch]);
      applied.push(patch);
    }
    run('cmake', [
      '-S',
      shim,
      '-B',
      build,
      '-G',
      'Ninja',
      '-DCMAKE_BUILD_TYPE=Release',
      '-DBUILD_SHARED_LIBS=OFF',
      '-DWORMHOLE_REQUIRE_OPENVPN3=ON',
      '-DCMAKE_C_COMPILER=clang',
      '-DCMAKE_CXX_COMPILER=clang++',
      `-DCMAKE_OSX_ARCHITECTURES=${architecture === 'x64' ? 'x86_64' : 'arm64'}`,
      `-DCMAKE_OSX_SYSROOT=${sdk}`,
      '-DCMAKE_OSX_DEPLOYMENT_TARGET=12.0',
      `-DCMAKE_TOOLCHAIN_FILE=${path.join(vcpkg, 'scripts', 'buildsystems', 'vcpkg.cmake')}`,
      `-DVCPKG_TARGET_TRIPLET=${architecture}-osx`,
    ]);
    run('cmake', [
      '--build',
      build,
      '--config',
      'Release',
      '--target',
      'ovpn_shim',
      '--parallel',
      '2',
    ]);

    // External archives are not part of Go's cgo cache key. Stamp the full static
    // dependency set so a changed C++ engine or TLS library forces a fresh link.
    const archives = [
      path.join(build, 'libovpn_shim.a'),
      ...['mbedtls', 'mbedx509', 'mbedcrypto'].map((name) =>
        path.join(build, 'third_party_mbedtls', 'library', `lib${name}.a`),
      ),
      ...['lz4', 'jsoncpp'].map((name) =>
        path.join(build, 'vcpkg_installed', `${architecture}-osx`, 'lib', `lib${name}.a`),
      ),
    ];
    const hash = createHash('sha256').update(architecture);
    for (const archive of archives) hash.update(readFileSync(archive));
    writeFileSync(
      path.join(source, 'shim_buildinfo.go'),
      `// Code generated by build-macos-ovpnproxy.mjs. DO NOT EDIT.\npackage main\nconst shimArchiveHash = "${hash.digest('hex')}"\n`,
    );
    run('go', ['build', '-trimpath', '-tags', 'ovpn3', '-ldflags', '-s -w', '-o', temporary, '.'], {
      cwd: source,
    });
    if (readFileSync(temporary).includes(Buffer.from('binding not linked'))) {
      throw new Error('Refusing to stage a mock-only OpenVPN sidecar.');
    }
    run('lipo', [temporary, '-verify_arch', architecture === 'x64' ? 'x86_64' : 'arm64']);
    const libraries = run('otool', ['-L', temporary], { stdio: 'pipe' })
      .stdout.trim()
      .split('\n')
      .slice(1);
    if (
      !libraries.length ||
      libraries.some((line) => !/^\s*\/(usr\/lib\/|System\/Library\/)/.test(line))
    ) {
      throw new Error('OpenVPN sidecar must depend only on macOS system libraries.');
    }
    if (architecture === hostArchitecture) {
      // Invalid, nonempty profile reaches the native parser without opening a network socket.
      const probe = execute(temporary, [], {
        stdio: 'pipe',
        timeout: 10000,
        input: `${JSON.stringify({ profile_ovpn: 'wormhole-invalid-profile\n', mock: false })}\n`,
      });
      if (probe.error || probe.status !== 1 || !probe.stderr.includes('ovpn_load_profile failed')) {
        throw new Error('OpenVPN engine smoke test did not reach the native profile parser.');
      }
    }
  } catch (error) {
    failure = error;
  } finally {
    // Never undo patches that were already present in a developer checkout.
    for (const patch of applied.reverse()) {
      const result = execute('git', ['-C', openvpn, 'apply', '--reverse', patch]);
      if (result.error || result.status !== 0) restorationFailures.push(path.basename(patch));
    }
  }
  if (restorationFailures.length) {
    failure = new Error(
      `${failure ? `${failure.message} ` : ''}Could not restore OpenVPN3 build patches: ${restorationFailures.join(', ')}`,
      { cause: failure },
    );
  }
  if (failure) {
    throw failure;
  }
  renameSync(temporary, output);
  return output;
}
