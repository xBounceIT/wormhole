import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { parse } from 'yaml';
import {
  buildMacFreeRdp,
  freeRdpRevision,
  verifyMacFreeRdp,
} from '../scripts/build-macos-freerdp.mjs';

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'wormhole rdp '));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const write = (relative, content = 'fixture') => {
    const file = path.join(root, relative);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, content);
    return file;
  };
  write('vcpkg/scripts/buildsystems/vcpkg.cmake');
  const calls = [];
  const spawn = (command, args, options) => {
    calls.push({ command, args, options });
    let stdout = '';
    if (command === 'git' && args[0] === 'clone') {
      write('obj/freerdp-source/LICENSE', 'FreeRDP license');
      write('obj/freerdp-source/resources/font/OFL.txt', 'OpenSans license');
      write('obj/freerdp-source/NOTICE', 'FreeRDP notice');
    }
    if (command === 'git' && args.includes('rev-parse')) stdout = `${freeRdpRevision}\n`;
    if (command === 'lipo' && args[0] === '-create') writeFileSync(args.at(-1), 'universal');
    if (command === 'otool')
      stdout = `${args.at(-1)}:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit (compatibility version 1.0.0)\n`;
    return { status: 0, stdout, stderr: '' };
  };
  write('obj/macos-freerdp/installed/arm64-osx/arm64-osx/share/sdl3/copyright', 'SDL license');
  write('obj/macos-freerdp/installed/arm64-osx/arm64-osx/share/no-license/config');
  write('obj/macos-freerdp/installed/arm64-osx/arm64-osx/share/not-a-directory');
  return {
    root,
    write,
    calls,
    spawn,
    options: { repoRoot: root, platform: 'darwin', vcpkgRoot: path.join(root, 'vcpkg'), spawn },
  };
}

test('builds and verifies both static slices and ships a relocatable signed client with licenses', (t) => {
  const f = fixture(t);
  const binary = buildMacFreeRdp(f.options);
  assert.equal(readFileSync(binary, 'utf8'), 'universal');
  const configs = f.calls.filter(({ command, args }) => command === 'cmake' && args[0] === '-S');
  assert.equal(configs.length, 2);
  for (const [i, arch] of ['x86_64', 'arm64'].entries()) {
    assert.ok(configs[i].args.includes(`-DCMAKE_OSX_ARCHITECTURES=${arch}`));
    for (const flag of [
      '-DBUILD_SHARED_LIBS=OFF',
      '-DWITH_SDL_LINK_SHARED=OFF',
      '-DWITH_CLIENT_SDL3=ON',
      '-DOPENSSL_USE_STATIC_LIBS=TRUE',
      '-DWITH_FREERDP_DEPRECATED_COMMANDLINE=ON',
    ]) {
      assert.ok(configs[i].args.includes(flag));
    }
  }
  assert.equal(f.calls.filter(({ command }) => command === 'otool').length, 2);
  assert.ok(f.calls.some(({ command, args }) => command === 'codesign' && args.includes('-')));
  assert.equal(
    readFileSync(path.join(path.dirname(binary), 'licenses', 'sdl3.txt'), 'utf8'),
    'SDL license',
  );
  assert.equal(
    readFileSync(path.join(path.dirname(binary), 'licenses', 'FreeRDP-NOTICE.txt'), 'utf8'),
    'FreeRDP notice',
  );
  // Existing source checkout, absent optional NOTICE, and replacement of a previous build.
  rmSync(path.join(f.root, 'obj/freerdp-source/NOTICE'));
  f.calls.length = 0;
  buildMacFreeRdp(f.options);
  assert.ok(!f.calls.some(({ args }) => args[0] === 'clone'));
  assert.ok(!existsSync(path.join(path.dirname(binary), 'licenses', 'FreeRDP-NOTICE.txt')));
});

test('both SDKs survive manifest installs for later canvas adapter builds', (t) => {
  const f = fixture(t);
  const installedTriplets = new Map();
  const configuredSdks = [];
  const option = (args, prefix) => args.find((arg) => arg.startsWith(prefix))?.slice(prefix.length);
  const spawn = (command, args, options) => {
    if (command.endsWith('vcpkg') && args[0] === 'install') {
      // vcpkg manifest mode synchronizes each install root to the current triplet.
      installedTriplets.set(option(args, '--x-install-root='), option(args, '--triplet='));
    }
    if (command === 'cmake' && args[0] === '-S') {
      const root = option(args, '-DVCPKG_INSTALLED_DIR=');
      const triplet = option(args, '-DVCPKG_TARGET_TRIPLET=');
      assert.equal(installedTriplets.get(root), triplet);
      configuredSdks.push({ root, triplet });
    }
    return f.spawn(command, args, options);
  };
  buildMacFreeRdp({ ...f.options, spawn });
  assert.equal(configuredSdks.length, 2);
  for (const { root, triplet } of configuredSdks) {
    assert.equal(installedTriplets.get(root), triplet, `${triplet} SDK must remain available`);
  }
});

test('rejects unsupported hosts and missing toolchains before building', (t) => {
  const f = fixture(t);
  assert.throws(() => buildMacFreeRdp({ ...f.options, platform: 'win32' }), /on macOS/);
  assert.throws(() => buildMacFreeRdp({ ...f.options, vcpkgRoot: '' }), /pinned, bootstrapped/);
  assert.throws(() => buildMacFreeRdp({ ...f.options, vcpkgRoot: f.root }), /pinned, bootstrapped/);
  assert.equal(f.calls.length, 0);
});

test('a failed toolchain check invalidates staging and releases its lock for retry', (t) => {
  const f = fixture(t);
  const staged = f.write('dist-electron/freerdp/sdl-freerdp', 'stale');
  assert.throws(() => buildMacFreeRdp({ ...f.options, vcpkgRoot: '' }), /pinned, bootstrapped/);
  assert.ok(!existsSync(staged));
  assert.ok(!existsSync(path.join(f.root, 'obj/macos-freerdp-build.lock')));
  assert.ok(existsSync(buildMacFreeRdp(f.options)));
});

test('overlapping builds cannot delete output or the lock owned by another invocation', (t) => {
  const f = fixture(t);
  const lock = path.join(f.root, 'obj/macos-freerdp-build.lock');
  let attempted = false;
  const spawn = (command, args, options) => {
    if (!attempted && command === 'cmake') {
      attempted = true;
      const marker = f.write('dist-electron/freerdp/build-owner', 'owned');
      assert.throws(() => buildMacFreeRdp(f.options), /build lock exists/);
      assert.equal(readFileSync(marker, 'utf8'), 'owned');
      assert.equal(readFileSync(path.join(lock, 'owner-pid'), 'utf8'), `${process.pid}\n`);
      rmSync(path.dirname(marker), { recursive: true });
    }
    return f.spawn(command, args, options);
  };
  assert.ok(existsSync(buildMacFreeRdp({ ...f.options, spawn })));
  assert.ok(attempted);
  assert.ok(!existsSync(lock));
});

test('relative toolchains and workspace roots are made absolute for every subprocess', (t) => {
  const f = fixture(t);
  buildMacFreeRdp({
    ...f.options,
    repoRoot: path.relative(process.cwd(), f.root),
    vcpkgRoot: path.relative(process.cwd(), f.options.vcpkgRoot),
  });
  const calls = f.calls.filter(({ command }) => command === 'cmake' || command.endsWith('vcpkg'));
  for (const { options } of calls) {
    assert.equal(options.cwd, f.root);
    assert.equal(options.env.VCPKG_ROOT, f.options.vcpkgRoot);
  }
  for (const { args } of calls.filter(({ args }) => args[0] === '-S')) {
    assert.ok(
      args.includes(
        `-DCMAKE_TOOLCHAIN_FILE=${path.join(f.options.vcpkgRoot, 'scripts', 'buildsystems', 'vcpkg.cmake')}`,
      ),
    );
  }
});

test('a pinned checkout with real local changes is rejected without discarding them', (t) => {
  for (const dirty of ['tracked', 'untracked']) {
    const f = fixture(t);
    const source = path.join(f.root, 'obj/freerdp-source');
    let revision;
    const git = (args) =>
      execFileSync('git', ['-C', source, ...args], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    const spawn = (command, args, options) => {
      if (command === 'git' && args[0] === 'clone') {
        f.spawn(command, args, options);
        git(['init']);
        git(['add', '.']);
        git([
          '-c',
          'user.name=Fixture',
          '-c',
          'user.email=fixture@example.invalid',
          'commit',
          '-m',
          'fixture',
        ]);
        revision = git(['rev-parse', 'HEAD']).trim();
        f.write(
          `obj/freerdp-source/${dirty === 'tracked' ? 'LICENSE' : 'untracked.c'}`,
          'local changes',
        );
        return { status: 0, stdout: '' };
      }
      if (command === 'git' && args.includes('checkout')) {
        return { status: 0, stdout: git(['checkout', '--detach', revision]) };
      }
      if (command === 'git' && args.includes('status')) {
        return { status: 0, stdout: git(args.slice(2)) };
      }
      return f.spawn(command, args, options);
    };
    assert.throws(
      () => buildMacFreeRdp({ ...f.options, spawn }),
      /source checkout has local changes/,
    );
    assert.equal(
      readFileSync(path.join(source, dirty === 'tracked' ? 'LICENSE' : 'untracked.c'), 'utf8'),
      'local changes',
    );
    assert.ok(!f.calls.some(({ command }) => command === 'cmake'));
    assert.ok(!existsSync(path.join(f.root, 'obj/macos-freerdp-build.lock')));
  }
});

test('failed builds cannot leave a stale client available for packaging', (t) => {
  for (const failure of ['spawn', 'configure', 'revision', 'dependency', 'architecture', 'sign']) {
    const f = fixture(t);
    const staged = f.write('dist-electron/freerdp/sdl-freerdp', 'stale');
    const spawn = (command, args) => {
      if (failure === 'spawn') return { error: new Error('missing tool') };
      if (failure === 'configure' && command === 'cmake')
        return { status: 1, stderr: 'configure failed' };
      if (failure === 'revision' && args.includes('rev-parse'))
        return { status: 0, stdout: 'wrong' };
      if (failure === 'dependency' && command === 'otool')
        return { status: 0, stdout: 'client:\n\t/opt/homebrew/lib/libssl.dylib (version 1)\n' };
      if (failure === 'architecture' && args.includes('-verify_arch'))
        return { status: 1, stdout: 'missing Intel slice' };
      if (failure === 'sign' && command === 'codesign')
        return { status: null, stderr: 'terminated' };
      return f.spawn(command, args);
    };
    assert.throws(
      () => buildMacFreeRdp({ ...f.options, spawn }),
      /Could not start|failed|revision|unbundled/,
    );
    assert.ok(!existsSync(staged), failure);
    assert.ok(!existsSync(path.join(f.root, 'obj/macos-freerdp-build.lock')), failure);
  }
});

test('packaging rejects missing clients, empty inspection, relative libraries, and failures in either slice', (t) => {
  const f = fixture(t);
  assert.throws(() => verifyMacFreeRdp(f.root, { spawn: f.spawn }), /client is missing/);
  f.write('freerdp/sdl-freerdp');
  for (const dependency of ['', '@rpath/libssl.dylib', '/usr/local/lib/libSDL3.dylib']) {
    const spawn = (command, args) =>
      command === 'otool'
        ? { status: 0, stdout: `client:\n${dependency ? `\t${dependency} (version 1)\n` : ''}` }
        : f.spawn(command, args);
    assert.throws(() => verifyMacFreeRdp(f.root, { spawn }), /no libraries|unbundled/);
  }
  const spawn = (command, args) =>
    command === 'otool' && args.includes('arm64')
      ? { status: 1, stderr: 'bad ARM slice' }
      : f.spawn(command, args);
  assert.throws(() => verifyMacFreeRdp(f.root, { spawn }), /bad ARM slice/);
});

test('release, native CI, resource inclusion, and dependency pins stay connected', () => {
  const read = (file) => readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
  const pkg = JSON.parse(read('package.json'));
  const release = parse(read('.github/workflows/release.yml'));
  const steps = Object.values(release.jobs).flatMap((job) => job.steps || []);
  const buildIndex = steps.findIndex((step) => step.run === 'npm run build:rdp:macos');
  assert.ok(buildIndex >= 0);
  assert.ok(steps.slice(buildIndex + 1).some((step) => step.run?.includes('npm run package')));
  assert.equal(steps[buildIndex].if, "matrix.builder_platform == 'mac'");
  assert.ok(
    pkg.build.mac.extraResources.some(
      (entry) => entry.from === 'dist-electron/freerdp' && entry.to === 'freerdp',
    ),
  );
  assert.match(pkg.scripts['test:packaging'], /macos-rdp-build.test.mjs/);
  const ci = parse(read('.github/workflows/ci.yml'));
  assert.ok(ci.jobs['macos-rdp'].steps.some((step) => step.run?.includes('PATH=/usr/bin:/bin')));
  assert.ok(
    ci.jobs['macos-rdp'].steps.some((step) =>
      step.run?.includes('WORMHOLE_RDP_SMOKE_CLIENT=$destination/freerdp/sdl-freerdp'),
    ),
  );
  assert.ok(
    ci.jobs['macos-rdp'].steps.some((step) =>
      step.run?.includes('TestBundledMacFreeRdpCommandLine'),
    ),
  );
  const smokeIndex = steps.findIndex((step) =>
    step.run?.includes('TestBundledMacFreeRdpCommandLine'),
  );
  assert.ok(smokeIndex > buildIndex);
  assert.ok(steps.slice(smokeIndex + 1).some((step) => step.run?.includes('npm run package')));
  assert.equal(steps[smokeIndex].if, "matrix.builder_platform == 'mac'");
  assert.match(
    steps[smokeIndex].env.WORMHOLE_RDP_SMOKE_CLIENT,
    /dist-electron\/freerdp\/sdl-freerdp$/,
  );
  const setup = parse(read('.github/actions/setup-macos-rdp/action.yml'));
  assert.equal(setup.runs.steps[0].with['fetch-depth'], 0);
  const manifest = JSON.parse(read('tools/macos-freerdp/vcpkg.json'));
  for (const [triplet, architecture] of [
    ['x64-osx', 'x86_64'],
    ['arm64-osx', 'arm64'],
  ]) {
    // VCPKG_TARGET_ARCHITECTURE alone does not set CMake's macOS compiler target.
    const config = read(`tools/macos-freerdp/triplets/${triplet}.cmake`);
    assert.ok(config.includes(`set(VCPKG_OSX_ARCHITECTURES ${architecture})`));
  }
  // FreeRDP 3.33.0 references unavailable SDL events when headers report 3.4.20.
  // A native CI build must validate any change to this compatibility pair.
  assert.deepEqual(manifest.overrides, [{ name: 'sdl3', version: '3.4.18' }]);
  assert.equal(setup.runs.steps[0].with.ref, manifest['builtin-baseline']);
});
