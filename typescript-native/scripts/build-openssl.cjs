#!/usr/bin/env node
// Copyright (c) AyanWorks. Licensed under the MIT License.
//
// Builds a static OpenSSL from source, for CI machines whose system
// OpenSSL is too old (didx509cpp requires >= 3.3; Ubuntu 24.04 ships 3.0).
// On Windows the build prefers jom (parallel nmake) and falls back to
// serial nmake when jom is not installed.
//
// Usage:
//   node scripts/build-openssl.js [--prefix <dir>]
//
// Defaults to `<package root>/.openssl`, which CMakeLists.txt picks up
// automatically. The build is idempotent: if the prefix already contains
// OpenSSL, nothing happens (CI additionally caches the prefix directory).
//
// Environment:
//   OPENSSL_VERSION  source version to build (default 3.6.5)

'use strict';

const { spawnSync } = require('child_process');
const { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } = require('fs');
const { tmpdir } = require('os');
const os = require('os');
const path = require('path');

const version = process.env.OPENSSL_VERSION || '3.6.5';
const packageRoot = path.join(__dirname, '..');

function parsePrefix() {
  const index = process.argv.indexOf('--prefix');
  if (index !== -1 && process.argv[index + 1]) {
    return path.resolve(process.argv[index + 1]);
  }
  return path.join(packageRoot, '.openssl');
}

function fail(message) {
  console.error(`build-openssl: ${message}`);
  process.exit(1);
}

function run(command, args, options) {
  const result = spawnSync(command, args, {
    stdio: ['ignore', 'inherit', 'inherit'],
    ...options,
  });
  if (result.error) {
    fail(`${command} failed to launch: ${result.error.message}`);
  }
  if (result.status !== 0) {
    fail(`${command} ${args.join(' ')} failed (exit ${result.status})`);
  }
}

// Locate an executable on PATH. On Windows, PATH may point at executables
// whose actual name is lowercase (perl.exe) while PATHEXT says .EXE.
//
// The literal name is tried first, then PATHEXT-suffixed variants. This
// matters because callers may pass an already-qualified name (jom.exe) and
// standard PATHEXT does not end with ';' — appending extensions blindly
// would then only ever produce jom.exe.exe, jom.exe.cmd, ... and never
// match the file that exists.
function findInPath(name) {
  const variants = [name];
  if (process.platform === 'win32') {
    const exts = (process.env.PATHEXT || '.EXE;.CMD;.BAT')
      .toLowerCase()
      .split(';')
      .filter(Boolean);
    for (const ext of exts) {
      if (!name.toLowerCase().endsWith(ext)) variants.push(name + ext);
    }
  }
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const variant of variants) {
      const candidate = path.join(dir, variant);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

// Windows: Git's bundled msys perl is too minimal for OpenSSL's Configure
// (missing core modules such as Locale::Maketext::Simple), and depending on
// PATH order it can win over Strawberry Perl — pick Strawberry explicitly.
function findPerl() {
  if (process.platform !== 'win32') return 'perl';
  for (const dir of (process.env.PATH || '').split(';')) {
    if (/strawberry[\\/]perl/i.test(dir)) {
      const exe = path.join(dir, 'perl.exe');
      if (existsSync(exe)) return exe;
    }
  }
  return findInPath('perl') || 'perl';
}

// Windows: locate vcvarsall.bat (VS 2022+ layout) so we can bootstrap the
// MSVC toolchain explicitly. ilammy/msvc-dev-cmd already sets this env on CI,
// but sourcing it ourselves keeps source builds working on plain shells too.
function findVcvarsall() {
  const vswhere =
    'C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe';
  if (existsSync(vswhere)) {
    const found = spawnSync(
      vswhere,
      ['-latest', '-products', '*', '-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
        '-property', 'installationPath'],
      { encoding: 'utf8' }
    ).stdout?.trim();
    if (found) {
      const candidate = path.join(found, 'VC', 'Auxiliary', 'Build',
        'vcvarsall.bat');
      if (existsSync(candidate)) return candidate;
    }
  }
  return findInPath('vcvarsall.bat');
}

// Windows: Git for Windows ships a POSIX `link` (coreutils) in usr\bin that
// shadows MSVC's link.exe, so OpenSSL's nmake dies with "link: extra operand
// '/dll'" when it shells out. Running the build through cmd.exe with the
// MSVC dev environment ensures cl.exe/link.exe/lib.exe resolve correctly.
//
// nmake is single-threaded, which makes the build take ~12 minutes. jom is
// a drop-in nmake replacement with parallelism (`jom -j<N>`); we prefer it
// when it is on PATH (CI installs it via chocolatey) and fall back to nmake.
function msvcMake(vcvarsall, makeArgs, cwd) {
  const args = Array.isArray(makeArgs) ? makeArgs : String(makeArgs).split(/\s+/).filter(Boolean);
  // Prefer the nmake that ships with the same MSVC install as vcvarsall
  // (VCINSTALLDIR is set by ilammy/msvc-dev-cmd on CI); fall back to PATH so
  // plain shells still work. This avoids grabbing a non-MSVC nmake that may
  // sit earlier on PATH.
  let nmake = null;
  if (process.env.VCINSTALLDIR) {
    const candidate = path.join(
      process.env.VCINSTALLDIR, 'Tools', 'MSVC',
      process.env.VCToolsVersion || '', 'bin', 'HostX64', 'x64', 'nmake.exe'
    );
    if (existsSync(candidate)) nmake = candidate;
  }
  if (!nmake) nmake = findInPath('nmake.exe');
  if (!vcvarsall || !nmake) {
    fail('could not locate vcvarsall.bat or nmake.exe for the MSVC toolchain');
  }
  const jom = findInPath('jom.exe') || findInPath('jom.cmd');
  const jobs = Math.max(1, os.cpus().length);
  const make = jom ? `"${jom}" -j${jobs}` : `"${nmake}"`;
  console.log(
    jom
      ? `build-openssl: building with jom -j${jobs} (parallel)`
      : 'build-openssl: jom not found — building with nmake (serial; ' +
        'install jom for a much faster build)'
  );
  const tail = args.length ? ` ${args.join(' ')}` : '';
  const command = `call "${vcvarsall}" x64 >nul && ${make}${tail}`;
  // windowsVerbatimArguments is essential: without it libuv assembles the
  // command line itself and escapes inner quotes as \" — which cmd.exe does
  // not understand (it treats the backslashes literally), so the quoted
  // paths end up as literal '"...\vcvarsall.bat\"' filenames and are not
  // found. Verbatim mode passes our string through untouched, so cmd sees
  // exactly `call "C:\...\vcvarsall.bat" x64 >nul && "C:\...\jom.exe" -j4`.
  // Full path to cmd.exe: spawnSync does not resolve it from PATH reliably.
  const cmd = process.env.ComSpec || 'C:\\Windows\\System32\\cmd.exe';
  run(cmd, ['/d', '/s', '/c', command], {
    cwd,
    windowsVerbatimArguments: true,
  });
}

const prefix = parsePrefix();
const header = path.join(prefix, 'include', 'openssl', 'ssl.h');

if (existsSync(header)) {
  console.log(`build-openssl: reusing cached OpenSSL at ${prefix}`);
  process.exit(0);
}

console.log(`build-openssl: building OpenSSL ${version} into ${prefix}`);

mkdirSync(prefix, { recursive: true });

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------
const workDir = mkdtempSync(path.join(tmpdir(), 'didx509-openssl-'));
const tarball = path.join(workDir, `openssl-${version}.tar.gz`);
const urls = [
  `https://github.com/openssl/openssl/releases/download/openssl-${version}/openssl-${version}.tar.gz`,
  `https://www.openssl.org/source/openssl-${version}.tar.gz`,
];

(async () => {
  let downloaded = false;
  for (const url of urls) {
    try {
      console.log(`build-openssl: downloading ${url}`);
      const response = await fetch(url, { redirect: 'follow' });
      if (!response.ok) {
        continue;
      }
      writeFileSync(tarball, Buffer.from(await response.arrayBuffer()));
      downloaded = true;
      break;
    } catch (error) {
      console.warn(`build-openssl: download failed: ${error.message}`);
    }
  }
  if (!downloaded) {
    fail(
      `could not download OpenSSL ${version}. ` +
        'Check network access or set OPENSSL_VERSION to an available release.'
    );
  }

  // ---------------------------------------------------------------------------
  // Extract + configure + build
  // ---------------------------------------------------------------------------
  // Use a *relative* filename inside workDir: on Windows, GNU tar (from
  // Git for Windows) parses absolute paths like C:\... as remote host
  // syntax ("host:path") and fails.
  run('tar', ['-xzf', path.basename(tarball)], { cwd: workDir });
  const sourceDir = path.join(workDir, `openssl-${version}`);
  if (!existsSync(path.join(sourceDir, 'Configure'))) {
    fail('extracted archive did not contain an OpenSSL source tree');
  }

  const commonArgs = [
    `--prefix=${prefix}`,
    `--openssldir=${path.join(prefix, 'ssl')}`,
    'no-shared',
    'no-tests',
    'no-docs',
  ];

  if (process.platform === 'win32') {
    const winArgs = [...commonArgs];
    if (!findInPath('nasm')) {
      // Not every runner ships NASM; Configure without assembly still
      // produces a correct (just less optimized) libcrypto.
      console.warn('build-openssl: nasm not found — configuring with no-asm');
      winArgs.push('no-asm');
    }
    run(findPerl(), ['Configure', 'VC-WIN64A', ...winArgs], { cwd: sourceDir });
    // Build via cmd.exe + vcvarsall: Git Bash's POSIX `link` (coreutils)
    // otherwise shadows MSVC's link.exe and OpenSSL's nmake link step fails.
    const vcvarsall = findVcvarsall();
    msvcMake(vcvarsall, [], sourceDir);
    msvcMake(vcvarsall, ['install_sw'], sourceDir);
  } else {
    // ./config auto-detects the platform (linux-x86_64, darwin64-*,
    // linux-aarch64, ...). Cross builds can override with OPENSSL_TARGET.
    const configureScript = process.env.OPENSSL_TARGET ? 'Configure' : 'config';
    const configureArgs = process.env.OPENSSL_TARGET
      ? [process.env.OPENSSL_TARGET, ...commonArgs]
      : commonArgs;
    run('perl', [configureScript, ...configureArgs], { cwd: sourceDir });
    const jobs = String(os.cpus().length);
    run('make', [`-j${jobs}`], { cwd: sourceDir });
    run('make', ['install_sw'], { cwd: sourceDir });
  }

  if (!existsSync(header)) {
    fail(`build finished but ${header} is missing`);
  }

  rmSync(workDir, { recursive: true, force: true });
  console.log(`build-openssl: done — set OPENSSL_ROOT_DIR=${prefix} (picked up automatically by this package's CMakeLists.txt)`);
})().catch((error) => fail(error.stack || String(error)));
