#!/usr/bin/env node
// Copyright (c) AyanWorks. Licensed under the MIT License.
//
// Builds a static OpenSSL from source, for CI machines whose system
// OpenSSL is too old (didx509cpp requires >= 3.3; Ubuntu 24.04 ships 3.0).
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
  if (result.status !== 0) {
    fail(`${command} ${args.join(' ')} failed (exit ${result.status})`);
  }
}

// Locate an executable on PATH. On Windows, PATH may point at executables
// whose actual name is lowercase (perl.exe) while PATHEXT says .EXE.
function findInPath(name) {
  const exts =
    process.platform === 'win32'
      ? (process.env.PATHEXT || '.EXE;.CMD;.BAT').toLowerCase().split(';')
      : [''];
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = path.join(dir, name + ext);
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
    run('nmake', [], { cwd: sourceDir });
    run('nmake', ['install_sw'], { cwd: sourceDir });
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
