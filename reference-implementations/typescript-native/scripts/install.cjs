#!/usr/bin/env node
// Copyright (c) AyanWorks. Licensed under the MIT License.
//
// Installs the native addon for @didx509/native.
//
//   1. If a prebuilt binary matches this machine, we are done.
//   2. Otherwise we compile from source with cmake-js. This needs:
//        - CMake >= 3.18
//        - a C++20 compiler
//        - OpenSSL >= 3.3 (set OPENSSL_ROOT_DIR if it lives somewhere unusual)
//
// Set npm_config_build_from_source=true (npm install --build-from-source)
// to skip the prebuilt binary and always compile.

'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const root = path.join(__dirname, '..');

const forceSourceBuild =
  process.argv.includes('--force') ||
  process.env.npm_config_build_from_source === 'true';

function fail(message) {
  console.error('\n@didx509/native: ' + message);
  console.error(
    'See docs/troubleshooting.md in the @didx509/native package for help.\n'
  );
  process.exit(1);
}

function hasUsablePrebuild() {
  if (forceSourceBuild) {
    return false;
  }
  try {
    // node-gyp-build finds a matching binary under prebuilds/ or build/
    // and throws when there is none.
    require('node-gyp-build')(root);
    return true;
  } catch {
    return false;
  }
}

function compileFromSource() {
  let cmakeJsBin;
  try {
    const pkg = require.resolve('cmake-js/package.json');
    const pkgDir = path.dirname(pkg);
    const binField = require(pkg).bin;
    const bin =
      typeof binField === 'string' ? binField : binField['cmake-js'];
    cmakeJsBin = path.join(pkgDir, bin);
  } catch {
    fail('cmake-js is not installed. Re-run npm install, or install it globally.');
    return;
  }

  console.log(
    '@didx509/native: no prebuilt binary for this platform, compiling from source ...'
  );

  const args = [cmakeJsBin, 'compile'];
  // node-addon-api may be hoisted to the consuming project's root
  // (npm/yarn), so resolve its real location at runtime instead of
  // assuming it sits next to this package.
  try {
    const napiDir = path.dirname(
      require.resolve('node-addon-api/package.json')
    );
    args.push(`--CDNODE_ADDON_API_INCLUDE=${napiDir}`);
  } catch {
    // CMake falls back to its own search paths.
  }
  if (process.env.DIDX509_STATIC_OPENSSL === '1' || process.env.DIDX509_STATIC_OPENSSL === 'ON') {
    // Required for redistributable prebuilds (CI sets this).
    args.push('--CDDIDX509_STATIC_OPENSSL=ON');
  }
  const result = spawnSync(process.execPath, args, {
    cwd: root,
    stdio: 'inherit',
    env: process.env,
  });

  if (result.status !== 0) {
    fail(
      'native build failed.\n' +
        '  You need: CMake >= 3.18, a C++20 compiler, and OpenSSL >= 3.3.\n' +
        '  macOS:   brew install cmake openssl@3\n' +
        '  Ubuntu:  sudo apt install cmake build-essential libssl-dev (OpenSSL >= 3.3 required)\n' +
        '  Windows: install CMake and OpenSSL, then set OPENSSL_ROOT_DIR.\n' +
        '  To point at a custom OpenSSL: OPENSSL_ROOT_DIR=/path/to/openssl npm install'
    );
  }
}

if (hasUsablePrebuild()) {
  if (process.env.npm_config_loglevel !== 'silent') {
    console.log('@didx509/native: using prebuilt native binary.');
  }
} else {
  compileFromSource();
}
