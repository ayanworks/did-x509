import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/cli.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2022',
  splitting: false,
  minify: false,
  // `src/node-crypto.ts` reads `import.meta.url` for its ESM branch and
  // `__filename` for its CJS branch, guarded by a runtime format check. In the
  // CommonJS output esbuild rewrites that `import.meta` to `{}` and warns that
  // it "is not available with the cjs output format" — but the line is
  // unreachable there, because `typeof __filename === 'string'` returns first,
  // so the warning is noise on every build and publish. `logOverride` quiets
  // just that one message; the behaviour is unchanged and still covered by the
  // tests for both formats.
  esbuildOptions(options) {
    options.logOverride = { ...options.logOverride, 'empty-import-meta': 'silent' };
  },
});
