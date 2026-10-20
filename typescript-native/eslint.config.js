// Copyright (c) AyanWorks. Licensed under the MIT License.
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/', 'build/', 'prebuilds/', 'coverage/', 'third_party/'] },
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  }
);
