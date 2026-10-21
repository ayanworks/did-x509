# Contributing to did-x509

Thank you for your interest in contributing to the did-x509 reference implementations!

## About This Repository

This repository provides reference implementations for the [did:x509](https://www.w3.org/TR/did-x509/) specification in TypeScript. It was originally created by Microsoft and is maintained as an open-source project with contributions from the community, including the TypeScript implementations contributed by [AyanWorks](https://ayanworks.com).

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request, please [open an issue](../../issues) with:

- A clear description of the problem or suggestion
- Steps to reproduce (for bugs)
- Your environment (OS, language runtime version)

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** from `main` for your change
3. **Make your changes** following the guidelines below
4. **Run tests** to verify nothing is broken
5. **Submit a pull request** with a clear description

### Development Setup

#### TypeScript

```bash
cd typescript
npm install
npm run typecheck
npm test
npm run build
```

### Code Guidelines

- Follow existing code style and conventions in each language
- Add tests for new functionality
- Keep commits focused and write clear commit messages
- Update documentation if your change affects the public API

### Attribution

When contributing, please ensure all files include proper attribution headers as described in the repository's licensing. The TypeScript implementation includes AyanWorks attribution in every source file header — maintain this convention when adding new files.

### Releasing

Each npm package versions independently and publishes from its own tag:

| Package | Directory | Tag | Workflow |
| --- | --- | --- | --- |
| `@didx509/core` | `typescript/` | `core-v0.1.0` | [`publish.yml`](.github/workflows/publish.yml) |
| `@didx509/credo` | `typescript-credo/` | `credo-v0.1.0` | [`publish.yml`](.github/workflows/publish.yml) |
| `@didx509/native` | `typescript-native/` | `native-v0.1.0` | [`prebuild.yml`](.github/workflows/prebuild.yml) |

Tags are prefixed with the package name because the packages version
separately: a bare `v0.1.0` would be ambiguous across three packages. The
workflow fails if the tag and the manifest version disagree, so a mistyped tag
cannot publish a surprise.

#### Cutting a release

1. Bump `version` in the package's `package.json` and add a dated entry to that
   package's `CHANGELOG.md`, linking the pull requests involved.
2. Merge both to `main`.
3. Tag that commit and push the tag:

   ```bash
   git tag -s core-v0.1.1 -m "core-v0.1.1"
   git push git@github.com:ayanworks/did-x509.git core-v0.1.1
   ```

The tag is what starts the publish, and it must exist before a GitHub release
can be created — a release attaches to a tag, and the UI's tag picker only
lists tags that have been pushed. `publish.yml` creates the release for you
after a successful publish with `gh release create`, so the release page and
the published version cannot drift apart.

Two ordering rules that matter:

- **Merge before tagging.** The release notes link to the package's
  `CHANGELOG.md` on `main`, so the changelog has to be merged before the tag
  is pushed or the link in the release notes is a 404.
- **Tag only one package per release.** Publish `@didx509/core` before
  `@didx509/credo`, since credo depends on it.

The release is a separate job from the publish, so if creating the release
fails you can re-run just that job. A re-run of the whole workflow would stop
at `npm publish` instead, because the version is already on npm.

#### When a `core` change forces a `credo` release

`@didx509/credo` depends on `@didx509/core`, and the dependency is a `file:`
link during development. The publish job rewrites it to `^<core version>` on a
throwaway copy of the manifest, so the committed `package.json` keeps the link.

Because that range is `^`-based, the two packages are coupled in one direction:

| `core` bump | Effect on `credo` | Action |
| --- | --- | --- |
| `patch` (`0.1.0` → `0.1.1`) | `^0.1.0` already matches | None — credo picks it up automatically. No credo release needed. |
| `minor` (`0.1.0` → `0.2.0`) | **`^0.1.0` does not match** — semver treats `0.x` minors as breaking | Release `credo` too, so its range is rewritten to `^0.2.0`. |
| `major` | Same as minor, once past `1.0.0` | Release `credo` too. |

While all packages are `0.x`, a `core` minor is a breaking change for credo.
If in doubt, check what the rewrite would produce:

```bash
cd typescript-credo
node -p "'^' + require('../typescript/package.json').version"
```

#### Publishing access

Publishing uses npm trusted publishing (OIDC), so no `NPM_TOKEN` secret is
needed. Configure a trusted publisher for each package on npmjs.com
(Packages → the package → Settings → Trusted publishing), naming this
repository, the `publish.yml` workflow (`prebuild.yml` for
`@didx509/native`), and allowing `npm publish`.

A trusted publisher can only be configured once a package exists on npm, and a
new configuration expires after two days without a successful publish — so add
it close to the release that will use it.


## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
