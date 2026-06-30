# Contributing to VaultGuard

VaultGuard public artifacts are fair-code under Sustainable Use License terms.
Contributions land in the public monorepo at
https://github.com/peter70700/vaultguard-obsidian.

## Code of Conduct

Be excellent to each other. Report serious conduct issues to peter@sedmak.sk.

## How to Contribute

1. Open an issue describing the bug or proposal before opening a PR for anything
   non-trivial. The maintainer (single-developer project for v1) will confirm scope
   and direction.
2. Fork the public repo (`peter70700/vaultguard-obsidian`).
3. Create a topic branch off `main`. Use a short, descriptive name (e.g.
   `fix/lease-renewal-timing`, `docs/self-hosting-typo`).
4. Make focused, atomic commits. One concern per commit; keep diffs reviewable.
5. Open a PR against `main`. The required `build-test-lint` status check must pass
   (lint + typecheck + vitest, see `.github/workflows/ci.yml`).
6. Sign-off / DCO is NOT required at this time (no CLA — see PROJECT.md).

### Commit Message Style

Follow `type(scope): subject` (Conventional-Commits-ish; observed throughout the
existing history):

- `feat(scope): ...` — new functionality
- `fix(scope): ...` — bug fix
- `docs(scope): ...` — documentation
- `refactor(scope): ...` — restructure without behavior change
- `test(scope): ...` — test changes only
- `chore(scope): ...` — build / tooling / dependencies

Scope is the affected area (e.g. `sync`, `auth`, `terraform`, `ci`).

### Pre-PR Checks (required to pass locally)

```bash
npm install
npm run lint       # biome check .
npm run typecheck  # tsc -noEmit -skipLibCheck
npm test           # vitest run
```

`npm run lint:fix` (`biome check --write .`) auto-fixes the formatting/lint
issues Biome can fix safely. Run it before committing if your editor doesn't.

The `build-test-lint` job in `.github/workflows/ci.yml` enforces all four checks
on every PR — keep your local run green before pushing.

### Documentation Changes

Use [docs/INDEX.md](docs/INDEX.md) as the canonical documentation map. When a
change affects vault scoping, file APIs, permissions, auth, security posture,
operations, testing, or release behavior, update the relevant docs in the same
PR and prefer repository-backed statements over roadmap language.

For file, permission, audit, and share-link APIs, keep
[docs/VAULTS.md](docs/VAULTS.md) and [docs/API.md](docs/API.md) aligned with the
handlers. Every file/permission API path must remain under
`/vaults/{vaultId}/...`; root `/files/*` and `/permissions/*` routes are not part
of the current contract.

## Release Ritual (maintainer)

VaultGuard plugin releases use **bare semver tags** (`1.0.0`, `1.0.1`, etc.) — not
`plugin-v1.0.0`. This is a hard requirement of the Obsidian community plugin
directory: the GitHub release tag must equal `manifest.json:version` exactly.

Three steps + a push:

1. `npm run version` — bumps `manifest.json` and `versions.json` (driven by the
   existing `version-bump.mjs`). Stages both files.
2. `npm version patch | minor | major` — bumps root `package.json` and creates a
   local git tag at the new bare-semver version. Picks `patch` / `minor` / `major`
   according to semver.
3. `npm run publish:public-monorepo` — re-exports the public monorepo via the
   validator-gated pipeline, then pushes the resulting commit to
   `peter70700/vaultguard-obsidian` `main`.
4. Push the tag to the public repo to trigger `.github/workflows/plugin-release.yml`,
   which builds and attaches `main.js`, `manifest.json`, `styles.css` to a new
   GitHub release.

(Step 3's `publish:public-monorepo` re-exports first, so the pushed bytes are
validator-clean by construction. The `build-test-lint` CI job then runs against
the new commit on the public repo.)

> Note: D-36 in the Phase 3 context locks the three logical steps (version → tag
> → push). In practice the public monorepo also requires `npm run
> publish:public-monorepo` between steps 2 and 3 to sync the new commit to the
> public repo before the tag push triggers `plugin-release.yml`. This expansion
> is operational, not a contract change.

## Branch Protection

`main` on the public repo is protected:

- Required status check: `build-test-lint` (the single CI job in
  `.github/workflows/ci.yml`)
- Linear history required (no merge commits — squash or rebase only)
- Force-pushes blocked

If you need to undo a bad commit, use `git revert` and submit it as a PR — do NOT
force-push to `main`. See `docs/REPO-MAINTENANCE.md` for the maintainer click-path
to (re-)enable these rules.

## Reporting Security Issues

Privately email peter@sedmak.sk. Do NOT open a public issue for security-sensitive
reports. See `SECURITY.md` if present.
