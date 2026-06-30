# VaultGuard Plugin Release Guide

This document covers the Obsidian plugin release only. The plugin is the
installable client that runs inside Obsidian.

> Current release operations map: [RELEASE-PROCESS.md](RELEASE-PROCESS.md).

## Release Scope

Ship one VaultGuard plugin artifact.

The same plugin supports both connection models:

| Mode | Included in plugin release | Setup path |
|------|----------------------------|------------|
| Hosted SaaS | Yes | User clicks **Continue with VaultGuard Cloud** or redeems an `obsidian://vaultguard-invite` link. The plugin ships the public Cloud API/Cognito identifiers and refreshes org-specific config after sign-in. |
| Self-hosted | Yes | User turns on manual configuration and applies a server config URL, or enters the API endpoint, organization ID, Cognito User Pool ID, and Cognito Client ID from their deployment outputs. |

Do not create separate plugin binaries for SaaS and self-hosted unless the
backend API contract diverges. Endpoint differences belong in settings, invite
links, or org config responses.

The free self-hosted public release is a plugin-only repository. It must not
include the React web admin panel, landing page, SaaS billing scripts,
Terraform/Lambda infrastructure, or customer-specific deployment material.

## Included Features

The plugin release includes:

- Hosted Cloud login without requiring an org slug.
- Hosted org-slug auto-configuration.
- Invite-link redemption for first-time users.
- Manual self-hosted configuration.
- Cognito login, password reset, and MFA handling.
- Permission-aware file visibility and file actions.
- Encrypted local cache and key lease lifecycle.
- Sync, conflict handling, status bar, and permission indicators.
- In-plugin admin views for users, permissions, audit, settings, and recovery.

## Not Included

The Obsidian plugin release does not include:

- SaaS backend deployment.
- Self-hosted AWS/Terraform infrastructure deployment.
- Admin panel hosting.
- React web admin panel source.
- Landing page.
- Stripe setup.
- Secrets, environment files, or customer-specific configuration.

Those are separate deployment concerns. For self-hosted customers, distribute
deployment instructions or a deploy CLI separately from the Obsidian plugin.

## Public Plugin-Only Repository

Generate the free self-hosted public repository from the monorepo:

```bash
npm run export:public-plugin
```

This writes:

```text
dist/public-plugin-repo/
```

The export includes:

- `src/`
- selected plugin tests
- plugin build and release scripts
- `manifest.json`, `versions.json`, `styles.css`
- plugin-only README and self-hosted setup docs
- GitHub release workflow
- Sustainable Use License `LICENSE`

The export excludes:

- `admin-panel/`
- `landing/`
- `dev-server/`
- `infrastructure/`
- `terraform/`
- Stripe and SaaS billing scripts
- backend/admin-web deployment docs

Push the contents of `dist/public-plugin-repo/` to the public plugin repository.
That repository is the right target for Obsidian community plugin submission.

## Build Locally

```bash
npm install
npm run build
```

The build produces the Obsidian plugin assets at the repository root:

- `main.js`
- `manifest.json`
- `styles.css`

## Package a Release Zip

```bash
npm run package
```

This runs the production build, validates release metadata, copies the plugin
assets to `dist/vaultguard/`, and creates:

```text
dist/vaultguard-sync-<version>.zip
```

The zip contains only `main.js`, `manifest.json`, and `styles.css` at the zip
root, which is the expected layout for manual Obsidian installation.

## Install Into a Local Vault

For a one-command local test install:

```bash
npm run install:plugin -- "/absolute/path/to/YourVault"
```

This builds the plugin and copies the release assets into:

```text
/absolute/path/to/YourVault/.obsidian/plugins/vaultguard-sync/
```

Then restart Obsidian and enable VaultGuard Sync under Settings > Community plugins.

## Install on Another Device

For another device before the plugin is in the community gallery:

1. Run `npm run package`.
2. Send `dist/vaultguard-sync-<version>.zip` to the test device.
3. Extract it into the test vault:

   ```text
   <Vault>/.obsidian/plugins/vaultguard-sync/
   ```

4. Restart Obsidian.
5. Enable VaultGuard Sync under Settings > Community plugins.

For less manual beta testing, use BRAT with the public GitHub repository and
release assets.

## GitHub Release Flow

Version files must agree:

- `package.json` version
- `manifest.json` version
- `versions.json` entry for the version

To prepare a release:

```bash
npm version patch
npm run package
git push origin main
git push origin <version>
```

This repo sets `tag-version-prefix=` in `.npmrc`, so `npm version` creates tags
like `0.1.1` instead of `v0.1.1`.

When a tag like `0.1.1` is pushed, `.github/workflows/plugin-release.yml` runs
tests, packages the plugin, and creates a GitHub release with:

- `main.js`
- `manifest.json`
- `styles.css`
- `dist/vaultguard-sync-<version>.zip`

The tag must exactly match `manifest.json` version.

## Official Community Plugin Status

Repo-local release docs must not be treated as live community-directory proof.
Before claiming VaultGuard Sync is admitted, manually reviewed, or installable
from Obsidian's community directory, verify the current state in the Obsidian
community dashboard or directory during the release task. The expected public
plugin id is `vaultguard-sync`, and the expected public repo is
`peter70700/vaultguard-obsidian`.

**Submission flow** (for reference / future plugins): Obsidian uses
[community.obsidian.md](https://community.obsidian.md) — sign in, link GitHub,
Plugins → New plugin → paste GitHub repo URL → Submit. Automated review runs
against `manifest.json` at the listed repo's default-branch HEAD. The old
"fork `obsidianmd/obsidian-releases` and open a PR" flow is deprecated and no
longer accepts submissions.

**Ongoing release hygiene:**

- Use `/release-plugin` (or `npm run sync:public-monorepo && npm run sync:public-plugin`) for every version bump.
- Keep release tags exactly aligned with `manifest.json` versions (bare semver — Obsidian's directory uses the tag to fetch release assets).
- Disclose network usage clearly in the README, including the hosted VaultGuard
  endpoint and self-hosted endpoint behavior.
- Keep backend secrets and customer configuration out of the plugin release.
