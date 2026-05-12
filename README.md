# VaultGuard for Obsidian

VaultGuard is an Obsidian plugin for permission-aware encrypted sync. This
public plugin repository contains only the Obsidian client.

## Free Self-Hosted Edition

The free self-hosted edition is plugin-only:

- No hosted SaaS backend.
- No React web admin panel.
- No Terraform, Lambda, Stripe, or landing-page code.
- No secrets or customer-specific configuration.

Bring your own compatible VaultGuard API endpoint and Cognito app client, then
configure the plugin manually from Obsidian settings.

## Hosted Mode

Hosted organizations can use the same plugin. Enter your organization slug or
redeem an invite link from your administrator, and the plugin will resolve the
connection settings automatically.

## Install From a Release

1. Download `vaultguard-<version>.zip` from the latest GitHub release.
2. Extract it into:

   ```text
   <Vault>/.obsidian/plugins/vaultguard/
   ```

3. Restart Obsidian.
4. Enable VaultGuard under Settings > Community plugins.

The plugin folder must contain:

```text
main.js
manifest.json
styles.css
```

## Build From Source

```bash
npm install
npm run build
```

To package the release zip:

```bash
npm run package
```

To install directly into a local vault:

```bash
npm run install:plugin -- "/absolute/path/to/YourVault"
```

## Self-Hosted Configuration

Open Settings > VaultGuard > Connection, enable manual configuration, then enter:

- API endpoint
- Organization ID
- Cognito User Pool ID
- Cognito Client ID

See [docs/SELF_HOSTED_PLUGIN.md](docs/SELF_HOSTED_PLUGIN.md) for the plugin-only
self-hosting setup contract, and [docs/openapi.yaml](docs/openapi.yaml) for the
OpenAPI 3.1 schema describing the backend HTTP contract a self-hosted server
must implement.

## Network Use

VaultGuard connects to the API endpoint configured in plugin settings and to the
configured AWS Cognito User Pool endpoint for authentication. The plugin uses
Obsidian's `requestUrl` API for all HTTP calls.

## Account, Data, and Privacy

VaultGuard requires an account on the configured backend. In hosted mode, that
account is provided by the hosted VaultGuard organization. In self-hosted mode,
the account is provided by your own compatible backend and Cognito User Pool.

The plugin sends vault-relative file paths, file metadata, encrypted file
contents, permission checks, audit events, and authentication tokens to the
configured backend as part of sync and access control. It does not include
client-side telemetry, ads, or analytics. Billing and subscription management
are handled outside the public plugin.

VaultGuard stores plugin settings, vault binding data, and auth session data in
Obsidian's plugin data store and browser storage so it can restore your session.
The local at-rest encryption key is wrapped on device; the recovery code is
shown only to you and is never sent to the backend.

## Development

```bash
npm run dev
npm test
```

## License

Sustainable Use License — see [LICENSE](LICENSE)
