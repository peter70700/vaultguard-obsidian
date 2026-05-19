# VaultGuard Sync for Obsidian

> **This is the flat release mirror of the plugin** for Obsidian's community directory.
> Canonical source (plugin + server, for self-hosters and auditors):
> https://github.com/peter70700/vaultguard-obsidian/tree/main/packages/plugin

VaultGuard Sync is the Obsidian plugin for permission-aware encrypted sync, part
of the VaultGuard product family. This public plugin repository contains only
the Obsidian client.

- **Try Pro free for 14 days (no card):** https://admin.vaultguard.cloud/#/signup
- **Learn more / managed hosting:** https://vaultguard.cloud
- **Compare editions:** https://vaultguard.cloud/#/compare

## Editions

VaultGuard Community Edition is the open-source, self-hosted stack (your AWS,
`edition=community` codebase, Pro-only features gated off). Pro and Enterprise
are the managed VaultGuard Cloud running the Pro Edition codebase — they add
the operational layer most teams want once they scale past a few users,
**without paywalling any of the security primitives**.

| | Community Edition | Pro | Enterprise |
| --- | --- | --- | --- |
| **Where it runs** | Your own AWS | Our AWS (managed) | Dedicated infra |
| **Price** | Free, self-hosted | €12 / user / month | Custom |
| **Edition (code)** | `community` | `pro` | `pro` |
| **License** | Sustainable Use License | Cloud ToS | Commercial contract |
| **User cap** | Unlimited (you provision) | Up to 100 | Unlimited |
| **Storage** | Limited by your AWS | 100 GB included | Unlimited |
| **Trial** | Clone + deploy | 14 days, no card | Sales call |

### Security plane

Identical in every tier — security primitives are never paywalled.

| Capability | CE | Pro | Enterprise |
| --- | :---: | :---: | :---: |
| End-to-end encryption (AES-256-GCM + AWS KMS) | ✓ | ✓ | ✓ |
| Per-file permissions with role inheritance | ✓ | ✓ | ✓ |
| Re-encryption on user offboarding | ✓ | ✓ | ✓ |
| Time-bound key leases (4h default, configurable) | ✓ | ✓ | ✓ |
| Multi-vault support per organization | ✓ | ✓ | ✓ |
| Plugin allowlist enforcement | ✓ | ✓ | ✓ |
| Cognito auth (password + BYO IdP via Cognito) | ✓ | ✓ | ✓ |
| Local at-rest encryption via OS keychain | ✓ | ✓ | ✓ |
| TLS 1.2+ in transit (TLS 1.3 when negotiated) | ✓ | ✓ | ✓ |

### Admin & operations

Where Pro starts to earn its keep.

| Capability | CE | Pro | Enterprise |
| --- | --- | --- | --- |
| In-Obsidian admin (users / permissions / settings / recovery) | ✓ | ✓ | ✓ |
| Hosted web admin panel (admin.vaultguard.cloud) | ✗ | ✓ | ✓ |
| Share links + share-bridge for internal teammates | ✗ | ✓ | ✓ |
| Basic audit log (`GET /vaults/{vaultId}/audit/logs`) | ✓ | ✓ | ✓ |
| Advanced audit — dashboards, alerts, CSV export, per-user / per-file reports | ✗ | ✓ | ✓ |
| Audit retention | 30 days (configurable) | 1 year | Custom |
| Stripe-backed billing | ✗ | ✓ | ✓ |
| Transactional email (invites, password reset) | Your SES | Managed | Managed |
| Org signup | Single-tenant lockdown | Multi-tenant | Custom |
| Managed AWS infrastructure | ✗ | ✓ | ✓ |
| Automatic security updates + patches | ✗ | ✓ | ✓ |
| Daily backups | ✗ | ✓ | ✓ |
| Uptime SLA | None | 99.9% | 99.99% |
| Support | Community (GitHub) | Email, 24h SLA | Priority, 4h SLA |

### Enterprise-only

| Capability | CE | Pro | Enterprise |
| --- | :---: | :---: | :---: |
| SAML / OIDC SSO integration | ✗ | ✗ | ✓ |
| SOC 2 / HIPAA attestations | ✗ | ✗ | ✓ |
| Dedicated infrastructure | ✗ | ✗ | ✓ |
| Custom data residency | ✗ | ✗ | ✓ |
| Custom key rotation & retention policies | ✗ | ✗ | ✓ |

### Responsibility split

What you do vs. what we do.

| Responsibility | CE | Pro | Enterprise |
| --- | --- | --- | --- |
| Deploy the backend | You (`terraform apply`) | Us | Us (or you, with license) |
| Patch Lambda runtimes / dependencies | You | Us | Us |
| Rotate KMS keys | You | Us | Us / custom |
| Run backups | You | Us | Us |
| Monitor uptime / page on-call | You | Us | Us |
| Pay AWS bill | You | — | Custom |
| Compliance evidence | You | — | Us |

### What CE actually delivers

- Working AWS Cognito + API Gateway + Lambda + DynamoDB + S3 + KMS + SES stack via Terraform
- Plugin connects with no code changes — capability discovery hides Pro-only UI surfaces
- Single-tenant by default — public signup refuses after the first org exists
- Unlimited users, unlimited vaults, every security guarantee
- Cost: AWS resources only. Idle deployment ~$5–15/month on low traffic.

### What CE doesn't deliver (and why Pro is worth paying for)

- No web admin panel — managing 50 users from inside Obsidian is painful for non-technical leads
- No share links — every external collaboration needs the recipient to be a full vault member
- No audit dashboards, alerts, or CSV exports for compliance teams
- No SLA, no managed backups, no patch pipeline — AWS deprecations are your problem
- No SSO, no compliance attestations — Enterprise is the only path for regulated environments

### The one-sentence pitch

Community Edition is the trust signal and the escape hatch. Pro is what you pay
for once the team grows past two non-technical admins, needs to share with
outsiders, or has a compliance team asking for audit evidence. Enterprise adds
SSO, dedicated infra, and compliance attestations on top of Pro.

> **Want managed hosting?** [Start a 14-day Pro trial](https://admin.vaultguard.cloud/#/signup)
> — no card required. Or [contact Enterprise sales](mailto:support@vaultguard.cloud?subject=VaultGuard%20Enterprise%20Inquiry)
> for SSO and compliance.

## Self-Hosting (Community Edition)

VaultGuard Community Edition is a monorepo: this `packages/plugin/` is the
Obsidian client, and `packages/server/` is the AWS backend (Cognito, API
Gateway, Lambda, DynamoDB, S3, KMS, SES) deployable with Terraform on your own
AWS account. Single-tenant by default; Pro-only features (web admin, share
links, Stripe billing, landing page) are excluded.

The end-to-end deploy walkthrough lives at [`docs/SELF-HOSTING.md`](docs/SELF-HOSTING.md).

## Hosted Mode

Hosted organizations use the same plugin. Click **Continue with VaultGuard
Cloud** or redeem an invite link from your administrator; the plugin includes
the public VaultGuard Cloud API and Cognito identifiers and refreshes
organization-specific settings after sign-in. Entering an organization slug is
still available for admins who want to pre-resolve a specific org.

## Install From a Release

1. Open the [latest release](https://github.com/peter70700/vaultguard-obsidian/releases/latest)
   and download these three files:

   ```text
   main.js
   manifest.json
   styles.css
   ```

2. Place them into your vault at:

   ```text
   <Vault>/.obsidian/plugins/vaultguard-sync/
   ```

3. Restart Obsidian.
4. Enable VaultGuard Sync under Settings > Community plugins.

## Build From Source

```bash
npm install
npm run -w vaultguard build
```

The build produces `packages/plugin/main.js` alongside the existing
`packages/plugin/manifest.json` and `packages/plugin/styles.css`. To install
the built plugin directly into a local vault:

```bash
npm run -w vaultguard install:plugin -- "/absolute/path/to/YourVault"
```

## Self-Hosted Configuration

Open Settings > VaultGuard Sync > Connection, enable manual configuration, then
paste your server config URL, for example
`https://your-server.com/.well-known/vaultguard.json`. The config response fills:

- API endpoint
- Organization ID
- Cognito User Pool ID
- Cognito Client ID

You can still edit those fields manually after applying the config URL.

See [`docs/SELF-HOSTING.md`](docs/SELF-HOSTING.md) for the end-to-end
Community Edition deploy walkthrough, and
[`packages/plugin/docs/openapi.yaml`](packages/plugin/docs/openapi.yaml) for
the OpenAPI 3.1 schema describing the backend HTTP contract a self-hosted
server must implement.

## Network Use

VaultGuard Sync connects to the effective API endpoint shown in plugin settings
and to the configured AWS Cognito User Pool endpoint for authentication. Fresh
installs default to `https://api.vaultguard.cloud`, but the plugin does not make
Cloud requests on load; network calls begin when you sign in, redeem an invite,
connect an organization, or restore an existing session. Manual configuration
bypasses the bundled Cloud fallback. The plugin uses Obsidian's `requestUrl` API
for all HTTP calls.

## Account, Data, and Privacy

VaultGuard Sync requires an account on the configured backend. In hosted mode,
that account is provided by the hosted VaultGuard organization. In self-hosted
mode, the account is provided by your own compatible backend and Cognito User
Pool.

The plugin sends vault-relative file paths, file metadata, encrypted file
contents, permission checks, audit events, and authentication tokens to the
configured backend as part of sync and access control. It does not include
client-side telemetry, ads, or analytics. Billing and subscription management
are handled outside the public plugin.

VaultGuard Sync stores plugin settings, vault binding data, and auth session
data in Obsidian's plugin data store and browser storage so it can restore your
session. The local at-rest encryption key is wrapped on device; the recovery
code is shown only to you and is never sent to the backend.

## Development

```bash
npm run -w vaultguard dev    # esbuild watch
npm run -w vaultguard test   # vitest
```

## License

Sustainable Use License — see [LICENSE](LICENSE)
