# VaultGuard Server — Community Edition

Open-source server stack for [VaultGuard](https://example.com) — an
end-to-end encrypted, permission-aware sync backend for Obsidian vaults.

This repository ships the AWS infrastructure you self-host. Pair it with the
[VaultGuard Obsidian plugin](https://github.com/peter70700/vaultguard-obsidian)
to encrypt your team's vault, enforce per-file permissions, and revoke access
cleanly when people leave.

CE is licensed under the Sustainable Use License and feature-complete for the security plane. Some
operational and convenience features stay in the managed Pro plan — see
[What's NOT included](#whats-not-included).

## Quick start

```bash
# 1. Clone and install Lambda deps
git clone <this-repo>
cd vaultguard-server/infrastructure
npm install

# 2. Build Lambda bundles
npm run build

# 3. Configure your deployment
cd ../terraform
cp environments/ce.tfvars.example environments/ce.tfvars
# Edit ce.tfvars: set stage, admin_email, sender_email, etc.

# 4. Deploy
terraform init
terraform apply -var-file=environments/ce.tfvars
```

After `terraform apply` finishes, the outputs section prints:

- `api_url` — point the Obsidian plugin's API endpoint here.
- `user_pool_id`, `user_pool_client_id` — Cognito IDs the plugin needs.
- `vault_bucket_name` — S3 bucket holding encrypted vault content.
- `kms_key_arn` — your customer-managed KMS key.

### 5. Create your first admin user

Steps 1-4 deploy the infrastructure, but the deployment lands with zero users
and zero organizations. Bootstrap a single admin via the public `POST /signup`
endpoint:

```bash
API_URL=$(terraform output -raw api_url)

curl -X POST "$API_URL/signup" \
  -H "Content-Type: application/json" \
  -d '{
    "orgName": "Acme Corp",
    "orgSlug": "acme-corp",
    "email": "you@example.com",
    "password": "YourSecurePassword123!",
    "displayName": "Your Name"
  }'
```

This call creates, in one transaction, the Cognito admin user (permanent
password), the `org-{slug}` and `admin` Cognito groups, the organization
record, a default vault, the owner VaultMember row, and a default allow-all
permission rule.

For slug rules, password policy, the auto-lock behavior, and troubleshooting,
see [`docs/SELF-HOSTING.md#create-the-first-admin-user`](SELF-HOSTING.md#create-the-first-admin-user).
After this first call succeeds, Community Edition locks public signup — see
[Single-tenant lockdown](#single-tenant-lockdown) below for re-enabling it
later via `vaultguard_allow_public_signup = true`.

## What you get

| Capability | Included |
|---|---|
| End-to-end file encryption (AES-256-GCM + AWS KMS) | ✅ |
| Per-file permissions with role inheritance | ✅ |
| Re-encryption on user offboarding | ✅ |
| Multi-vault support per organization | ✅ |
| Plugin allowlist enforcement | ✅ |
| Time-bound key leases (4h default, configurable) | ✅ |
| Cognito-based auth (federate to your IdP if desired) | ✅ |
| Basic audit trail (`GET /vaults/{vaultId}/audit/logs`) | ✅ |
| In-Obsidian admin UI (users / permissions / settings) | ✅ |
| Transactional email via AWS SES | ✅ |
| Unlimited users, no seat caps | ✅ |

## What's NOT included

These features stay in the managed Pro plan ([upgrade](https://example.com)):

| Feature | Why it's in Pro |
|---|---|
| **Share links** for external collaborators | Token resolver + share-bridge SPA — Pro infrastructure |
| **Hosted web admin panel** (`admin.example.com`) | React app for non-technical admins to manage users/permissions/audit without opening Obsidian |
| **Advanced audit** (dashboards, alerts, CSV export, per-user/per-file reports) | Anomaly detection, scheduled reports, long retention |
| **Stripe-backed billing** | Managed subscription lifecycle |
| **Managed AWS infrastructure** | We run it, patch it, back it up |
| **Daily backups, 99.9% uptime SLA** | Operational guarantees |
| **Email support, 24h SLA** | Human help when you need it |
| **SOC 2 / HIPAA attestations** | Compliance evidence (Enterprise) |
| **SAML / OIDC SSO integration** | Federate to your IdP cleanly (Enterprise) |

Share-link, billing, and web-admin endpoints exist in the CE terraform graph
as **inert 404 stubs** — they cost effectively $0 in idle AWS spend, keep the
deployment valid, and refuse all requests with a clear error. If you upgrade
to a hosted Pro deployment, the same plugin install routes seamlessly to the
managed backend.

## Configuration

### Single-tenant lockdown

CE defaults to **single-tenant mode**: the public `POST /signup` endpoint
becomes a `403` once the first organization is created. This stops drive-by
strangers from spinning up their own orgs on your deployment.

To re-enable public signup (for example, you're running CE as a community
service), set `vaultguard_allow_public_signup = true` in your tfvars. Terraform
passes that through as the `VAULTGUARD_ALLOW_PUBLIC_SIGNUP` env var on the
**signup** Lambda function.

### Audit retention

The audit log is written for every action and queryable via
`GET /vaults/{vaultId}/audit/logs`.
Default retention is 365 days, enforced by a DynamoDB TTL attribute. Change
`retentionDays` in organization settings from the in-Obsidian admin UI or the
org settings API; updates apply to new audit writes.

Advanced audit endpoints (`/audit/alerts`, `/audit/export`, `/audit/user/...`,
`/audit/file/...`) are Pro-only and return `404` on CE.

### Edition flag

Every Lambda checks the `VAULTGUARD_EDITION` env var at cold start. The
terraform in this repo sets it to `"community"` by default; the
`GET /orgs/{slug}/config` endpoint advertises that to the plugin so it can
hide Pro-only UI surfaces (share-link buttons, advanced audit tabs, etc.)
on the client side.

Do not flip this to `"pro"` on a CE deployment — the Pro-only handlers
(`shares/`, `billing/`) ship as 404 stubs in this repo and will not gain
functionality just by changing the flag.

### Custom domain

Set `domain_name = "vaultguard.example.com"` in `ce.tfvars` to wire up
Route 53 + ACM + API Gateway custom domain. The terraform will output the
nameservers to configure at your registrar.

If you leave `domain_name` empty, the deployment uses the raw API Gateway and
CloudFront URLs (less pretty but works).

### SES sender identity

Transactional emails (invites, password resets) require a verified SES sender.
After the first `terraform apply`:

1. Open the AWS SES console in your deployment region.
2. Verify the email address you set as `sender_email`.
3. If you're in the SES sandbox, also verify each recipient or request
   production access.

## Architecture

```
┌─────────────────┐
│ Obsidian plugin │
└────────┬────────┘
         │ HTTPS (Cognito JWT)
         ▼
┌─────────────────────┐
│   API Gateway       │
│   (REST, regional)  │
└──┬──────────────────┘
   │
   ├──► Lambda: auth          ── Cognito sessions, key leases
   ├──► Lambda: signup        ── Org bootstrap (single-tenant gated on CE)
   ├──► Lambda: vaults        ── Vault CRUD + membership
   ├──► Lambda: files         ── Encrypted file CRUD via S3 + KMS
   ├──► Lambda: permissions   ── Rule evaluation, wildcard matching
   ├──► Lambda: users         ── Lifecycle (invite/revoke), org settings
   ├──► Lambda: audit         ── Write + GET /vaults/{vaultId}/audit/logs (basic)
   ├──► Lambda: reencryption  ── Post-offboarding key + file rotation
   ├──► Lambda: email         ── SES transactional sender
   ├──► Lambda: shares        ── 404 stub (Pro)
   └──► Lambda: billing       ── 404 stub (Pro)

DynamoDB tables, S3 vault bucket, KMS CMK, SES, CloudFront (CDN for API).
WAF (rate limits, IP allowlists). Route 53 + ACM (optional custom domain).
```

The full HTTP contract is documented in
[`docs/openapi.yaml`](docs/openapi.yaml). The plugin only calls the routes
listed there; any backend that satisfies the spec works.

## Upgrading

Upgrading from CE to managed Pro is a settings change in the Obsidian plugin,
not a re-install. Point the plugin at the Pro API endpoint, sign in with your
new org, and you're done. Your CE deployment can be torn down with
`terraform destroy` (or kept running indefinitely if you prefer self-host).

Migrating data between CE and Pro is not automated — vault content lives in
S3 in your account on CE and in our account on Pro. Contact
[support@example.com](mailto:support@example.com) for a
managed migration if you want to move a large team.

## Support

- **Bugs / feature requests:** open an issue on this repo.
- **General questions:** [GitHub Discussions](https://github.com/peter70700/vaultguard-obsidian/discussions).
- **Security disclosures:** email support@example.com.
- **Commercial support, SLA, SSO, compliance:** [example.com](https://example.com).

## License

Sustainable Use License. See [`LICENSE`](LICENSE).

This project includes AWS SDK clients (Apache 2.0) and esbuild (MIT) as
build dependencies. No proprietary code or hidden license restrictions.
