# Self-Hosted Plugin Setup

> ⚠️ **DEPRECATED — superseded by Community Edition.** This document describes
> the older "plugin-only public repo" story (plugin open, backend closed),
> which predates the current open-core model. The shipping story is now
> **VaultGuard Community Edition**: both plugin **and** server are open-source,
> deployable via Terraform on your own AWS.
>
> **Canonical replacement:** [`docs/SELF-HOSTING.md`](SELF-HOSTING.md). See
> also [`docs/TERMINOLOGY.md`](TERMINOLOGY.md) for the edition / plan /
> deployment word map.

The free self-hosted release is a plugin-only public repository. It does not
include the VaultGuard SaaS backend, web admin panel, deployment code, billing
code, or hosted infrastructure.

## What Is Included

- Obsidian plugin source.
- Build and release scripts.
- Manual connection settings for self-hosted deployments.
- Plugin-local user, permission, audit, settings, and recovery views where the
  backend API supports those endpoints.

## What Is Not Included

- React web admin panel.
- Admin web hosting.
- Terraform, Lambda source, or AWS deployment automation.
- SaaS signup, billing, or Stripe setup.
- Hosted VaultGuard API service.

## Required Backend Contract

The plugin expects a compatible VaultGuard API with endpoints for auth-adjacent
key leases, files, permissions, users, audit, organization settings, and
re-encryption jobs. The exact backend can be self-hosted or hosted elsewhere,
but the plugin release does not ship that backend.

The full HTTP contract is documented as an OpenAPI 3.1 schema in
[`openapi.yaml`](openapi.yaml). It enumerates every endpoint the plugin calls,
the expected request and response shapes, and the auth scheme. Any backend
that satisfies this schema will work with the unmodified plugin.

Self-hosted users must provide these values in Settings > VaultGuard >
Connection:

| Setting | Description |
|---------|-------------|
| API endpoint | Base URL for the compatible VaultGuard REST API or CloudFront distribution. |
| Organization ID | Tenant or organization ID used by the API. |
| Cognito User Pool ID | AWS Cognito User Pool used for authentication. |
| Cognito Client ID | Public app client ID used by the plugin. |

## Invite Links

Self-hosted deployments can still use invite links if their backend exposes the
public org config endpoint:

```text
obsidian://vaultguard-invite?org=acme-corp&email=user@example.com&api=https://api.example.com
```

The `api` parameter tells the plugin which self-hosted API base URL to query for
organization config.

## Admin Surface

There is no separate web admin in the free self-hosted public repo. If the
backend exposes admin endpoints and the signed-in user has an admin role, the
plugin can show plugin-local admin views inside Obsidian.
