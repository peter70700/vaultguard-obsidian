# VaultGuard Vaults — Multi-Vault Architecture

VaultGuard models **vaults as first-class server-side entities**. An organization
can have many vaults; each vault is an isolated namespace for files, permission
rules, and members. This document is the canonical reference for the data model,
APIs, and end-to-end flows.

> **Why this exists.** The pre-multi-vault model used a single flat keyspace
> per organization (`vault/{orgId}/{relativePath}`). That meant two different
> local Obsidian vaults pointed at the same org collapsed every same-named file
> into one server record — `Welcome.md` in vault A and vault B were literally
> the same S3 object and shared permissions. This document describes the
> multi-vault rewrite that fixes the collision by construction.

---

## 1. Data model

```
Organization (1) ─< Vault (N)
Vault (1) ─< VaultMember (N)         (user × vault × role)
Vault (1) ─< File @ relPath (N)      S3 key = vault/{orgId}/{vaultId}/{relPath}
Vault (1) ─< PermissionRule (N)      (rule × pathPattern × principal × effect × actions × priority × expiresAt)
```

### `Vaults` table

`PK = orgId, SK = vaultId`. GSI `slug-index` on `(orgId, slug)` for human-readable
URL lookups.

| field          | type     | notes                                                        |
| -------------- | -------- | ------------------------------------------------------------ |
| `orgId`        | string   | Hash key — owning organization. Strict tenant isolation.     |
| `vaultId`      | string   | Range key — server-generated UUID. Stable forever.           |
| `name`         | string   | Display name (e.g. "Engineering Notes").                     |
| `slug`         | string   | URL-safe lowercased; unique per org via slug-index.          |
| `kind`         | enum     | `team`, `personal`, or `shared`.                             |
| `defaultRole`  | enum     | New-member default: `viewer`, `editor`, or `admin`.          |
| `createdAt`    | ISO time | Creation timestamp.                                          |
| `createdBy`    | string   | UserId of creator (auto-promoted to vault admin).            |
| `archived`     | boolean  | Soft-archive flag; archived vaults are read-only.            |
| `description?` | string   | Optional admin-facing description.                           |

### `VaultMembers` table

`PK = vaultId, SK = userId`. GSI `userId-index` on `(userId, vaultId)` for
"list all vaults this user belongs to".

| field      | type     | notes                                              |
| ---------- | -------- | -------------------------------------------------- |
| `vaultId`  | string   | Hash key.                                          |
| `userId`   | string   | Range key — Cognito `sub`.                         |
| `role`     | enum     | `viewer` (read), `editor` (read+write), `admin`.   |
| `joinedAt` | ISO time | When the user joined.                              |
| `invitedBy`| string   | Admin who granted this membership.                 |

### `Permissions` table (vault-scoped)

The existing table now requires `vaultId` on every rule. Queries filter by
`(orgId, vaultId)` so rules in vault A never bleed into vault B.

| field          | type     | notes                                                               |
| -------------- | -------- | ------------------------------------------------------------------- |
| `id`           | string   | Rule UUID.                                                          |
| `orgId`        | string   | Tenant isolation.                                                   |
| `vaultId`      | string   | Vault scope. **NEW** — required.                                    |
| `userId`       | string   | Target user, or `*` for all users in the vault.                     |
| `role`         | string?  | Target role for role-based rules.                                   |
| `pathPattern`  | string   | Glob: `/folder/**`, `/notes/*.md`, `/exact/path.md`.                |
| `actions`      | string[] | Subset of `read`, `write`, `delete`, `admin`, `list`.               |
| `effect`       | enum     | `allow` or `deny`.                                                  |
| `priority`     | number   | Higher = more specific; auto-derived if omitted.                    |
| `expiresAt?`   | ISO time | **NEW** — time-bound shares (rule ignored after this).              |
| `createdAt`    | ISO time | —                                                                   |
| `updatedAt`    | ISO time | —                                                                   |
| `createdBy`    | string   | Admin who created the rule.                                         |

### S3 layout

```
s3://vault-bucket/vault/{orgId}/{vaultId}/{relPath}
```

Both `orgId` and `vaultId` are required at every read/write — `vaultS3Prefix()`
in `infrastructure/lambda/files/handler.ts` raises an exception if either is
missing, preventing tenant or vault isolation breaches by code path.

---

## 2. Authorization model

Three roles intersect:

1. **Org-level role** — `member`, `editor`, `admin`, `owner`. Stored as a
   Cognito group and surfaced in the JWT.
2. **Vault membership role** — `viewer`, `editor`, `admin`. Stored in
   `VaultMembers`. Distinct from org role.
3. **Permission rule** — fine-grained allow/deny on a path pattern within
   a vault.

### `requireVaultMember(user, vaultId, requiredRole)`

The canonical authorization gate (`infrastructure/lambda/shared/utils.ts`):

1. Vault must exist and belong to the user's org (tenant check).
2. Either:
    - the user has a `VaultMember` row with role ≥ `requiredRole`, **or**
    - the user is org-`admin`/`owner` (full-org bypass).
3. Archived vaults are read-only — writes are rejected.
4. On success returns the resolved `VaultRecord`. On failure throws `AuthError`.

Every `/vaults/{vaultId}/...` route calls this before doing any work. The
`files`, `permissions`, and `auth` lambdas all flow through it.

### `evaluatePermission(userId, roles, action, path, orgId, vaultId)`

Path-glob ACL evaluator. Now requires `vaultId` (throws if missing). Drops
rules whose `expiresAt` is in the past, then matches the path against
`pathPattern`. Specificity ordering: more-specific paths win; deny beats allow
at equal specificity; explicit priority breaks ties.

---

## 3. API surface

All file and permission routes live under `/vaults/{vaultId}`. The routes
prior to multi-vault (`/files/...`, `/permissions/...` at root) no longer exist.

### Vault entity

```
GET    /vaults                                 → list user's vaults (or all in org if admin)
POST   /vaults                                 → create vault (org-admin only)
GET    /vaults/{vaultId}                       → vault details (any vault member)
PATCH  /vaults/{vaultId}                       → update name/desc/defaultRole (vault-admin)
DELETE /vaults/{vaultId}                       → soft-archive (org-admin)
GET    /vaults/{vaultId}/overview              → metadata-only file/folder inventory (vault-admin)
```

### Members

```
GET    /vaults/{vaultId}/members               → list members (any vault member)
POST   /vaults/{vaultId}/members               → add member (vault-admin)
PATCH  /vaults/{vaultId}/members/{userId}      → change role (vault-admin)
DELETE /vaults/{vaultId}/members/{userId}      → remove member (vault-admin, can't remove last admin)
```

### Files (vault-scoped)

```
GET    /vaults/{vaultId}/files                 → list files (filtered by permissions)
GET    /vaults/{vaultId}/files/{path+}         → read content
PUT    /vaults/{vaultId}/files/{path+}         → write content
DELETE /vaults/{vaultId}/files/{path+}         → soft-delete (S3 delete marker)
GET    /vaults/{vaultId}/files/{path+}/history → version history
POST   /vaults/{vaultId}/files/sync            → delta sync (server returns changed files)
```

`GET /vaults/{vaultId}/overview` is intentionally separate from content routes.
It is restricted to vault admins/org admins and returns only metadata needed for
inventory comparison: paths, inferred folders, sizes, timestamps, aggregate counts,
file-type counts, and largest-file summaries. It must not return file bodies,
wrapped keys, checksums, ETags, version IDs, or any decrypted content.

### Permissions (vault-scoped)

```
GET    /vaults/{vaultId}/permissions                      → list raw rules in vault (vault-admin)
GET    /vaults/{vaultId}/permissions/user/{userId}        → effective perms for a user (self or vault-admin)
POST   /vaults/{vaultId}/permissions                      → create rule (vault-admin)
PUT    /vaults/{vaultId}/permissions/{id}                 → update rule (vault-admin)
DELETE /vaults/{vaultId}/permissions/{id}                 → delete rule (vault-admin)
POST   /vaults/{vaultId}/permissions/check                → check action on path (any member, self only unless admin)
POST   /vaults/{vaultId}/permissions/access               → effective per-file access list (any member with read on path)
POST   /vaults/{vaultId}/permissions/access/batch         → batch access summaries for many paths (any member; cap 100)
```

### Audit (vault-scoped)

```
GET    /vaults/{vaultId}/audit                            → list audit events in vault
GET    /vaults/{vaultId}/audit/logs                       → list audit events in vault
GET    /vaults/{vaultId}/audit/alerts                     → list anomaly alerts in vault
PATCH  /vaults/{vaultId}/audit/alerts/{alertId}           → dismiss or restore anomaly alert in vault
GET    /vaults/{vaultId}/audit/user/{userId}              → user activity in vault
GET    /vaults/{vaultId}/audit/file/{path+}               → file activity in vault
POST   /vaults/{vaultId}/audit/export                     → export vault audit CSV
POST   /vaults/{vaultId}/audit/report                     → legacy export alias
```

Audit rows carry a top-level `vaultId` when the event is vault-scoped. Admin
audit views and exports must use the vault routes above; root `/audit/*` routes
are intentionally not part of the API surface.

### Auth (vault-scoped scope leases)

```
POST /auth/key-lease/scoped  body: { sessionId, scope, vaultId }
```

Scoped key leases now require a `vaultId` so the cryptographic key the lease
issues is bound to a single vault's keyspace.

### Share links (vault-scoped)

```
POST   /vaults/{vaultId}/shares                     → mint a share link (vault viewer+, must have read on the file)
GET    /vaults/{vaultId}/shares                     → list active shares (vault viewer+)
GET    /vaults/{vaultId}/shares/{shareId}           → resolve to (vaultId, relPath) (vault viewer+, file-level read)
DELETE /vaults/{vaultId}/shares/{shareId}           → revoke (creator OR vault admin)
```

Opaque pointer tokens — the URL itself grants nothing. Resolution still
runs through `requireVaultMember` *and* `evaluatePermission(read, /relPath)`,
so a leaked link in Slack is unusable to anyone outside the team. Cross-vault
forgery is blocked by a `record.vaultId !== vault.vaultId` check; expired
tokens return `410`. Full reference:
[`docs/SHARE-LINKS.md`](SHARE-LINKS.md).

---

## 4. End-to-end flows

### A. New user invited (path: invite email → Obsidian deep link)

1. Org admin invites by email → invite Lambda creates a Cognito user, sends
   a branded email with an `obsidian://vaultguard-invite?org=...&email=...`
   deep link.
2. Invitee installs the VaultGuard plugin in a fresh Obsidian vault.
3. Clicking the deep link auto-resolves the org config and opens the login
   modal in "set your password" mode (one-shot reset code → password).
4. After login, the plugin checks `settings.serverVaultId`. If empty, it
   opens the **Vault Picker Modal**.
5. User picks an existing vault they belong to — or, if they're an org admin,
   creates a new one. Their `serverVaultId` is now set.
6. Sync engine boots and starts mirroring server vault contents into the
   local Obsidian folder.

### B. Self-signup (org founder)

1. `POST /signup` creates the org + admin Cognito user. (Pre-multi-vault no
   default vault was created.)
2. After login, the picker shows zero vaults but offers "Create vault" since
   the user is an org-admin.
3. Default suggestion: the local Obsidian folder name. Slug is auto-derived.

### C. Two local Obsidian vaults bound to the same org

Each gets its own server vault. Their `serverVaultId` settings differ. Their
S3 prefixes are `vault/{orgId}/{vaultIdA}/...` and `vault/{orgId}/{vaultIdB}/...`
respectively. **`Welcome.md` in vault A is a different S3 object from
`Welcome.md` in vault B** — collisions are impossible by construction.

### D. Sharing across vaults

Cross-vault sharing is not supported as a primitive — by design. To grant
someone read access in another vault, you add them as a member of that vault
(viewer/editor/admin). This is the same model Notion, Drive, ClickUp, and
GitHub use; isolation by default, explicit membership for collaboration.

### E. Sharing a single file inside one vault

For pointing a teammate at one specific file (without changing membership
or rules), VaultGuard mints opaque deep-link tokens via
`POST /vaults/{vaultId}/shares`. The recipient clicks
`https://share.example.com/s/{shareId}?v={vaultId}`; the share-bridge
SPA hands off to `obsidian://vaultguard-share?...`; the plugin verifies
vault binding, calls the resolve endpoint (which re-checks vault membership
*and* file-level `read`), and opens the file in the recipient's local vault.
Tokens are not capabilities — `read` permission must already exist server-side.
Full flow, security gates, and component map: [`docs/SHARE-LINKS.md`](SHARE-LINKS.md).

---

## 5. Granular permission patterns

Inside a vault, the existing path-glob ACL is still in force. Combine them with
membership roles to build ClickUp-style permission setups.

### Pattern: team folder, viewer-by-default

```
Vault: "Engineering Notes"
defaultRole: viewer

Rules:
- /eng/** allow [read, list, write] for role:engineering    priority 50
- /eng/private/** deny  [read,list,write] for *              priority 100
```

Anyone added to the vault as a viewer gets read access on `/eng/**`. Editors
get full edit. The deny rule on `/eng/private/**` overrides for everyone but
explicit admins.

### Pattern: temporary share

```
Rules:
- /board-meetings/2026-04/** allow [read,list] for user:contractor-1
  expiresAt: 2026-05-01T00:00:00Z
```

After May 1 the rule is automatically ignored — no manual cleanup needed.

### Pattern: per-folder editor delegation

```
Rules:
- /docs/onboarding/** allow [read, write, list] for user:alice
- /docs/onboarding/** deny  [delete] for user:alice
```

Alice can edit but not delete files under `/docs/onboarding/**`. Other vault
members keep their default role.

---

## 6. Plugin binding

The plugin stores three new settings:

```ts
serverVaultId:   string  // UUID of the bound server vault
serverVaultName: string  // cached for UI
serverVaultSlug: string  // cached for UI
```

`vaultPath()` in `src/plugin/main.ts` and `vaultBase()` in `src/api/client.ts`
hard-fail any file/permission API call when `serverVaultId` is empty, with the
message:

> VaultGuard: this Obsidian folder is not bound to a server vault yet. Open
> the VaultGuard sidebar to pick or create one.

The user can run **Pick or Switch Server Vault** from the command palette
at any time.

---

## 7. Admin panel

The admin panel surfaces vaults as a top-level concept:

- **Vaults page** (`/vaults`) — list, create, archive.
- **Vault detail page** (`/vaults/{vaultId}`) with three tabs:
    - **Members** — add/remove org users to this vault, change vault role.
    - **Permissions** — path-pattern rules with optional `expiresAt`.
    - **Settings** — edit name/description/defaultRole, archive/reactivate.

Note: there is no longer a top-level "Permissions" page; rules are always
scoped to a vault, so the only sensible entry point is from a specific
vault's detail page.

---

## 8. What's still implicit (gaps)

- **Cross-vault search.** A user belonging to N vaults today gets N separate
  views. A federated search UI would require either client-side fan-out or
  a search service.
- **Cross-vault file moves.** The re-encryption Lambda has the primitives; a
  "move file from vault A to vault B" feature would wrap re-encrypt + relocate.
- **Per-vault encryption keys.** Today's hybrid-zk model uses one key per user.
  In a future iteration each vault should have its own key so revoking a user
  from one vault doesn't require re-keying the others.
- **Public link sharing.** Signed URLs that grant read access to anyone with
  the link are not yet wired; they would be a per-vault setting plus a
  `/vaults/{vaultId}/public-links` route family. The existing
  `/vaults/{vaultId}/shares` family covers the *internal-team* share case
  (recipient must be a vault member), but does **not** grant access to
  non-members. See [`docs/SHARE-LINKS.md`](SHARE-LINKS.md) §7 for the
  contrast.

---

## 9. Migration

The model is a clean break from the pre-multi-vault layout. Since no users
were live at cutover, no migration job is needed — every fresh install picks
or creates a vault on first connection. Anyone running pre-multi-vault local
state should:

1. Delete plugin data: `~/<vault>/.obsidian/plugins/obsidian-vaultguard/data.json`.
2. Restart Obsidian and log in again.
3. Pick or create a server vault when prompted (or, if the org was just
   created via `/signup`, the default vault is auto-bound after the first
   login since signup auto-seeds one).

Backend operators should run `terraform apply` after pulling this revision —
the new tables, Lambda, and API Gateway routes are all additive plus a few
parent-resource changes that Terraform handles in-place.

### CDN / CloudFront

`terraform/modules/cloudfront/main.tf` uses the AWS-managed `CachingDisabled`
policy with `AllViewerExceptHostHeader` origin request policy. All HTTP
methods are allowed in the default cache behavior and there are no
path-pattern-based behaviors — every request to the CDN is forwarded
verbatim to API Gateway with no edge caching.

That means **no CloudFront invalidation or behavior change is required** for
the new `/vaults/*` routes. Plugin clients already pointing at the
`*.cloudfront.net` URL will see them as soon as `terraform apply` finishes
and the API Gateway stage is redeployed.

### Default vault

`POST /signup` auto-creates a `default` vault for the new org and adds the
admin user as its admin member (see `infrastructure/lambda/signup/handler.ts`).
The signup response includes a `vault: { vaultId, name, slug }` block so
clients can pre-bind to it without showing the picker. The plugin still
shows the picker for any subsequent local Obsidian vault that connects to
the same org.

### Terraform footprint

Production runs on Terraform. The Vaults and VaultMembers tables, the
`vaults` Lambda, and the `/vaults/*` API routes are all defined under
`terraform/modules/dynamodb/`, `terraform/modules/lambda/`, and
`terraform/modules/apigateway/`. CE deployers get the full vault data
model with `terraform apply`; no extra steps needed.

### Local dev server

`dev-server/server.ts` mirrors all vault routes against an in-memory store.
A default vault `vault-dev-001` is seeded with the three test users as
members. Use it to exercise the full flow without AWS.
