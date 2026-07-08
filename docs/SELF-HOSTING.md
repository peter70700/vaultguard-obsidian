# VaultGuard — Self-Hosting Guide (BYO AWS)

End-to-end guide for running VaultGuard Community Edition on your own AWS account
using the public Terraform modules. No managed cloud account required.

This is the Path A self-hosting story for VaultGuard v1: you bring an AWS account,
run `terraform apply` against the open-source modules, and connect the Obsidian
plugin to the resulting API. (Non-AWS Docker Compose self-hosting is on the v2
roadmap.)

***

## Table of Contents

- [Prerequisites](#prerequisites)
- [Clone the Repository](#clone-the-repository)
- [Install AWS CLI and Terraform](#install-aws-cli-and-terraform)
- [Configure the Terraform Variables](#configure-the-terraform-variables)
- [Deploy the Infrastructure](#deploy-the-infrastructure)
- [Create the First Admin User](#create-the-first-admin-user)
- [Install the Obsidian Plugin](#install-the-obsidian-plugin)
- [Configure the Plugin to Connect to Your Server](#configure-the-plugin-to-connect-to-your-server)
- [Verify the Deployment End-to-End](#verify-the-deployment-end-to-end)
- [Common Errors](#common-errors)

***

## Prerequisites

### Required Tools

| Tool       | Version  | Purpose                                |
| ---------- | -------- | -------------------------------------- |
| AWS CLI    | >= 2.x   | AWS account interaction                |
| Node.js    | >= 20.x  | Lambda bundling and plugin build       |
| Terraform  | >= 1.6   | Infrastructure deployment              |
| npm        | Latest   | Package management                     |
| Git        | >= 2.x   | Source control                         |
| Obsidian   | >= 1.4.0 | Plugin host                            |

### AWS Account Requirements

- An AWS account with administrator access (or, at minimum, permissions for
  **IAM, Cognito, DynamoDB, S3, Lambda, API Gateway, CloudWatch, KMS, and SES**).
- A registered domain for the API endpoint is **optional** — if you set
  `domain_name`, you must also have a matching Route53 hosted zone in the same
  AWS account.
- AWS CLI configured with credentials: `aws configure`.

### Verify Prerequisites

```bash
aws --version        # AWS CLI v2.x
node --version       # v20+
terraform --version  # 1.6+
npm --version        # 9+
git --version        # 2.x
```

***

## Clone the Repository

The public monorepo contains the plugin (under `packages/plugin/`) and the
server stack (under `packages/server/`). Clone it and install root workspace
dependencies in one step:

```bash
git clone https://github.com/peter70700/vaultguard-obsidian.git
cd vaultguard-obsidian
npm install
```

`npm install` at the repo root materializes the npm workspaces and any
shared dev dependencies. Each package also has its own `npm install` step
documented below.

***

## Install AWS CLI and Terraform

If you do not already have AWS CLI v2 and Terraform installed, follow the
upstream installation docs:

- AWS CLI v2: <https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html>
- Terraform: <https://developer.hashicorp.com/terraform/install>

Then configure AWS credentials. The credentials need permission to create the
resources listed under [AWS Account Requirements](#prerequisites) above.

```bash
aws configure
# AWS Access Key ID:     [paste]
# AWS Secret Access Key: [paste]
# Default region:        eu-central-1   (or your preferred region)
# Default output format: json
```

Confirm you can reach the account:

```bash
aws sts get-caller-identity
```

***

## Configure the Terraform Variables

The Terraform inputs for a Community Edition deployment live in
`packages/server/terraform/environments/ce.tfvars.example`. Copy it to a real
tfvars file (which is gitignored by default — never commit a populated tfvars):

```bash
cd packages/server/terraform
cp environments/ce.tfvars.example environments/ce.tfvars
```

Open `environments/ce.tfvars` in your editor and review each variable. The
defaults are sensible for a first deployment; you only need to change
`admin_email` (and optionally `domain_name`) to get a working stack.

### Variable Walkthrough

- **`stage`** — `"dev"`, `"staging"`, or `"prod"`. Becomes the suffix on every
  AWS resource name so multiple stages can co-exist in one account.
- **`domain_name`** — Leave as `""` to use AWS-default domains (API Gateway
  invoke URLs, Cognito hosted UI default). Set to a domain you own
  (e.g. `vaultguard.example.com`) if you want custom URLs. Requires a matching
  Route53 hosted zone.
- **`admin_email`** — Where SNS sends operational alerts. Set this to a real
  inbox you read.
- **`sender_email`** — `From:` address for transactional mail sent through SES.
- **`sender_domain`** — The SES-verified domain identity. Must match
  `sender_email`'s domain.
- **`cognito_callback_urls` / `cognito_logout_urls`** — OAuth redirect URIs.
  The defaults point at `http://localhost:5173` for local development.
- **`key_lease_duration_seconds`** — How long a cloud DEK lease is valid before
  the plugin must renew. Default `3600` (1 hour).
- **`session_duration_seconds`** — How long a user session token is valid.
  Default `28800` (8 hours).
- **`max_file_size_bytes`** — Hard upload ceiling. Default `26214400` (25 MiB).
- **`vaultguard_edition`** — **Keep this as `"community"`**. It is the
  runtime gate that disables Pro-only features (share links, hosted admin
  panel, billing, advanced audit) on the Lambda layer.
- **`vaultguard_allow_public_signup`** — When `true`, `POST /signup` stays open
  after your first admin organization is created. Set to `false` for a closed
  deployment.
- **Google Workspace DNS records** — the Workspace site-verification TXT and
  DKIM TXT records are managed manually in the Route 53 console (terraform
  doesn't model them, so a forgotten `-var-file` cannot destroy a live DKIM
  key). Add them in Google Admin → Account → Domains and Google Admin → Apps
  → Google Workspace → Gmail → Authenticate email, then mirror the values
  into Route 53. Outbound transactional mail goes through AWS SES regardless.

***

## Deploy the Infrastructure

### 1. Build the Lambda Bundles

The Terraform module deploys pre-bundled Lambda artifacts from
`infrastructure/dist/`. Build them first:

```bash
cd packages/server/infrastructure
npm install
npm run build:lambdas
```

### 2. Terraform Init / Plan / Apply

```bash
cd ../terraform
terraform init
terraform plan -var-file=environments/ce.tfvars
terraform apply -var-file=environments/ce.tfvars
```

The first `terraform apply` typically takes 4–8 minutes. When it finishes,
note the outputs:

```bash
terraform output
```

Critical values you'll need for the plugin:

- **`api_url`** — Base URL for the VaultGuard API (e.g.
  `https://abc123def4.execute-api.eu-central-1.amazonaws.com/dev`).
- **`cognito_user_pool_id`** — Cognito User Pool ID
  (e.g. `eu-central-1_XXXXXXXXX`).
- **`cognito_client_id`** — Cognito App Client ID.
- **`vault_bucket_name`** — The S3 bucket that stores encrypted vault content
  (you only need this for ops/diagnostics).

Save these — the plugin asks for them in Settings.

### 3. Re-deploying After Code Changes

When you pull updated Lambda source, rebuild before each apply:

```bash
cd packages/server/infrastructure
npm run build:lambdas
cd ../terraform
terraform apply -var-file=environments/ce.tfvars
```

***

## Create the First Admin User

A fresh deployment has zero users, zero organizations, and zero vaults. The
bootstrap path is a single call to the public `POST /signup` endpoint. On a
fresh deployment Community Edition's single-tenant gate is open because no
organization exists yet; the moment this first call succeeds, the gate
auto-locks so drive-by strangers cannot create their own orgs on your
deployment.

> **Note:** Do **not** bootstrap with `aws cognito-idp admin-create-user`.
> Earlier versions of these docs (and some third-party guides) suggested that
> path — it only creates a Cognito user with no organization, no vault, no
> VaultMember row, and no permission rule, which leaves every API call after
> login at `403`.

Run the bootstrap from the same shell you used for `terraform apply`:

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

### Request body

| Field         | Description                                                              |
| ------------- | ------------------------------------------------------------------------ |
| `orgName`     | Display name for the organization (e.g. `Acme Corp`).                    |
| `orgSlug`     | URL-safe organization identifier. Lowercased server-side.                |
| `email`       | Admin user email. Lowercased server-side. Used as the Cognito username.  |
| `password`    | Admin user password (see policy below).                                  |
| `displayName` | Admin user display name.                                                 |

### Slug rules

- 3-48 characters.
- Regex: `^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$` — lowercase alphanumeric and
  hyphens only.
- Cannot start or end with a hyphen.
- Reserved slugs (rejected with `400`): `admin`, `api`, `app`, `www`, `auth`,
  `signup`, `login`, `vaultguard`, `support`, `help`, `docs`.

### Password policy

Minimum 12 characters and must include at least one uppercase letter, one
lowercase letter, one digit, and one symbol. Passwords that fail this policy
are rejected with `400` and the message
`Password does not meet requirements: min 12 chars, uppercase, lowercase, digit, symbol`.

### What the call creates atomically

A successful `POST /signup` creates, in one transaction:

- The Cognito user with a **permanent** password — no forced reset on first
  login.
- The `org-{slug}` Cognito group, plus the `admin` Cognito group (the user is
  added to both).
- The organization record (`VaultGuard-{stage}-Organizations`).
- A default vault for the organization (`VaultGuard-{stage}-Vaults`), named
  `{orgName} — Default`.
- The owner `VaultMember` row binding the new user to the default vault with
  the `admin` role.
- A default allow-all permission rule scoped to the new vault so the admin can
  immediately read and write files.

### Auto-lock behavior

As soon as the first organization exists, subsequent `POST /signup` calls
return `403` with the message
`Public signup is disabled on this Community Edition deployment.` This is the
correct behavior for a single-tenant self-host.

If you want to re-enable public signup later (for example, you are running
Community Edition as a community service), set
`vaultguard_allow_public_signup = true` in your tfvars and re-run
`terraform apply`. Terraform passes that through as the
`VAULTGUARD_ALLOW_PUBLIC_SIGNUP` env var on the signup Lambda. Most
self-hosters should leave it `false`. See also the "Single-tenant lockdown"
notes in `docs/SERVER_README.md`.

### Troubleshooting

If the curl call returns `403` with a `Public signup is disabled` message on
what you believe is a fresh deployment, an organization already exists in the
DynamoDB table. Confirm with:

```bash
aws dynamodb scan --table-name VaultGuard-{stage}-Organizations
```

Replace `{stage}` with the value of the `stage` variable in your `ce.tfvars`
(e.g. `VaultGuard-dev-Organizations`). If the scan returns items, the gate is
working as designed — either log in with the existing admin or flip
`vaultguard_allow_public_signup = true` as described above.

Additional admins and users are created via the plugin's invite flow once you
log in with the admin account you just created.

***

## Install the Obsidian Plugin

There are two ways to install the plugin into your Obsidian vault:

### Option 1: Obsidian Community Plugin Directory (easy path, future)

Once VaultGuard is listed in Obsidian's community plugin directory:

1. Open Obsidian → **Settings → Community plugins → Browse**.
2. Search for **VaultGuard** and click **Install**.
3. Enable the plugin.

This path only works after the Obsidian directory submission lands — until then,
use Option 2.

### Option 2: Manual Install From a GitHub Release (works today)

1. Go to the public repo's Releases page:
   <https://github.com/peter70700/vaultguard-obsidian/releases>.
2. Download `main.js`, `manifest.json`, and `styles.css` from the latest tag
   (tag format is bare semver, e.g. `1.0.0`).
3. Create the plugin directory inside your vault:

   ```bash
   mkdir -p /path/to/your/vault/.obsidian/plugins/vaultguard
   ```

4. Copy the three files into that directory.
5. Open Obsidian, go to **Settings → Community plugins**, and enable
   **VaultGuard**.

### Option 3: Build From Source

If you want to run a development build:

```bash
cd packages/plugin
npm install
npm run build
# Output: main.js, manifest.json, styles.css
```

Copy those three files into your vault's `.obsidian/plugins/vaultguard/`
directory and enable the plugin in Obsidian.

***

## Configure the Plugin to Connect to Your Server

Once the plugin is enabled, open **Settings → VaultGuard → Connection** and
turn on manual configuration.

For the normal single-tenant Community Edition setup, paste this server config
URL:

```text
<api_url output>/.well-known/vaultguard.json
```

The plugin fetches a public, non-secret JSON document from your server and fills
the connection fields for you. If you need to enter the advanced fields by hand,
use:

| Setting              | Value                                                            |
| -------------------- | ---------------------------------------------------------------- |
| API endpoint         | `api_url` output (e.g. `https://abc123.execute-api...`)         |
| Organization ID      | The `orgId` returned by signup, or the value from `/orgs/{slug}/config` |
| Cognito User Pool ID | `cognito_user_pool_id` output                                    |
| Cognito Client ID    | `cognito_client_id` output                                       |

Then click **Log in** with the admin email + password you set in the previous
step. On a successful login, the plugin will pick up your organization, fetch
its feature config, and (because `vaultguard_edition` is `"community"`) hide the
Pro-only UI surfaces.

***

## Verify the Deployment End-to-End

Run through this smoke test to confirm the deployment is healthy:

1. **Log in as admin** in the plugin. The connection status indicator should
   transition to "Connected".
2. **Create a test note** in your vault. Save it.
3. **Confirm the note appears in S3** as encrypted content (raw bytes, not
   readable plaintext):

   ```bash
   aws s3 ls s3://<vault_bucket_name>/ --recursive
   aws s3 cp s3://<vault_bucket_name>/<some-key> /tmp/check.bin
   file /tmp/check.bin
   # Expected: "data" — the file is encrypted ciphertext, NOT a markdown file.
   ```

4. **Edit the note** in Obsidian, save, and re-list S3: the object should have
   a new last-modified timestamp.
5. **Log out** of the plugin and **log back in** with the same credentials.
   The note should still open and decrypt correctly.

If all five steps pass, your self-hosted Community Edition deployment is
working end-to-end.

***

## Common Errors

### `terraform apply` fails: certificate not in `us-east-1`

CloudFront-attached ACM certificates **must** live in `us-east-1`. The DNS
module pins the `aws.us_east_1` provider alias for this case. If you see an
error like `certificate not in us-east-1`, confirm:

1. Your default region is set (`aws_region` variable, defaults to
   `eu-central-1`).
2. The `aws.us_east_1` provider alias is configured in `versions.tf`.
3. You have not edited the DNS module to remove the us-east-1 alias.

API-Gateway-attached regional certs (when `domain_name` is set without
CloudFront) live in the same region as the rest of the stack — that's normal.

### `terraform apply` fails: Route53 hosted zone not found

If `domain_name` is non-empty, you must already have a Route53 hosted zone for
that domain (or its parent) in the same AWS account. Either:

- Create the hosted zone in the AWS Console, **or**
- Set `domain_name = ""` to skip the custom-domain logic entirely (the API
  will be reachable via its default API Gateway invoke URL).

### `npm run build:lambdas` fails with a Node version error

Lambda bundling requires **Node.js 20** locally. If `node --version` reports
18 or lower (or 22+), install Node 20 via `nvm` or your platform's package
manager and retry:

```bash
nvm install 20
nvm use 20
node --version  # v20.x.x
```

### Terraform state lock stuck after an interrupted apply

If an apply was interrupted (Ctrl-C, network drop) the state may be
left locked. Unlock with:

```bash
terraform force-unlock <LOCK_ID>
```

The lock ID is printed in the error message.

### Default state backend is local — for production, use S3

The repo ships with **local Terraform state** for simplicity. For a real
deployment you should configure an S3 backend (with DynamoDB locking) so the
state survives a lost laptop and can be shared across team members. Add a
`backend "s3" { ... }` block to `terraform/versions.tf` and run
`terraform init -migrate-state`.

### Plugin reports "Cannot connect to API"

Check, in order:

1. **API endpoint URL** in the plugin settings matches `terraform output -raw
   api_url`. The plugin requires `https://` and no trailing slash.
2. **Cognito User Pool ID** and **Client ID** match
   `terraform output -raw cognito_user_pool_id` and
   `terraform output -raw cognito_client_id`.
3. **Region** in the plugin matches the region where you deployed.
4. The Lambda functions are healthy (CloudWatch Logs under
   `/aws/lambda/vaultguard-<stage>-*`).

### Pro feature appears in the plugin UI

If a share-link, hosted-admin-panel, or billing button appears, your server
is advertising `edition: "pro"` instead of `"community"`. Confirm
`vaultguard_edition = "community"` is set in `ce.tfvars` and re-apply
Terraform. The `/orgs/{slug}/config` endpoint reports the active edition; the
plugin reads it on every login and hides Pro UI when it is `"community"`.
