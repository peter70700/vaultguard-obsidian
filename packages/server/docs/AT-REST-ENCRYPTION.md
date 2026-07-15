# Local At-Rest Encryption

Canonical reference for how VaultGuard protects vault files on the user's
local disk: threat model, key hierarchy, file format, recovery model,
re-auth gate, and how this relates to the cloud-layer encryption / org
recovery flows.

**Audience**: anyone touching the adapter interceptors, the at-rest
cipher, the recovery flow, the settings UI, or anyone trying to
understand "how is my vault actually protected?"

---

## Why this doc exists

Until v1.x the code wrote **plaintext to disk** and only encrypted in
transit + at S3. The README and ARCHITECTURE.md described an "encrypted
local cache" that didn't actually exist — `src/crypto/cache-store.ts`
was a dead module. Anyone with filesystem access (Finder, another
process, Spotlight) could read every note regardless of the plugin's
permission rules.

This was discovered during real testing. The architecture sequence
diagrams describe the *intended* model and now match what the code
does. The implementation lives in `src/crypto/at-rest-cipher.ts`,
`src/plugin/at-rest-modals.ts`, `src/plugin/main.ts` (interceptors +
helpers), and the settings panel in `src/plugin/settings.ts`.

---

## Two encryption layers — do not conflate

VaultGuard has **two** independent encryption layers. Mixing them up is
the most common source of confusion in support questions. Each has its
own keys, its own recovery story, its own threat model.

```
┌──────────────────────────────────────────────────────────────────┐
│  CLOUD LAYER (server / sync wire)                                 │
│  ─ Per-vault CMK in AWS KMS                                       │
│  ─ Per-vault/scope cloud DEKs wrapped by CMK                      │
│  ─ Per-session lease tokens (1h default, configurable)             │
│  ─ Hybrid ZK mode: per-user UMK derived from passphrase           │
│  Recovery: Manage Organization → Recovery (admin only, escrow)    │
│  See: docs/KEY-LEASE-AND-ZK-IMPLEMENTATION.md                     │
├──────────────────────────────────────────────────────────────────┤
│  AT-REST LAYER (local disk)                                       │
│  ─ Per-device LAK (Local At-rest Key, AES-256)                    │
│  ─ Wrapped by Electron safeStorage (OS keychain)                  │
│  ─ Files on disk are AES-256-GCM ciphertext                       │
│  Recovery: Settings → Local at-rest encryption (user only, code)  │
│  This document describes this layer.                              │
└──────────────────────────────────────────────────────────────────┘
```

The cloud layer protects bytes in transit and at S3; the at-rest layer
protects bytes on the user's local disk. They use **completely
different keys** and **completely different recovery flows**. Encrypting
or decrypting at one layer does not affect the other.

See the [§ "Org recovery vs at-rest recovery"](#org-recovery-vs-at-rest-recovery)
table below for the side-by-side comparison.

---

## Repository-root vaults and Local Project Memory Mode

Local at-rest encryption is not safe for Obsidian vaults whose root is also a
development repository root. In that layout, source files, package files,
tests, Terraform, docs, reports, and agent-memory files must remain plaintext
for Git, editors, package managers, CI-style checks, and coding agents that
read files directly from disk.

Use [Local Project Memory Mode](LOCAL-PROJECT-MEMORY-MODE.md) for repo-root
vaults. That mode disables the at-rest layer, encrypt-on-write behavior,
encrypt-all/background migration jobs, sync, share links, server vault binding,
and organization/company/team controls for the current vault.

"Local-only" by itself does not mean plaintext. Organization sharing and remote
sync are cloud-layer features, while at-rest encryption is a separate local
disk layer. A vault can be local-only and still write `VG1\0` ciphertext unless
at-rest encryption is explicitly disabled. Local Project Memory Mode is the
repo-root-safe way to make that distinction explicit.

If a repository-root vault already contains `VG1\0` files, use **Decrypt vault
and disable at-rest encryption**. That flow persists encryption-disabled state
before plaintext writes, uses raw non-encrypting adapter writes, keeps
encryption disabled after completion, and reports any remaining ciphertext
paths.

---

## Threat model

### What at-rest encryption protects against

- **Cold-disk theft / lost laptop**: a forensic image of the disk
  cannot reveal vault contents without the keychain entry that wraps
  the LAK.
- **Other OS users on the same machine**: their account can't read
  another user's keychain, so vault files appear as ciphertext.
- **Cloud-backup leakage**: iCloud, Time Machine, OneDrive, Backblaze
  back up the *encrypted* bytes. Any backup of `~/Documents/MyVault/`
  is ciphertext.
- **Casual filesystem inspection**: opening the vault folder in Finder
  / Explorer / `cat` shows ciphertext, not notes.
- **External processes searching the vault**: Spotlight indexers,
  AI assistants, "open with" handlers see ciphertext.

### What at-rest encryption does NOT protect against

- **The same OS user with VaultGuard installed**: by definition, the
  user can run Obsidian and see their own notes. This is the same
  trust boundary as Obsidian Sync, FileVault, or any local-app
  encryption.
- **A malicious process running as the same OS user**: it can read
  the keychain entry the same way the plugin does. Mitigate via OS
  process isolation; out of scope.
- **Memory inspection of a running Obsidian**: decrypted content
  lives in process memory while Obsidian is rendering it.
- **Plugin uninstalled while still authenticated**: a user can run
  *Decrypt vault at rest* before disabling. Required because some
  workflows expect the vault to remain readable through normal tools
  after the plugin is removed.
- **Filename leakage**: paths and file names on disk are unchanged.
  An attacker reading the raw filesystem still sees the directory
  tree and file names. Encrypting names would break Obsidian's
  link/wikilink resolution and is out of scope. If filename leakage
  is unacceptable, use generic filenames.
- **Search-index leakage**: Obsidian builds its metadata cache in
  `.obsidian/cache` (extracted links, tags, headings). That directory
  is excluded from at-rest encryption — encrypting it would break
  search. If the cache is sensitive in your threat model, also exclude
  it from cloud backups.
- **Wholesale folder swap**: AES-GCM authenticates each file
  individually. We don't maintain a Merkle tree of the vault, so an
  attacker holding the LAK could swap files in or out without
  per-vault tamper detection.

---

## Key hierarchy

```
OS keychain (macOS Keychain / Windows DPAPI / Linux libsecret)
   │
   └─▶ KEK — managed by Electron safeStorage, opaque to JS
            │
            └─▶ LAK (Local At-rest Key)
                 ─ AES-256, generated once per device-vault binding
                 ─ Stored at .obsidian/plugins/vaultguard/lak.envelope
                   (wrapped by safeStorage; binary-opaque on disk)
                 ─ Never leaves the device through normal operation
                 ─ Held in process memory only while the plugin runs
                 │
                 └─▶ Per-file ciphertext on disk
                      (random 12-byte nonce per write)
```

The LAK is **not** the cloud-layer key lease. The lease encrypts
content for transit and S3 storage and defaults to a 1-hour lease
(configurable by the server deployment). The LAK
encrypts local-disk content, is stable for the life of the device-vault
binding, and never participates in sync.

### Storage method tiers

The cipher probes for the strongest available wrapping mechanism at
init time and falls back gracefully:

| Method | When used | Strength | Recovery story |
|---|---|---|---|
| `safe-storage` | OS keychain available (the normal case) | OS-level encryption, bound to the logged-in user | Recovery code restores on a different machine |
| `localstorage-fallback` | Keychain unavailable / refused (the normal case on **mobile**) | KEK lives in localStorage **and** a durable adapter file (`at-rest-kek.dat`); a full profile/plugin-folder theft can recover the LAK | Same recovery code works; status badge warns the user |
| `ephemeral` | No persistent storage at all (tests, headless) | KEK lives only in memory | Files written this session are unreadable after restart — by design |

The settings UI surfaces the active method in the status badge so the
user can tell whether they're getting full or degraded protection.

#### Fallback-KEK durability (mobile)

On mobile there is no OS keychain, so the LAK is wrapped by a device-local
**fallback KEK**. That KEK used to live **only** in the WebView's
`localStorage`, which Obsidian mobile does **not** durably persist — the OS
evicts it when the app is backgrounded. Once the KEK was gone the LAK could no
longer be unwrapped, so the cipher fell into `needs-recovery` **and the at-rest
sealed session (which survives in `data.json`) became undecryptable — the user
was silently logged out**, with the last-opened file failing to decrypt.

The KEK is therefore **dual-homed**: `localStorage` stays the fast primary, and
a durable adapter file (`.obsidian/plugins/<id>/at-rest-kek.dat`, a sibling of
`lak.envelope`) is the backup. On load, if `localStorage` is empty the KEK is
recovered from the file and `localStorage` is re-seeded; existing installs are
back-filled on first load after upgrade.

**Security trade-off (honest).** The durable copy sits next to `lak.envelope` in
the (at-rest-**excluded**, non-synced) plugin folder, so anyone with the plugin
folder holds both the KEK and the wrapped LAK. That is the same "file access →
decrypt" posture a no-PIN / passkey-model device already accepts (see
*PIN passkey model* — the transparent wrap is kept on purpose). Users who want a
stronger guarantee **enroll a PIN**: the PIN-derived key never touches disk, and
`requirePinOnStartup` removes the transparent `lak.envelope` entirely, so the
durable KEK then wraps nothing decryptable. On mobile, durable persistence is
impossible without *some* on-disk key material — so this is the correct default,
with the PIN as the opt-in hardening.

---

## File format

Files in the vault folder are written in this format:

```
offset  size   field
0       4      magic = "VG1\0" (0x56 0x47 0x31 0x00)
4       1      version = 0x01
5       3      reserved (zero)
8       12     nonce (per-file random)
20      ...    AES-256-GCM ciphertext + auth tag
```

A file that does not start with the `VG1\0` magic is treated as legacy
plaintext and decoded directly. This enables:

- **Lazy migration**: legacy vaults still read; first write encrypts.
- **External adds are auto-encrypted after remote durability is established**:
  when a plaintext file lands in the vault folder from outside Obsidian
  (Finder drop, git checkout), the plugin re-encrypts the identical bytes in
  place — via `vault.on("create")` (with a stat-stability guard against
  mid-copy clobbering) while Obsidian is running, or via the local-only
  catch-up hook after the file's first upload when it was added while
  Obsidian was closed. Files up to `BINARY_SYNC_MAX_BYTES` use the bounded JSON
  path. Larger text and binary files use the vault-scoped direct-transfer path
  up to the deployment's configured maximum. The plugin writes the local VG1
  form only after the encrypted remote object is durable. If a large upload is
  unavailable or fails, the exact local plaintext is preserved and a
  metadata-only pending record is shown for retry; the file is not copied into
  the offline queue or made dependent on the local access key alone.
- **Drag-dropped binaries are ingested end-to-end**: a binary pasted or
  dropped into a protected vault flows through `interceptedWriteBinary` —
  permission check → encrypted JSON or direct upload → VG1 at-rest write after
  remote durability. Offline or failed large uploads remain local plaintext
  with visible pending state. The configured server file-size limit remains
  authoritative.
- **Forward compatibility**: the version byte gives one bump for
  changing scheme without breaking existing vaults.

---

## Excluded paths

The plugin never at-rest-encrypts:

- The entire `.obsidian/` directory — Obsidian reads its config,
  plugin code, and theme files directly from disk before our plugin
  loads. Encrypting any of these would brick the install.
- The `.trash/` directory — Obsidian's trash UX expects readable files.
- Anything in the user's `excludedPaths` setting (sync exclusion list).

The check is `isAtRestExcluded()` in `main.ts`, a superset of the
sync-level `isPathExcluded()`.

### Protected plugin-cache envelopes

The normal vault-file interception above does not automatically make every
file under `.obsidian/plugins/` safe to persist. Protected plugin caches must
use the saved raw adapter boundary plus `AtRestCipher.encryptBinary()` /
`decryptBinary()` so they are authenticated once and do not pass through a
double-encryption loop.

P2 uses this pattern for the semantic index at
`.obsidian/plugins/{manifestId}/semantic/index.v1.envelope`. Only validated
vectors, bounded headings/offsets, and source fingerprints are serialized;
note bodies and snippets are not persisted. The binary envelope is bound to
the current user, local vault, server vault, provider origin, model, chunker,
schema, and vector dimension. `SemanticIndexStore` writes encrypted temporary
bytes, reads/decrypts/validates them through the saved raw adapter, atomically
replaces the prior generation with rollback protection, and deletes final,
temporary, and backup files on purge. Encoded and decrypted intermediate index
buffers are zeroed in `finally` paths, including encryption and validation
failures. See
[Secure Discovery](SECURE-DISCOVERY.md) and the
[semantic-index contract](../specs/006-p2-secure-expansion/contracts/semantic-index.md).

This envelope does not encrypt or replace Obsidian's own metadata or search
indexes.

---

## Media preview (encrypted attachments render decrypted)

At-rest encryption stores every attachment (images, PDFs, audio, video)
as VG1 ciphertext on disk. But Obsidian's renderer does **not** read media
through the intercepted `readBinary` — it loads media from the URL returned
by `adapter.getResourcePath(path)`, an `app://…/<abs-path>?<mtime>` URL that
Electron reads **directly from disk**. Left alone, the renderer would decode
raw VG1 ciphertext → a broken/blank preview. (Text notes are unaffected: they
render through the intercepted `adapter.read`, which decrypts.)

The fix is a **`getResourcePath` override** (`interceptedGetResourcePath` in
`src/plugin/at-rest-adapter-runtime.ts`) that serves a decrypted `blob:` URL:

- **Cache hit** → returns the cached `blob:` URL synchronously (instant render).
- **Cold miss** → `getResourcePath` is synchronous but decryption is async, so
  it returns the real (ciphertext) URL immediately, then decrypts in the
  background, caches a `blob:` URL, and swaps the rendered element's `src` so
  the broken preview repaints itself. A `file-open` pre-warm decrypts opened
  media ahead of standalone image/PDF views to avoid the first-view flash.
- **Passthrough** for non-media, excluded, or not-yet-encrypted paths.

The files **stay VG1-encrypted on disk** — the at-rest guarantee is preserved;
only the in-memory rendered copy is plaintext (a `blob:` URL, same trust
boundary as the decrypted JS string a markdown note already becomes).

**Blob lifecycle:** the cache is keyed by path + resource mtime (so an edited
file re-decrypts), bounded FIFO at 64 entries, and every `blob:` URL is revoked
on eviction, delete, rename, and adapter restore (unload) — no leaks. Decrypt
failures **fail open** (the ciphertext fallback stays; a broken preview, never
a wipe), mirroring the at-rest read philosophy.

The dev-only command *"VaultGuard (debug): Diagnose attachment preview"* reports
the on-disk (VG1) vs decrypted (real magic) header per attachment and whether
the override is active.

> **Known limitation (tracked):** the file **permission header/banner** is
> injected only into `MarkdownView`, so it does not appear on image/PDF/other
> non-markdown file views even though those files now render. See
> `reports/permission-header-non-md-HANDOFF.md`.

---

## Initialization & unlock

- **First load on a device**: a fresh 32-byte LAK is generated, wrapped
  by `safeStorage`, and persisted to
  `.obsidian/plugins/vaultguard/lak.envelope`. New writes are
  encrypted from this moment on.
- **Subsequent loads**: `lak.envelope` is read, unwrapped via
  `safeStorage`, and held in memory. No user prompt — at-rest is
  transparent during normal use.
- **Unwrap fails** (envelope present but can't be decrypted): the
  cipher's status becomes `needs-recovery` and a sticky banner is
  shown pointing the user at the recovery flow. This is the typical
  "moved to a different machine" / "OS keychain reset" path.

The first-run UX surfaces a one-shot Notice when there are still
plaintext files on disk after the cipher initializes, with an
"Encrypt them now →" link to the settings panel. The user can
dismiss it permanently (`atRestFirstRunDismissed` setting).

---

## Vault idle-lock & PIN (Phase 12)

A device PIN adds a **fast idle-lock**: after the org's `autoLockMinutes` of
inactivity the vault **locks** (the in-memory LAK is evicted, managed reads fail
closed, an opaque curtain covers the workspace) instead of logging the user out.
Entering the PIN re-derives the LAK and unlocks — no full email+password+MFA
re-login. The revocation heartbeat keeps running while locked (NN-2), so a
server-side revoke or the session-duration cap still forces a real logout.

### Passkey model (default) — what setting a PIN does

Enrolling a PIN wraps the LAK a **second** way — PBKDF2(PIN)+pepper → AES-GCM →
`lak-pin.envelope` — **alongside** the transparent `safeStorage` wrap
(`lak.envelope`), which is **kept**. Consequences:

- A full login or an app restart unlocks the vault **transparently** via
  `lak.envelope` — **no PIN prompt**. `initAtRestCipher` lands UNLOCKED whenever a
  valid transparent wrap is present. The PIN is only the fast re-lock after idle.
- **Threat model (honest):** this is the **same** posture a device with **no** PIN
  already has — the LAK is recoverable from the OS keychain, so a full-OS-access
  attacker on the **unlocked, logged-in** machine can decrypt. What a PIN still
  buys: the idle-lock UX, plus — because the second wrap is PBKDF2+pepper — it does
  **not** weaken cold-disk theft (the keychain-held KEK/pepper are still required).
  This **relaxes decision D2** ("undecryptable without the PIN even with full OS
  access"), by the product owner's explicit choice, to remove the
  double-authentication of "log in, then also enter a PIN."

### Max-security path — "Require PIN on startup"

Turning on **Settings → Vault lock / PIN → Require PIN on startup** removes the
transparent `lak.envelope`, so `lak-pin.envelope` becomes the **only** wrap:

- The vault is genuinely **undecryptable without the PIN**, even with full OS
  access — this is the original **D2** guarantee.
- Cost: a PIN prompt on **every** startup / login (`initAtRestCipher` lands LOCKED;
  the curtain appears). `enrollPinLock` removes the transparent wrap when this is
  on; toggling it back off restores it (`persistWrappedLak`).

### Legacy-device migration

A device that enrolled a PIN under the pre-12-07 model has **no** `lak.envelope`
(enroll used to delete it), so it lands LOCKED on startup. The first successful PIN
unlock regenerates the transparent wrap (`unlockWithPin` → `persistWrappedLak`),
auto-migrating it into the passkey model — the next startup unlocks transparently.

**Seams:** `enrollPinLock`, `unlockWithPin`, `initAtRestCipher` (the `landLocked`
decision), `setRequirePinOnStartup`, and the `requirePinOnStartup` setting.

---

## Migration

Two command-palette entries plus equivalents in the settings panel:

- **Encrypt vault at rest (full pass)** — walks every non-excluded
  file, reads via raw `readBinary`, writes ciphertext back.
  Idempotent — files already starting with `VG1\0` are skipped. The
  settings panel reports a tally (`12 plaintext, 230 encrypted, 4
  excluded`) before and after.
- **Decrypt vault at rest (back to plaintext)** — reverse. Use this
  before disabling the plugin if you want the vault folder to remain
  readable through normal tools.

Lazy migration also runs automatically: any normal save through
Obsidian writes ciphertext, so a vault converts itself over time even
without the full pass.

---

## Recovery model

### What "recovery" means here

The LAK is generated locally and bound to one device. If that
device's keychain entry is lost — disk failure, OS reinstall, vault
folder copied to a different laptop, plugin reinstalled — the
on-disk ciphertext becomes unreadable on that device until the LAK
is restored. **Recovery** is the process of getting the LAK back
onto a device that no longer has it in keychain form.

### Recovery code format

```
VG1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
└─┬─┘ └────────────────── 64 hex chars ──────────────────────┘ └─┬──┘
prefix  raw 32-byte LAK in hex, grouped 4-by-4 for legibility    2-byte
                                                                 SHA-256
                                                                 checksum
```

- **Prefix** lets us reject obviously-wrong inputs (different
  product, future format) without leaking which part failed.
- **Checksum** catches transcription errors at restore time
  (1-in-65k collision rate — sufficient for typo detection, not a
  security primitive). Cryptographic authenticity comes from
  AES-GCM at decrypt time.
- The string is **case-insensitive** and **whitespace-tolerant** at
  restore — paste from a notes file, type from paper, or read off a
  password manager all work.

### Per-device, per-user — not shared

Each machine generates its own random LAK. Therefore:

- **Two members of the same vault have different recovery codes.**
- **The same user on two different laptops has different codes for
  each.**
- **The recovery code is not stored on the server, ever.** No org
  admin, no AWS service, no log endpoint sees it.

This is the correct design because the LAK only encrypts the *local*
on-disk copy. Cloud sync uses a separate server-issued lease key —
that's how member A's edit ends up readable on member B's machine
without any LAK sharing. See
[§ Two encryption layers](#two-encryption-layers--do-not-conflate).

### Re-auth gate (privileged operations)

Two operations in the settings panel are gated behind a Cognito
password re-auth:

1. **View recovery code** — exporting the LAK is, by design, an
   export channel for the actual key. Without the gate, a brief
   evil-maid moment (locked screen unlocked, unattended Mac) would
   be enough to copy the recovery code and exfiltrate enough to
   decrypt the entire on-disk vault forever. With the gate, the
   attacker needs the user's account password too.
2. **Decrypt vault** (revert to plaintext) — same threat shape: a
   logged-in unattended Obsidian shouldn't be able to silently strip
   the at-rest layer.

The gate uses `verifyAccountPassword()` in `main.ts`, which calls
`cognitoLogin` against the same user pool as the active session and
treats a successful auth (full token set OR any MFA challenge
response) as proof of password knowledge — without mutating session
state. Wrong-password attempts are surfaced inline in the modal.

**Restore from recovery code is intentionally NOT gated.** Possessing
the code is itself the proof of authorization, and gating it would
lock out the very scenario the recovery flow exists for: you've lost
your keychain entry and need a way back in. Requiring two factors to
recover from one factor's loss defeats the purpose.

### Where to keep the recovery code

Recommended, in priority order:

1. **A password manager** with its own master password / hardware
   key (1Password emergency kit, Bitwarden, KeePassXC). Most users.
2. **Printed and stored physically** — fireproof safe, safety
   deposit box, sealed envelope at home. Good for high-value vaults.
3. **A second password manager or air-gapped device** as redundancy.

Do **not**:

- Email it to yourself (mail provider can read it).
- Store it in the same vault it protects.
- Save it in iCloud Notes / Google Keep / any cloud-backed plain
  text — those products' threat models are weaker than VaultGuard's.

### What happens if the recovery code is lost

Two sub-cases:

1. **Keychain entry still works on at least one device** → no
   problem. The user can re-enter the settings panel on that
   device, click *View recovery code* (re-auth), and save a new
   copy. The code itself doesn't change; the cipher always derives
   it deterministically from the LAK.
2. **Keychain lost on all devices, recovery code also lost** →
   the on-disk ciphertext on every device is permanently unreadable.
   This is an intentional security property (no escrow at this
   layer) and the user's recourse is to start fresh: install the
   plugin on a clean machine, log in, and **resync from S3** — all
   files come back. The user has lost the ability to read any
   *salvaged old disk* that wasn't resynced, but no actual data
   loss occurs as long as the cloud copy is intact.

This last point is important: **for normal use, an at-rest recovery
loss is recoverable from the cloud**. The recovery code is only
load-bearing for "I want to read an old disk image without
contacting the server" scenarios.

---

## Org recovery vs at-rest recovery

The two recovery paths protect different layers and serve different
people. They are complementary, not redundant.

| | **Org Recovery** (Manage Organization → Recovery) | **At-rest Recovery** (Settings → Local at-rest encryption) |
|---|---|---|
| Layer it protects | Cloud sync (UMK → DEK → S3 ciphertext) | Local disk (LAK → on-disk ciphertext) |
| Who initiates | Org admin / owner recovering *someone else's* access | The owner on *their own* new device |
| Where the secret lives | On the server, wrapped by the org's RSA recovery public key — `wrappedUMK_org` field | In the user's password manager / on paper, never on the server |
| Who can use it | Org admin holding the org's recovery **private** key (escrow, in HSM / Yubikey / safe) | Anyone holding the printed/exported `VG1-...` code |
| Audit-logged? | Yes — every recovery hits a server audit endpoint | No — purely local; no server call |
| Use case | Offboarded employee, forgotten passphrase, legal hold, account disabled | Same user moves laptops, keychain wipe, OS reinstall, salvaged old disk |
| Granularity | Per-user (recovers their entire cloud key) | Per-device (recovers that machine's at-rest layer) |
| Failure mode | If org loses its private key, no admin recovery is possible — but users can still self-recover via passphrase | If user loses both keychain AND code, that disk's ciphertext is permanently unreadable; cloud copies still recoverable via fresh login + S3 resync |
| Implementation | `recoverUserKey()` in `src/api/client.ts`; UI in `src/admin/admin-modal.ts` "Recovery" tab; data flow in `src/crypto/passphrase-manager.ts` (`wrappedUMK_org`) | `exportRecoveryCode()` / `restoreFromRecoveryCode()` in `src/crypto/at-rest-cipher.ts`; UI in `src/plugin/settings.ts` + `src/plugin/at-rest-modals.ts` |
| Doc references | `docs/KEY-LEASE-AND-ZK-IMPLEMENTATION.md`, `docs/SECURITY-MODEL.md` | This document |

### Disaster matrix

| Scenario | Org Recovery applies? | At-rest Recovery applies? | Outcome |
|---|---|---|---|
| User forgets passphrase | ✅ admin can recover UMK | ❌ irrelevant — at-rest never sees the passphrase | Admin recovers, sets new passphrase, user back online |
| User offboarded, must re-encrypt their files | ✅ admin recovers UMK, triggers re-encryption job | ❌ at-rest never left the user's device anyway | Files re-encrypted server-side under new keys |
| User's laptop disk dies | ❌ no per-device escrow on at-rest layer | Optional — if they had the recovery code, can read salvaged disk; otherwise just relogin and resync | Files come back from S3 on a fresh install |
| User moves vault folder to a new laptop without reinstalling plugin | ❌ | ✅ — recovery code unlocks the on-disk ciphertext | Files readable again on new laptop |
| Org loses its recovery private key | irreparable for admin-recovery flow, but user-driven recovery still works (passphrase still works) | unaffected | No admin overrides; users self-manage |
| User loses keychain AND recovery code AND can still log in | ❌ | ❌ | Old disk unreadable; new install resyncs from S3 — no data loss |
| User loses everything (keychain, code, account, device) | depends on org policy | ❌ | Data loss — at this point the threat model is "burned to the ground" |

---

## Operational checklist (for users / admins)

- [ ] After enabling the plugin on a device, open Settings → Local
      at-rest encryption and click *View recovery code*. Save the
      code in your password manager **and** a second location.
- [ ] If the status badge shows "localstorage-fallback" or
      "ephemeral", investigate why the OS keychain isn't available
      — protection is degraded.
- [ ] Run *Encrypt vault at rest (full pass)* once after install
      to migrate any pre-existing plaintext files. Lazy migration
      handles the long tail, but new users typically want all-at-once.
- [ ] Org admins: confirm `wrappedUMK_org` is populated for every
      hybrid-ZK user. The recovery tab in Manage Organization will
      surface failures.
- [ ] Org admins: store the org's RSA recovery **private key** in
      an HSM, hardware token, or split via Shamir's Secret Sharing.
      Without it, the admin recovery flow cannot decrypt anything.
- [ ] Before disabling the plugin: run *Decrypt vault at rest* if
      you want to keep reading the vault folder through normal
      tools. Otherwise the files remain ciphertext and you'll need
      either the keychain entry or the recovery code to read them.

---

## Code map

- `src/crypto/at-rest-cipher.ts` — owns the LAK, file format, recovery
  code export/import, safeStorage probe, fallback logic, and authenticated
  binary helpers for approved protected-cache callers.
- `src/plugin/at-rest-adapter-runtime.ts` — `interceptVaultAdapter()`
  (wires the read/write/readBinary/writeBinary/rename/**getResourcePath**
  hooks), the `interceptedRead/Write/…` methods, `readPlainFromDisk()` /
  `readPlainBinaryFromDisk()` / `writePlainToDisk()` /
  `writePlainBinaryToDisk()`, `ensureAtRestEncryptedInPlace()`, and the
  media-preview blob cache (`interceptedGetResourcePath`,
  `prewarmResourcePreview`, `revokeAllResourcePreviews`).
- `src/plugin/main.ts` — thin delegates to the runtime above, plus
  `initAtRestCipher()`, migration commands, first-run prompt, recovery
  banner, `verifyAccountPassword()`, and the `file-open` preview pre-warm.
- `src/plugin/at-rest-modals.ts` — `AtRestRecoveryCodeModal` (display),
  `AtRestRestoreModal` (input), `AtRestPasswordConfirmModal` (re-auth
  gate).
- `src/plugin/settings.ts` — `renderAtRestSection()`,
  `renderAtRestStatusBadge()`.
- `tests/at-rest-cipher.test.ts` — round-trip, format, recovery,
  tamper detection, format tolerance.

## What this implementation deliberately does NOT do

- **Filename encryption**: see [§ Threat model](#what-at-rest-encryption-does-not-protect-against).
- **Obsidian search/metadata-index encryption**: the Secure Discovery semantic
  envelope is a separate VaultGuard-owned cache and is not an encryption layer
  for Obsidian's indexes.
- **Memory hygiene**: decrypted content is held in JS strings while
  Obsidian renders it. We don't try to scrub heap memory.
- **Tamper detection beyond GCM**: AES-GCM authenticates each file,
  but no Merkle tree of vault contents.
- **Server escrow of the LAK**: deliberate. The at-rest layer's whole
  point is "the server can't decrypt my disk." If you need
  org-recoverable protection of *cloud-side* content, use the hybrid
  ZK / org recovery flow at the cloud layer; that's a different
  problem with a different solution.
