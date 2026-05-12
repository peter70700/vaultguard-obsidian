/**
 * Installs / removes a Claude Code skill at `~/.claude/skills/vaultguard/SKILL.md`.
 *
 * Why this exists
 * ---------------
 * Claude Code's built-in `Read` / `Glob` / `Grep` tools see VaultGuard files
 * as `VG1\0`-prefixed ciphertext. The MCP bridge exposes a clean tool
 * surface (`mcp__vaultguard__*`) that returns plaintext, but the model
 * doesn't *know* to use those tools by default. A Claude Code skill is the
 * documented way to teach the model: when it encounters an Obsidian vault
 * with VG1 magic, it should reach for the bridge tools instead of the
 * filesystem ones.
 *
 * Why it's a separate file
 * ------------------------
 * The skill content is bundled at build time via esbuild's `text` loader
 * (`./SKILL.md` import below). This installer writes that content to the
 * user's home directory using Node `fs` — outside Obsidian's vault
 * adapter, since `~/.claude/skills/` is intentionally not in the vault.
 * Keeping the FS-touching code isolated from the rest of the plugin makes
 * it easy to audit and to skip on platforms where home-dir writes are
 * inappropriate (e.g. mobile Obsidian, where Node FS isn't available).
 *
 * No secrets here
 * ---------------
 * The skill file contains *no* per-user state — no bearer token, no lease
 * id, no endpoint URL. Those live only in the user's MCP server config
 * (e.g. `.claude/mcp.json`) and rotate independently of skill install.
 * Re-running installSkill() never invalidates a lease or token.
 */

import skillBody from "./SKILL.md";

export const VAULTGUARD_SKILL_NAME = "vaultguard";

// Bumped on every meaningful skill body change. The installer uses this
// to decide whether to overwrite an existing file — we don't want to
// stomp a user-edited skill, but we *do* want to push fixes the next
// time they ask us to install.
//
// The marker lives inside the YAML frontmatter as `vaultguard-managed:
// true` + `vaultguard-schema: N` so the skill loader's "first body
// line" parsing sees the real description, not our marker. (The
// schema=1 build accidentally placed an HTML comment *before* the
// frontmatter, which made the skill listing show the marker as the
// description.)
const SKILL_VERSION = 2;

const MANAGED_MARKER_REGEX = /vaultguard-managed:\s*true[\s\S]{0,200}?vaultguard-schema:\s*(\d+)/m;
// Detects the legacy schema-1 marker (HTML comment before frontmatter)
// so a re-install after upgrading replaces the busted file rather than
// flagging it as a "managed conflict".
const LEGACY_MARKER_REGEX = /<!--\s*vaultguard-skill:\s*managed\s+schema=(\d+)\s*-->/;

export interface SkillInstallStatus {
  // True when Claude Code's skills directory exists. Absent on machines
  // where Claude Code was never installed (or installed under a non-
  // default location); the installer will refuse rather than create the
  // directory tree to avoid surprising users.
  claudeCodeAvailable: boolean;
  // Resolved absolute path of the skill file. Populated even when
  // `claudeCodeAvailable` is false so the UI can tell the user where
  // we *would* write.
  skillFilePath: string;
  // True when our managed skill file is on disk (matched by the
  // `vaultguard-skill: managed` marker — not a generic "any file
  // present" check, so we don't claim ownership over a hand-written
  // SKILL.md the user may have placed there).
  installed: boolean;
  // True when an existing file was found but doesn't carry our marker.
  // The UI surfaces this as "Skill conflict — file exists but wasn't
  // installed by VaultGuard. Overwrite?" so the user is in control.
  managedConflict: boolean;
  // The schema number embedded in the installed file, if present.
  // When less than `SKILL_VERSION`, the UI shows an "Update available"
  // affordance.
  installedSchema: number | null;
}

export interface SkillInstallerDeps {
  fs: {
    existsSync(path: string): boolean;
    readFileSync(path: string, encoding: "utf-8"): string;
    writeFileSync(path: string, data: string, encoding: "utf-8"): void;
    mkdirSync(path: string, options?: { recursive?: boolean }): void;
    rmSync(path: string, options?: { recursive?: boolean; force?: boolean }): void;
  };
  path: {
    join(...segments: string[]): string;
  };
  homedir(): string;
  log(message: string): void;
}

/**
 * Computes the current skill install status without touching disk
 * beyond stat / read. Safe to call repeatedly from the settings UI.
 */
export function inspectSkillInstall(deps: SkillInstallerDeps): SkillInstallStatus {
  const claudeRoot = deps.path.join(deps.homedir(), ".claude");
  const skillsRoot = deps.path.join(claudeRoot, "skills");
  const skillDir = deps.path.join(skillsRoot, VAULTGUARD_SKILL_NAME);
  const skillFilePath = deps.path.join(skillDir, "SKILL.md");

  const claudeCodeAvailable = deps.fs.existsSync(claudeRoot) && deps.fs.existsSync(skillsRoot);

  if (!deps.fs.existsSync(skillFilePath)) {
    return {
      claudeCodeAvailable,
      skillFilePath,
      installed: false,
      managedConflict: false,
      installedSchema: null,
    };
  }

  const existing = deps.fs.readFileSync(skillFilePath, "utf-8");
  const ours = MANAGED_MARKER_REGEX.exec(existing);
  if (ours) {
    return {
      claudeCodeAvailable,
      skillFilePath,
      installed: true,
      managedConflict: false,
      installedSchema: Number(ours[1]),
    };
  }
  // Legacy install (schema=1 used an HTML comment before the YAML
  // frontmatter). Treat it as ours so a re-install replaces it cleanly
  // instead of asking the user to confirm an "overwrite unmanaged" prompt
  // for a file we authored.
  const legacy = LEGACY_MARKER_REGEX.exec(existing);
  if (legacy) {
    return {
      claudeCodeAvailable,
      skillFilePath,
      installed: true,
      managedConflict: false,
      installedSchema: Number(legacy[1]),
    };
  }
  return {
    claudeCodeAvailable,
    skillFilePath,
    installed: false,
    managedConflict: true,
    installedSchema: null,
  };
}

export interface InstallResult {
  filePath: string;
  // What the installer actually did. Useful for the audit event so we
  // can distinguish "user clicked install but file was already current"
  // from "we genuinely wrote new content to disk".
  action: "created" | "updated" | "noop" | "overwrote-conflict";
}

/**
 * Writes (or overwrites) the skill file. Creates `~/.claude/skills/`
 * tree if it doesn't exist (only when `force=true` — by default we
 * refuse to create the Claude Code directory ourselves, since its
 * absence usually means Claude Code isn't installed and silently
 * provisioning it would surprise the user).
 *
 * `overwriteUnmanaged=true` is required to overwrite a hand-written
 * SKILL.md that doesn't carry our marker; the settings UI gates this
 * behind an explicit confirmation.
 */
export function installSkill(
  deps: SkillInstallerDeps,
  options: { force?: boolean; overwriteUnmanaged?: boolean } = {}
): InstallResult {
  const status = inspectSkillInstall(deps);

  if (!status.claudeCodeAvailable && !options.force) {
    throw new Error(
      "Claude Code does not appear to be installed (no ~/.claude/skills/ directory). " +
        "Install Claude Code first, then re-run this command."
    );
  }
  if (status.managedConflict && !options.overwriteUnmanaged) {
    throw new Error(
      "A SKILL.md already exists at this path but wasn't installed by VaultGuard. " +
        "Pass overwriteUnmanaged=true to replace it, or remove it manually first."
    );
  }

  const desired = skillBody;
  const skillDir = deps.path.join(deps.homedir(), ".claude", "skills", VAULTGUARD_SKILL_NAME);

  if (!deps.fs.existsSync(skillDir)) {
    deps.fs.mkdirSync(skillDir, { recursive: true });
  }

  let action: InstallResult["action"];
  if (!status.installed && !status.managedConflict) {
    action = "created";
  } else if (status.managedConflict) {
    action = "overwrote-conflict";
  } else if (status.installedSchema === SKILL_VERSION) {
    // Even when schema matches, re-read and compare. A user could have
    // hand-edited within the managed range; we still write so the latest
    // content is on disk, but report "noop" if bytes match.
    const existing = deps.fs.readFileSync(status.skillFilePath, "utf-8");
    action = existing === desired ? "noop" : "updated";
  } else {
    action = "updated";
  }

  if (action !== "noop") {
    deps.fs.writeFileSync(status.skillFilePath, desired, "utf-8");
    deps.log(
      `VaultGuard skill installed at ${status.skillFilePath} (action: ${action}, schema: ${SKILL_VERSION})`
    );
  } else {
    deps.log(`VaultGuard skill already current at ${status.skillFilePath}`);
  }

  return { filePath: status.skillFilePath, action };
}

/**
 * Removes the managed skill file (and the per-skill directory if empty).
 * Refuses to delete an unmanaged SKILL.md without `force=true`.
 */
export function uninstallSkill(
  deps: SkillInstallerDeps,
  options: { force?: boolean } = {}
): { filePath: string; removed: boolean } {
  const status = inspectSkillInstall(deps);

  if (!status.installed && !status.managedConflict) {
    return { filePath: status.skillFilePath, removed: false };
  }
  if (status.managedConflict && !options.force) {
    throw new Error(
      "SKILL.md exists but wasn't installed by VaultGuard — refusing to delete. " +
        "Pass force=true to remove it anyway."
    );
  }

  // rmSync on the directory cleans up the SKILL.md plus any companion
  // assets (none today, but future skill bumps may add `references/`
  // subfolders).
  const skillDir = deps.path.join(deps.homedir(), ".claude", "skills", VAULTGUARD_SKILL_NAME);
  deps.fs.rmSync(skillDir, { recursive: true, force: true });
  deps.log(`VaultGuard skill removed from ${status.skillFilePath}`);
  return { filePath: status.skillFilePath, removed: true };
}

