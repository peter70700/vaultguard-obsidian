/**
 * Installs / removes a Codex skill at
 * `~/.agents/skills/vaultguard-obsidian/SKILL.md`.
 *
 * The skill has no per-user state. Bearer tokens stay in the shell
 * environment (`VAULTGUARD_AGENT_TOKEN`) and MCP configuration, never in
 * the skill body.
 */

import skillBody from "./SKILL.md";
import type { SkillInstallerDeps } from "../agent-bridge-skill/installer";

export const VAULTGUARD_CODEX_SKILL_NAME = "vaultguard-obsidian";

const CODEX_SKILL_VERSION = 1;
const MANAGED_MARKER_REGEX =
  /vaultguard-managed:\s*true[\s\S]{0,300}?vaultguard-client:\s*codex[\s\S]{0,300}?vaultguard-schema:\s*(\d+)/m;

export interface CodexSkillInstallStatus {
  codexSkillsAvailable: boolean;
  skillFilePath: string;
  installed: boolean;
  managedConflict: boolean;
  installedSchema: number | null;
}

export interface CodexInstallResult {
  filePath: string;
  action: "created" | "updated" | "noop" | "overwrote-conflict";
}

export function inspectCodexSkillInstall(deps: SkillInstallerDeps): CodexSkillInstallStatus {
  const skillsRoot = deps.path.join(deps.homedir(), ".agents", "skills");
  const skillDir = deps.path.join(skillsRoot, VAULTGUARD_CODEX_SKILL_NAME);
  const skillFilePath = deps.path.join(skillDir, "SKILL.md");
  const codexSkillsAvailable = deps.fs.existsSync(skillsRoot);

  if (!deps.fs.existsSync(skillFilePath)) {
    return {
      codexSkillsAvailable,
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
      codexSkillsAvailable,
      skillFilePath,
      installed: true,
      managedConflict: false,
      installedSchema: Number(ours[1]),
    };
  }

  return {
    codexSkillsAvailable,
    skillFilePath,
    installed: false,
    managedConflict: true,
    installedSchema: null,
  };
}

export function installCodexSkill(
  deps: SkillInstallerDeps,
  options: { force?: boolean; overwriteUnmanaged?: boolean } = {},
): CodexInstallResult {
  const status = inspectCodexSkillInstall(deps);

  if (!status.codexSkillsAvailable && !options.force) {
    throw new Error(
      "Codex skills directory was not found (no ~/.agents/skills/ directory). " +
        "Create it by installing anyway only if you use Codex skills on this machine.",
    );
  }
  if (status.managedConflict && !options.overwriteUnmanaged) {
    throw new Error(
      "A SKILL.md already exists at this path but was not installed by VaultGuard. " +
        "Pass overwriteUnmanaged=true to replace it, or inspect it manually first.",
    );
  }

  const desired = skillBody;
  const skillDir = deps.path.join(
    deps.homedir(),
    ".agents",
    "skills",
    VAULTGUARD_CODEX_SKILL_NAME,
  );

  if (!deps.fs.existsSync(skillDir)) {
    deps.fs.mkdirSync(skillDir, { recursive: true });
  }

  let action: CodexInstallResult["action"];
  if (!status.installed && !status.managedConflict) {
    action = "created";
  } else if (status.managedConflict) {
    action = "overwrote-conflict";
  } else if (status.installedSchema === CODEX_SKILL_VERSION) {
    const existing = deps.fs.readFileSync(status.skillFilePath, "utf-8");
    action = existing === desired ? "noop" : "updated";
  } else {
    action = "updated";
  }

  if (action !== "noop") {
    deps.fs.writeFileSync(status.skillFilePath, desired, "utf-8");
    deps.log(
      `VaultGuard Codex skill installed at ${status.skillFilePath} (action: ${action}, schema: ${CODEX_SKILL_VERSION})`,
    );
  } else {
    deps.log(`VaultGuard Codex skill already current at ${status.skillFilePath}`);
  }

  return { filePath: status.skillFilePath, action };
}

export function uninstallCodexSkill(
  deps: SkillInstallerDeps,
  options: { force?: boolean } = {},
): { filePath: string; removed: boolean } {
  const status = inspectCodexSkillInstall(deps);

  if (!status.installed && !status.managedConflict) {
    return { filePath: status.skillFilePath, removed: false };
  }
  if (status.managedConflict && !options.force) {
    throw new Error(
      "SKILL.md exists but was not installed by VaultGuard; refusing to delete. " +
        "Pass force=true to remove it anyway.",
    );
  }

  const skillDir = deps.path.join(
    deps.homedir(),
    ".agents",
    "skills",
    VAULTGUARD_CODEX_SKILL_NAME,
  );
  deps.fs.rmSync(skillDir, { recursive: true, force: true });
  deps.log(`VaultGuard Codex skill removed from ${status.skillFilePath}`);
  return { filePath: status.skillFilePath, removed: true };
}
