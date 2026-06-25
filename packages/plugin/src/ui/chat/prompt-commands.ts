import type { ChatPromptTemplate } from "../../types";

export type PromptCommandPrefix = "/" | "$";
export type PromptTemplateKind = "command" | "skill";

export interface ParsedPromptTemplate {
  description?: string;
  argumentHint?: string;
  kind: PromptTemplateKind;
  body: string;
}

export interface BuiltInPromptSkill {
  name: string;
  description: string;
  argumentHint?: string;
  prompt: string;
}

const FRONTMATTER_RE = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)([\s\S]*)$/;

export const OBSIDIAN_CHAT_SKILLS: ReadonlyArray<BuiltInPromptSkill> = [
  {
    name: "format-note",
    description: "Format rough content into clean Obsidian Markdown.",
    argumentHint: "[[note]] or pasted text",
    prompt: `
You are helping format an Obsidian note inside VaultGuard.

Task:
- Format the provided note/content into clean, readable Obsidian Markdown.
- Preserve meaning and important details; do not invent facts.
- Use proper heading hierarchy, concise paragraphs, lists, code fences, tables, and Obsidian callouts when helpful.
- If I reference a note path or wikilink, inspect it with the VaultGuard tools before proposing edits.
- If I did not provide a path or content, ask me for the note or paste.

Input:
{{input}}
`.trim(),
  },
  {
    name: "polish-note",
    description: "Improve clarity, structure, and readability of an Obsidian note.",
    argumentHint: "[[note]] or pasted text",
    prompt: `
Polish this Obsidian note for clarity and usefulness.

Keep the author's intent, remove repetition, improve flow, and return a clean Markdown version. Keep links, tags, frontmatter, checkboxes, code blocks, quotes, and callouts valid for Obsidian. If a referenced note needs reading, use VaultGuard tools; if no note/content is provided, ask for it.

Input:
{{input}}
`.trim(),
  },
  {
    name: "frontmatter",
    description: "Create or repair YAML frontmatter for a note.",
    argumentHint: "[[note]] or fields",
    prompt: `
Help create or repair Obsidian YAML frontmatter.

Return valid YAML frontmatter plus any needed note body changes. Keep keys predictable, avoid duplicate fields, normalize tags as a YAML list, and preserve existing user data. If a referenced note is provided, read it through VaultGuard tools first.

Input:
{{input}}
`.trim(),
  },
  {
    name: "callouts",
    description: "Convert important sections into Obsidian callouts.",
    argumentHint: "[[note]] or pasted text",
    prompt: `
Restructure this content with tasteful Obsidian callouts.

Use callouts only where they improve scanning, such as [!summary], [!note], [!tip], [!warning], [!question], or [!todo]. Keep normal prose normal; do not over-decorate. Preserve links, tags, tasks, and code fences.

Input:
{{input}}
`.trim(),
  },
  {
    name: "tables",
    description: "Clean up Markdown tables and tabular notes.",
    argumentHint: "table or [[note]]",
    prompt: `
Clean up the Markdown tables in this Obsidian content.

Align columns, normalize headers, keep cells concise, preserve links/code spans, and suggest when a list would be clearer than a table. If I reference a note, read it through VaultGuard tools before transforming it.

Input:
{{input}}
`.trim(),
  },
  {
    name: "wikilinks",
    description: "Suggest Obsidian wikilinks, tags, aliases, and backlinks.",
    argumentHint: "[[note]] or pasted text",
    prompt: `
Review this Obsidian note for better internal linking.

Suggest useful wikilinks, aliases, tags, and backlink opportunities. Prefer concrete note names mentioned in the content. Do not fabricate existing files; if you need to verify note names, ask or use available VaultGuard search/list tools.

Input:
{{input}}
`.trim(),
  },
  {
    name: "outline",
    description: "Turn messy notes into an outline with next actions.",
    argumentHint: "[[note]] or pasted text",
    prompt: `
Turn this content into a strong Obsidian outline.

Create a clear heading structure, short bullets, open questions, decisions, and next actions using Markdown task syntax where appropriate. Preserve important details and links.

Input:
{{input}}
`.trim(),
  },
  {
    name: "meeting-notes",
    description: "Convert transcript or rough notes into meeting notes.",
    argumentHint: "transcript or [[note]]",
    prompt: `
Convert this into polished Obsidian meeting notes.

Use sections for Summary, Decisions, Action items, Risks/Open questions, and Raw notes if needed. Use Markdown checkboxes for action items and keep owners/dates when present.

Input:
{{input}}
`.trim(),
  },
  {
    name: "daily-note",
    description: "Format a daily note with priorities, log, and tasks.",
    argumentHint: "rough daily note",
    prompt: `
Format this as a useful Obsidian daily note.

Use concise sections such as Focus, Schedule, Notes, Tasks, Wins, and Follow-up. Preserve existing tasks and dates; do not add fake events.

Input:
{{input}}
`.trim(),
  },
  {
    name: "dataview",
    description: "Draft or debug an Obsidian Dataview query.",
    argumentHint: "goal or broken query",
    prompt: `
Help with an Obsidian Dataview query.

Ask for missing folder/property details when needed. Return a concise explanation and a fenced dataview or dataviewjs block. Keep query assumptions explicit and avoid touching note content unless asked.

Input:
{{input}}
`.trim(),
  },
  {
    name: "organize-knowledge-base",
    description: "Survey your vault and propose + apply a clean knowledge-base structure (PARA / team wiki).",
    argumentHint: "PARA, team wiki, by-project…",
    prompt: `
You are VaultGuard's knowledge-base organizer, working inside the user's Obsidian vault through VaultGuard's local, encrypted, permission-checked tools. Nothing leaves the vault; changes follow the user's active AI Chat permission mode before they are written.

Your job: help the user move toward a clean, navigable knowledge base (their preference may be PARA, a team wiki with MOC/index notes, by-project, or whatever they describe in the input). Work in THREE PHASES and do not skip ahead.

PHASE 1 — SURVEY (read-only). Use vaultguard_graph with op=overview to get the structural shape (hubs, orphans, tag landscape, folder spread) cheaply, then vaultguard_list to see the files and their effective permissions, and vaultguard_search / vaultguard_read only as needed to understand ambiguous areas. Do NOT read every file — sample. Summarize what you found: rough topic clusters, existing folders, tag usage, orphaned notes, and obvious naming inconsistencies.

PHASE 2 — PROPOSE (present the plan IN CHAT, write NOTHING to disk, then ask for approval). Design a target structure that fits the user's stated preference. Write the full plan DIRECTLY IN YOUR CHAT MESSAGE — do NOT create any file — laying out: the proposed folder hierarchy; which existing notes move where; the MOC/index notes you will create; the frontmatter and tag conventions you will apply; and an explicit ORDERED, CHUNKED execution checklist (group the work folder-by-folder or cluster-by-cluster, each chunk small enough to finish in a few tool calls). The plan and its checklist live ONLY in this chat — do NOT create a plan note, an "_Organization Plan" file, or any other meta/WIP note in the vault. Do NOT call vaultguard_create / vaultguard_rename / vaultguard_apply_patch in this phase. Then use vaultguard_ask_user to ask the user to review and approve the plan, or tell you what to change. Create or move files ONLY after the user explicitly approves through that tool result.

PHASE 3 — EXECUTE (after the user approves). Keep the checklist IN THIS CHAT — restate the remaining items and mark off what you finished; never write the checklist or a progress note into the vault. Match your pace to the size of the job, and do not manufacture busywork: if it is SMALL (roughly 8 notes/moves or fewer), do the WHOLE thing in ONE turn and report — do NOT call vaultguard_ask_user between individual notes. Only when it is genuinely LARGE work in a few sizeable chunks (group by folder/cluster, each chunk a batch — never one note at a time), doing as much as comfortably fits per turn; after each chunk report what changed and the remaining checklist and let the user say "continue" before the next. For each item: create the needed MOC/index notes (vaultguard_create), move/rename notes (vaultguard_rename), repair frontmatter and tags (vaultguard_apply_patch), and wire wikilinks. The only notes you create are real content/MOC notes the user approved.

Hard rules:
- You only have these tools: vaultguard_list, vaultguard_search, vaultguard_read, vaultguard_create, vaultguard_apply_patch, vaultguard_rename, vaultguard_delete, vaultguard_graph, vaultguard_ask_user. Use them; do not assume any other capability.
- NEVER create plan / checklist / TODO / progress / scratch / WIP / implementation / meta notes in the vault. The plan lives only in this chat; the only notes you create are real, finished content or MOC/index notes.
- Vault writes follow the user's active AI Chat permission mode — never ask the user to weaken permissions mid-task.
- Never delete a note to "move" it — use vaultguard_rename. Only use vaultguard_delete when the user explicitly asks to remove content, and call it out clearly first.
- Respect permissions: if a path is out of scope or read-only, note it and skip it rather than forcing it.
- Prefer additive, reversible steps. When unsure, propose rather than act.

User preference / scope (may be empty — if so, ask what structure they want and which folders to include before Phase 1):
{{input}}
`.trim(),
  },
];

export function parsePromptTemplate(prompt: string): ParsedPromptTemplate {
  const match = FRONTMATTER_RE.exec(prompt);
  if (!match) {
    return { body: prompt, kind: "command" };
  }

  const frontmatter = match[1];
  const body = match[2] ?? "";
  const kind = readFrontmatterString(frontmatter, ["kind", "type"]) === "skill" ? "skill" : "command";
  return {
    description: readFrontmatterString(frontmatter, ["description"]),
    argumentHint: readFrontmatterString(frontmatter, ["argument-hint", "argumentHint"]),
    kind,
    body,
  };
}

export function promptTemplatePrefix(template: ChatPromptTemplate): PromptCommandPrefix {
  return parsePromptTemplate(template.prompt).kind === "skill" ? "$" : "/";
}

export function expandPromptTemplate(template: ChatPromptTemplate, arg: string): string {
  return expandPromptBody(parsePromptTemplate(template.prompt).body, arg);
}

export function expandBuiltInSkill(name: string, arg: string): string | null {
  const skill = OBSIDIAN_CHAT_SKILLS.find((candidate) => sameCommandName(candidate.name, name));
  return skill ? expandPromptBody(skill.prompt, arg) : null;
}

export function firstPromptLine(prompt: string): string {
  const body = parsePromptTemplate(prompt).body;
  const line = body
    .split(/\n+/)
    .map((part) => part.trim())
    .find(Boolean);
  if (!line) return "";
  return line.length > 96 ? `${line.slice(0, 93)}...` : line;
}

export function sameCommandName(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

function expandPromptBody(body: string, arg: string): string {
  const prompt = body.trim();
  if (!prompt) return arg;
  if (prompt.includes("{{input}}")) {
    return prompt.replace(/\{\{input\}\}/g, arg);
  }
  return arg ? `${prompt}\n\n${arg}` : prompt;
}

function readFrontmatterString(frontmatter: string, keys: string[]): string | undefined {
  const wanted = new Set(keys.map((key) => key.toLowerCase()));
  for (const rawLine of frontmatter.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    if (!wanted.has(key)) continue;
    const value = line.slice(colon + 1).trim();
    if (!value) return undefined;
    return stripYamlQuotes(value);
  }
  return undefined;
}

function stripYamlQuotes(value: string): string {
  if (
    (value.startsWith("\"") && value.endsWith("\"")) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}
