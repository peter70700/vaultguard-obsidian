export interface WelcomePromptChip {
  label: string;
  value: string;
}

/**
 * Outcome-first starters for a fresh AI Chat.
 *
 * Values only prefill the composer; the user can review or complete them before
 * sending. Keep note-specific starters explicit about `@` because the chat does
 * not receive an implicit "current note" reference.
 */
export const WELCOME_PROMPT_CHIPS: ReadonlyArray<WelcomePromptChip> = [
  {
    label: "Map my vault",
    value:
      "Give me a read-only overview of this vault: main folders, hubs, orphaned notes, " +
      "and tag patterns. Sample only what is necessary and make no changes.",
  },
  {
    label: "Find notes about…",
    value: "Find notes about ",
  },
  {
    label: "Explore a note…",
    value:
      "Show links, backlinks, and related notes for a note " +
      "(type @ to choose the note): ",
  },
  {
    label: "Summarize a note…",
    value:
      "Summarize a note into key points, decisions, open questions, and next actions " +
      "(type @ to choose the note): ",
  },
  {
    label: "Format a note…",
    value: "$format-note ",
  },
  {
    label: "Organize my knowledge base…",
    value: "$organize-knowledge-base ",
  },
];
