// Dependency-free diff renderer for the write-confirm modal (AI-CHAT-PANEL.md
// §9.5). Parses unified-diff hunks and renders added lines green / removed
// lines red / context muted, with intra-line word-level highlighting on
// changed lines via a hand-rolled LCS. For `create` (no diff, just content)
// every line is rendered as an addition.
//
// Pure presentation: no network, no filesystem. The logic functions
// (`diffWords`, `parseUnifiedDiff`) are exported for unit testing; `render*`
// take a DOM element and paint into it.

const DIFF_CLS = "vaultguard-chat-diff";
const ROW_CLS = "vaultguard-chat-diff-row";
const GUTTER_CLS = "vaultguard-chat-diff-gutter";
const TEXT_CLS = "vaultguard-chat-diff-text";
const ADD_CLS = "is-add";
const DEL_CLS = "is-del";
const CTX_CLS = "is-context";
const META_CLS = "is-meta";
const WORD_ADD_CLS = "vaultguard-chat-diff-word-add";
const WORD_DEL_CLS = "vaultguard-chat-diff-word-del";

export type DiffLineKind = "add" | "del" | "context" | "meta";

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
}

export interface WordToken {
  kind: "same" | "add" | "del";
  text: string;
}

/**
 * Classify the lines of a unified diff. Hunk headers (`@@ ... @@`), file
 * markers (`---`, `+++`, `diff `, `index `) are `meta`; `+` lines are `add`,
 * `-` lines are `del`, everything else is `context`. The leading marker
 * character is stripped from add/del/context text so the renderer shows the
 * payload only.
 */
export function parseUnifiedDiff(diff: string): DiffLine[] {
  const out: DiffLine[] = [];
  // Normalize line endings, then split. A trailing newline produces an empty
  // final element which we drop so we don't render a spurious blank context row.
  const lines = diff.replace(/\r\n/g, "\n").split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();

  for (const line of lines) {
    if (
      line.startsWith("@@") ||
      line.startsWith("---") ||
      line.startsWith("+++") ||
      line.startsWith("diff ") ||
      line.startsWith("index ")
    ) {
      out.push({ kind: "meta", text: line });
      continue;
    }
    if (line.startsWith("+")) {
      out.push({ kind: "add", text: line.slice(1) });
      continue;
    }
    if (line.startsWith("-")) {
      out.push({ kind: "del", text: line.slice(1) });
      continue;
    }
    // ` ` context line or a bare line (e.g. "\ No newline at end of file").
    out.push({ kind: "context", text: line.startsWith(" ") ? line.slice(1) : line });
  }
  return out;
}

/**
 * Word-level diff between two strings using a longest-common-subsequence over
 * whitespace-delimited tokens. Returns a flat token list tagged `same` / `del`
 * (only in `a`) / `add` (only in `b`). Hand-rolled — no diff library (§ no new
 * deps). Whitespace runs are preserved as their own tokens so spacing renders
 * faithfully.
 */
export function diffWords(a: string, b: string): WordToken[] {
  const at = tokenize(a);
  const bt = tokenize(b);
  const n = at.length;
  const m = bt.length;

  // LCS DP table. (n+1) x (m+1); fine for the short single lines we diff.
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      if (at[i] === bt[j]) dp[i][j] = dp[i + 1][j + 1] + 1;
      else dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const out: WordToken[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (at[i] === bt[j]) {
      pushToken(out, "same", at[i]);
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      pushToken(out, "del", at[i]);
      i++;
    } else {
      pushToken(out, "add", bt[j]);
      j++;
    }
  }
  while (i < n) pushToken(out, "del", at[i++]);
  while (j < m) pushToken(out, "add", bt[j++]);
  return out;
}

// Split into alternating word / whitespace tokens so spacing is preserved.
function tokenize(s: string): string[] {
  if (s.length === 0) return [];
  return s.match(/\s+|\S+/g) ?? [];
}

// Merge adjacent tokens of the same kind so the renderer emits fewer spans.
function pushToken(out: WordToken[], kind: WordToken["kind"], text: string): void {
  const last = out[out.length - 1];
  if (last && last.kind === kind) last.text += text;
  else out.push({ kind, text });
}

/**
 * Render a unified diff into `el`. Changed-line pairs (a `del` immediately
 * followed by an `add`) get intra-line word highlighting; standalone add/del
 * lines render whole-line green/red. Line numbers are tracked from `@@`
 * headers when present, otherwise sequentially.
 */
export function renderUnifiedDiff(el: HTMLElement, diff: string): void {
  const root = el.createDiv({ cls: DIFF_CLS });
  const lines = parseUnifiedDiff(diff);

  let oldNo = 0;
  let newNo = 0;

  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];

    if (line.kind === "meta") {
      const hunk = parseHunkHeader(line.text);
      if (hunk) {
        oldNo = hunk.oldStart;
        newNo = hunk.newStart;
      }
      renderRow(root, META_CLS, "", line.text);
      continue;
    }

    // Pair a removal directly followed by an addition into a word-diff row.
    if (line.kind === "del" && idx + 1 < lines.length && lines[idx + 1].kind === "add") {
      const next = lines[idx + 1];
      renderWordRow(root, oldNo, line.text, "del");
      renderWordRow(root, newNo, next.text, "add", diffWords(line.text, next.text));
      oldNo++;
      newNo++;
      idx++; // consumed the paired add
      continue;
    }

    if (line.kind === "add") {
      renderRow(root, ADD_CLS, String(newNo), line.text, "+");
      newNo++;
    } else if (line.kind === "del") {
      renderRow(root, DEL_CLS, String(oldNo), line.text, "-");
      oldNo++;
    } else {
      renderRow(root, CTX_CLS, String(newNo), line.text, " ");
      oldNo++;
      newNo++;
    }
  }
}

/**
 * Render plain content (e.g. a `create`) as an all-addition view: every line
 * green with sequential new-line numbers.
 */
export function renderAllAdditions(el: HTMLElement, content: string): void {
  const root = el.createDiv({ cls: DIFF_CLS });
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  let no = 1;
  for (const text of lines) {
    renderRow(root, ADD_CLS, String(no), text, "+");
    no++;
  }
  if (lines.length === 0) {
    renderRow(root, CTX_CLS, "", "(empty file)");
  }
}

// ─── internal DOM helpers ────────────────────────────────────────────────────

function renderRow(
  root: HTMLElement,
  kindCls: string,
  gutter: string,
  text: string,
  marker = "",
): void {
  const row = root.createDiv({ cls: `${ROW_CLS} ${kindCls}` });
  row.createSpan({ cls: GUTTER_CLS, text: gutter });
  const body = row.createSpan({ cls: TEXT_CLS });
  body.setText(`${marker}${text}`);
}

// A word-diffed row: the gutter + marker, then per-word add/del spans.
function renderWordRow(
  root: HTMLElement,
  gutter: number,
  text: string,
  side: "add" | "del",
  tokens?: WordToken[],
): void {
  const kindCls = side === "add" ? ADD_CLS : DEL_CLS;
  const marker = side === "add" ? "+" : "-";
  const row = root.createDiv({ cls: `${ROW_CLS} ${kindCls}` });
  row.createSpan({ cls: GUTTER_CLS, text: String(gutter) });
  const body = row.createSpan({ cls: TEXT_CLS });
  body.appendText(marker);

  if (!tokens) {
    body.appendText(text);
    return;
  }

  for (const tok of tokens) {
    // On the del row, show `same` + `del`; on the add row, show `same` + `add`.
    if (tok.kind === "same") {
      body.appendText(tok.text);
    } else if (side === "del" && tok.kind === "del") {
      body.createSpan({ cls: WORD_DEL_CLS, text: tok.text });
    } else if (side === "add" && tok.kind === "add") {
      body.createSpan({ cls: WORD_ADD_CLS, text: tok.text });
    }
    // del-tokens on the add side and add-tokens on the del side are omitted.
  }
}

interface HunkHeader {
  oldStart: number;
  newStart: number;
}

// Parse `@@ -<oldStart>[,<oldLen>] +<newStart>[,<newLen>] @@`.
function parseHunkHeader(text: string): HunkHeader | null {
  const m = text.match(/^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/);
  if (!m) return null;
  return { oldStart: Number(m[1]), newStart: Number(m[2]) };
}

export { DIFF_CLS };
