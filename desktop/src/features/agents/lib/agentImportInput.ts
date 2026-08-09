import { nsecToPubkeyHex, safeNpub } from "@/shared/lib/nostrUtils";

/**
 * Parsing for the bulk "import existing agents" paste box.
 *
 * Importing adopts identities that already exist — agents already running
 * under another launcher, or being moved between machines. The paste is the
 * only place a private key is typed by hand, so every line is classified
 * before anything is created and the whole plan is shown back to the user:
 * a half-applied import of twelve agents is far worse than a refused one.
 *
 * Pure and synchronous. No key material is ever logged, and `nsec` is carried
 * only so the caller can hand it straight to the create command.
 */

/** One line the user pasted, after classification. */
export type AgentImportEntry =
  | {
      status: "ok";
      lineNumber: number;
      name: string;
      /** The key itself. Never log this. */
      nsec: string;
      pubkey: string;
      npub: string;
    }
  | {
      status: "error";
      lineNumber: number;
      /** The line as typed, with any key material stripped out. */
      label: string;
      reason: string;
    };

export type AgentImportPlan = {
  /** Every non-blank, non-comment line, in the order pasted. */
  entries: AgentImportEntry[];
  /** The subset that can be created, in order. */
  importable: Extract<AgentImportEntry, { status: "ok" }>[];
  errorCount: number;
};

/**
 * A line's display label, with key material removed.
 *
 * Error rows are rendered in the dialog and may be copied into a bug report,
 * so the raw line must never survive into one: a mistyped key is still a key.
 */
function safeLabel(line: string): string {
  const redacted = line.replace(/nsec1[0-9a-z]+/gi, "nsec1…");
  return redacted.length > 60 ? `${redacted.slice(0, 57)}…` : redacted;
}

/**
 * Classify a pasted block into an import plan.
 *
 * Accepted line shape is `name = nsec1…`. Blank lines and `#` comments are
 * skipped. Splitting on the *first* `=` means a name may not contain one,
 * which is fine, and a key never does.
 *
 * @param text the raw contents of the paste box
 * @param existingPubkeys hex pubkeys of agents this workspace already has, so
 *   a re-import is reported up front rather than failing one-by-one against
 *   the backend's duplicate check
 */
export function parseAgentImportInput(
  text: string,
  existingPubkeys: Iterable<string> = [],
): AgentImportPlan {
  const alreadyImported = new Set(
    [...existingPubkeys].map((pubkey) => pubkey.trim().toLowerCase()),
  );
  // Tracks pubkeys seen earlier *in this paste* so the second occurrence is
  // reported against the first, rather than both looking fine and the create
  // loop failing halfway through.
  const seenInPaste = new Map<string, number>();
  const entries: AgentImportEntry[] = [];

  text.split(/\r?\n/).forEach((rawLine, index) => {
    const lineNumber = index + 1;
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) {
      return;
    }

    const separator = line.indexOf("=");
    if (separator === -1) {
      entries.push({
        status: "error",
        lineNumber,
        label: safeLabel(line),
        reason: line.startsWith("nsec1")
          ? "give this key a name, as `name = nsec1…`"
          : "expected `name = nsec1…`",
      });
      return;
    }

    const name = line.slice(0, separator).trim();
    const nsec = line.slice(separator + 1).trim();

    if (name === "") {
      entries.push({
        status: "error",
        lineNumber,
        label: safeLabel(line),
        reason: "the name is empty",
      });
      return;
    }
    if (nsec === "") {
      entries.push({
        status: "error",
        lineNumber,
        label: name,
        reason: "the key is empty",
      });
      return;
    }

    const pubkey = nsecToPubkeyHex(nsec);
    if (pubkey === null) {
      entries.push({
        status: "error",
        lineNumber,
        label: name,
        reason: "not a valid nsec1… key",
      });
      return;
    }

    const duplicateOf = seenInPaste.get(pubkey);
    if (duplicateOf !== undefined) {
      entries.push({
        status: "error",
        lineNumber,
        label: name,
        reason: `same key as line ${duplicateOf}`,
      });
      return;
    }
    if (alreadyImported.has(pubkey)) {
      entries.push({
        status: "error",
        lineNumber,
        label: name,
        reason: "already imported",
      });
      return;
    }

    seenInPaste.set(pubkey, lineNumber);
    entries.push({
      status: "ok",
      lineNumber,
      name,
      nsec,
      pubkey,
      // A pubkey that just decoded always re-encodes; the fallback keeps the
      // type honest rather than asserting.
      npub: safeNpub(pubkey) ?? pubkey,
    });
  });

  return {
    entries,
    importable: entries.filter(
      (entry): entry is Extract<AgentImportEntry, { status: "ok" }> =>
        entry.status === "ok",
    ),
    errorCount: entries.filter((entry) => entry.status === "error").length,
  };
}
