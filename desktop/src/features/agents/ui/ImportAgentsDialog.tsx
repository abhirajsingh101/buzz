import * as React from "react";

import { useCreateManagedAgentMutation } from "@/features/agents/hooks";
import { Button } from "@/shared/ui/button";
import { ChooserDialogContent } from "@/shared/ui/chooser-dialog-content";
import { Dialog } from "@/shared/ui/dialog";
import { Textarea } from "@/shared/ui/textarea";
import {
  type AgentImportEntry,
  parseAgentImportInput,
} from "../lib/agentImportInput";
import { WhereToRunSection } from "./WhereToRunSection";
import {
  canSubmitWhereToRun,
  emptyWhereToRunDraft,
  resolveBackendIntent,
  type WhereToRunDraft,
} from "./whereToRunIntent";

/**
 * Adopt agent identities that already exist.
 *
 * Every other create path mints a fresh keypair. This one takes keys the user
 * already has — agents already running under another launcher, or being moved
 * between machines — and gives them records, so the app stops treating them as
 * strangers.
 *
 * Bulk by design: the situation that calls for this is a host already running
 * a dozen hand-launched agents, and adopting them one dialog at a time is
 * twelve chances to fumble a private key. The paste is parsed and shown back
 * in full *before* anything is created, because a half-applied import of
 * twelve agents is much worse than a refused one.
 *
 * Imported agents are deliberately **not** started. Adoption and launching are
 * separate decisions, and the safe order is to confirm the record looks right
 * first — which is also what lets an owner trial this on a single agent.
 */
export function ImportAgentsDialog({
  existingPubkeys,
  onImported,
  onOpenChange,
  open,
}: {
  /** Hex pubkeys already in this workspace, so a re-import is caught up front. */
  existingPubkeys: readonly string[];
  /** Called after at least one agent was created, so callers can refetch. */
  onImported: () => void;
  onOpenChange: (open: boolean) => void;
  open: boolean;
}) {
  const createAgent = useCreateManagedAgentMutation();
  const [text, setText] = React.useState("");
  const [whereToRun, setWhereToRun] =
    React.useState<WhereToRunDraft>(emptyWhereToRunDraft);
  const [isImporting, setIsImporting] = React.useState(false);
  const [failures, setFailures] = React.useState<
    { name: string; message: string }[]
  >([]);

  const plan = React.useMemo(
    () => parseAgentImportInput(text, existingPubkeys),
    [existingPubkeys, text],
  );

  const reset = React.useCallback(() => {
    setText("");
    setWhereToRun(emptyWhereToRunDraft);
    setFailures([]);
  }, []);

  const handleOpenChange = React.useCallback(
    (next: boolean) => {
      // Never leave pasted keys sitting in component state behind a closed
      // dialog.
      if (!next) reset();
      onOpenChange(next);
    },
    [onOpenChange, reset],
  );

  const handleImport = React.useCallback(async () => {
    setIsImporting(true);
    setFailures([]);
    const backend = resolveBackendIntent(whereToRun);
    const failed: { name: string; message: string }[] = [];
    let created = 0;

    // Sequential on purpose. Each create takes the managed-agents store lock,
    // mints an auth tag, and publishes a kind:30177 — firing twelve at once
    // contends on all three for no gain, and makes a partial failure much
    // harder to read.
    for (const entry of plan.importable) {
      try {
        await createAgent.mutateAsync({
          name: entry.name,
          importPrivateKeyNsec: entry.nsec,
          ...(backend ? { backend } : {}),
          // Adoption is not launching — see the component docs.
          spawnAfterCreate: false,
          startOnAppLaunch: false,
        });
        created += 1;
      } catch (error) {
        failed.push({
          name: entry.name,
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }

    setIsImporting(false);
    setFailures(failed);
    if (created > 0) onImported();
    // Only dismiss on a clean run: if something failed, the list is the only
    // record of which agents still need attention.
    if (failed.length === 0) handleOpenChange(false);
  }, [createAgent, handleOpenChange, onImported, plan.importable, whereToRun]);

  const canImport =
    plan.importable.length > 0 &&
    !isImporting &&
    canSubmitWhereToRun(whereToRun);

  return (
    <Dialog onOpenChange={handleOpenChange} open={open}>
      <ChooserDialogContent
        className="max-w-2xl"
        data-testid="import-agents-dialog"
        title="Import existing agents"
      >
        <div className="flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            Give records to agents whose identities already exist — one per
            line, as <code className="font-mono">name = nsec1…</code>. They are
            imported but not started.
          </p>

          <Textarea
            aria-label="Agents to import"
            className="min-h-40 font-mono text-sm"
            data-testid="import-agents-input"
            disabled={isImporting}
            onChange={(event) => setText(event.target.value)}
            placeholder={"ace = nsec1…\narchitect = nsec1…"}
            spellCheck={false}
            value={text}
          />

          {plan.entries.length > 0 && <ImportPlanList entries={plan.entries} />}

          <WhereToRunSection
            draft={whereToRun}
            isPending={isImporting}
            onDraftChange={setWhereToRun}
          />

          {failures.length > 0 && (
            <div
              className="flex flex-col gap-1 rounded-md border border-destructive/40 bg-destructive/5 p-3"
              data-testid="import-agents-failures"
            >
              <p className="text-sm font-medium">
                {failures.length} agent{failures.length === 1 ? "" : "s"} could
                not be imported
              </p>
              {failures.map((failure) => (
                <p className="text-xs text-muted-foreground" key={failure.name}>
                  <span className="font-mono">{failure.name}</span> —{" "}
                  {failure.message}
                </p>
              ))}
            </div>
          )}

          <div className="flex items-center justify-end gap-2">
            <Button
              disabled={isImporting}
              onClick={() => handleOpenChange(false)}
              variant="ghost"
            >
              Cancel
            </Button>
            <Button
              data-testid="import-agents-submit"
              disabled={!canImport}
              onClick={handleImport}
            >
              {isImporting
                ? "Importing…"
                : `Import ${plan.importable.length || ""}`.trim()}
            </Button>
          </div>
        </div>
      </ChooserDialogContent>
    </Dialog>
  );
}

/**
 * The parsed paste, shown back before anything is created.
 *
 * Both halves matter: the ready rows carry the derived `npub` so the owner can
 * confirm each key is the identity they meant, and the rejected rows say
 * exactly what to fix rather than failing one at a time against the backend.
 */
function ImportPlanList({ entries }: { entries: readonly AgentImportEntry[] }) {
  return (
    <ul
      className="flex max-h-56 flex-col gap-1 overflow-y-auto rounded-md border p-2"
      data-testid="import-agents-plan"
    >
      {entries.map((entry) =>
        entry.status === "ok" ? (
          <li
            className="flex items-baseline gap-2 text-sm"
            key={`ok-${entry.lineNumber}`}
          >
            <span aria-hidden className="text-muted-foreground">
              ✓
            </span>
            <span className="font-medium">{entry.name}</span>
            <span className="truncate font-mono text-2xs text-muted-foreground">
              {entry.npub}
            </span>
          </li>
        ) : (
          <li
            className="flex items-baseline gap-2 text-sm text-muted-foreground"
            key={`err-${entry.lineNumber}`}
          >
            <span aria-hidden>⚠</span>
            <span className="font-medium">
              {entry.label || `line ${entry.lineNumber}`}
            </span>
            <span className="text-xs">{entry.reason}</span>
          </li>
        ),
      )}
    </ul>
  );
}
