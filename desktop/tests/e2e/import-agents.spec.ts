import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";

/**
 * Adopting agent identities that already exist.
 *
 * The behavior worth pinning is not "a dialog opens" — it is that the paste is
 * classified *before* anything is created, and that a created record carries
 * the identity that was pasted rather than a freshly minted one. Both are
 * invisible in unit tests: the parser cannot prove the dialog wires it up, and
 * the backend cannot prove the frontend sends the key.
 */

// Published NIP-19 test vectors, never live identities.
const NSEC_A =
  "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
const NSEC_B =
  "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

test.beforeEach(async ({ page }) => {
  await installMockBridge(page);
});

async function openImportDialog(page: import("@playwright/test").Page) {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("open-agents-view")).toBeVisible({
    timeout: 15_000,
  });
  await page.getByTestId("open-agents-view").click();
  await page.getByTestId("import-agents-button").click();
  await expect(page.getByTestId("import-agents-dialog")).toBeVisible();
}

test("the paste is classified before anything is created", async ({ page }) => {
  await openImportDialog(page);

  // Nothing to import yet, so there is nothing to submit.
  await expect(page.getByTestId("import-agents-submit")).toBeDisabled();

  await page
    .getByTestId("import-agents-input")
    .fill(
      [
        `ace = ${NSEC_A}`,
        "broken = not-a-key",
        `duplicate = ${NSEC_A}`,
        `architect = ${NSEC_B}`,
      ].join("\n"),
    );

  const plan = page.getByTestId("import-agents-plan");
  await expect(plan).toBeVisible();

  // Ready rows carry the derived npub, which is how an owner confirms each
  // key is the identity they meant before committing to it.
  await expect(plan).toContainText("ace");
  await expect(plan).toContainText("architect");
  await expect(plan).toContainText("npub1");

  // Rejected rows say what to fix rather than failing one at a time later.
  await expect(plan).toContainText("not a valid nsec1… key");
  await expect(plan).toContainText("same key as line 1");

  // Two of the four lines are importable, and the button says so.
  await expect(page.getByTestId("import-agents-submit")).toHaveText("Import 2");
});

test("an imported agent adopts the pasted identity", async ({ page }) => {
  await openImportDialog(page);

  await page.getByTestId("import-agents-input").fill(`ace = ${NSEC_A}`);
  await expect(page.getByTestId("import-agents-submit")).toBeEnabled();
  await page.getByTestId("import-agents-submit").click();

  // A clean run dismisses; anything left open means something failed.
  await expect(page.getByTestId("import-agents-dialog")).toBeHidden({
    timeout: 15_000,
  });

  // The whole point: the record carries the *pasted* key's identity, not a
  // newly minted one. Asserted through the IPC payload the dialog actually
  // sent, so a frontend that dropped the field would fail here.
  const created = await page.evaluate(() =>
    (window.__BUZZ_E2E_COMMAND_PAYLOADS__ ?? []).filter(
      (entry) => entry.command === "create_managed_agent",
    ),
  );
  expect(created).toHaveLength(1);
  const input = (created[0].payload as { input: Record<string, unknown> })
    .input;
  expect(input.name).toBe("ace");
  expect(input.importPrivateKeyNsec).toBe(NSEC_A);

  // Adoption is not launching — the two are separate decisions, and a Start
  // that rode along with the import would deploy twelve agents on one click.
  expect(input.spawnAfterCreate).toBe(false);
  expect(input.startOnAppLaunch).toBe(false);

  // Exact match: a substring search for "ace" also hits the hidden
  // drag-and-drop instructions ("press the sp*ace*"), which is visible-adjacent
  // enough to make a loose locator pass or fail for the wrong reason.
  await expect(page.getByText("ace", { exact: true }).first()).toBeVisible();
});

test("a key the workspace already has is refused before submit", async ({
  page,
}) => {
  await openImportDialog(page);

  await page.getByTestId("import-agents-input").fill(`ace = ${NSEC_A}`);
  await page.getByTestId("import-agents-submit").click();
  await expect(page.getByTestId("import-agents-dialog")).toBeHidden({
    timeout: 15_000,
  });

  // Re-importing the same key must be caught in the plan, not by a backend
  // error after a partial batch has already been created.
  await page.getByTestId("import-agents-button").click();
  await page.getByTestId("import-agents-input").fill(`ace-again = ${NSEC_A}`);

  await expect(page.getByTestId("import-agents-plan")).toContainText(
    "already imported",
  );
  await expect(page.getByTestId("import-agents-submit")).toBeDisabled();

  // The refusal happens in the plan, so no second create is ever attempted.
  // The name differs ("ace-again"), so this is an identity collision the mock
  // could only report because it derives the pubkey from the key.
  const created = await page.evaluate(() =>
    (window.__BUZZ_E2E_COMMAND_PAYLOADS__ ?? []).filter(
      (entry) => entry.command === "create_managed_agent",
    ),
  );
  expect(created).toHaveLength(1);
});
