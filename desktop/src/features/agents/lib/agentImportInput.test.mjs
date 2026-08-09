import assert from "node:assert/strict";
import test from "node:test";

import { parseAgentImportInput } from "./agentImportInput.ts";

// Published NIP-19 test vectors, never live identities.
const NSEC_A =
  "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
const PUBKEY_A =
  "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
const NSEC_B =
  "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";

test("parses `name = nsec` lines and derives the identity", () => {
  const plan = parseAgentImportInput(`ace = ${NSEC_A}`);

  assert.equal(plan.errorCount, 0);
  assert.equal(plan.importable.length, 1);
  const [entry] = plan.importable;
  assert.equal(entry.name, "ace");
  assert.equal(entry.pubkey, PUBKEY_A);
  assert.ok(entry.npub.startsWith("npub1"));
  // The key is carried through untouched — the caller hands it straight to
  // the create command.
  assert.equal(entry.nsec, NSEC_A);
});

test("tolerates the spacing people actually paste", () => {
  const plan = parseAgentImportInput(
    [
      `ace=${NSEC_A}`,
      "",
      "# a comment",
      `   architect   =   ${NSEC_B}   `,
      "   ",
    ].join("\n"),
  );

  assert.equal(plan.errorCount, 0);
  assert.deepEqual(
    plan.importable.map((entry) => entry.name),
    ["ace", "architect"],
  );
});

test("reports line numbers against the original paste", () => {
  // Blank and comment lines are skipped but must not shift the numbering, or
  // the error list points at the wrong row.
  const plan = parseAgentImportInput(
    ["", "# header", `ace = ${NSEC_A}`, "junk"].join("\n"),
  );

  assert.equal(plan.importable[0].lineNumber, 3);
  assert.equal(plan.entries.at(-1).lineNumber, 4);
});

test("a bare key is refused with a fixable instruction", () => {
  const plan = parseAgentImportInput(NSEC_A);

  assert.equal(plan.importable.length, 0);
  assert.match(plan.entries[0].reason, /name/);
});

test("a hex pubkey is refused rather than adopted as an identity", () => {
  // The footgun this rule exists for: a 64-hex public key is a syntactically
  // valid secret key, so accepting hex would mint an agent whose private key
  // nobody holds — failing much later, as an agent that never authenticates.
  const plan = parseAgentImportInput(`ace = ${PUBKEY_A}`);

  assert.equal(plan.importable.length, 0);
  assert.match(plan.entries[0].reason, /nsec1/);
});

test("malformed keys are refused", () => {
  const plan = parseAgentImportInput(
    ["ace = nsec1notarealkey", "bob = npub1abcdef"].join("\n"),
  );

  assert.equal(plan.importable.length, 0);
  assert.equal(plan.errorCount, 2);
});

test("empty names and empty keys are each named", () => {
  const plan = parseAgentImportInput([` = ${NSEC_A}`, "ace ="].join("\n"));

  assert.equal(plan.importable.length, 0);
  assert.match(plan.entries[0].reason, /name/);
  assert.match(plan.entries[1].reason, /key/);
});

test("the same key twice in one paste is caught before anything is created", () => {
  // Both lines look fine in isolation; without this the create loop would
  // succeed on the first and fail halfway through on the second, leaving a
  // partly-applied import.
  const plan = parseAgentImportInput(
    [`ace = ${NSEC_A}`, `ace-again = ${NSEC_A}`].join("\n"),
  );

  assert.equal(plan.importable.length, 1);
  assert.equal(plan.importable[0].name, "ace");
  assert.match(plan.entries[1].reason, /line 1/);
});

test("keys this workspace already has are reported up front", () => {
  const plan = parseAgentImportInput(`ace = ${NSEC_A}`, [PUBKEY_A]);

  assert.equal(plan.importable.length, 0);
  assert.match(plan.entries[0].reason, /already imported/);
});

test("existing pubkeys match regardless of case or padding", () => {
  const plan = parseAgentImportInput(`ace = ${NSEC_A}`, [
    `  ${PUBKEY_A.toUpperCase()}  `,
  ]);

  assert.match(plan.entries[0].reason, /already imported/);
});

test("valid lines still import when others fail", () => {
  // A twelve-agent paste with one typo should not force a re-paste of all
  // twelve; the plan shows what will and will not be created.
  const plan = parseAgentImportInput(
    [`ace = ${NSEC_A}`, "broken = nope", `architect = ${NSEC_B}`].join("\n"),
  );

  assert.equal(plan.errorCount, 1);
  assert.deepEqual(
    plan.importable.map((entry) => entry.name),
    ["ace", "architect"],
  );
});

test("error labels never carry key material", () => {
  // Error rows are rendered, and get copied into bug reports. A mistyped key
  // is still a key.
  const plan = parseAgentImportInput(`${NSEC_A}extra`);

  const [entry] = plan.entries;
  assert.equal(entry.status, "error");
  assert.ok(
    !entry.label.includes("vl029mgpspedva"),
    `label leaked key material: ${entry.label}`,
  );
  assert.ok(entry.label.includes("nsec1…"));
});

test("an empty paste is an empty plan, not an error", () => {
  const plan = parseAgentImportInput("   \n\n# nothing here\n");

  assert.deepEqual(plan.entries, []);
  assert.equal(plan.importable.length, 0);
  assert.equal(plan.errorCount, 0);
});
