//! Resolving the keypair a new agent record will carry.
//!
//! Kept beside the other managed-agent record logic so the two refusals below sit
//! next to the
//! tests that pin them: they are the whole security surface of importing an
//! identity, and they should not have to be found inside a 1400-line command
//! module to be reviewed.

use nostr::Keys;

/// Resolve the keypair a new agent record will carry.
///
/// `None` mints a fresh identity — the default, and what every ordinary create
/// does. `Some` **adopts an identity that already exists**: an agent already
/// running under another launcher, or one being moved between machines.
/// Everything downstream is identical either way — the keyring write, the
/// NIP-OA auth tag, the kind:30177 publish — so this is the only branch the
/// two paths need.
///
/// Pure, and separated from the command for that reason: the two refusals
/// below are the whole security surface of importing, and they are worth
/// pinning by test rather than by reading the command's phase-1 block.
pub fn resolve_agent_keys(imported_nsec: Option<&str>, owner_hex: &str) -> Result<Keys, String> {
    // Normalizing here rather than at the call site keeps "what counts as an
    // import" in one place: a field present but blank is not an import, and a
    // pasted key carries whitespace.
    let Some(nsec) = imported_nsec.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(Keys::generate());
    };

    // bech32 only, deliberately. `Keys::parse` also accepts a 64-hex secret,
    // and a hex *public* key is a syntactically valid secret key — so
    // accepting hex would let a pasted pubkey mint an agent whose private key
    // nobody holds. That failure surfaces much later, as an agent that simply
    // never authenticates, and is near-impossible to trace back to the paste.
    if !nsec.starts_with("nsec1") {
        return Err(
            "the imported private key must be an nsec1… key — a hex key is refused because \
             a public key in hex is indistinguishable from a private one"
                .to_string(),
        );
    }
    let keys = Keys::parse(nsec)
        .map_err(|_| "the imported private key could not be decoded".to_string())?;

    // Importing the workspace's own key would create an "agent" that signs as
    // the human who owns it: every message it sent would be indistinguishable
    // from theirs, and revoking it would mean revoking themselves.
    if keys.public_key().to_hex() == owner_hex {
        return Err(
            "that is this workspace's own identity, not an agent's — importing it would \
             create an agent that signs as you"
                .to_string(),
        );
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Importing an existing agent identity ────────────────────────────────────
    //
    // The published NIP-19 test vector, never a live identity.
    const IMPORT_TEST_NSEC: &str =
        "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const IMPORT_TEST_PUBKEY: &str =
        "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    const SOME_OWNER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// The default path is unchanged: no import means a brand-new identity, and
    /// two creates never collide.
    #[test]
    fn generates_a_fresh_identity_when_nothing_is_imported() {
        let first = resolve_agent_keys(None, SOME_OWNER).unwrap();
        let second = resolve_agent_keys(None, SOME_OWNER).unwrap();
        assert_ne!(first.public_key(), second.public_key());
    }

    /// The whole point of importing: the record carries the identity that already
    /// exists, so an agent already running under another launcher can be adopted
    /// rather than replaced by a stranger with the same name.
    #[test]
    fn adopts_the_imported_identity() {
        let keys = resolve_agent_keys(Some(IMPORT_TEST_NSEC), SOME_OWNER).unwrap();
        assert_eq!(keys.public_key().to_hex(), IMPORT_TEST_PUBKEY);
    }

    #[test]
    fn tolerates_whitespace_around_a_pasted_key() {
        let padded = format!("  {IMPORT_TEST_NSEC}\n");
        // The command trims before calling; this pins that a trimmed value still
        // decodes, so the trim and the parser cannot drift apart.
        let keys = resolve_agent_keys(Some(padded.trim()), SOME_OWNER).unwrap();
        assert_eq!(keys.public_key().to_hex(), IMPORT_TEST_PUBKEY);
    }

    /// A 64-hex *public* key is a syntactically valid *secret* key, so accepting
    /// hex would let a pasted pubkey mint an agent whose private key nobody holds
    /// — an agent that simply never authenticates, with nothing pointing back at
    /// the paste that caused it.
    #[test]
    fn refuses_a_hex_key_because_a_pubkey_is_indistinguishable_from_one() {
        let error = resolve_agent_keys(Some(IMPORT_TEST_PUBKEY), SOME_OWNER).unwrap_err();
        assert!(error.contains("nsec1"), "{error}");

        // A hex *secret* is refused by the same rule, deliberately: the validator
        // cannot tell the two apart, which is exactly why the rule exists.
        let hex_secret = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";
        assert!(resolve_agent_keys(Some(hex_secret), SOME_OWNER).is_err());
    }

    /// Importing the workspace's own key would create an "agent" that signs as
    /// the human who owns it: its messages would be indistinguishable from
    /// theirs, and revoking it would mean revoking themselves.
    #[test]
    fn refuses_the_workspaces_own_identity() {
        let error = resolve_agent_keys(Some(IMPORT_TEST_NSEC), IMPORT_TEST_PUBKEY).unwrap_err();
        assert!(error.contains("signs as you"), "{error}");
    }

    #[test]
    fn refuses_an_undecodable_key() {
        let error = resolve_agent_keys(Some("nsec1notarealkey"), SOME_OWNER).unwrap_err();
        assert!(error.contains("could not be decoded"), "{error}");
    }
}
