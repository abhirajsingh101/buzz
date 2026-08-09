//! Identity derivation and the naming contract.
//!
//! Every name and comparison below is derived from the pubkey the provider
//! decoded itself from `private_key_nsec` — never from a caller-supplied one
//! (§Deploy State Machine step 0).

use nostr::nips::nip19::FromBech32;

/// The management marker written beside every instance this provider creates.
///
/// Protocol ownership evidence, not proof (§Auto-repair fencing): identity
/// evidence alone does not license a destructive action, so no residue is
/// cleared unless this marker is present. Its job is making an accidental
/// collision — or another launcher's process — fail closed, not defeating
/// someone with write access to the host.
pub const MANAGED_BY: &str = "buzz-backend-super";

/// Schema version of the on-host layout this provider writes. Bump when the
/// state directory shape changes in a way an older provider would mishandle.
pub const BINDING_VERSION: &str = "1";

/// An agent identity the provider derived itself, plus the names it implies.
///
/// Constructing this type is the *only* way to obtain those names, so a
/// caller-supplied pubkey cannot reach a path or a comparison by any route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pubkey_hex: String,
}

impl AgentIdentity {
    /// Derive from the payload's `private_key_nsec`.
    ///
    /// I1's first half: an empty key is refused here rather than launched,
    /// and a malformed one fails before any SSH contact (§step 0).
    pub fn from_nsec(nsec: &str) -> Result<Self, String> {
        let trimmed = nsec.trim();
        if trimmed.is_empty() {
            return Err(
                "deploy refused: the agent has no private key (I1: never launch identityless)"
                    .to_string(),
            );
        }
        let secret = nostr::SecretKey::from_bech32(trimmed)
            .map_err(|_| "private_key_nsec is not a decodable nsec1 key".to_string())?;
        Ok(Self {
            pubkey_hex: nostr::Keys::new(secret).public_key().to_hex(),
        })
    }

    /// Full 64-hex public key — the directory name and the comparison operand
    /// for authenticating a candidate instance.
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    /// The provider's stable handle for this deployment, stored by the
    /// desktop as `backend_agent_id`.
    ///
    /// It names the *identity on the host*, not the process — which is what
    /// makes it stable across restarts, and what lets an instance started by
    /// another launcher on the same host be returned under the same id (I4 is
    /// keyed on identity within a scope, and the scope here is the host).
    pub fn agent_id(&self, host: &str) -> String {
        format!("{host}/{}", self.pubkey_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spec's own example key, also used by the Kubernetes binding's
    /// fixtures — a published test vector, never a live identity.
    const TEST_NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    #[test]
    fn derives_pubkey_from_nsec() {
        let id = AgentIdentity::from_nsec(TEST_NSEC).unwrap();
        assert_eq!(id.pubkey_hex().len(), 64);
        assert!(id.pubkey_hex().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let bare = AgentIdentity::from_nsec(TEST_NSEC).unwrap();
        let padded = AgentIdentity::from_nsec(&format!("  {TEST_NSEC}\n")).unwrap();
        assert_eq!(bare, padded);
    }

    /// I1: an empty key is a refusal, and its message says so — a generic
    /// decode error would send the user hunting for a typo that is not there.
    #[test]
    fn empty_key_is_an_identity_refusal() {
        let err = AgentIdentity::from_nsec("   ").unwrap_err();
        assert!(err.contains("no private key"), "{err}");
        assert!(err.contains("I1"), "{err}");
    }

    #[test]
    fn malformed_key_is_refused() {
        assert!(AgentIdentity::from_nsec("nsec1notarealkey").is_err());
        assert!(AgentIdentity::from_nsec("npub1xyz").is_err());
    }

    /// The id must be stable for a given identity and host: the desktop
    /// persists it, and an id that moved would orphan the record.
    #[test]
    fn agent_id_is_stable_and_scoped() {
        let id = AgentIdentity::from_nsec(TEST_NSEC).unwrap();
        assert_eq!(id.agent_id("super"), id.agent_id("super"));
        assert_ne!(id.agent_id("super"), id.agent_id("other-host"));
        assert!(id.agent_id("super").starts_with("super/"));
        assert!(id.agent_id("super").ends_with(id.pubkey_hex()));
    }
}
