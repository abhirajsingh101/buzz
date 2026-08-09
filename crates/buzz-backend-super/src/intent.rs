//! The create-intent fingerprint (§Create-intent fingerprint, normative).
//!
//! Recorded beside every instance at create time, and compared —
//! recorded-annotation vs freshly-computed intent — to tell "the user changed
//! the configuration and is waiting for it to take effect" apart from "the
//! host is slow". Divergence is evidence, not a clock; no timeout ever
//! authorizes a replacement.
//!
//! **Scope rule.** The input covers exactly the provider-controlled fields
//! that can affect *process creation*, and never the environment. Env values
//! cannot cause the never-started wedge this discriminator exists to clear: a
//! bad launch value produces a harness that starts and then fails at the
//! relay, which is a different row entirely. Hashing them would buy nothing
//! and would turn a plain SHA-256 over low-entropy secrets into a dictionary
//! oracle for anyone who can read the state directory — which is why
//! excluding them removes any need for a keyed hash.

use crate::config::ProviderConfig;
use crate::identity::BINDING_VERSION;
use crate::wire::AgentPayload;
use sha2::{Digest, Sha256};

/// Compute the fingerprint for what *this* deploy would create.
///
/// Serialized as a canonical JSON object — `serde_json::json!` writes object
/// keys in the order given, so the shape is stable by construction, and
/// nothing server-produced (pids, timestamps, the recorded fingerprint
/// itself) is ever in scope: the serializer never sees it, which is an
/// invariant checkable by inspection rather than by test.
pub fn fingerprint(agent: &AgentPayload, cfg: &ProviderConfig) -> String {
    let launch = agent.launch.as_ref();
    let canonical = serde_json::json!({
        "binding_version": BINDING_VERSION,
        "harness_command": cfg.harness_command,
        "path_prepend": cfg.path_prepend,
        "state_dir": cfg.state_dir,
        "inactivity_seconds": cfg.inactivity_seconds,
        "agent_command": launch.and_then(|l| l.command.clone()),
        "agent_args": launch.map(|l| l.args.clone()).unwrap_or_default(),
    });

    let serialized = serde_json::to_string(&canonical).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    fn cfg(extra: serde_json::Value) -> ProviderConfig {
        let mut base = serde_json::json!({"host": "super"});
        if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        crate::config::parse(&base).unwrap()
    }

    fn payload(launch: serde_json::Value) -> AgentPayload {
        serde_json::from_value(serde_json::json!({
            "relay_url": "wss://relay.example",
            "private_key_nsec": TEST_NSEC,
            "auth_tag": "tag-1",
            "launch": launch,
        }))
        .unwrap()
    }

    fn base_launch() -> serde_json::Value {
        serde_json::json!({
            "command": "goose",
            "args": ["acp"],
            "env": {"USER_KEY": "user-value"},
            "policy_env": {"GOOSE_MODE": "auto"},
            "owner_pubkey": "aa"
        })
    }

    #[test]
    fn is_stable_for_identical_intent() {
        let a = fingerprint(&payload(base_launch()), &cfg(serde_json::json!({})));
        let b = fingerprint(&payload(base_launch()), &cfg(serde_json::json!({})));
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    /// The whole point: a config change the user made must be visible as
    /// divergence, or it could never reach a never-started instance.
    #[test]
    fn diverges_when_process_creation_changes() {
        let base = fingerprint(&payload(base_launch()), &cfg(serde_json::json!({})));

        let other_harness = fingerprint(
            &payload(base_launch()),
            &cfg(serde_json::json!({"harness_command": "/opt/buzz-acp"})),
        );
        assert_ne!(base, other_harness, "harness_command must be in scope");

        let other_path = fingerprint(
            &payload(base_launch()),
            &cfg(serde_json::json!({"path_prepend": "/usr/local/bin"})),
        );
        assert_ne!(base, other_path, "path_prepend must be in scope");

        let other_dir = fingerprint(
            &payload(base_launch()),
            &cfg(serde_json::json!({"state_dir": "/srv/agents"})),
        );
        assert_ne!(base, other_dir, "state_dir must be in scope");

        let other_bound = fingerprint(
            &payload(base_launch()),
            &cfg(serde_json::json!({"inactivity_seconds": 900})),
        );
        assert_ne!(base, other_bound, "inactivity_seconds must be in scope");

        let mut launch = base_launch();
        launch["command"] = serde_json::json!("claude-agent-acp");
        let other_command = fingerprint(&payload(launch), &cfg(serde_json::json!({})));
        assert_ne!(base, other_command, "agent command must be in scope");

        let mut launch = base_launch();
        launch["args"] = serde_json::json!(["acp", "--verbose"]);
        let other_args = fingerprint(&payload(launch), &cfg(serde_json::json!({})));
        assert_ne!(base, other_args, "agent args must be in scope");
    }

    /// Env values are deliberately out of scope. They cannot cause a
    /// never-started wedge, and hashing them would publish a dictionary
    /// oracle over the user's API keys in a world-readable file.
    #[test]
    fn env_values_are_out_of_scope() {
        let base = fingerprint(&payload(base_launch()), &cfg(serde_json::json!({})));

        let mut launch = base_launch();
        launch["env"] = serde_json::json!({"USER_KEY": "a-completely-different-value"});
        launch["policy_env"] = serde_json::json!({"GOOSE_MODE": "chat"});
        assert_eq!(
            base,
            fingerprint(&payload(launch), &cfg(serde_json::json!({})))
        );
    }

    /// The nsec must never reach the hash input — that is the oracle the
    /// scope rule exists to remove.
    #[test]
    fn identity_and_relay_are_out_of_scope() {
        let base = fingerprint(&payload(base_launch()), &cfg(serde_json::json!({})));

        let mut other: AgentPayload = payload(base_launch());
        other.private_key_nsec =
            "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99".to_string();
        other.relay_url = "wss://other.example".to_string();
        other.auth_tag = Some("tag-2".to_string());
        assert_eq!(base, fingerprint(&other, &cfg(serde_json::json!({}))));
    }
}
