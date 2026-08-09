//! Agent environment assembly (§Launch data, §Entrypoint mapping table).
//!
//! Three tiers, later wins:
//!   1. `launch.policy_env` — overridable behavior defaults
//!   2. `launch.env`        — user/layered env
//!   3. authoritative       — identity and control-plane values
//!
//! The ordering is not cosmetic. Locally the user env is written *after* the
//! policy defaults, so a policy-wins order here would make remote agents
//! ignore overrides that work on a laptop — the divergence §Launch data
//! exists to prevent.

use crate::config::ProviderConfig;
use crate::identity::AgentIdentity;
use crate::wire::AgentPayload;
use std::collections::BTreeMap;

/// Keys the desktop resolves to paths on *its own* filesystem, or to state
/// that only means something there. Forwarding any of them to another machine
/// is a guaranteed failure, so they are dropped from the inherited tiers
/// (§Host-resolved values).
const HOST_RESOLVED_KEYS: [&str; 5] = [
    "PATH",
    "HOME",
    "CLAUDE_CODE_EXECUTABLE",
    "BUZZ_ACP_SETUP_PAYLOAD",
    // Brands a *local* harness so the desktop's orphan sweep can prove
    // ownership by scanning process env. There is no local process to sweep.
    "BUZZ_MANAGED_AGENT",
];

/// Identity and control-plane keys the authoritative tier owns outright.
///
/// The desktop strips these before it sends `env_vars`, but a provider that
/// trusted that strip would be one desktop bug away from an identityless or
/// misowned agent. Re-stripping here is the cheap half of defense in depth.
const RESERVED_KEYS: [&str; 12] = [
    "BUZZ_PRIVATE_KEY",
    "NOSTR_PRIVATE_KEY",
    "BUZZ_AUTH_TAG",
    "BUZZ_RELAY_URL",
    "BUZZ_ACP_AGENT_OWNER",
    "BUZZ_ACP_AGENT_COMMAND",
    "BUZZ_ACP_AGENT_ARGS",
    "BUZZ_ACP_RESPOND_TO",
    "BUZZ_ACP_RESPOND_TO_ALLOWLIST",
    "BUZZ_ACP_MCP_COMMAND",
    "BUZZ_ACP_EXIT_AFTER_INACTIVITY",
    "BUZZ_MANAGED_AGENT_START_NONCE",
];

/// A POSIX-shaped environment variable name.
///
/// Validated because a key like `BUZZ_AUTH_TAG=x` — a name *containing* an
/// `=` — would smuggle a second assignment past the reserved-key strip when
/// the map is serialized to an env file.
fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Insert an inherited (tier 1 / tier 2) entry, dropping anything the
/// authoritative tier owns or the substrate must re-derive.
fn insert_inherited(out: &mut BTreeMap<String, String>, key: &str, value: &str) {
    if !is_valid_env_name(key) {
        return;
    }
    if HOST_RESOLVED_KEYS.contains(&key) || RESERVED_KEYS.contains(&key) {
        return;
    }
    out.insert(key.to_string(), value.to_string());
}

/// Build the full environment for one agent instance.
///
/// `nonce` is the attempt's generation token: the harness stamps it into every
/// observer lifecycle frame, so the launch generation and the lifecycle
/// correlator become one identity rather than an empty string.
pub fn build(
    agent: &AgentPayload,
    identity: &AgentIdentity,
    cfg: &ProviderConfig,
    nonce: &str,
) -> Result<BTreeMap<String, String>, String> {
    let launch = agent.launch.as_ref();

    let owner_pubkey = launch
        .and_then(|l| l.owner_pubkey.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let auth_tag = agent
        .auth_tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // §Launch data owner rule — checked before any mutation. Without an owner
    // the harness cannot match `!shutdown` and answers its own stop command
    // conversationally, which would make §Stop describe a mechanism that does
    // not work.
    if auth_tag.is_none() && owner_pubkey.is_none() {
        return Err(
            "deploy refused: the agent has neither an auth tag nor a resolved owner pubkey, \
             so it could never be stopped with !shutdown"
                .to_string(),
        );
    }

    let mut env: BTreeMap<String, String> = BTreeMap::new();

    // ── Tier 1: overridable behavior defaults ────────────────────────────────
    if let Some(l) = launch {
        for (k, v) in &l.policy_env {
            insert_inherited(&mut env, k, v);
        }
    }

    // ── Tier 2: user / layered env ──────────────────────────────────────────
    // `launch.env` has already merged global < persona < agent, so the legacy
    // `env_vars` field must NOT be re-merged on top of it. It is consulted
    // only when `launch` is absent altogether — a desktop predating the
    // launch block.
    match launch {
        Some(l) => {
            for (k, v) in &l.env {
                insert_inherited(&mut env, k, v);
            }
        }
        None => {
            for (k, v) in &agent.env_vars {
                insert_inherited(&mut env, k, v);
            }
        }
    }

    // ── Tier 3: authoritative ───────────────────────────────────────────────
    // Written last, and backed by the reserved-key strip above, so nothing in
    // the inherited tiers can reach these names by any route.
    let nsec = agent.private_key_nsec.trim();
    env.insert("BUZZ_PRIVATE_KEY".into(), nsec.to_string());
    // The git credential and signing helpers read the NOSTR_ spelling.
    env.insert("NOSTR_PRIVATE_KEY".into(), nsec.to_string());

    let relay_url = agent.relay_url.trim();
    if relay_url.is_empty() {
        return Err("deploy refused: the agent has no relay URL".to_string());
    }
    env.insert("BUZZ_RELAY_URL".into(), relay_url.to_string());

    if let Some(tag) = auth_tag {
        env.insert("BUZZ_AUTH_TAG".into(), tag.to_string());
    }
    if let Some(owner) = owner_pubkey {
        env.insert("BUZZ_ACP_AGENT_OWNER".into(), owner.to_string());
    }

    if let Some(command) = launch
        .and_then(|l| l.command.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        // A *name*, resolved against the remote PATH. Never a desktop path.
        env.insert("BUZZ_ACP_AGENT_COMMAND".into(), command.to_string());
    }
    if let Some(args) = launch.map(|l| l.args.as_slice()).filter(|a| !a.is_empty()) {
        // Comma-joined because that is what the harness's CLI parser decodes.
        // An argument containing a comma is unrepresentable in the local
        // spawn too; matching that limitation is correct, inventing a private
        // escaping scheme the harness would not decode is not.
        env.insert("BUZZ_ACP_AGENT_ARGS".into(), args.join(","));
    }

    if let Some(respond_to) = agent
        .respond_to
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        env.insert("BUZZ_ACP_RESPOND_TO".into(), respond_to.to_string());
    }
    if let Some(list) = agent
        .respond_to_allowlist
        .as_deref()
        .filter(|l| !l.is_empty())
    {
        env.insert("BUZZ_ACP_RESPOND_TO_ALLOWLIST".into(), list.join(","));
    }

    // Resolved on the host, like every other command name.
    env.insert("BUZZ_ACP_MCP_COMMAND".into(), "buzz-dev-mcp".into());

    if let Some(seconds) = cfg.inactivity_seconds {
        env.insert("BUZZ_ACP_EXIT_AFTER_INACTIVITY".into(), seconds.to_string());
    }

    env.insert("BUZZ_MANAGED_AGENT_START_NONCE".into(), nonce.to_string());

    // Belt and braces for the one thing that must never be wrong: whatever
    // the tiers did, the key that ended up in the environment is the key this
    // deploy derived its identity from (I1).
    debug_assert_eq!(
        AgentIdentity::from_nsec(env.get("BUZZ_PRIVATE_KEY").map_or("", String::as_str))
            .ok()
            .as_ref()
            .map(AgentIdentity::pubkey_hex),
        Some(identity.pubkey_hex())
    );
    let _ = identity;

    Ok(env)
}

/// Every secret value in the environment, for [`crate::redact::scrub`].
pub fn secret_values(env: &BTreeMap<String, String>) -> Vec<String> {
    // Every *value* is treated as sensitive rather than a curated subset:
    // user env is exactly where API keys live, and a curated list is a list
    // someone forgets to extend.
    env.values().cloned().collect()
}

/// Render the environment as a shell-sourceable file.
///
/// Single-quoted with `'` escaped as `'\''`, so a value containing spaces,
/// newlines, `$`, or quotes survives `set -a; . file` byte-for-byte. The
/// alternative — bare `KEY=VALUE` as the hand-written env files use — silently
/// mangles any value with whitespace in it.
pub fn render_env_file(env: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (key, value) in env {
        out.push_str(key);
        out.push_str("='");
        out.push_str(&value.replace('\'', r"'\''"));
        out.push_str("'\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::LaunchBlock;

    const TEST_NSEC: &str = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    const OWNER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn cfg() -> ProviderConfig {
        crate::config::parse(&serde_json::json!({"host": "super"})).unwrap()
    }

    fn payload(launch: Option<LaunchBlock>) -> AgentPayload {
        serde_json::from_value(serde_json::json!({
            "name": "worker",
            "relay_url": "wss://relay.example",
            "private_key_nsec": TEST_NSEC,
            "auth_tag": "tag-1",
            "launch": launch.map(|l| serde_json::json!({
                "command": l.command,
                "args": l.args,
                "env": l.env,
                "policy_env": l.policy_env,
                "owner_pubkey": l.owner_pubkey,
            })),
        }))
        .unwrap()
    }

    fn built(agent: &AgentPayload) -> BTreeMap<String, String> {
        let id = AgentIdentity::from_nsec(TEST_NSEC).unwrap();
        build(agent, &id, &cfg(), "nonce-1").unwrap()
    }

    #[test]
    fn identity_comes_from_top_level_fields() {
        let env = built(&payload(None));
        assert_eq!(env["BUZZ_PRIVATE_KEY"], TEST_NSEC);
        assert_eq!(env["NOSTR_PRIVATE_KEY"], TEST_NSEC);
        assert_eq!(env["BUZZ_RELAY_URL"], "wss://relay.example");
        assert_eq!(env["BUZZ_AUTH_TAG"], "tag-1");
        assert_eq!(env["BUZZ_ACP_MCP_COMMAND"], "buzz-dev-mcp");
        assert_eq!(env["BUZZ_MANAGED_AGENT_START_NONCE"], "nonce-1");
    }

    /// Tier 2 beats tier 1 — the local spawn writes user env after the policy
    /// defaults, and a remote agent that inverted this would ignore an
    /// override that works locally.
    #[test]
    fn user_env_overrides_policy_defaults() {
        let launch = LaunchBlock {
            command: Some("goose".into()),
            args: vec!["acp".into()],
            env: [("GOOSE_MODE".to_string(), "chat".to_string())]
                .into_iter()
                .collect(),
            policy_env: [("GOOSE_MODE".to_string(), "auto".to_string())]
                .into_iter()
                .collect(),
            owner_pubkey: Some(OWNER.into()),
        };
        let env = built(&payload(Some(launch)));
        assert_eq!(env["GOOSE_MODE"], "chat");
    }

    /// Tier 3 beats everything: a user env var must not be able to redirect
    /// the agent's relay, owner, or identity.
    #[test]
    fn authoritative_tier_cannot_be_overridden() {
        let launch = LaunchBlock {
            command: None,
            args: vec![],
            env: [
                ("BUZZ_RELAY_URL".to_string(), "wss://attacker".to_string()),
                ("BUZZ_PRIVATE_KEY".to_string(), "nsec1evil".to_string()),
                ("BUZZ_ACP_AGENT_OWNER".to_string(), "deadbeef".to_string()),
            ]
            .into_iter()
            .collect(),
            policy_env: Default::default(),
            owner_pubkey: Some(OWNER.into()),
        };
        let env = built(&payload(Some(launch)));
        assert_eq!(env["BUZZ_RELAY_URL"], "wss://relay.example");
        assert_eq!(env["BUZZ_PRIVATE_KEY"], TEST_NSEC);
        assert_eq!(env["BUZZ_ACP_AGENT_OWNER"], OWNER);
    }

    /// A name containing `=` would smuggle a second assignment into the env
    /// file and bypass the reserved-key strip entirely.
    #[test]
    fn malformed_env_names_are_dropped() {
        let launch = LaunchBlock {
            command: None,
            args: vec![],
            env: [
                ("BAD NAME".to_string(), "x".to_string()),
                ("SNEAKY=BUZZ_AUTH_TAG".to_string(), "x".to_string()),
                ("9LEADING".to_string(), "x".to_string()),
                ("GOOD_NAME".to_string(), "y".to_string()),
            ]
            .into_iter()
            .collect(),
            policy_env: Default::default(),
            owner_pubkey: Some(OWNER.into()),
        };
        let env = built(&payload(Some(launch)));
        assert_eq!(env["GOOD_NAME"], "y");
        assert!(!env.contains_key("BAD NAME"));
        assert!(!env.contains_key("9LEADING"));
        assert!(env.keys().all(|k| !k.contains('=')));
        assert_eq!(env["BUZZ_AUTH_TAG"], "tag-1");
    }

    /// Forwarding the desktop's PATH or HOME into another machine is a
    /// guaranteed failure, not a nice-to-have cleanup.
    #[test]
    fn host_resolved_values_are_not_forwarded() {
        let launch = LaunchBlock {
            command: None,
            args: vec![],
            env: [
                ("PATH".to_string(), "/Users/me/bin".to_string()),
                ("HOME".to_string(), "/Users/me".to_string()),
                (
                    "CLAUDE_CODE_EXECUTABLE".to_string(),
                    "/Users/me/.local/bin/claude".to_string(),
                ),
                ("BUZZ_ACP_SETUP_PAYLOAD".to_string(), "{}".to_string()),
                ("BUZZ_MANAGED_AGENT".to_string(), "1".to_string()),
            ]
            .into_iter()
            .collect(),
            policy_env: Default::default(),
            owner_pubkey: Some(OWNER.into()),
        };
        let env = built(&payload(Some(launch)));
        for key in HOST_RESOLVED_KEYS {
            assert!(!env.contains_key(key), "{key} was forwarded");
        }
    }

    /// The legacy field is a fallback for a desktop with no launch block, not
    /// an extra layer applied on top of one (§Launch data, tier 2).
    #[test]
    fn legacy_env_vars_are_used_only_without_a_launch_block() {
        let mut with_launch: AgentPayload = payload(Some(LaunchBlock {
            command: None,
            args: vec![],
            env: [("K".to_string(), "from-launch".to_string())]
                .into_iter()
                .collect(),
            policy_env: Default::default(),
            owner_pubkey: Some(OWNER.into()),
        }));
        with_launch
            .env_vars
            .insert("K".to_string(), "from-legacy".to_string());
        assert_eq!(built(&with_launch)["K"], "from-launch");

        let mut without_launch = payload(None);
        without_launch
            .env_vars
            .insert("K".to_string(), "from-legacy".to_string());
        assert_eq!(built(&without_launch)["K"], "from-legacy");
    }

    #[test]
    fn refuses_an_agent_with_no_owner() {
        let mut agent = payload(None);
        agent.auth_tag = None;
        let id = AgentIdentity::from_nsec(TEST_NSEC).unwrap();
        let err = build(&agent, &id, &cfg(), "n").unwrap_err();
        assert!(err.contains("!shutdown"), "{err}");
    }

    /// An auth tag alone is enough; so is an owner pubkey alone.
    #[test]
    fn either_owner_signal_suffices() {
        let mut tag_only = payload(None);
        tag_only.auth_tag = Some("tag-1".into());
        assert!(built(&tag_only).contains_key("BUZZ_AUTH_TAG"));

        let mut owner_only = payload(Some(LaunchBlock {
            command: None,
            args: vec![],
            env: Default::default(),
            policy_env: Default::default(),
            owner_pubkey: Some(OWNER.into()),
        }));
        owner_only.auth_tag = None;
        let env = built(&owner_only);
        assert_eq!(env["BUZZ_ACP_AGENT_OWNER"], OWNER);
        assert!(!env.contains_key("BUZZ_AUTH_TAG"));
    }

    #[test]
    fn inactivity_bound_is_emitted_only_when_set() {
        let agent = payload(None);
        let id = AgentIdentity::from_nsec(TEST_NSEC).unwrap();

        let unbounded = build(&agent, &id, &cfg(), "n").unwrap();
        assert!(!unbounded.contains_key("BUZZ_ACP_EXIT_AFTER_INACTIVITY"));

        let bounded_cfg =
            crate::config::parse(&serde_json::json!({"host":"h","inactivity_seconds":900}))
                .unwrap();
        let bounded = build(&agent, &id, &bounded_cfg, "n").unwrap();
        assert_eq!(bounded["BUZZ_ACP_EXIT_AFTER_INACTIVITY"], "900");
    }

    #[test]
    fn args_are_comma_joined_like_the_local_spawn() {
        let env = built(&payload(Some(LaunchBlock {
            command: Some("goose".into()),
            args: vec!["acp".into(), "--verbose".into()],
            env: Default::default(),
            policy_env: Default::default(),
            owner_pubkey: Some(OWNER.into()),
        })));
        assert_eq!(env["BUZZ_ACP_AGENT_COMMAND"], "goose");
        assert_eq!(env["BUZZ_ACP_AGENT_ARGS"], "acp,--verbose");
    }

    #[test]
    fn refuses_an_agent_with_no_relay_url() {
        let mut agent = payload(None);
        agent.relay_url = "   ".into();
        let id = AgentIdentity::from_nsec(TEST_NSEC).unwrap();
        assert!(build(&agent, &id, &cfg(), "n").is_err());
    }

    /// The env file is sourced with `set -a; . file`, so a value containing a
    /// quote, a space, or a newline must survive verbatim.
    #[test]
    fn env_file_quoting_survives_hostile_values() {
        let env: BTreeMap<String, String> = [
            ("A".to_string(), "it's got a quote".to_string()),
            ("B".to_string(), "two words".to_string()),
            ("C".to_string(), "line1\nline2".to_string()),
            ("D".to_string(), "$(touch /tmp/pwned)".to_string()),
            ("E".to_string(), "back\\slash".to_string()),
        ]
        .into_iter()
        .collect();

        let rendered = render_env_file(&env);
        let parsed = shell_source(&rendered);
        assert_eq!(parsed["A"], "it's got a quote");
        assert_eq!(parsed["B"], "two words");
        assert_eq!(parsed["C"], "line1\nline2");
        assert_eq!(parsed["D"], "$(touch /tmp/pwned)");
        assert_eq!(parsed["E"], "back\\slash");
    }

    /// Source the rendered file with a real shell and read the values back.
    /// A hand-rolled parser would only prove this module agrees with itself;
    /// the property under test is what `bash` does with the bytes.
    fn shell_source(rendered: &str) -> BTreeMap<String, String> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let script = format!(
            "set -a\n{rendered}\nset +a\nfor k in A B C D E; do \
             printf '%s\\0%s\\0' \"$k\" \"${{!k}}\"; done"
        );
        let mut child = Command::new("bash")
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("bash is available");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(script.as_bytes())
            .expect("write script");
        let out = child.wait_with_output().expect("bash ran");
        assert!(out.status.success(), "bash failed sourcing the env file");

        let text = String::from_utf8_lossy(&out.stdout);
        let fields: Vec<&str> = text.split('\0').collect();
        fields
            .chunks_exact(2)
            .map(|kv| (kv[0].to_string(), kv[1].to_string()))
            .collect()
    }
}
