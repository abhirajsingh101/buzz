//! The stdin/stdout JSON protocol (spec §Provider Protocol).
//!
//! One process per operation: one JSON object in, one JSON object out. These
//! types are this binding's view of the contract; they are deliberately a
//! near-copy of `buzz-backend-kubernetes/src/wire.rs`, because the contract is
//! the desktop's, not the substrate's — a binding that "improved" the shape
//! would be the one that broke.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The wire-contract version this provider speaks (spec §Info).
pub const PROTOCOL_VERSION: u32 = 1;

/// Request envelope. `op` discriminates; unknown ops are an in-band error.
///
/// `request_id` is deliberately untyped: the desktop sends it, but the
/// exchange is one request and one response per process, so there is nothing
/// to correlate and no response field to echo it into.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    Info,
    Deploy(Box<DeployRequest>),
}

#[derive(Debug, Deserialize)]
pub struct DeployRequest {
    pub agent: AgentPayload,
    #[serde(default)]
    pub provider_config: serde_json::Value,
}

/// The agent payload (spec §Deploy).
///
/// Only fields this binding consumes are typed. `name`, `model` and
/// `provider` are absent on purpose: every path that decides anything keys on
/// the derived pubkey rather than a display name, the model/provider pair
/// arrives already resolved inside `launch`, and typing any of them would
/// invite the provider-side remap §Launch data forbids.
#[derive(Debug, Deserialize)]
pub struct AgentPayload {
    pub relay_url: String,
    pub private_key_nsec: String,
    #[serde(default)]
    pub auth_tag: Option<String>,
    #[serde(default)]
    pub respond_to: Option<String>,
    #[serde(default)]
    pub respond_to_allowlist: Option<Vec<String>>,
    /// User env, already merged global < persona < agent by the desktop and
    /// already stripped of reserved keys. Superseded by `launch.env` when
    /// `launch` is present — a provider MUST NOT re-merge it on top
    /// (§Launch data, precedence tier 2).
    #[serde(default)]
    pub env_vars: BTreeMap<String, String>,
    /// The desktop-resolved launch contract. Absent only from a desktop
    /// predating Known Defect 3's fix.
    #[serde(default)]
    pub launch: Option<LaunchBlock>,
}

/// Desktop-resolved launch data (spec §Launch data).
#[derive(Debug, Default, Deserialize)]
pub struct LaunchBlock {
    /// Command *name*, resolved against the remote host's PATH — never a
    /// path from the desktop's filesystem.
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// Layered env: baked → runtime metadata → definition → global → persona
    /// → agent. Precedence tier 2.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Overridable behavior defaults. Precedence tier 1 — user env beats
    /// these, matching the local spawn.
    #[serde(default)]
    pub policy_env: BTreeMap<String, String>,
    /// Resolved workspace owner (hex). Without it or `auth_tag` the harness
    /// cannot match `!shutdown`.
    #[serde(default)]
    pub owner_pubkey: Option<String>,
}

/// Response envelope. Serialized flat — `{"ok": true, …}` — because the
/// desktop reads `ok`, `error`, and `agent_id` off the top level.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    Info(Box<InfoResponse>),
    Deploy(DeployResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Serialize)]
pub struct InfoResponse {
    pub ok: bool,
    pub name: &'static str,
    pub version: &'static str,
    pub protocol_version: u32,
    pub description: &'static str,
    pub config_schema: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct DeployResponse {
    pub ok: bool,
    pub agent_id: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub ok: bool,
    pub error: String,
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Response::Error(ErrorResponse {
            ok: false,
            error: message.into(),
        })
    }

    /// The provider's self-description (spec §Info). Pure — no SSH contact —
    /// because the desktop calls it to render the config form before any host
    /// is known to be reachable, and because §Discovery's pre-secret gate
    /// invokes it on a staged copy that must not need credentials.
    pub fn info() -> Self {
        Response::Info(Box::new(InfoResponse {
            ok: true,
            name: "super",
            version: env!("CARGO_PKG_VERSION"),
            protocol_version: PROTOCOL_VERSION,
            description: "Runs agents as processes on a host reached over SSH",
            config_schema: crate::config::config_schema(),
        }))
    }

    pub fn deployed(agent_id: impl Into<String>) -> Self {
        Response::Deploy(DeployResponse {
            ok: true,
            agent_id: agent_id.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_info_request() {
        let r: Request = serde_json::from_str(r#"{"op":"info","request_id":"abc"}"#).unwrap();
        assert!(matches!(r, Request::Info));
    }

    /// The desktop sends `request_id` on every call, but the exchange is 1:1
    /// per process — hard-requiring it would fail a conforming-but-minimal
    /// caller for no safety gain.
    #[test]
    fn request_id_is_optional() {
        let r: Request = serde_json::from_str(r#"{"op":"info"}"#).unwrap();
        assert!(matches!(r, Request::Info));
    }

    #[test]
    fn rejects_unknown_op() {
        assert!(serde_json::from_str::<Request>(r#"{"op":"undeploy"}"#).is_err());
    }

    /// The desktop sends `model`, `provider`, `system_prompt` and more; a
    /// provider that rejected them would break on every real deploy.
    #[test]
    fn ignores_unconsumed_payload_fields() {
        let json = r#"{
            "op":"deploy","request_id":"r1",
            "agent":{
                "name":"a","relay_url":"wss://r","private_key_nsec":"nsec1x",
                "model":"gpt-5","provider":"openai","system_prompt":"hi",
                "turn_timeout_seconds":30,"parallelism":10,
                "agent_command":"goose","agent_args":[]
            },
            "provider_config":{"host":"super"}
        }"#;
        let r: Request = serde_json::from_str(json).unwrap();
        let Request::Deploy(d) = r else {
            panic!("wrong op")
        };
        assert_eq!(d.agent.relay_url, "wss://r");
        assert!(d.agent.launch.is_none());
    }

    #[test]
    fn parses_launch_block() {
        let json = r#"{
            "op":"deploy",
            "agent":{
                "relay_url":"wss://r","private_key_nsec":"nsec1x",
                "launch":{
                    "command":"goose","args":["acp"],
                    "env":{"GOOSE_MODEL":"gpt-5"},
                    "policy_env":{"GOOSE_MODE":"auto"},
                    "owner_pubkey":"aa"
                }
            },
            "provider_config":{}
        }"#;
        let r: Request = serde_json::from_str(json).unwrap();
        let Request::Deploy(d) = r else {
            panic!("wrong op")
        };
        let launch = d.agent.launch.unwrap();
        assert_eq!(launch.command.as_deref(), Some("goose"));
        assert_eq!(launch.args, vec!["acp"]);
        assert_eq!(launch.owner_pubkey.as_deref(), Some("aa"));
    }
}
