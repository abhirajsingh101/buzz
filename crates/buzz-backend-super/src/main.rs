//! SSH/process backend provider for Buzz remote agents
//! (spec `docs/remote-agents.md`).
//!
//! Runs agents as plain processes on a host reached over SSH — the substrate
//! the spec names as its live non-Kubernetes example (§Launchers, layer 3).
//! It conforms to layers 1 and 2 and writes its own layer 3, which is
//! deliberately smaller than the Kubernetes binding's: there is no image to
//! pull, nothing to schedule, and no supervisor, so several of that binding's
//! rows have no states here.
//!
//! One process per operation: read exactly one JSON request from stdin, write
//! exactly one JSON response to stdout, exit. The exit code carries exactly
//! one bit — 0 for a response that was produced, 1 for a failure to produce
//! one. Everything a caller needs to distinguish lives inside the response's
//! `ok` field.

mod config;
mod env;
mod host;
mod identity;
mod intent;
mod reconcile;
mod redact;
mod remote;
mod wire;

use std::io::Read;
use wire::{Request, Response};

/// The provider a shared-compute agent resolves to. Refused here as the
/// spec's backstop: mesh transport is a loopback proxy on the *desktop*, so
/// an agent carrying it would be pointed at a port on the remote host where
/// nothing listens.
const RELAY_MESH_PROVIDER: &str = "relay-mesh";

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        // No request means no response contract to honor. This is the one
        // path that exits nonzero.
        eprintln!("could not read the request from stdin: {e}");
        std::process::exit(1);
    }

    let response = respond(&input);
    println!(
        "{}",
        serde_json::to_string(&response).unwrap_or_else(|e| {
            // The response types are plain data, so this cannot fail in
            // practice — and a hand-built object is still a conforming
            // response.
            format!(r#"{{"ok":false,"error":"could not serialize a response: {e}"}}"#)
        })
    );
}

/// Produce the single response for one request. Separated from `main` so the
/// whole dispatch is testable without a process.
fn respond(input: &str) -> Response {
    // Parsed as raw JSON first: the relay-mesh refusal below must see the
    // wire value, and `AgentPayload` deliberately does not carry `provider`.
    let raw: serde_json::Value = match serde_json::from_str(input) {
        Ok(value) => value,
        Err(e) => return Response::error(format!("request is not valid JSON: {e}")),
    };

    if let Some(refusal) = refuse_relay_mesh(&raw) {
        return Response::error(refusal);
    }

    let request: Request = match serde_json::from_value(raw) {
        Ok(request) => request,
        Err(e) => return Response::error(format!("could not understand the request: {e}")),
    };

    match request {
        Request::Info => Response::info(),
        Request::Deploy(deploy) => match reconcile::deploy(&deploy) {
            Ok(agent_id) => Response::deployed(agent_id),
            Err(e) => Response::error(e),
        },
    }
}

/// Refuse a shared-compute agent, reading the **raw wire value**.
///
/// Trimmed before comparing, because the desktop's own layers disagree about
/// padding — a backstop that shares its bypass with the layer it backs is not
/// a backstop.
fn refuse_relay_mesh(raw: &serde_json::Value) -> Option<String> {
    let provider = raw.get("agent")?.get("provider")?.as_str()?;
    (provider.trim() == RELAY_MESH_PROVIDER).then(|| {
        "deploy refused: this agent is configured for shared compute \
         (relay-mesh), which runs on the relay rather than on a host of your \
         own. Switch the agent to a local runtime before deploying it."
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json_of(response: &Response) -> serde_json::Value {
        serde_json::to_value(response).unwrap()
    }

    #[test]
    fn info_declares_an_explicit_protocol_version() {
        let response = respond(r#"{"op":"info","request_id":"r1"}"#);
        let value = json_of(&response);
        assert_eq!(value["ok"], true);
        assert_eq!(value["name"], "super");
        // A missing protocol_version is an error on the desktop side, not a
        // presumed 1 — so declaring it explicitly is what makes this provider
        // deployable at all (§Info).
        assert_eq!(value["protocol_version"], wire::PROTOCOL_VERSION);
        assert!(value["config_schema"]["properties"]["host"].is_object());
    }

    /// `info` must not touch the network: the desktop calls it to render the
    /// settings form before any host is known to be reachable, and the
    /// pre-secret gate invokes it on a staged copy of the binary.
    #[test]
    fn info_needs_no_host() {
        let response = respond(r#"{"op":"info"}"#);
        assert_eq!(json_of(&response)["ok"], true);
    }

    #[test]
    fn malformed_json_is_an_in_band_error() {
        let value = json_of(&respond("not json at all"));
        assert_eq!(value["ok"], false);
        assert!(value["error"].as_str().unwrap().contains("valid JSON"));
    }

    #[test]
    fn unknown_ops_are_in_band_errors() {
        let value = json_of(&respond(r#"{"op":"undeploy","request_id":"r1"}"#));
        assert_eq!(value["ok"], false);
    }

    /// Mesh transport is a loopback proxy on the desktop. Deploying it to
    /// another machine points the agent at a port where nothing listens, so
    /// the refusal must come before any host contact.
    #[test]
    fn relay_mesh_agents_are_refused_before_any_host_contact() {
        let value = json_of(&respond(
            r#"{"op":"deploy","agent":{"relay_url":"wss://r",
                "private_key_nsec":"nsec1x","provider":"relay-mesh"},
                "provider_config":{"host":"nonexistent.invalid"}}"#,
        ));
        assert_eq!(value["ok"], false);
        assert!(value["error"].as_str().unwrap().contains("shared compute"));
    }

    /// Padding must not bypass the backstop.
    #[test]
    fn relay_mesh_refusal_ignores_padding() {
        let value = json_of(&respond(
            r#"{"op":"deploy","agent":{"relay_url":"wss://r",
                "private_key_nsec":"nsec1x","provider":"  relay-mesh  "},
                "provider_config":{"host":"h"}}"#,
        ));
        assert_eq!(value["ok"], false);
        assert!(value["error"].as_str().unwrap().contains("shared compute"));
    }

    /// I1, and it must fail before the provider ever reaches for a host: an
    /// identityless agent is a refusal, not a connection error.
    #[test]
    fn an_empty_key_is_refused_before_any_host_contact() {
        let value = json_of(&respond(
            r#"{"op":"deploy","agent":{"relay_url":"wss://r","private_key_nsec":"",
                "auth_tag":"t"},"provider_config":{"host":"nonexistent.invalid"}}"#,
        ));
        assert_eq!(value["ok"], false);
        let error = value["error"].as_str().unwrap();
        assert!(error.contains("no private key"), "{error}");
    }

    /// A config error must be reported as a config error, not as a failed
    /// connection to a host the user never named.
    #[test]
    fn a_missing_host_is_a_config_error() {
        let value = json_of(&respond(
            r#"{"op":"deploy","agent":{"relay_url":"wss://r",
                "private_key_nsec":"nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
                "auth_tag":"t"},"provider_config":{}}"#,
        ));
        assert_eq!(value["ok"], false);
        assert!(value["error"].as_str().unwrap().contains("host"));
    }

    /// An agent nothing can stop is refused before any host contact, because
    /// without an owner the harness answers `!shutdown` conversationally.
    #[test]
    fn an_unstoppable_agent_is_refused_before_any_host_contact() {
        let value = json_of(&respond(
            r#"{"op":"deploy","agent":{"relay_url":"wss://r",
                "private_key_nsec":"nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"},
                "provider_config":{"host":"nonexistent.invalid"}}"#,
        ));
        assert_eq!(value["ok"], false);
        assert!(value["error"].as_str().unwrap().contains("!shutdown"));
    }

    /// The desktop's real, *recorded* deploy payload must parse and resolve
    /// here.
    ///
    /// Shared with the Kubernetes binding on purpose rather than copied: that
    /// fixture is the output of the desktop's actual
    /// `build_launch_block` → `deploy_payload_json` path, and its README's
    /// first rule is that requests are recorded, not invented. A private
    /// hand-written copy would test a contract nobody emits — which is
    /// exactly how the original acquired four impossible values at once.
    /// `include_str!` also means a moved or renamed fixture breaks this build
    /// loudly instead of silently skipping.
    #[test]
    fn the_recorded_desktop_payload_is_accepted() {
        const RECORDED: &str = include_str!(
            "../../buzz-backend-kubernetes/tests/fixtures/provider-wire/deploy-full-launch.request.json"
        );

        let request: Request = serde_json::from_str(RECORDED).expect("recorded payload parses");
        let Request::Deploy(deploy) = request else {
            panic!("the recorded fixture is not a deploy")
        };

        let identity = identity::AgentIdentity::from_nsec(&deploy.agent.private_key_nsec)
            .expect("recorded nsec derives an identity");
        let cfg = config::parse(&serde_json::json!({"host": "super"})).expect("config");
        let environment =
            env::build(&deploy.agent, &identity, &cfg, "nonce").expect("environment resolves");

        // The launch block the desktop actually sends must drive the agent
        // command, not the raw record fields beside it.
        assert_eq!(environment["BUZZ_ACP_AGENT_COMMAND"], "goose");
        assert_eq!(environment["BUZZ_ACP_AGENT_ARGS"], "acp");
        assert_eq!(environment["GOOSE_MODEL"], "gpt-5");
        assert_eq!(environment["GOOSE_PROVIDER"], "openai");
        assert_eq!(environment["GOOSE_MODE"], "auto");
        assert_eq!(environment["BUZZ_ACP_AGENTS"], "10");
        assert_eq!(environment["USER_KEY"], "user-value");
        assert_eq!(environment["BUZZ_RELAY_URL"], "wss://relay.example");
        assert_eq!(environment["BUZZ_AUTH_TAG"], "tag-1");
        assert_eq!(environment["BUZZ_ACP_RESPOND_TO"], "allowlist");
        assert!(environment["BUZZ_ACP_RESPOND_TO_ALLOWLIST"].contains(','));
    }

    /// Every response is a flat object with `ok` at the top level — the shape
    /// the desktop reads.
    #[test]
    fn responses_are_flat() {
        for input in [r#"{"op":"info"}"#, r#"{"op":"nope"}"#, "garbage"] {
            let value = json_of(&respond(input));
            assert!(value.is_object(), "{input}");
            assert!(value.get("ok").is_some(), "{input}");
        }
    }
}
