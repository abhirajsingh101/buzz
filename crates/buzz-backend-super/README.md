# `buzz-backend-super`

A backend provider that runs Buzz agents as plain processes on a host reached
over SSH. It implements the contract in [`docs/remote-agents.md`](../../docs/remote-agents.md)
— the same one `buzz-backend-kubernetes` implements, against a different
substrate.

The spec names this shape as its live non-Kubernetes example (§Launchers,
layer 3): a binding conforms to layers 1 and 2 and writes its own layer 3.
This document is that layer 3.

## Where it runs

The provider runs on **the desktop machine**, and SSHes **to the host**. It is
not installed on the host.

```
   admin's desktop                      the host
 ┌────────────────────┐              ┌──────────────────┐
 │ Buzz Desktop       │              │  buzz-acp        │
 │   └─ buzz-backend- │──── ssh ────▶│  buzz-acp        │
 │      super         │              │  buzz-acp  …     │
 └────────────────────┘              └──────────────────┘
          │                                   │
          └──────────── relay ────────────────┘
              status, !shutdown  (axiom M1)
```

After `deploy` returns, the provider is out of the loop entirely. Status is
relay presence, stop is a relay `!shutdown`, and reconfiguration is a
re-deploy — axiom M1. There is no management channel and no substrate API.

## Installing

Discovery scans the desktop executable's directory, every `PATH` entry, and
then `~/.local/bin`, for a file named `buzz-backend-<id>`. So:

```bash
cargo build --release -p buzz-backend-super
cp target/release/buzz-backend-super ~/.local/bin/
```

No registration, no configuration file. **Build it on the machine that runs
the desktop** — a Linux binary will not run on a Mac.

Each admin who wants to launch agents needs the binary *and* their own SSH
access to the host. That provisioning is the main scaling cost of this
approach, and it is deliberate: the provider is handed the agent's private
key by design (§Scope), so "who can deploy" and "who is trusted with agent
identities" are the same question.

## Configuration

| field | default | meaning |
|---|---|---|
| `host` | `super` | SSH destination — a hostname or `~/.ssh/config` alias |
| `user` | *(empty)* | SSH user; empty uses your SSH config's default |
| `port` | `22` | SSH port |
| `identity_file` | *(empty)* | optional path to a private key file |
| `harness_command` | `buzz-acp` | the harness on the host: a name resolved against its `PATH`, or an absolute path |
| `path_prepend` | `$HOME/.npm-global/bin:$HOME/.local/bin` | prepended to the host's `PATH` before the harness runs |
| `state_dir` | `$HOME/.buzz/provider-super` | where this provider keeps its own per-agent state |
| `inactivity_seconds` | `0` | stop after this many idle seconds; `0` means no bound |
| `startup_settle_seconds` | `5` | how long the harness must stay up before a deploy reports success |

There is no credential field, by I2 — SSH auth comes from your agent and
`~/.ssh/config`. `identity_file` holds a *path*, which is why it is spelled
that way: the desktop's I2 lint rejects any field name whose word-split
contains `key`, and the spec's instruction on hitting that lint is to rename
the field, never to weaken the validator.

`path_prepend` is not a convenience. A non-interactive `ssh host cmd` gets a
login shell's minimal `PATH`, and ACP agent binaries installed by npm live in
`$HOME/.npm-global/bin`. Without it the harness starts, fails to spawn its
agent, and dies.

## Layer 3: this binding's policy

**Unit of execution.** One `setsid` process per agent, with the harness
`exec`'d so it is the process that receives the termination signal. A wrapper
that ran the harness as a child without forwarding signals would void both
I5's substrate half and the graceful-shutdown budget.

**No supervisor.** Nothing restarts the process. This satisfies I5's restart
rule vacuously — the spec's explicit allowance for a launcher with no
supervisor at all. A `Restart=on-failure` unit would be better *after* the
harness's exit-code contract is pinned by test (Known Defect 6); shipping it
first is how every clean `!shutdown` silently becomes a restart loop with no
failing test to catch it. That is the upgrade path, in that order.

**Lifetime.** `inactivity_seconds` defaults to `0` — no bound — where the
Kubernetes binding defaults to two hours. Both are blessed (§Auto-Stop). A pod
is metered compute with nobody watching it; this substrate is a host the owner
already runs continuously, hosting agents whose job is to be present in a
channel. Reaping those after two idle hours would be a bug, not a saving.

**State on the host.** One directory per agent pubkey under `state_dir`:

```
<state_dir>/<pubkey>/
  env        the resolved environment, mode 0600
  pid        the harness pid
  exe        the binary that pid was, so a reused pid is detectable
  intent     the create-intent fingerprint
  marker     "buzz-backend-super" — the management marker
  binding    the on-host layout version
  nonce      this generation's start nonce
  log        the harness's stdout and stderr
  workspace/ the harness's cwd
```

**Rows the Kubernetes binding has that this one does not.** There is no image
to pull and nothing to schedule, so the "never started but recoverable —
observe, never delete" rows have no states here: a process either exists or it
does not. Six rows, no clocks, and nothing destructive that is not fenced on
the management marker.

## At most one live instance, across launchers

I4 is "at most one live instance per agent key per deployment scope". **For
this binding the scope is the host** — not "instances this provider started".

That is a stronger promise than the spec requires, and it is here because the
host this was built for already runs agents launched by hand from a script.
The spec permits a provider to ignore them ("hand-launched agents sit outside
it by construction"), but a user who pressed Start would then get a second
process holding the same key, and both would answer every message.

So `deploy` also scans the host's hand-launcher conventions
(`~/.buzz/run/*.pid` and `~/.config/buzz-agents/*.env`) and adopts a match
rather than launching a second copy.

The match is by **salted digest**, never by reading other agents' keys back to
the desktop. Each call sends a fresh random salt; the host returns
`sha256(salt || nsec)` per running agent; only digests cross the wire. A
collision proves same-key, and a non-match reveals nothing. Reading a dozen
live private keys onto every admin's laptop to answer a yes/no question would
be the wrong trade.

If the hand-launcher convention ever changes, the scan finds nothing and this
binding falls back to the spec's baseline promise, in which hand launchers
carry the uniqueness discipline themselves.

## Testing

```bash
cargo test -p buzz-backend-super
```

The suite runs without a host: the state machine's classifier is pure, the
scripts are syntax-checked with `bash -n`, the env-file quoting is verified by
sourcing it with a real `bash`, and the desktop payload is the recorded
fixture shared with the Kubernetes binding.

To exercise it against a real host, `ssh` to that host must already work
non-interactively (`ssh -o BatchMode=yes <host> true`), and `deploy` requests
can be piped straight in:

```bash
echo '{"op":"info"}' | ./target/debug/buzz-backend-super
```
