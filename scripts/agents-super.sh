#!/usr/bin/env bash
# Buzz agent launcher.
#
# Fork-local, and specific to `super`: the paths below are absolute and this
# host's. Version-controlled at scripts/agents-super.sh on the `personal`
# branch; the deployed copy is /data/abhi/deployments/buzz/agents.sh. They are
# two copies, not a symlink -- a symlink would break the fleet the moment the
# repo was on a branch without this file. Edit one, copy to the other.
#
# The agents were previously started ad-hoc and orphaned to init, with no way
# to restart them reliably. This script makes that repeatable.
#
# Config:     ~/.config/buzz-agents/<name>.env   (key, relay URL, ACP settings)
# Workspace:  ~/.buzz/workspaces/<name>          (falls back to the repo for `ace`)
# Logs:       /tmp/buzz-agent-<name>.log
# PIDs:       ~/.buzz/run/<name>.pid
#
# Processes are tracked by PID file, never by pgrep pattern: every agent runs
# the same `buzz-acp` binary with no distinguishing argv, and a -f pattern also
# matches the shell running this script (that footgun kills your own session).
#
# Usage:  ./agents.sh list
#         ./agents.sh status
#         ./agents.sh start [name ...]     # default: all configured agents
#         ./agents.sh stop  [name ...]
#         ./agents.sh restart [name ...]
#         ./agents.sh logs <name>
set -uo pipefail

CFG_DIR="$HOME/.config/buzz-agents"
WS_DIR="$HOME/.buzz/workspaces"
RUN_DIR="$HOME/.buzz/run"
BIN="/home/abhi/projects/buzz/target/debug/buzz-acp"
FALLBACK_WS="/home/abhi/projects/buzz"

# The harness resolves its ACP agent through PATH -- claude-agent-acp lives in
# ~/.npm-global/bin, its `#!/usr/bin/env node` shebang needs node, and it
# spawns ~/.local/bin/claude. This script previously passed on whatever PATH
# its caller happened to have: started from a login shell it worked, and from
# cron, a systemd unit, or a bare `sh -c` it did not -- so a restart stopped
# all twelve agents and then failed to start any of them.
#
# Prepend rather than replace. These agents' dev-MCP shell tool legitimately
# uses the rest of the inherited PATH (bun, flutter, gcloud, conda), so pinning
# a minimal PATH would trade one breakage for another. The baseline is appended
# for the case where the caller had no usable PATH at all.
AGENT_PATH_PREPEND="$HOME/.npm-global/bin:$HOME/.local/bin"
AGENT_PATH_BASELINE="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# The PATH a child will actually get. An env file may still override it.
agent_path() {
  if [[ -n "${PATH:-}" ]]; then
    printf '%s' "$AGENT_PATH_PREPEND:$PATH:$AGENT_PATH_BASELINE"
  else
    printf '%s' "$AGENT_PATH_PREPEND:$AGENT_PATH_BASELINE"
  fi
}

mkdir -p "$RUN_DIR"

all_agents() { find "$CFG_DIR" -maxdepth 1 -name '*.env' -printf '%f\n' 2>/dev/null | sed 's/\.env$//' | sort; }
workspace_for() { [[ -d "$WS_DIR/$1" ]] && echo "$WS_DIR/$1" || echo "$FALLBACK_WS"; }

# Live PID for an agent, or empty. Verifies the PID is actually our binary so a
# recycled PID never gets signalled.
#
# Reads the raw symlink rather than `readlink -f`. Once `cargo build` replaces
# the harness, a still-running agent reports its exe as "<path> (deleted)" --
# the inode is gone, the process is not. `readlink -f` cannot canonicalise that
# and returns empty, so the old comparison declared a live agent stale, removed
# its pidfile, and returned "not running": `stop` skipped it, `start` launched a
# second one, and the fleet silently doubled to 24 processes, half of them
# orphaned on the old binary and all still answering mentions (2026-08-10).
#
# Stripping the suffix keeps the recycled-PID guard intact -- the path still has
# to match -- while surviving a binary swap underneath a running fleet.
pid_for() {
  local f="$RUN_DIR/$1.pid" p exe
  [[ -f "$f" ]] || return 0
  p=$(<"$f")
  [[ -n "$p" && -d "/proc/$p" ]] || { rm -f "$f"; return 0; }
  exe=$(readlink "/proc/$p/exe" 2>/dev/null)
  exe=${exe% (deleted)}
  [[ -n "$exe" && ( "$exe" == "$BIN" || "$exe" == "$(readlink -f "$BIN" 2>/dev/null)" ) ]] \
    || { rm -f "$f"; return 0; }
  echo "$p"
}

# Everything that must be true before an agent can start, checked without
# starting it. `restart` runs this over every target BEFORE stopping any, so a
# misconfigured fleet is refused rather than stopped-and-not-restarted.
#
# The config is read with sed, never sourced: sourcing would pull each agent's
# private key into this shell's environment for no reason.
preflight_one() {
  local n=$1 cfg="$CFG_DIR/$1.env" acp
  if [[ ! -f "$cfg" ]]; then echo "  $n: no config at $cfg" >&2; return 1; fi
  if [[ ! -x "$BIN" ]]; then echo "  $n: harness missing at $BIN" >&2; return 1; fi
  acp=$(sed -n 's/^[[:space:]]*BUZZ_ACP_AGENT_COMMAND=//p' "$cfg" 2>/dev/null \
        | tail -n 1 | tr -d '\042\047\015')
  # No explicit command means the harness picks its own default; nothing for
  # this check to resolve.
  if [[ -z "$acp" ]]; then return 0; fi
  if PATH="$(agent_path)" command -v "$acp" >/dev/null 2>&1; then return 0; fi
  echo "  $n: '$acp' not found on the agent PATH" >&2
  return 1
}

start_one() {
  local n=$1 cfg="$CFG_DIR/$1.env" ws log
  preflight_one "$n" || return 1
  [[ -n "$(pid_for "$n")" ]] && { echo "  $n: already running"; return 0; }
  ws=$(workspace_for "$n"); log="/tmp/buzz-agent-$n.log"
  # The child writes its own PID and then execs, so the recorded PID *is* the
  # buzz-acp process. Capturing $! in the parent would record the intermediate
  # shell instead, and setsid re-parents anyway.
  # PATH is exported before the config is sourced, so an env file can still
  # override it deliberately.
  setsid bash -c '
      cd "$1" || exit 1
      export PATH="$6"
      set -a; . "$2" || exit 1; set +a
      echo $$ > "$3"
      exec "$4" >>"$5" 2>&1
    ' _ "$ws" "$cfg" "$RUN_DIR/$n.pid" "$BIN" "$log" "$(agent_path)" < /dev/null &
  disown 2>/dev/null || true
  sleep 0.8
  if [[ -n "$(pid_for "$n")" ]]; then echo "  $n: started (ws=${ws##*/})"; else
    echo "  $n: FAILED — tail $log" >&2; return 1; fi
}

stop_one() {
  local n=$1 p; p=$(pid_for "$n")
  [[ -z "$p" ]] && { echo "  $n: not running"; return 0; }
  kill "$p" 2>/dev/null; sleep 0.4
  [[ -n "$(pid_for "$n")" ]] && { kill -9 "$p" 2>/dev/null; sleep 0.2; }
  rm -f "$RUN_DIR/$n.pid"; echo "  $n: stopped"
}

cmd=${1:-status}; shift || true
targets=("$@"); [[ ${#targets[@]} -eq 0 ]] && mapfile -t targets < <(all_agents)

case "$cmd" in
  list)   all_agents ;;
  logs)   tail -f "/tmp/buzz-agent-${targets[0]}.log" ;;
  status)
    printf '%-22s %-9s %s\n' AGENT PID RELAY
    for n in "${targets[@]}"; do
      printf '%-22s %-9s %s\n' "$n" "$(pid_for "$n" || true)" \
        "$(grep -h '^BUZZ_RELAY_URL=' "$CFG_DIR/$n.env" 2>/dev/null | cut -d= -f2-)"
    done ;;
  start)   echo "starting:"; for n in "${targets[@]}"; do start_one "$n"; done ;;
  stop)    echo "stopping:"; for n in "${targets[@]}"; do stop_one  "$n"; done ;;
  restart) echo "checking:"
           fail=0
           for n in "${targets[@]}"; do preflight_one "$n" || fail=1; done
           if [[ $fail -ne 0 ]]; then
             echo "refusing to restart -- nothing was stopped" >&2; exit 1
           fi
           echo "stopping:"; for n in "${targets[@]}"; do stop_one "$n"; done
           echo "starting:"; for n in "${targets[@]}"; do start_one "$n"; done ;;
  *) echo "usage: $0 {list|status|start|stop|restart|logs} [name ...]" >&2; exit 1 ;;
esac
