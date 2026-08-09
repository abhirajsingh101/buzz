/**
 * Where a managed agent runs, and what the desktop knows about the backend
 * providers that can run it.
 *
 * Split out of `types.ts` — which is at its size ceiling — as one cohesive
 * cluster rather than an arbitrary slice: these four types are the whole
 * "somewhere other than this computer" surface, and they are re-exported from
 * `types.ts` so every existing import keeps working.
 */

/**
 * The agent's execution substrate. `local` spawns a process on this machine;
 * `provider` hands the launch to a discovered `buzz-backend-<id>` executable
 * (see `docs/remote-agents.md`).
 */
export type ManagedAgentBackend =
  | { type: "local" }
  | { type: "provider"; id: string; config: Record<string, unknown> };

/** A `buzz-backend-<id>` executable found by discovery. */
export type BackendProviderCandidate = {
  id: string;
  binaryPath: string;
};

/** A provider's answer to the `info` operation. */
export type BackendProviderProbeResult = {
  ok: boolean;
  name?: string;
  version?: string;
  description?: string;
  config_schema?: Record<string, unknown>;
};

export type RelayMeshConfig = {
  modelRef: string;
};
