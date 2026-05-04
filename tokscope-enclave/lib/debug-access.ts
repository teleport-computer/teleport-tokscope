// File: tokscope-enclave/lib/debug-access.ts
//
// Future home of the auth-gated, runtime-toggleable debug-access endpoints.
// Phase 4c implements GET /debug/auth/:authSessionId/{state, dom,
// screenshot, console, network, cookies}. Cookie *names* never values.
//
// Two layers of off-switch (both must be on for endpoints to return 200):
//   1. DEBUG_ACCESS_TOKEN env var — if unset, endpoints don't register at
//      all (hardest off; only redeploy can re-enable).
//   2. system_config.debug_access_enabled bool — runtime toggle via PG
//      NOTIFY system_config_changed (no redeploy). When false, registered
//      endpoints return 404.
//
// Per-session ring buffers (200-entry console + network metadata) attach
// only when the flag is true at session start, so steady-state log volume
// is unchanged when the feature is off.
//
// Currently a placeholder.

export {};
