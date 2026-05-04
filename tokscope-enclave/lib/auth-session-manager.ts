// File: tokscope-enclave/lib/auth-session-manager.ts
//
// Future home of AuthSessionManager, currently inline at server.ts:192-266.
//
// Phase 2 (server.ts split) extracts the class here so server-auth.ts can
// import it cleanly. Phase 3 adds an EventEmitter to it so the new
// sse-channel.ts can subscribe to auth lifecycle events (qr_ready,
// scan_detected, auth_complete, failed) for the push-driven auth flow.
//
// Currently a placeholder — empty export keeps TS strict mode happy and
// establishes the file as a module (not a script). Nothing imports it yet.

export {};
