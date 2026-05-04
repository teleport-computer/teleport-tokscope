// File: tokscope-enclave/lib/tee-init.ts
//
// Future home of initDStack() and related TEE-startup code, currently
// inline at server.ts:625-650 (approximate lines for getKey calls
// 'session-encryption' / 'cookie-encryption' / 'watch-history-encryption').
//
// Phase 2 (server.ts split) extracts this so server-auth.ts and
// server-data.ts both import the same DStack init path — same app_id
// derives the same KMS keys on both CVMs, which is the load-bearing
// invariant for the auth-CVM / data-CVM cookie-sharing pattern (see
// Appendix A in RELEASE-v2.5.md).
//
// Currently a placeholder.

export {};
