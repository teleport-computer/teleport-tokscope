// File: tokscope-enclave/server-auth.ts
//
// Entrypoint for the AUTH CVM (v2.5 phase 2 step 3).
//
// Sets TOKSCOPE_MODE=auth before loading server.ts so the mode-gated
// route registrations register only auth routes (browser orchestration,
// QR/portal flows, /scrape, /modules/*, /containers, /upload-session,
// /sessions, /load-session, etc.) plus the shared health/ready/tee-info.
// Data routes (`/api/tiktok/execute`, `/api/enclave/decrypt-*`,
// `/api/enclave/encrypt-watch-history`, `/migrate/*`) get registered
// against the `noopApp` shim and silently no-op (404 at request time).
//
// The shim still exists today; removing it (so each entrypoint registers
// exclusively its own routes with no mode gate) is a follow-up Phase 2
// step. This wrapper alone satisfies the Phase 2 exit criterion of
// "running this file boots in auth mode."
//
// CRITICAL: process.env.TOKSCOPE_MODE MUST be set before the require('./server')
// — server.ts reads it at module-load time (top-level const at line 65).

process.env.TOKSCOPE_MODE = 'auth';
require('./server');
