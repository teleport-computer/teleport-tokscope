// File: tokscope-enclave/server-data.ts
//
// Entrypoint for the DATA CVM (v2.5 phase 2 step 3).
//
// Sets TOKSCOPE_MODE=data before loading server.ts so the mode-gated
// route registrations register both data-customer routes (/api/tiktok/execute,
// /api/enclave/decrypt-watch-history{,-v2}) AND data-bulk routes
// (/api/enclave/encrypt-watch-history, /migrate/*) plus the shared
// health/ready/tee-info. Auth routes get the noopApp shim treatment
// (404 at request time).
//
// We use mode='data' (combined customer+bulk) rather than 'data-customer'
// alone so the data CVM serves both the customer hot-path AND admin/migration
// bulk operations. The two are separable into distinct CVMs later if/when
// migration workloads need their own isolation; v2.5 keeps them on one
// data CVM.
//
// The mode-gate shim still exists today; removing it is a follow-up step.
//
// CRITICAL: process.env.TOKSCOPE_MODE MUST be set before the require('./server')
// — server.ts reads it at module-load time (top-level const at line 65).

process.env.TOKSCOPE_MODE = 'data';
require('./server');
