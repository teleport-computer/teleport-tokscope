// Entrypoint for the data-customer (scrape-only) process. Handles
// /api/tiktok/execute. Decrypt routes were moved to data-bulk in
// v2.5.1.4 — see RELEASE-v2.5.1.4-PROD1.md for rationale.
process.env.TOKSCOPE_MODE = 'data-customer';
require('./server');
