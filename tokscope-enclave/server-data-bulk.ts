// Entrypoint for the data-bulk process. Handles decrypt-watch-history{,-v2},
// encrypt-watch-history, and /migrate/* admin routes. v2.5.1.4 moved the
// heavy decrypt routes here so a power-user decrypt cannot starve the
// customer scrape event loop, and to pre-position bulk for v2.6.0
// compaction backfill.
process.env.TOKSCOPE_MODE = 'data-bulk';
require('./server');
