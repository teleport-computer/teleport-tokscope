// File: tokscope-enclave/lib/inbound-semaphore.ts
//
// TEE inbound concurrency cap. Originally inline in server.ts:1922-1955
// (v1.2.1.1.9 T1). Extracted in v2.5 phase 2 step 1 so the data-customer
// process gets its own semaphore independent of any other route group;
// when server.ts splits into server-auth.ts + server-data.ts, only the
// data process imports this.
//
// Symmetric safety-net to xordi-api's outbound semaphore. Bounds in-flight
// handlers so the Node event loop doesn't fill with stuck requests under
// multi-instance / cold-cache load.
//
// Counter is module-scoped per process. The 'all' / legacy single-process
// mode and the data-customer mode each instantiate their own copy with
// their own counter.
//
// Knob: TEE_INBOUND_CONCURRENCY_LIMIT env var, default 20. v2.5 doesn't
// pre-bump this — it's per-CVM tunable at deploy.

const TEE_INBOUND_LIMIT = parseInt(
  process.env.TEE_INBOUND_CONCURRENCY_LIMIT || '20',
  10
);
let inflight = 0;

/**
 * Result of an acquire attempt. When `acquired === false`, the caller
 * should respond 503 with the suggested `retryAfterSeconds` value.
 */
export interface AcquireResult {
  acquired: boolean;
  retryAfterSeconds?: number;
}

/**
 * Try to acquire one inbound slot. Returns synchronously — non-blocking.
 *
 * Caller MUST call `releaseInbound()` once the handler exits (success,
 * 4xx, 5xx, or thrown error) iff `result.acquired === true`. Use a
 * try/finally to guarantee release.
 *
 * On rejection: returns `{ acquired: false, retryAfterSeconds }` with a
 * jittered 30-60s value to spread retries across a window — without
 * jitter, every client 503'd in the same instant retries simultaneously
 * and re-saturates the cap. 30-60s spread lets clients arrive over a 30s
 * window so the TEE drains naturally between waves.
 */
export function tryAcquireInbound(): AcquireResult {
  if (inflight >= TEE_INBOUND_LIMIT) {
    // Math.random() is fine here — non-security-sensitive, just spread.
    const retryAfter = 30 + Math.floor(Math.random() * 30);
    return { acquired: false, retryAfterSeconds: retryAfter };
  }
  inflight++;
  return { acquired: true };
}

/**
 * Release one inbound slot. Integer decrement is event-loop-atomic so
 * this cannot throw. Always pair with a successful tryAcquireInbound()
 * — calling release without acquire underflows the counter.
 */
export function releaseInbound(): void {
  inflight--;
}

/**
 * Observability hook for /health-style endpoints that report capacity.
 * Returns a snapshot; safe to call any time.
 */
export function getInboundStats(): { limit: number; inflight: number } {
  return { limit: TEE_INBOUND_LIMIT, inflight };
}
