// File: tokscope-enclave/lib/tee-init.ts
//
// DStack KMS initialization. Originally inline in server.ts:627-661
// (initDStack function) plus module-level state at server.ts:538-539
// (dstackSDK + encryptionKey). Extracted in v2.5 phase 2 step 2 so both
// server-auth.ts and server-data.ts can share the same init path —
// same app_id derives the same KMS keys on both, which is the
// load-bearing invariant for the auth-CVM / data-CVM cookie-sharing
// pattern (see Appendix A in RELEASE-v2.5.md).
//
// Four keys derive deterministically per (app_id, key_purpose) from
// DStack KMS:
//   - 'session-encryption'        → encryptionKey (used by upload/load-session)
//   - 'cookie-encryption'         → cookie key (held inside teeCrypto module)
//   - 'watch-history-encryption'  → watch-history key (held inside teeCrypto)
//   - 'watch-history-dedup'       → HMAC key for write-time event dedup (v2.6.0).
//                                    Returned as raw 32 bytes; HMAC algorithm
//                                    selection is done locally via
//                                    crypto.createHmac. DStack's getKey(path,
//                                    purpose) takes two domain strings, NOT an
//                                    algorithm selector — domain separation
//                                    comes from the path string only.
//
// Module-scoped state: dstackSDK (the client) + encryptionKey (used by
// session helpers in server.ts) + dedupHmacKey (used by /api/tiktok/execute
// to dedup events at write time). Getters expose them so server.ts doesn't
// have to share variable references with the lib.

import * as crypto from 'crypto';
const teeCrypto = require('../tee-crypto.js');
import { log } from './log';

let dstackSDK: any = null;
let encryptionKey: Buffer | null = null;
let dedupHmacKey: Buffer | null = null;

/**
 * Initialize DStack-derived keys + crypto worker pool. Idempotent: if
 * called twice, the second call re-derives (same bytes, same outcome).
 *
 * On DStack failure (CVM not running on Phala / SDK unreachable), falls
 * back to a deterministic seed-derived encryptionKey — used in dev
 * environments. The cookie + watch-history keys stay at teeCrypto's
 * built-in fallback. teeCrypto.waitForWorkersReady() blocks until the
 * crypto worker pool has acknowledged the keys, guaranteeing the HTTP
 * server doesn't answer requests before the pool is ready.
 */
export async function initDStack(): Promise<void> {
  try {
    const { DstackClient } = require('@phala/dstack-sdk');
    const client = new DstackClient();

    // Session encryption key
    const sessionKeyResult = await client.getKey('session-encryption', 'aes');
    encryptionKey = Buffer.from(sessionKeyResult.key).slice(0, 32);

    // Cookie encryption key (separate derivation path = separate key)
    const cookieKeyResult = await client.getKey('cookie-encryption', 'aes');
    const cookieKey = Buffer.from(cookieKeyResult.key).slice(0, 32);
    teeCrypto.setDStackKey(cookieKey);

    // Watch history encryption key (SEPARATE derivation path — never shares key with cookies)
    const watchHistoryKeyResult = await client.getKey('watch-history-encryption', 'aes');
    const watchHistoryKey = Buffer.from(watchHistoryKeyResult.key).slice(0, 32);
    teeCrypto.setDStackWatchHistoryKey(watchHistoryKey);

    // v2.6.0: HMAC key for watch-history write-time dedup. Independent path
    // from the AES encryption key — DStack guarantees domain-separated paths
    // produce uncorrelated keys. Stored at module scope; consumed by
    // server.ts /api/tiktok/execute to compute per-event fingerprints.
    const dedupKeyResult = await client.getKey('watch-history-dedup', '');
    dedupHmacKey = Buffer.from(dedupKeyResult.key).slice(0, 32);

    // v1.1.9: block until the crypto worker pool has acknowledged the key.
    // This guarantees the HTTP server never answers a request before the
    // pool is ready — no race between startup and first scrape.
    await teeCrypto.waitForWorkersReady();

    // Keep reference for /health endpoint
    dstackSDK = client;

    console.log('✅ DStack initialized, using TEE-derived keys for sessions + cookies + watch-history + dedup-hmac');
  } catch (error: any) {
    console.log('⚠️ DStack unavailable, using fallback encryption keys:', error.message);
    const seed = 'tcb-session-encryption-fallback-seed-12345';
    encryptionKey = crypto.createHash('sha256').update(seed).digest();
    // v2.6.0: dev fallback for dedup HMAC key. Never used in prod (DStack
    // succeeds in prod). Different seed than encryption key to keep the
    // domain separation property intact even in dev.
    const dedupSeed = 'tcb-watch-history-dedup-fallback-seed-12345';
    dedupHmacKey = crypto.createHash('sha256').update(dedupSeed).digest();
    // tee-crypto.js keeps its constructor fallback key
  }
}

/**
 * Returns the session-encryption key (32-byte Buffer) once initDStack
 * has run, or null otherwise. Callers (encryptSessionData /
 * decryptSessionData in server.ts) throw if null.
 */
export function getEncryptionKey(): Buffer | null {
  return encryptionKey;
}

/**
 * Returns the DStack client instance once initDStack has run, or null
 * if init failed (or hasn't run yet). Used by /health and /tee-info to
 * report DStack status and to call client.info() for app_id /
 * compose_hash / instance_id.
 */
export function getDstackSDK(): any {
  return dstackSDK;
}

/**
 * v2.6.0: Returns the HMAC key for watch-history write-time dedup
 * (32-byte Buffer) once initDStack has run. Throws if init hasn't run
 * — callers (server.ts /api/tiktok/execute) MUST be downstream of init.
 *
 * Used to compute per-event fingerprints:
 *   fingerprint = HMAC-SHA256(dedupHmacKey, sec_user_id || '|' ||
 *                              video_id || '|' || watched_at_seconds)[:16]
 *
 * Domain separation from the AES encryption key is enforced by DStack
 * (different paths → uncorrelated keys). HMAC algorithm choice happens
 * at the call site via crypto.createHmac('sha256', key).
 */
export function getDedupHmacKey(): Buffer {
  if (!dedupHmacKey) {
    throw new Error('Dedup HMAC key not initialized; initDStack() must complete first');
  }
  return dedupHmacKey;
}

/**
 * v2.6.0: Returns true once the dedup HMAC key has been derived. Used
 * by /health to surface the dedup-key state alongside the other crypto
 * readiness flags.
 */
export function isDedupHmacKeyReady(): boolean {
  return dedupHmacKey !== null;
}
