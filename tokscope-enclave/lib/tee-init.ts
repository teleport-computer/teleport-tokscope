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
// Three keys derive deterministically per (app_id, key_purpose) from
// DStack KMS:
//   - 'session-encryption' → encryptionKey (used by upload/load-session)
//   - 'cookie-encryption'  → cookie key (held inside teeCrypto module)
//   - 'watch-history-encryption' → watch-history key (held inside teeCrypto)
//
// Module-scoped state: dstackSDK (the client) + encryptionKey (used by
// session helpers in server.ts). Getters expose them to callers so
// server.ts doesn't have to share variable references with the lib.

import * as crypto from 'crypto';
const teeCrypto = require('../tee-crypto.js');
import { log } from './log';

let dstackSDK: any = null;
let encryptionKey: Buffer | null = null;

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

    // v1.1.9: block until the crypto worker pool has acknowledged the key.
    // This guarantees the HTTP server never answers a request before the
    // pool is ready — no race between startup and first scrape.
    await teeCrypto.waitForWorkersReady();

    // Keep reference for /health endpoint
    dstackSDK = client;

    console.log('✅ DStack initialized, using TEE-derived keys for sessions + cookies + watch-history');
  } catch (error: any) {
    console.log('⚠️ DStack unavailable, using fallback encryption keys:', error.message);
    const seed = 'tcb-session-encryption-fallback-seed-12345';
    encryptionKey = crypto.createHash('sha256').update(seed).digest();
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
