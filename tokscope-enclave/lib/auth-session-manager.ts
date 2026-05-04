// File: tokscope-enclave/lib/auth-session-manager.ts
//
// AuthSessionManager + AuthSession interface. Originally inline in
// server.ts:102-115 (interface) and server.ts:193-267 (class).
// Extracted in v2.5 phase 2 step 4 so the auth lifecycle state
// machine can live alongside the SSE channel (Phase 3) — the SSE
// endpoint will subscribe to events emitted by this class to stream
// terminal-event updates (qr_ready, scan_detected, auth_complete,
// failed) out to borgcube's authRelay.
//
// Dependency injection:
//   - destroyContainer: callback to recycle the auth container when
//     a session is cleaned up. server.ts owns the actual
//     destroyAuthContainer fn (which fetches the browser-manager URL
//     etc.); this lib doesn't know about browser-manager and stays
//     pure session-state.
//
// EventEmitter mixin:
//   - 'session_removed' (authSessionId) — fires after removeAuthSession.
//     server.ts listens to clean up auxiliary state (e.g.
//     authScreenshotSteps Map).
//   - Phase 3 adds: 'qr_ready', 'scan_detected', 'auth_complete', 'failed'.

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import type { Browser, Page } from 'playwright';
import { log } from './log';

// SessionData is server.ts-internal but referenced by AuthSession. We
// re-declare a minimal compatible shape here to avoid importing back
// into server.ts (which would cause a circular import).
export interface SessionData {
  user?: {
    sec_user_id?: string;
    username?: string;
    nickname?: string;
    uid?: string;
  };
  cookies?: any[];
  tokens?: any;
  device_id?: string;
  install_id?: string;
}

export interface AuthSession {
  authSessionId: string;
  sessionId: string;
  browser: Browser | null;
  page: Page | null;
  containerId: string | null;
  status: 'awaiting_scan' | 'complete' | 'failed';
  qrCodeData: string | null;
  qrDecodedUrl?: string | null; // Magic link URL
  sessionData: SessionData | null;
  startedAt: number;
  // v1.1.3login: per-session timeout — QR sessions use AUTH_TIMEOUT_MS,
  // portal sessions use a different value supplied at create time.
  timeoutMs: number;
  portalSessionUrl?: string | null; // v1.1.3login
}

export interface AuthSessionManagerDeps {
  /**
   * Called when a session expires (cleanupExpired) to release its browser
   * container. Implementation lives in server.ts because it knows the
   * browser-manager URL; this lib just calls the callback.
   */
  destroyContainer: (sessionId: string) => Promise<void>;
}

export class AuthSessionManager extends EventEmitter {
  private authSessions = new Map<string, AuthSession>();
  private readonly AUTH_TIMEOUT_MS = 120000; // 2 minutes
  private readonly deps: AuthSessionManagerDeps;

  constructor(deps: AuthSessionManagerDeps) {
    super();
    this.deps = deps;
    // Allow up to 20 listeners — multiple SSE clients per session is
    // unusual but the EventEmitter default cap of 10 would warn-spam.
    this.setMaxListeners(20);
  }

  generateAuthSessionId(): string {
    return crypto.randomUUID();
  }

  createAuthSession(sessionId: string, timeoutMs?: number): string {
    const authSessionId = this.generateAuthSessionId();
    this.authSessions.set(authSessionId, {
      authSessionId,
      sessionId,
      browser: null,
      page: null,
      containerId: null,
      status: 'awaiting_scan',
      qrCodeData: null,
      sessionData: null,
      startedAt: Date.now(),
      timeoutMs: timeoutMs !== undefined ? timeoutMs : this.AUTH_TIMEOUT_MS,
      portalSessionUrl: null
    });
    return authSessionId;
  }

  getAuthSession(authSessionId: string): AuthSession | null {
    return this.authSessions.get(authSessionId) || null;
  }

  updateAuthSession(authSessionId: string, updates: Partial<AuthSession>): void {
    const session = this.authSessions.get(authSessionId);
    if (session) {
      Object.assign(session, updates);
    }
  }

  removeAuthSession(authSessionId: string): void {
    this.authSessions.delete(authSessionId);
    // Fire 'session_removed' so server.ts can clean up auxiliary state
    // (e.g. authScreenshotSteps Map). Listeners attached via .on().
    this.emit('session_removed', authSessionId);
  }

  async cleanupExpired(): Promise<void> {
    const now = Date.now();
    const expired: string[] = [];

    for (const [authSessionId, session] of this.authSessions.entries()) {
      const sessionTimeoutMs =
        session.timeoutMs !== undefined ? session.timeoutMs : this.AUTH_TIMEOUT_MS;
      if (now - session.startedAt > sessionTimeoutMs) {
        expired.push(authSessionId);
      }
    }

    for (const authSessionId of expired) {
      console.log(`🧹 Cleaning up expired auth session: ${authSessionId.substring(0, 8)}...`);
      log.ok('AUTH', 'session_expired', { session: authSessionId.substring(0, 8) });

      // CRITICAL: Release the browser container BEFORE removing session
      try {
        await this.deps.destroyContainer(authSessionId);
        console.log(`✅ Released container for expired session ${authSessionId.substring(0, 8)}...`);
      } catch (e) {
        console.error(`⚠️ Failed to release container for ${authSessionId}:`, e);
      }

      this.removeAuthSession(authSessionId);
    }

    if (expired.length > 0) {
      console.log(`🧹 Cleaned up ${expired.length} expired sessions`);
    }
  }
}
