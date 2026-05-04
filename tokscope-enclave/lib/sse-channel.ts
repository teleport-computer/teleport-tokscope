// File: tokscope-enclave/lib/sse-channel.ts
//
// Server-Sent Events endpoint for streaming AuthSessionManager
// lifecycle events out to borgcube's authRelay consumer. Replaces the
// 3s/2s polling layer cake with push-driven event delivery.
//
// Event types streamed (each named SSE event):
//   - qr_ready       payload: { qrCodeData, qrDecodedUrl }
//   - scan_detected  payload: { timestamp }    (Phase 3 step 3 wires this)
//   - auth_complete  payload: { secUserId? }
//   - failed         payload: { reason }
//
// Stream closes on terminal events (auth_complete or failed) or when
// the client disconnects (req 'close' event). The matching emits live
// in server.ts auth flow code (Phase 3 step 2 wires them).
//
// Subscription pattern: AuthSessionManager extends EventEmitter and
// emits with `(authSessionId, payload)` so this handler can filter
// events to the URL-specified session id.

import type { Request, Response, Express } from 'express';
import type { AuthSessionManager } from './auth-session-manager';

type SseEventName =
  | 'qr_ready'
  | 'scan_detected'
  | 'auth_complete'
  | 'failed';

const TERMINAL_EVENTS: ReadonlySet<SseEventName> = new Set(['auth_complete', 'failed']);

// Total stream lifetime cap. Mirrors AUTH_TIMEOUT_MS in
// AuthSessionManager (120s) — past that the session is gone anyway, so
// no further events will ever fire on it.
const SSE_LIFETIME_MS = 120_000;

/**
 * Write one SSE event line to a Response. Format:
 *   event: <name>
 *   data: <json>
 *   <blank line>
 */
function sendSse(res: Response, eventName: string, data: unknown): void {
  if (res.writableEnded) return;
  res.write(`event: ${eventName}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

/**
 * Initialize SSE response headers. Express's default keep-alive is fine;
 * we only need to set Content-Type and disable caching/buffering.
 */
function initSseResponse(res: Response): void {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // disable nginx/cloudflare buffering
  res.flushHeaders();
}

/**
 * Register GET /auth/events/:authSessionId on the given Express app.
 * Caller passes the AuthSessionManager instance so this lib doesn't
 * have to know how it was constructed.
 *
 * Idempotent on the EventEmitter side — each request adds its own
 * listeners and removes them on disconnect; nothing leaks across
 * requests. Concurrent SSE consumers per session are supported (rare
 * but not forbidden).
 */
export function registerSseChannel(
  app: Pick<Express, 'get'>,
  authSessionManager: AuthSessionManager
): void {
  app.get('/auth/events/:authSessionId', (req: Request, res: Response) => {
    const authSessionId = req.params.authSessionId;

    if (!authSessionId) {
      return res.status(400).json({ error: 'authSessionId required' });
    }

    // Reject if the session doesn't exist OR has already terminated.
    // Caller can fall back to the legacy /auth/poll for already-completed
    // sessions (which return cached state from the AuthSession record).
    const session = authSessionManager.getAuthSession(authSessionId);
    if (!session) {
      return res.status(404).json({ error: 'auth session not found' });
    }

    initSseResponse(res);

    // If the session already has a QR (e.g. client connected after the
    // QR was generated but before scan), emit a synthetic qr_ready so
    // the consumer doesn't have to poll for the initial state.
    if (session.qrCodeData) {
      sendSse(res, 'qr_ready', {
        qrCodeData: session.qrCodeData,
        qrDecodedUrl: session.qrDecodedUrl ?? null,
      });
    }
    // Same for terminal states — if the consumer connected after
    // completion, deliver the final event and close immediately.
    if (session.status === 'complete') {
      sendSse(res, 'auth_complete', {
        secUserId: session.sessionData?.user?.sec_user_id ?? null,
      });
      res.end();
      return;
    }
    if (session.status === 'failed') {
      sendSse(res, 'failed', { reason: 'session already failed' });
      res.end();
      return;
    }

    // Build per-event listeners that filter by authSessionId.
    const makeListener = (eventName: SseEventName) =>
      (eventAuthSessionId: string, payload: unknown) => {
        if (eventAuthSessionId !== authSessionId) return;
        sendSse(res, eventName, payload);
        if (TERMINAL_EVENTS.has(eventName)) {
          cleanup();
          res.end();
        }
      };

    const listeners: Array<[SseEventName, (...args: any[]) => void]> = [
      ['qr_ready', makeListener('qr_ready')],
      ['scan_detected', makeListener('scan_detected')],
      ['auth_complete', makeListener('auth_complete')],
      ['failed', makeListener('failed')],
    ];

    for (const [name, fn] of listeners) {
      authSessionManager.on(name, fn);
    }

    // Hard-cap stream lifetime. Mirrors the AuthSessionManager session
    // timeout — past that, no events will fire on this session.
    const lifetimeTimer = setTimeout(() => {
      sendSse(res, 'failed', { reason: 'stream lifetime exceeded' });
      cleanup();
      res.end();
    }, SSE_LIFETIME_MS);

    let cleaned = false;
    const cleanup = () => {
      if (cleaned) return;
      cleaned = true;
      clearTimeout(lifetimeTimer);
      for (const [name, fn] of listeners) {
        authSessionManager.removeListener(name, fn);
      }
    };

    // Client disconnect → drop our listeners. Don't try to write to
    // res after this; the socket is gone.
    req.on('close', cleanup);
  });
}
