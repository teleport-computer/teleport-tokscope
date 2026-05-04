import express from 'express';
import { chromium, Browser, BrowserContext, Page } from 'playwright';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as net from 'net';
import jsQR from 'jsqr';
import { log } from './lib/log';
import { tryAcquireInbound, releaseInbound } from './lib/inbound-semaphore';
import { initDStack, getEncryptionKey, getDstackSDK } from './lib/tee-init';
import { AuthSessionManager, AuthSession } from './lib/auth-session-manager';
import { registerSseChannel } from './lib/sse-channel';
import { attachScanWatcher } from './lib/scan-watcher';
import { Jimp } from 'jimp';
import axios from 'axios';
import { SocksProxyAgent } from 'socks-proxy-agent';

const BrowserAutomationClient = require('./lib/browser-automation-client');
const WebApiClient = require('./lib/web-api-client');
const { PublicApiClient } = require('./lib/public-api-client');
const { EnclaveModuleLoader } = require('./lib/enclave-module-loader');
const QRExtractor = require('./lib/qr-extractor');
const xordiSecurityModule = require('./xordi-security-module');
const teeCrypto = require('./tee-crypto');

// Issue 7a: Prevent crashes from unhandled promise rejections
process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  console.error('⚠️ Unhandled Rejection at:', promise, 'reason:', reason?.message || reason);
  // Don't exit - let the process continue serving other requests
});

process.on('uncaughtException', (error: Error) => {
  console.error('🚨 Uncaught Exception:', error.message);
  console.error(error.stack);
  // Don't exit for recoverable errors
});

const BROWSER_MANAGER_URL = process.env.BROWSER_MANAGER_URL || 'http://browser-manager:3001';

// ---------------------------------------------------------------------------
// v1.2.1 — Dual-process mode gate.
//
// The tokscope-enclave image runs in one of these modes, selected at startup
// by the TOKSCOPE_MODE env var (set in docker-compose per service):
//
//   TOKSCOPE_MODE=auth          → only authentication routes (/auth/*,
//                                  /upload-session, /containers, etc.)
//                                  No crypto worker pool, no data routes.
//
//   TOKSCOPE_MODE=data-customer → only customer-hot-path data routes:
//                                  /api/tiktok/execute, /api/enclave/decrypt-
//                                  watch-history{,-v2}. Owns its own crypto
//                                  worker pool. v1.2.1.1 split.
//
//   TOKSCOPE_MODE=data-bulk     → only bulk/admin data routes:
//                                  /api/enclave/encrypt-watch-history,
//                                  /migrate/*. Own crypto pool. v1.2.1.1 split.
//
//   TOKSCOPE_MODE=data          → backward-compat: registers BOTH data-customer
//                                  and data-bulk route sets in a single process
//                                  (matches pre-v1.2.1.1 single-data-process
//                                  behavior). Used for v1.2.1 → v1.2.1.1
//                                  rollback without a code revert.
//
//   TOKSCOPE_MODE=all           → registers every route. Local dev convenience.
//
// Both processes share the same CVM, same app_id, same DStack-derived keys —
// key derivation is deterministic per (app_id, key_id), a DStack platform
// guarantee. Encrypted rows written by one process are readable by the other.
// ---------------------------------------------------------------------------
const MODE = (process.env.TOKSCOPE_MODE || 'all').toLowerCase();
const isAuth = MODE === 'auth' || MODE === 'all';
const isDataCustomer = MODE === 'data-customer' || MODE === 'data' || MODE === 'all';
const isDataBulk = MODE === 'data-bulk' || MODE === 'data' || MODE === 'all';
const isData = isDataCustomer || isDataBulk;  // any data-bearing mode
console.log(`[TEE] Starting in TOKSCOPE_MODE=${MODE} (auth=${isAuth}, data-customer=${isDataCustomer}, data-bulk=${isDataBulk})`);

interface SessionData {
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

// v3-v: Updated - server.ts now owns CDP connection and creates context/page
interface BrowserInstance {
  browser: Browser;
  context: BrowserContext;
  page: Page;
  containerId: string;
  cdpUrl: string;
  containerIp: string;   // v1.1.3combo3: for VNC TCP proxy
}

interface Config {
  tcb: {
    session_timeout_ms: number;
  };
}

// v2.5 phase-2 step-4: AuthSession interface moved to
// lib/auth-session-manager.ts. Imported above.

// v3-s: Debug screenshot storage (in-memory with TTL)
interface DebugScreenshot {
  buffer: Buffer;
  timestamp: number;
  authSessionId: string;
  reason: string;  // 'qr_visible' | 'url_change' | 'timeout' | 'success'
  url: string;
  title: string;
  step: number;    // 1, 2, 3... for ordering within session
}

const debugScreenshots = new Map<string, DebugScreenshot>();
const DEBUG_SCREENSHOT_TTL_MS = parseInt(process.env.DEBUG_SCREENSHOT_TTL_MS || '300000'); // 5 min default

// Cleanup expired screenshots every minute
setInterval(() => {
  if (process.env.ENABLE_DEBUG_SCREENSHOTS !== 'true') return;
  const now = Date.now();
  for (const [token, screenshot] of debugScreenshots.entries()) {
    if (now - screenshot.timestamp > DEBUG_SCREENSHOT_TTL_MS) {
      debugScreenshots.delete(token);
    }
  }
}, 60000);

// z-4: Track step counter per auth session
const authScreenshotSteps = new Map<string, number>();

/**
 * v3-s: Capture debug screenshot and return access URL
 * Only runs when ENABLE_DEBUG_SCREENSHOTS=true
 */
async function captureDebugScreenshot(
  page: Page,
  authSessionId: string,
  reason: string
): Promise<string | null> {
  if (process.env.ENABLE_DEBUG_SCREENSHOTS !== 'true') {
    return null;
  }

  try {
    const buffer = await page.screenshot({ fullPage: true });
    const token = crypto.randomBytes(16).toString('hex');
    const url = page.url();
    const title = await page.title();

    // z-4: Increment step counter for this auth session
    const currentStep = (authScreenshotSteps.get(authSessionId) || 0) + 1;
    authScreenshotSteps.set(authSessionId, currentStep);

    debugScreenshots.set(token, {
      buffer,
      timestamp: Date.now(),
      authSessionId,
      reason,
      url,
      title,
      step: currentStep
    });

    // Log clickable URL (appears in docker logs)
    const baseUrl = process.env.DEBUG_SCREENSHOT_BASE_URL || '';
    const screenshotUrl = baseUrl
      ? `${baseUrl}/debug/screenshot/${token}`
      : `/debug/screenshot/${token}`;
    console.log(`📸 Debug screenshot: ${screenshotUrl}`);
    console.log(`   Auth: ${authSessionId.substring(0, 8)}..., Reason: ${reason}`);

    return token;
  } catch (err: any) {
    console.error(`⚠️ Screenshot capture failed: ${err.message}`);
    return null;
  }
}

// v2.5 phase-2 step-4: AuthSessionManager class moved to
// lib/auth-session-manager.ts. Construction site below passes
// destroyAuthContainer as a callback dependency, and listens to
// 'session_removed' to clean up authScreenshotSteps (which used
// to be done inline in removeAuthSession).

/**
 * v3-v: Request browser instance - NOW CREATES THE ONLY CDP CONNECTION
 * This is the fix for the dual CDP connection bug (Solution F)
 * browser-manager only manages Docker lifecycle, we own CDP/context/page
 */
async function requestBrowserInstance(sessionId: string): Promise<BrowserInstance> {
  const assignPath = `assign/${sessionId}`;
  console.log(`🔄 Requesting browser instance from ${BROWSER_MANAGER_URL}/${assignPath}`);
  const response = await fetch(`${BROWSER_MANAGER_URL}/${assignPath}`, {
    method: 'POST'
  });
  console.log(`🔄 Browser manager response status: ${response.status}`);
  if (!response.ok) {
    throw new Error(`Failed to get browser instance: ${response.statusText}`);
  }
  const result = await response.json();
  console.log(`🔄 Container assigned: ${result.container.containerId?.substring(0, 20)}... (IP: ${result.container.ip})`);

  // v3-v: Connect via CDP - THIS IS THE ONLY CONNECTION
  // browser-manager no longer creates a CDP connection
  let browser = null;
  const maxRetries = 3;
  for (let i = 0; i < maxRetries; i++) {
    try {
      browser = await chromium.connectOverCDP(result.container.cdpUrl);
      break;
    } catch (error: any) {
      if (i === maxRetries - 1) throw error;
      log.warn('AUTH', 'cdp_retry', { session: sessionId.substring(0, 8), attempt: i + 1, max_attempts: maxRetries, error: error.message });
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  // v1.1.3F2: Reuse default context + pre-navigated page (tiktok.com already loaded)
  // browser-manager pre-navigated the default page via CDP during pool warmup.
  // Playwright's connectOverCDP sees that page via contexts()[0].pages()[0].
  console.log(`📦 Acquiring browser context (v1.1.3F2: reuse pre-navigated page)...`);

  let context, page;
  try {
    const contexts = browser!.contexts();
    context = contexts[0]; // Default context from connectOverCDP
    const existingPages = context.pages();
    if (existingPages.length > 0) {
      page = existingPages[0];
      console.log(`✅ Browser instance ready (reusing pre-navigated page at ${page.url()})`);
    } else {
      page = await context.newPage();
      console.log(`✅ Browser instance ready (fresh page, no pre-nav available)`);
    }
  } catch (error: any) {
    if (error.name === 'TargetClosedError' || error.message?.includes('Target closed')) {
      console.error(`⚠️ Browser closed during context setup for ${sessionId}`);
      throw new Error('BROWSER_DISCONNECTED');
    }
    throw error;
  }

  // z-4 Phase 2b: Verify relay is configured
  try {
    const relayStatus = await fetch(`http://${result.container.ip}:1081/status`);
    const status = await relayStatus.json();
    if (status.mode === 'proxied') {
      console.log(`✅ [relay] configured → ${status.upstream}`);
    } else {
      console.log(`⚠️ [relay] NOT configured (mode: ${status.mode})`);
    }
  } catch (e) {
    console.log(`⚠️ [relay] status check failed`);
  }

  // z-4 Phase 2a: Log failed network requests
  page.on('requestfailed', request => {
    const url = request.url();
    const failure = request.failure();
    if (url.includes('tiktok.com')) {
      console.log(`❌ [network] ${url.substring(0, 80)}... - ${failure?.errorText || 'unknown'}`);
    }
  });

  // z-5a: Removed QR poll status logging (was causing screenshot spam)
  // Detection reverted to v2.4 style: URL-based + sessionid cookie

  // z-4 Phase 2d: Log URL changes (domain + path only)
  page.on('framenavigated', frame => {
    if (frame === page.mainFrame()) {
      try {
        const parsed = new URL(frame.url());
        console.log(`🔀 [url] ${parsed.hostname}${parsed.pathname}`);
      } catch (e) { /* ignore invalid URLs */ }
    }
  });

  // z-4 Phase 2e: Log when auth cookies are set via Set-Cookie header
  // Use headersArray() to handle multiple Set-Cookie headers correctly
  const AUTH_COOKIES = ['sessionid', 'sid_guard', 'uid_tt', 'sid_tt'];
  const seenCookies = new Set<string>();
  page.on('response', async response => {
    try {
      const headers = await response.headersArray();
      const setCookies = headers
        .filter(h => h.name.toLowerCase() === 'set-cookie')
        .map(h => h.value);

      for (const cookieStr of setCookies) {
        for (const cookieName of AUTH_COOKIES) {
          if (cookieStr.startsWith(`${cookieName}=`) && !seenCookies.has(cookieName)) {
            seenCookies.add(cookieName);
            console.log(`🍪 [+cookie] ${cookieName}`);
          }
        }
      }

      // v1.2.1.1.11 P1: log all tiktok.com responses (URL + status, no body)
      // for diagnosing why the QR-scan flow stalls. Skips static assets.
      const url = response.url();
      if (url.includes('tiktok.com') &&
          !/\.(css|js|png|jpg|jpeg|gif|woff2?|svg|ico|map)(\?|$)/i.test(url)) {
        console.log(`📡 [resp] ${response.status()} ${response.request().method()} ${url.substring(0, 140)}`);
      }

      // v1.2.1.1.11 P3: log non-AUTH Set-Cookie event cookie NAMES (no values)
      // so we can see what TikTok IS setting if it's not the four we're listening for.
      for (const cookieStr of setCookies) {
        const cookieName = cookieStr.split('=')[0];
        if (!AUTH_COOKIES.includes(cookieName) && !seenCookies.has(`other:${cookieName}`)) {
          seenCookies.add(`other:${cookieName}`);
          console.log(`🍪 [+other] ${cookieName}`);
        }
      }
    } catch (e) { /* response may be closed */ }
  });

  return {
    browser: browser!,
    context: context!,
    page: page!,
    containerId: result.container.containerId,
    cdpUrl: result.container.cdpUrl,
    containerIp: result.container.ip   // v1.1.3combo3
  };
}

async function releaseBrowserInstance(sessionId: string): Promise<void> {
  await fetch(`${BROWSER_MANAGER_URL}/release/${sessionId}`, {
    method: 'POST'
  });
}

/**
 * v3-q: Destroy auth container after use (prevents state contamination)
 * Browser-manager will destroy container and pool maintenance will create fresh ones
 */
async function destroyAuthContainer(sessionId: string): Promise<void> {
  try {
    const response = await fetch(`${BROWSER_MANAGER_URL}/recycle/${sessionId}`, {
      method: 'POST'
    });
    if (!response.ok) {
      throw new Error(`Failed to destroy container: ${response.statusText}`);
    }
    console.log(`🗑️ Destroyed auth container for session ${sessionId.substring(0, 8)}...`);
  } catch (error: any) {
    console.error(`⚠️ Failed to destroy container for ${sessionId}:`, error.message);
  }
}

class SessionManager {
  private sessions = new Map<string, SessionData>();
  private lastAccess = new Map<string, number>();
  private config: Config = {
    tcb: {
      session_timeout_ms: 3600000 // 1 hour
    }
  };

  initialize(): void {
    this.startCleanupInterval();
  }

  generateSessionId(): string {
    return crypto.randomUUID();
  }

  storeSession(sessionData: SessionData): string {
    const sessionId = sessionData.user?.sec_user_id || this.generateSessionId();
    this.sessions.set(sessionId, sessionData);
    this.lastAccess.set(sessionId, Date.now());
    return sessionId;
  }

  getSession(sessionId: string): SessionData | null {
    if (!this.sessions.has(sessionId)) {
      return null;
    }
    this.lastAccess.set(sessionId, Date.now());
    return this.sessions.get(sessionId) || null;
  }

  removeSession(sessionId: string): void {
    this.sessions.delete(sessionId);
    this.lastAccess.delete(sessionId);
  }

  getAllSessions(): string[] {
    return Array.from(this.sessions.keys());
  }

  getSessionCount(): number {
    return this.sessions.size;
  }

  private startCleanupInterval(): void {
    const timeoutMs = this.config.tcb?.session_timeout_ms || 3600000;

    setInterval(() => {
      const now = Date.now();
      const expired: string[] = [];

      for (const [sessionId, lastAccess] of this.lastAccess.entries()) {
        if (now - lastAccess > timeoutMs) {
          expired.push(sessionId);
        }
      }

      expired.forEach(sessionId => {
        console.log(`🧹 Cleaning up expired session: ${sessionId.substring(0, 8)}...`);
        this.removeSession(sessionId);
      });

      if (expired.length > 0) {
        console.log(`🧹 Cleaned up ${expired.length} expired sessions. Active: ${this.getSessionCount()}`);
      }
    }, 300000); // Check every 5 minutes
  }
}

const app = express();
app.use(express.json({ limit: '500kb' }));

// ---------------------------------------------------------------------------
// v1.2.1.1 — Mode-gated route registrars.
//
// Each route uses ONE of these registrars:
//   appAuth.X(...)         → only when isAuth (MODE=auth or all)
//   appDataCustomer.X(...) → only when isDataCustomer (MODE=data-customer,
//                            data, or all)
//   appDataBulk.X(...)     → only when isDataBulk (MODE=data-bulk, data, or all)
//   app.X(...)             → ALWAYS registered (shared: /health, /ready, /tee-info)
//
// In the "off" mode the methods no-op at registration time — an unregistered
// route will 404 at request time, which is the correct behavior.
//
// When adding a new route: decide which process should own it and use the
// matching registrar. See route table in RELEASE-v1.2.1.1-PROD1.md.
// ---------------------------------------------------------------------------
const noopApp: any = {
  get: () => noopApp,
  post: () => noopApp,
  delete: () => noopApp,
  put: () => noopApp,
  use: () => noopApp,
};
const appAuth: typeof app = (isAuth ? app : noopApp) as any;
const appDataCustomer: typeof app = (isDataCustomer ? app : noopApp) as any;
const appDataBulk: typeof app = (isDataBulk ? app : noopApp) as any;

let browser: Browser | null = null;
let page: Page | null = null;
// v2.5 phase-2 step-2: dstackSDK + encryptionKey moved to lib/tee-init.ts.
// Read via getDstackSDK() / getEncryptionKey().
let lastKnownGatewayUrl: string = ''; // Set from borgcube's gatewayUrl in portal requests
let sessionManager: SessionManager | null = null;
let authSessionManager: AuthSessionManager | null = null;
let moduleLoader: any = null;

// v1.1.3login: In-memory portal session token store (single-use, time-limited)
interface PortalSessionToken {
  authSessionId: string;
  containerId: string | null;
  createdAt: number;
  expiresAt: number;
  used: boolean;
  gatewayUrl?: string;   // v1.1.3combo3: stored at mint time for noVNC redirect
}
const portalSessionTokens = new Map<string, PortalSessionToken>();

// Retrieve container IP from browser-manager
async function getContainerIp(containerId: string): Promise<string | null> {
  try {
    const bmUrl = process.env.BROWSER_MANAGER_URL || 'http://browser-manager:3001';
    const resp = await fetch(`${bmUrl}/stats`);
    if (!resp.ok) return null;
    // Fall back to Docker inspect if needed
    const { execAsync: _exec } = await import('child_process').then(m => ({ execAsync: (cmd: string) => new Promise<{stdout: string}>((res, rej) => m.exec(cmd, (err, stdout) => err ? rej(err) : res({ stdout }))) }));
    const { stdout } = await _exec(`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${containerId}`);
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

// v1.1.3combo3: TCP proxy state for portal VNC access
let activePortalProxy: {
  sessionId: string;
  containerId: string;
  containerIp: string;
  server: net.Server;
} | null = null;

function startPortalProxy(containerId: string, containerIp: string, sessionId: string): void {
  if (activePortalProxy) {
    console.warn(`⚠️ Portal proxy already active for session ${activePortalProxy.sessionId.substring(0, 8)}, stopping first`);
    stopPortalProxy();
  }

  const server = net.createServer((clientSocket) => {
    const upstream = net.connect(6080, containerIp, () => {
      clearTimeout(connectTimeout);
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    });
    const connectTimeout = setTimeout(() => {
      upstream.destroy();
      clientSocket.destroy();
    }, 5000);
    upstream.on('error', () => { clearTimeout(connectTimeout); clientSocket.destroy(); });
    clientSocket.on('error', () => { clearTimeout(connectTimeout); upstream.destroy(); });
  });

  server.listen(6080, '0.0.0.0', () => {
    console.log(`🌐 Portal VNC proxy: 0.0.0.0:6080 → ${containerIp}:6080 (websockify → x11vnc)`);
  });

  server.on('error', (err: any) => {
    console.error(`❌ Portal VNC proxy error: ${err.message}`);
  });

  activePortalProxy = { sessionId, containerId, containerIp, server };
}

function stopPortalProxy(): void {
  if (!activePortalProxy) return;
  console.log(`🔌 Stopping portal VNC proxy for session ${activePortalProxy.sessionId.substring(0, 8)}`);
  activePortalProxy.server.close();
  activePortalProxy = null;
}

// Cleanup expired portal session tokens every minute
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of portalSessionTokens.entries()) {
    if (now > data.expiresAt) {
      portalSessionTokens.delete(token);
    }
  }
}, 60000);

// v2.5 phase-2 step-2: initDStack moved to lib/tee-init.ts. Imported above.
// Both server-auth.ts and server-data.ts (when this file splits in step 3)
// will share that same init path.

function encryptSessionData(data: SessionData): string {
  const encryptionKey = getEncryptionKey();
  if (!encryptionKey) throw new Error('Encryption key not initialized');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
  cipher.setAutoPadding(true);

  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return iv.toString('hex') + ':' + encrypted;
}

function decryptSessionData(encryptedData: any): SessionData {
  const encryptionKey = getEncryptionKey();
  if (!encryptionKey) throw new Error('Encryption key not initialized');

  const { encrypted, iv, authTag, userId } = encryptedData;
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(iv, 'hex'));

  if (userId) {
    decipher.setAAD(Buffer.from(userId, 'utf8'));
  }

  decipher.setAuthTag(Buffer.from(authTag, 'hex'));

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return JSON.parse(decrypted);
}

appAuth.post('/upload-session', (req, res) => {
  try {
    const { sessionData } = req.body;

    if (!sessionData) {
      return res.status(400).json({ error: 'Session data required' });
    }

    if (!sessionManager) {
      return res.status(500).json({ error: 'Session manager not initialized' });
    }

    const sessionId = sessionManager.storeSession(sessionData);
    const encryptedSession = encryptSessionData(sessionData);

    console.log(`📤 Session uploaded: ${sessionId.substring(0, 8)}... (user: @${sessionData.user?.username || 'unknown'})`);
    console.log(`📊 Active sessions: ${sessionManager.getSessionCount()}`);

    res.json({
      sessionId,
      encrypted: encryptedSession,
      status: 'uploaded'
    });
  } catch (error: any) {
    console.error('Session upload error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

appAuth.post('/load-session', (req, res) => {
  try {
    const { encryptedSession, sessionData } = req.body;

    let actualSessionData = sessionData;
    if (encryptedSession && !sessionData) {
      // Decrypt the session data
      actualSessionData = decryptSessionData(encryptedSession);
    }

    if (!actualSessionData) {
      return res.status(400).json({ error: 'Session data required' });
    }

    if (!sessionManager) {
      return res.status(500).json({ error: 'Session manager not initialized' });
    }

    const sessionId = sessionManager.storeSession(actualSessionData);

    console.log(`✅ Session loaded for user: ${actualSessionData.user?.username || 'unknown'} (ID: ${sessionId.substring(0, 8)}...)`);

    res.json({
      sessionId,
      status: 'loaded'
    });
  } catch (error: any) {
    console.error('Session load error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

appAuth.get('/sessions', (req, res) => {
  if (!sessionManager) {
    return res.status(500).json({ error: 'Session manager not initialized' });
  }

  const sessions = sessionManager.getAllSessions();
  res.json({
    count: sessions.length,
    sessions: sessions.map(id => ({
      id: id.substring(0, 8) + '...',
      fullId: id
    }))
  });
});

// Authentication endpoints
appAuth.post('/auth/start/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    // v1.1.3login: accept portalMode, portalTimeoutMs, portalLoginUrl in addition to preAuthToken
    const {
      preAuthToken,
      portalMode,
      portalTimeoutMs: rawPortalTimeoutMs,
      portalLoginUrl,
      gatewayUrl
    } = req.body;

    if (!authSessionManager) {
      return res.status(500).json({ error: 'Auth session manager not initialized' });
    }

    // v1.1.3login: portal mode — validate and resolve timeout
    const isPortalMode = !!portalMode;
    const DEFAULT_PORTAL_TIMEOUT_MS = 300000; // 5 minutes
    const portalTimeoutMs = isPortalMode
      ? (rawPortalTimeoutMs && Number.isFinite(Number(rawPortalTimeoutMs)) && Number(rawPortalTimeoutMs) > 0
          ? Number(rawPortalTimeoutMs)
          : DEFAULT_PORTAL_TIMEOUT_MS)
      : 0;

    if (preAuthToken) {
      console.log(`🔐 Starting TEE-integrated authentication for session ${sessionId.substring(0, 8)}... (pre-auth token provided)`);
    } else {
      console.log(`🔐 Starting legacy authentication for session ${sessionId.substring(0, 8)}... (no pre-auth token)`);
    }
    if (isPortalMode) {
      console.log(`🌐 Portal mode enabled for session ${sessionId.substring(0, 8)}... (timeout: ${portalTimeoutMs}ms)`);
    }
    log.ok('AUTH', 'auth_started', { session: sessionId.substring(0, 8), mode: isPortalMode ? 'portal' : 'qr' });

    // Create auth session with per-session timeout
    const authSessionTimeoutMs = isPortalMode ? portalTimeoutMs : undefined;
    const authSessionId = authSessionManager.createAuthSession(sessionId, authSessionTimeoutMs);

    // Start authentication flow asynchronously
    (async () => {
      let browserInstance: BrowserInstance | null = null;

      try {
        // v3-v: Request browser container - NOW INCLUDES context/page creation
        // This is the Solution F fix: single CDP connection owns everything
        browserInstance = await requestBrowserInstance(authSessionId);

        authSessionManager.updateAuthSession(authSessionId, {
          containerId: browserInstance.containerId,
          browser: browserInstance.browser,
          page: browserInstance.page
        });

        const authPage = browserInstance.page;

        // v1.1.3login: Portal mode branch — skip QR, navigate to email login, start cookie-only detection
        if (isPortalMode) {
          const loginUrl = portalLoginUrl
            || process.env.PORTAL_LOGIN_URL
            || 'https://www.tiktok.com/login/phone-or-email/email';

          console.log(`🌐 Portal mode: navigating to ${loginUrl} for ${authSessionId.substring(0, 8)}...`);
          await authPage.goto(loginUrl, {
            waitUntil: 'domcontentloaded',
            timeout: 30000
          });
          console.log(`✅ Portal login page loaded for ${authSessionId.substring(0, 8)}...`);

          // Generate one-time session token (256-bit random, maps to container Neko credentials)
          const sessionToken = crypto.randomBytes(32).toString('hex');

          // Build portal URL using gatewayUrl from borgcube (knows the CVM's public URL)
          const dstackGateway = gatewayUrl || process.env.DSTACK_GATEWAY_URL || lastKnownGatewayUrl;
          let portalSessionUrl: string;
          if (dstackGateway) {
            // Cache for use in /auth/portal redirect (Neko URL construction)
            lastKnownGatewayUrl = dstackGateway;
            portalSessionUrl = `${dstackGateway}/auth/portal/${sessionToken}`;
          } else {
            // Fallback for non-Dstack environments: use local URL
            const localPort = process.env.PORT || '3000';
            portalSessionUrl = `http://localhost:${localPort}/auth/portal/${sessionToken}`;
          }

          // Store session token in-memory for auth proxy validation (single-use, time-limited)
          portalSessionTokens.set(sessionToken, {
            authSessionId,
            containerId: browserInstance.containerId,
            createdAt: Date.now(),
            expiresAt: Date.now() + portalTimeoutMs,
            used: false,
            gatewayUrl: dstackGateway   // v1.1.3combo3: stored at mint time for noVNC redirect
          });

          // Store portal URL in auth session for polling
          authSessionManager.updateAuthSession(authSessionId, {
            portalSessionUrl
          });

          console.log(`🔑 Portal session token generated for ${authSessionId.substring(0, 8)}...`);

          // v1.1.3combo3: Start VNC TCP proxy to this container
          if (!browserInstance.containerIp) {
            throw new Error(`Container IP not available for portal proxy: ${browserInstance.containerId}`);
          }
          startPortalProxy(browserInstance.containerId, browserInstance.containerIp, authSessionId);

          // Start cookie-only detection loop (no URL-change dependency)
          await waitForPortalLoginCompletion(authSessionId, authPage, preAuthToken, portalTimeoutMs);

          return; // Portal flow complete — do not fall through to QR flow
        }

        // v1.1.11: pre-nav disabled in browser-manager. This goto is the FIRST
        // and ONLY CDP-driven navigation per container lifetime — avoids the
        // sequential-CDP handoff issue that caused page.goto timeouts.
        // Cold DNS/TLS cost absorbed here (~1-3s) rather than hidden in pre-nav.
        //
        // v1.1.10 diagnostic: instrument the page to capture WHICH network requests
        // hang when page.goto times out. page.goto with waitUntil='domcontentloaded'
        // has been failing at 30s on prod1 with no visible cause. These listeners
        // produce definitive logs showing: pending requests at timeout, failed
        // requests with error text, console errors, and page JS exceptions.
        const navStart = Date.now();
        const sessionPrefix = authSessionId.substring(0, 8);
        console.log(`🌐 Navigating to QR login page for auth ${sessionPrefix}... (from ${authPage.url()})`);

        const pendingRequests: Set<string> = new Set();
        const failedRequests: Array<{ url: string; err: string }> = [];
        const consoleErrors: string[] = [];
        const pageErrors: string[] = [];

        const onRequest = (req: any) => { pendingRequests.add(req.url()); };
        const onRequestFinished = (req: any) => { pendingRequests.delete(req.url()); };
        const onRequestFailed = (req: any) => {
          pendingRequests.delete(req.url());
          failedRequests.push({ url: req.url().substring(0, 150), err: req.failure()?.errorText || 'unknown' });
        };
        const onConsole = (msg: any) => {
          if (msg.type() === 'error' || msg.type() === 'warning') {
            consoleErrors.push(`[${msg.type()}] ${msg.text().substring(0, 200)}`);
          }
        };
        const onPageError = (err: any) => { pageErrors.push(err.message?.substring(0, 200) || String(err)); };

        authPage.on('request', onRequest);
        authPage.on('requestfinished', onRequestFinished);
        authPage.on('requestfailed', onRequestFailed);
        authPage.on('console', onConsole);
        authPage.on('pageerror', onPageError);

        try {
          await authPage.goto('https://www.tiktok.com/login/qrcode', {
            waitUntil: 'domcontentloaded',
            timeout: 30000
          });
          console.log(`⏱️ QR page loaded in ${Date.now() - navStart}ms for ${sessionPrefix}...`);
          log.ok('AUTH', 'goto_success', {
            session: sessionPrefix,
            duration_ms: Date.now() - navStart,
            pending_at_finish: pendingRequests.size,
            failed_count: failedRequests.length
          });
        } catch (navErr: any) {
          // THE diagnostic output: dump what Chrome was actually doing when it timed out.
          const pendingList = Array.from(pendingRequests).slice(0, 10).map((u) => u.substring(0, 150));
          log.fail('AUTH', 'goto_timeout_diagnosis', {
            session: sessionPrefix,
            duration_ms: Date.now() - navStart,
            current_url: authPage.url().substring(0, 150),
            pending_count: pendingRequests.size,
            failed_count: failedRequests.length,
            console_errors: consoleErrors.length,
            page_errors: pageErrors.length,
            err: navErr.message?.substring(0, 200) || String(navErr)
          });
          // Log first 10 pending URLs individually so they survive log line length limits
          for (const u of pendingList) {
            log.fail('AUTH', 'goto_timeout_pending_url', { session: sessionPrefix, url: u });
          }
          for (const f of failedRequests.slice(0, 10)) {
            log.fail('AUTH', 'goto_request_failed', { session: sessionPrefix, url: f.url, err: f.err });
          }
          for (const msg of consoleErrors.slice(0, 10)) {
            log.fail('AUTH', 'goto_console_error', { session: sessionPrefix, msg: msg.substring(0, 180) });
          }
          for (const err of pageErrors.slice(0, 10)) {
            log.fail('AUTH', 'goto_page_error', { session: sessionPrefix, err: err.substring(0, 180) });
          }
          // Do NOT rethrow — fall through to waitForSelector. If the page rendered
          // enough for the QR <img> to appear, we can still succeed. If not, the
          // existing qr_not_visible diagnostic path fires and captures the screenshot.
        }

        // Wait for QR code with diagnostics on failure
        try {
          await authPage.waitForSelector('img[alt="qrcode"]', {
            timeout: 15000,  // z-5a: increased from 10s to 15s
            state: 'visible'
          });
          console.log(`✅ QR code visible for auth ${authSessionId.substring(0, 8)}...`);
          // Capture screenshot when QR is visible (for debugging)
          await captureDebugScreenshot(authPage, authSessionId, 'qr_visible');
        } catch (qrWaitError) {
          // QR didn't appear - diagnose what's blocking
          const currentUrl = authPage.url();
          const pageState = await authPage.evaluate(() => {
            const hasCaptcha = !!(
              document.querySelector('#captcha_container') ||
              document.querySelector('#verify-ele') ||
              document.querySelector('#captcha-verify-image') ||
              document.querySelector('.captcha_verify_img_slide') ||
              document.querySelector('.secsdk-captcha-drag-icon')
            );
            const hasRecaptcha = !!document.querySelector('iframe[src*="recaptcha"]');
            const bodyText = document.body?.innerText?.substring(0, 500) || '';
            const title = document.title || '';

            return { hasCaptcha, hasRecaptcha, bodyText, title };
          });

          const truncatedUrl = currentUrl.length > 100 ? currentUrl.substring(0, 100) + '...' : currentUrl;
          const truncatedTitle = pageState.title.length > 80 ? pageState.title.substring(0, 80) + '...' : pageState.title;

          console.error(`🚫 Auth ${authSessionId.substring(0, 8)} QR not visible after 10s`);
          console.error(`   URL: ${truncatedUrl}`);
          console.error(`   Title: ${truncatedTitle}`);

          if (pageState.hasCaptcha) {
            console.error(`   Blocker: [TIKTOK_CAPTCHA]`);
          } else if (pageState.hasRecaptcha) {
            console.error(`   Blocker: [RECAPTCHA]`);
          } else {
            console.error(`   Blocker: [UNKNOWN]`);
          }
          console.error(`   Body preview: ${pageState.bodyText.replace(/\n/g, ' ').substring(0, 200)}`);

          // Capture screenshot before cleanup
          await captureDebugScreenshot(authPage, authSessionId, 'qr_not_visible');

          // Cleanup and fail
          if (browserInstance) {
            await destroyAuthContainer(authSessionId);
          }
          authSessionManager.updateAuthSession(authSessionId, { status: 'failed' });
          return;
        }

        // Extract and decode QR code
        const qrNavDuration = Date.now() - navStart;
        const qrData = await QRExtractor.extractQRCodeFromPage(authPage, authSessionId);
        authSessionManager.updateAuthSession(authSessionId, {
          qrCodeData: qrData.image,
          qrDecodedUrl: qrData.decodedUrl
        });

        if (qrData.image) {
          log.ok('AUTH', 'qr_generated', { session: authSessionId.substring(0, 8), duration: `${qrNavDuration}ms` });
        } else {
          log.fail('AUTH', 'qr_failed', { session: authSessionId.substring(0, 8), reason: qrData.error || 'no_image', duration: `${qrNavDuration}ms` });
        }
        console.log(`✅ QR code extracted for auth ${authSessionId.substring(0, 8)}...`);
        if (qrData.decodedUrl) {
          console.log(`🔗 QR URL validated: ${qrData.decodedUrl}`);
        }
        if (qrData.error) {
          console.log(`⚠️ QR extraction warning: ${qrData.error}`);
          await captureDebugScreenshot(authPage, authSessionId, 'qr_extraction_error');
        }

        // v2.5 phase-3 step-3: attach the in-page scan-watcher so we
        // get an early 'scan_detected' SSE event the moment TikTok
        // renders its "scanned, confirm on phone" indicator. The
        // watcher's selector candidates are placeholders; the real
        // selector gets discovered during Phase 4 PROD2 iteration via
        // debug-access DOM diff (see Scan-signal discovery section).
        // If the watcher fails to attach OR the placeholders don't
        // match the real DOM, auth still completes via URL detection
        // inside waitForLoginCompletion — this is a UX/telemetry win,
        // not a correctness gate.
        await attachScanWatcher(authPage, () => {
          authSessionManager!.emitScanDetected(authSessionId);
        });

        // Start polling for login completion
        await waitForLoginCompletion(authSessionId, authPage, preAuthToken);

      } catch (error: any) {
        console.error(`❌ Auth flow error for ${authSessionId}:`, error.message);
        authSessionManager.updateAuthSession(authSessionId, {
          status: 'failed'
        });

        // Release browser container
        if (browserInstance) {
          try {
            await destroyAuthContainer(authSessionId);
          } catch (releaseError) {
            console.error(`⚠️ Failed to release browser for ${authSessionId}`);
          }
        }
      }
    })();

    // Return immediately with authSessionId
    res.json({
      authSessionId,
      status: 'awaiting_scan'
    });

  } catch (error: any) {
    console.error('Auth start error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

async function waitForLoginCompletion(authSessionId: string, page: Page, preAuthToken?: string): Promise<void> {
  const timeout = 120000; // 2 minutes
  const startTime = Date.now();

  // v3-o: Track state for diagnostics
  const seenUrls = new Set<string>();
  const arrivedCookies = new Set<string>();
  const requiredCookies = ['sessionid', 'msToken', 'ttwid', 'sid_guard', 'uid_tt', 'sid_tt'];
  let lastHeartbeat = startTime;

  console.log(`⏳ Waiting for login completion for auth ${authSessionId.substring(0, 8)}...`);

  // v3-p: Set up real-time page state detection via MutationObserver
  let lastWarnings = new Set<string>();
  let pageStateChanged = false;
  let latestPageState: any = { hasQRCode: true };

  // Expose function for browser to notify us of changes
  await page.exposeFunction('onPageStateChange', (state: any) => {
    latestPageState = state;
    pageStateChanged = true;
  }).catch(() => {}); // Ignore if already exposed

  // Set up MutationObserver to detect changes immediately
  await page.evaluate(() => {
    const checkPageState = () => {
      // Real TikTok CAPTCHA selectors (researched from tiktok-captcha-solver)
      const hasCaptcha = !!(
        document.querySelector('#captcha_container') ||
        document.querySelector('#verify-ele') ||
        document.querySelector('#captcha-verify-image') ||
        document.querySelector('.captcha_verify_img_slide') ||
        document.querySelector('.secsdk-captcha-drag-icon')
      );

      const hasRecaptcha = !!document.querySelector('iframe[src*="recaptcha"]');

      // QR code presence (good sign if visible)
      const hasQRCode = !!(
        document.querySelector('canvas') ||
        document.querySelector('[class*="qr"]') ||
        document.querySelector('img[src*="qr"]')
      );

      // Error/expiry text detection
      const bodyText = document.body?.innerText?.toLowerCase() || '';
      const hasExpired = bodyText.includes('expired') || bodyText.includes('timed out') || bodyText.includes('scan again');
      const hasError = bodyText.includes('something went wrong') || bodyText.includes('try again later');
      const hasPhoneVerify = bodyText.includes('verify your phone') || bodyText.includes('verification code');

      return { hasCaptcha, hasRecaptcha, hasQRCode, hasExpired, hasError, hasPhoneVerify };
    };

    // Initial state
    (window as any).onPageStateChange(checkPageState());

    // Watch for DOM changes
    const observer = new MutationObserver(() => {
      (window as any).onPageStateChange(checkPageState());
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }).catch(() => {});

  while (Date.now() - startTime < timeout) {
    try {
      // 1. Track URL changes (truncate query strings)
      const fullUrl = page.url();
      const baseUrl = fullUrl.split('?')[0].substring(0, 80);
      if (!seenUrls.has(baseUrl)) {
        seenUrls.add(baseUrl);
        console.log(`📍 Auth ${authSessionId.substring(0, 8)} URL: ${baseUrl}`);

        // v3-s: Capture on URL transition away from QR page with 0 cookies
        // This is the "moment of silent rejection" - TikTok acknowledged scan but didn't auth
        if (!baseUrl.includes('/login/qrcode') && arrivedCookies.size === 0) {
          await captureDebugScreenshot(page, authSessionId, 'url_transition_no_cookies');
        }
      }

      // 2. Early CAPTCHA detection - fail fast, don't wait 2 minutes
      if (baseUrl.includes('google.com') || baseUrl.includes('captcha') || baseUrl.includes('recaptcha')) {
        console.error(`🚫 Auth ${authSessionId.substring(0, 8)} CAPTCHA detected - aborting`);
        authSessionManager!.updateAuthSession(authSessionId, { status: 'failed' });
        await destroyAuthContainer(authSessionId);
        return;
      }

      // 3. Get ALL cookies - requiredCookies check handles filtering (v3-t)
      const cookies = await page.context().cookies();
      const cookieNames = cookies.map(c => c.name);

      // 4. Progressive cookie logging - log each cookie as it arrives
      const prevSize = arrivedCookies.size;
      for (const name of requiredCookies) {
        if (cookieNames.includes(name) && !arrivedCookies.has(name)) {
          arrivedCookies.add(name);
          console.log(`🍪 Auth ${authSessionId.substring(0, 8)} cookie: ${name} (${arrivedCookies.size}/6)`);
        }
      }
      // T8: Log when cookies first arrive (threshold: sessionid present = auth success)
      if (prevSize === 0 && arrivedCookies.size > 0) {
        log.ok('AUTH', 'cookie_arrived', { session: authSessionId.substring(0, 8), count: arrivedCookies.size, elapsed_ms: Date.now() - startTime });
      }

      // 5. Check for page state changes (real-time via MutationObserver)
      if (pageStateChanged) {
        pageStateChanged = false;

        const currentWarnings = new Set<string>();
        if (latestPageState.hasCaptcha) currentWarnings.add('TIKTOK_CAPTCHA');
        if (latestPageState.hasRecaptcha) currentWarnings.add('RECAPTCHA');
        if (latestPageState.hasExpired) currentWarnings.add('QR_EXPIRED');
        if (latestPageState.hasError) currentWarnings.add('ERROR');
        if (latestPageState.hasPhoneVerify) currentWarnings.add('PHONE_VERIFY');
        if (!latestPageState.hasQRCode && arrivedCookies.size < 6) currentWarnings.add('QR_GONE');

        // Log any NEW warnings immediately
        for (const warning of currentWarnings) {
          if (!lastWarnings.has(warning)) {
            const elapsed = Math.round((Date.now() - startTime) / 1000);
            console.warn(`⚠️ Auth ${authSessionId.substring(0, 8)} [${warning}] at ${elapsed}s`);
            console.warn(`   URL: ${baseUrl}`);
            if (warning === 'TIKTOK_CAPTCHA' || warning === 'RECAPTCHA') {
              log.warn('AUTH', 'captcha_detected', { session: authSessionId.substring(0, 8), elapsed: `${elapsed}s` });
            } else if (warning === 'PHONE_VERIFY') {
              log.warn('AUTH', 'phone_verify', { session: authSessionId.substring(0, 8) });
            }

            // v3-s: Capture screenshot on first warning occurrence
            await captureDebugScreenshot(page, authSessionId, `warning_${warning.toLowerCase()}`);
          }
        }

        // Log if warning CLEARED (state improved)
        for (const warning of lastWarnings) {
          if (!currentWarnings.has(warning)) {
            const elapsed = Math.round((Date.now() - startTime) / 1000);
            console.log(`✓ Auth ${authSessionId.substring(0, 8)} [${warning}] cleared at ${elapsed}s`);
          }
        }

        lastWarnings = currentWarnings;
      }

      // 6a. PRIMARY: URL-based login detection (v3-u, matches v2.4 behavior)
      // If TikTok redirected away from login, user is authenticated
      const fullUrlForDetection = page.url();
      if (fullUrlForDetection.includes('/foryou') || fullUrlForDetection.includes('/home') ||
          (fullUrlForDetection.includes('tiktok.com') && !fullUrlForDetection.includes('/login') && !fullUrlForDetection.includes('/qrcode'))) {
        console.log(`✅ Auth ${authSessionId.substring(0, 8)} login detected via URL: ${fullUrlForDetection.substring(0, 60)}`);
        log.ok('AUTH', 'login_detected', { session: authSessionId.substring(0, 8), duration: `${Math.round((Date.now() - startTime) / 1000)}s`, cookie_count: arrivedCookies.size });

        // Extract session data
        const sessionData = await extractAuthData(page);

        authSessionManager!.updateAuthSession(authSessionId, {
          status: 'complete',
          sessionData
        });

        // TEE Integration: Encrypt and store via Xordi
        if (preAuthToken && sessionData) {
          await storeUserWithTEEEncryption(sessionData, preAuthToken, authSessionId);
        } else {
          if (sessionManager && sessionData) {
            const newSessionId = sessionManager.storeSession(sessionData);
            console.log(`💾 Session stored locally: ${newSessionId.substring(0, 8)}...`);
          }
        }

        try {
          await destroyAuthContainer(authSessionId);
          log.ok('AUTH', 'auth_cleanup', { session: authSessionId.substring(0, 8), outcome: 'success' });
        } catch (recycleError) {
          console.error(`⚠️ Failed to recycle auth container for ${authSessionId}`);
        }

        return;
      }

      // 6b. SECONDARY: Cookie-based detection (sessionid sufficient, like Nov 13 version)
      if (arrivedCookies.has('sessionid')) {
        console.log(`✅ Auth ${authSessionId.substring(0, 8)} login successful (sessionid cookie detected)`);
        log.ok('AUTH', 'login_detected', { session: authSessionId.substring(0, 8), duration: `${Math.round((Date.now() - startTime) / 1000)}s`, cookie_count: arrivedCookies.size });

        // Extract session data (cookies in plaintext - INSIDE TEE)
        const sessionData = await extractAuthData(page);

        authSessionManager!.updateAuthSession(authSessionId, {
          status: 'complete',
          sessionData
        });

        // TEE Integration: Encrypt and store via Xordi
        if (preAuthToken && sessionData) {
          await storeUserWithTEEEncryption(sessionData, preAuthToken, authSessionId);
        } else {
          // Legacy flow: Store session locally (fallback)
          if (sessionManager && sessionData) {
            const newSessionId = sessionManager.storeSession(sessionData);
            console.log(`💾 Session stored locally: ${newSessionId.substring(0, 8)}...`);
          }
        }

        // v19: Recycle auth container (cleared and returned to pool for next user)
        try {
          await destroyAuthContainer(authSessionId);
          log.ok('AUTH', 'auth_cleanup', { session: authSessionId.substring(0, 8), outcome: 'success' });
        } catch (recycleError) {
          console.error(`⚠️ Failed to recycle auth container for ${authSessionId}`);
        }

        return;
      }

      // 7. Heartbeat every 30 seconds - status update with diagnostics
      if (Date.now() - lastHeartbeat > 30000) {
        const elapsed = Math.round((Date.now() - startTime) / 1000);
        const warningStr = lastWarnings.size > 0 ? ` [${[...lastWarnings].join(', ')}]` : '';
        console.log(`💓 Auth ${authSessionId.substring(0, 8)} waiting... (${elapsed}s, ${arrivedCookies.size}/6 cookies, ${cookies.length} total)${warningStr}`);
        console.log(`   URL: ${baseUrl}`);
        lastHeartbeat = Date.now();
      }

      await new Promise(resolve => setTimeout(resolve, 3000));  // z-5a: reduced polling frequency

    } catch (error: any) {
      // 7. Log errors instead of silent swallow
      console.warn(`⚠️ Auth ${authSessionId.substring(0, 8)} poll error: ${error.message}`);

      // v3-t: Break if browser died, delay on other errors
      if (error.message.includes('closed')) break;
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  // 8. Timeout - diagnostics showing what we got
  console.log(`⏰ Auth ${authSessionId.substring(0, 8)} timeout after 120s`);
  console.log(`   URLs: ${[...seenUrls].join(' → ')}`);
  console.log(`   Cookies: [${[...arrivedCookies].join(', ') || 'none'}] (${arrivedCookies.size}/6)`);
  if (arrivedCookies.size < 6) {
    const missing = requiredCookies.filter(name => !arrivedCookies.has(name));
    console.log(`   Missing: [${missing.join(', ')}]`);
  }

  // v3-s: Capture screenshot at timeout to see final page state
  await captureDebugScreenshot(page, authSessionId, 'timeout_no_cookies');

  authSessionManager!.updateAuthSession(authSessionId, { status: 'failed' });

  // v19: Recycle timed-out auth container
  try {
    await destroyAuthContainer(authSessionId);
    log.ok('AUTH', 'auth_cleanup', { session: authSessionId.substring(0, 8), outcome: 'timeout' });
  } catch (recycleError) {
    console.error(`⚠️ Failed to recycle timed-out auth container for ${authSessionId}`);
  }
}

/**
 * Store user with TEE-encrypted cookies (Phase 2 + 3 of pre-auth flow)
 */
async function storeUserWithTEEEncryption(sessionData: SessionData, preAuthToken: string, authSessionId: string): Promise<void> {
  try {
    const xordiApiUrl = process.env.XORDI_API_URL || 'http://xordi-private-api:3001';
    const xordiApiKey = process.env.XORDI_API_KEY;

    if (!xordiApiKey) {
      log.fail('AUTH', 'tee_config_missing', { reason: 'XORDI_API_KEY not set' });
      return;
    }

    console.log('🔐 Encrypting cookies with TEE key...');

    // Guard: If DStack socket exists (production Phala CVM) but DStack failed to init, refuse to encrypt
    const dstackSocketExists = fs.existsSync('/var/run/dstack.sock');
    if (dstackSocketExists && !teeCrypto.isDStackKey()) {
      throw new Error('DStack socket present but key not initialized — refusing to encrypt with fallback key');
    }

    // Phase 2a: Encrypt cookies IN TEE (plaintext only exists in TEE memory)
    const teeEncryptedCookies = teeCrypto.encryptCookies(sessionData.cookies);

    console.log(`  Encrypted ${sessionData.cookies?.length || 0} cookies (${teeEncryptedCookies.length} chars)`);

    // Phase 2b: Store user with encrypted cookies in Xordi DB
    console.log('📤 Storing user with TEE-encrypted cookies in Xordi...');

    const storeResponse = await axios.post(
      `${xordiApiUrl}/api/enclave/store-user`,
      {
        pre_auth_token: preAuthToken,
        user: sessionData.user,
        tee_encrypted_cookies: teeEncryptedCookies,
        device_id: sessionData.tokens?.device_id || sessionData.device_id,
        install_id: sessionData.tokens?.install_id || sessionData.install_id
      },
      {
        headers: {
          'X-Api-Key': xordiApiKey,
          'Content-Type': 'application/json'
        }
      }
    );

    if (!storeResponse.data.success) {
      throw new Error('Xordi rejected user storage');
    }

    const secUserId = storeResponse.data.sec_user_id;
    console.log(`✅ User stored in Xordi: ${secUserId} (trust_level=0, encrypted cookies)`);

    // Phase 3: Escalate trust level after verification
    // In staging mode, skip trust_level update but still complete the auth flow (update qr_sessions, etc.)
    const isStaging = process.env.DEPLOY_ENV === 'staging';
    if (isStaging) {
      console.log('🔼 Completing auth flow (staging mode - skip trust escalation)...');
    } else {
      console.log('🔼 Escalating trust level...');
    }

    // Issue 6: Wrap escalate-trust in separate try-catch (don't re-throw)
    try {
      const escalateResponse = await axios.post(
        `${xordiApiUrl}/api/enclave/escalate-trust`,
        {
          sec_user_id: secUserId,
          pre_auth_token: preAuthToken,
          tokscope_session_id: authSessionId,
          skip_trust_update: isStaging  // Staging: complete flow without trust escalation
        },
        {
          headers: {
            'X-Api-Key': xordiApiKey,
            'Content-Type': 'application/json'
          }
        }
      );

      if (!escalateResponse.data.success) {
        console.warn('⚠️ Trust escalation failed, user remains at trust_level=0');
      } else {
        if (isStaging) {
          console.log(`✅ Auth flow completed (staging): ${secUserId} (trust_level=0)`);
        } else {
          console.log(`✅ Trust escalated: ${secUserId} → trust_level=2 (verified)`);
        }
      }
    } catch (escalateError: any) {
      // DON'T throw - user is already stored, escalation failure is non-fatal
      console.warn(`⚠️ Trust escalation error (user stored OK): ${escalateError.message}`);
    }

    // Store in local session manager for immediate use
    if (sessionManager) {
      sessionManager.storeSession(sessionData);
      console.log(`💾 Session also stored locally for immediate use`);
    }

  } catch (error: any) {
    console.error('❌ TEE encryption/storage failed:', error.message);
    throw error;
  }
}

async function extractAuthData(page: Page): Promise<SessionData> {
  console.log('🔍 Extracting authentication data...');
  return await BrowserAutomationClient.extractAuthData(page);
}

/**
 * v1.1.3login: Cookie-only detection loop for portal mode
 * CDP automation is read-only (no navigation/interaction) — human drives via Neko WebRTC
 * Polls page.context().cookies() every 3s for the required 6-cookie set
 */
async function waitForPortalLoginCompletion(
  authSessionId: string,
  page: Page,
  preAuthToken?: string,
  portalTimeoutMs: number = 300000
): Promise<void> {
  const startTime = Date.now();
  const requiredCookies = ['sessionid', 'msToken', 'ttwid', 'sid_guard', 'uid_tt', 'sid_tt'];
  const POLL_INTERVAL_MS = 3000;
  let pollCount = 0;

  console.log(`⏳ Portal mode: waiting for cookie arrival for auth ${authSessionId.substring(0, 8)}... (timeout: ${portalTimeoutMs}ms)`);

  while (Date.now() - startTime < portalTimeoutMs) {
    try {
      const cookies = await page.context().cookies();
      const cookieNames = new Set(cookies.map((c: any) => c.name));
      const foundRequired = requiredCookies.filter(name => cookieNames.has(name));

      if (foundRequired.length === requiredCookies.length) {
        console.log(`✅ Portal: all required cookies detected for ${authSessionId.substring(0, 8)}...`);

        // Extract full auth data and store with TEE encryption (same path as QR flow)
        let sessionData;
        try {
          sessionData = await extractAuthData(page);
        } catch (extractError: any) {
          console.error(`⚠️ Portal: extractAuthData failed: ${extractError.message}`);
          authSessionManager!.updateAuthSession(authSessionId, { status: 'failed' });
          stopPortalProxy();
          await destroyAuthContainer(authSessionId);
          return;
        }

        if (preAuthToken) {
          await storeUserWithTEEEncryption(sessionData, preAuthToken, authSessionId);
        }

        authSessionManager!.updateAuthSession(authSessionId, {
          status: 'complete',
          sessionData
        });

        // Destroy container
        stopPortalProxy();  // v1.1.3combo3: tear down VNC proxy
        await destroyAuthContainer(authSessionId);
        log.ok('AUTH', 'auth_complete', { session: authSessionId.substring(0, 8), mode: 'portal', duration: `${Date.now() - startTime}ms` });
        return;
      }

      // Log progress periodically (every ~30s)
      if (++pollCount % 10 === 0) {
        console.log(`⏳ Portal ${authSessionId.substring(0, 8)}: ${foundRequired.length}/${requiredCookies.length} cookies (${foundRequired.join(', ')})`);
      }

    } catch (pollError: any) {
      console.error(`⚠️ Portal cookie poll error for ${authSessionId.substring(0, 8)}: ${pollError.message}`);
    }

    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
  }

  // Timeout — clean up
  console.log(`⏰ Portal session timed out for ${authSessionId.substring(0, 8)}...`);
  log.fail('AUTH', 'auth_timeout', { session: authSessionId.substring(0, 8), mode: 'portal', duration: `${portalTimeoutMs}ms` });
  stopPortalProxy();  // v1.1.3combo3: tear down VNC proxy
  authSessionManager!.updateAuthSession(authSessionId, { status: 'failed' });
  await destroyAuthContainer(authSessionId);
}


appAuth.get('/auth/poll/:authSessionId', (req, res) => {
  try {
    const { authSessionId } = req.params;

    if (!authSessionManager) {
      return res.status(500).json({ error: 'Auth session manager not initialized' });
    }

    const authSession = authSessionManager.getAuthSession(authSessionId);
    if (!authSession) {
      return res.status(404).json({ error: 'Auth session not found' });
    }

    if (authSession.status === 'awaiting_scan') {
      // v1.1.3login: Include portalUrl in poll response when available (for borgcube to relay to 3P)
      const pollResponse: any = {
        status: 'awaiting_scan',
        qrCodeData: authSession.qrCodeData,
        qrDecodedUrl: authSession.qrDecodedUrl  // Include magic link
      };
      if (authSession.portalSessionUrl) {
        pollResponse.portalUrl = authSession.portalSessionUrl;
      }
      res.json(pollResponse);
    } else if (authSession.status === 'complete') {
      // v1.1.3login: Remove sessionData from complete response — borgcube never reads it
      // (verified: borgcube only reads qrCodeData/qrDecodedUrl, detects completion via auth_sessions DB)
      res.json({
        status: 'complete'
      });

      // Clean up auth session after successful poll
      authSessionManager.removeAuthSession(authSessionId);
    } else {
      res.json({
        status: 'failed'
      });

      // Clean up failed auth session
      authSessionManager.removeAuthSession(authSessionId);
    }

  } catch (error: any) {
    console.error('Auth poll error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

appAuth.post('/auth/destroy/:authSessionId', async (req, res) => {
  try {
    const { authSessionId } = req.params;
    if (!/^[a-f0-9\-]{36}$/.test(authSessionId)) {
      return res.status(400).json({ error: 'Invalid authSessionId format' });
    }
    await destroyAuthContainer(authSessionId);
    res.json({ ok: true });
  } catch (error: any) {
    console.error('Auth destroy error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * v1.1.3combo3: Auth portal endpoint — validates one-time token, redirects to noVNC.
 * Token is invalidated after first use (single-use enforcement).
 * VNC access is gated by TCP proxy lifecycle — no session = port 6080 not listening.
 */
appAuth.get('/auth/portal/:sessionToken', async (req, res) => {
  try {
    const { sessionToken } = req.params;

    // Validate token (unchanged from v1.1.3login)
    const tokenData = portalSessionTokens.get(sessionToken);
    if (!tokenData) {
      return res.status(404).json({ error: 'Portal session not found or expired' });
    }
    if (tokenData.used) {
      return res.status(403).json({ error: 'Portal session token already used — single-use enforcement' });
    }
    if (Date.now() > tokenData.expiresAt) {
      portalSessionTokens.delete(sessionToken);
      return res.status(403).json({ error: 'Portal session token expired' });
    }

    // Invalidate token immediately (single-use)
    tokenData.used = true;
    console.log(`🔑 Portal token validated for auth ${tokenData.authSessionId.substring(0, 8)}...`);

    // v1.1.3combo3: Redirect to noVNC (VNC-over-WebSocket) instead of Neko WebRTC
    // Port 6080 on tokscope-enclave is TCP-proxied to the browser container's websockify
    // R4/B3: Use gateway URL stored with the token (survives process restart)
    const dstackGateway = tokenData.gatewayUrl || process.env.DSTACK_GATEWAY_URL || lastKnownGatewayUrl;
    let noVncUrl: string;
    if (dstackGateway) {
      // Replace -3000. with -6080. in gateway URL
      noVncUrl = dstackGateway.replace(/-3000\./, '-6080.');
    } else {
      noVncUrl = `http://localhost:6080`;
    }

    // noVNC URL params: autoconnect=true skips the connect dialog, resize=scale fits viewport
    const redirectUrl = `${noVncUrl}/vnc.html?autoconnect=true&resize=scale`;

    // No Neko login needed — VNC has no auth (x11vnc -nopw)
    // No login locking needed — TCP proxy lifecycle IS the auth mechanism
    res.redirect(302, redirectUrl);

  } catch (error: any) {
    console.error('Auth portal error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Playwright-based sampling endpoints
appAuth.post('/playwright/foryoupage/sample/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { count = 10 } = req.body;

    if (!sessionManager) {
      return res.status(500).json({ error: 'Session manager not initialized' });
    }

    const sessionData = sessionManager.getSession(sessionId);
    if (!sessionData) {
      return res.status(404).json({ error: 'Session not found' });
    }

    const requestId = req.headers['x-queue-request-id'] as string || '';
    log.ok('AUTH', 'sample_started', { session: sessionId.substring(0, 8), request_id: requestId, type: 'foryoupage' });
    console.log(`🎯 Starting For You page sampling for session ${sessionId.substring(0, 8)}... (count: ${count})`);
    const sampleStart = Date.now();

    const { browser: browserInstance, cdpUrl } = await requestBrowserInstance(sessionId);

    try {
      const client = new BrowserAutomationClient(sessionData, { cdpUrl });
      await client.initialize();
      const videos = await client.sampleForYouFeed(count);

      const result = {
        success: true,
        videos,
        method: 'browser_automation',
        sampled_at: new Date().toISOString()
      };

      log.ok('AUTH', 'sample_complete', { session: sessionId.substring(0, 8), request_id: requestId, type: 'foryoupage', count: result.videos?.length || 0, duration: `${Date.now() - sampleStart}ms` });
      res.json(result);

    } finally {
      try { await browserInstance?.close(); } catch {}
      await releaseBrowserInstance(sessionId);
    }

  } catch (error: any) {
    console.error(`❌ Sampling error for ${req.params.sessionId}:`, error.message);
    log.fail('AUTH', 'sample_failed', { session: req.params.sessionId.substring(0, 8), request_id: req.headers['x-queue-request-id'] as string || '', type: 'foryoupage', error: error.message, duration: '0ms' });
    res.status(500).json({ error: error.message });
  }
});

appAuth.post('/playwright/watchhistory/sample/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { count = 10 } = req.body;

    if (!sessionManager) {
      return res.status(500).json({ error: 'Session manager not initialized' });
    }

    const sessionData = sessionManager.getSession(sessionId);
    if (!sessionData) {
      return res.status(404).json({ error: 'Session not found' });
    }

    console.log(`📜 Starting Watch History sampling for session ${sessionId.substring(0, 8)}... (count: ${count})`);

    const { browser: browserInstance, cdpUrl } = await requestBrowserInstance(sessionId);

    try {
      const client = new BrowserAutomationClient(sessionData, { cdpUrl });
      await client.initialize();
      const videos = await client.sampleWatchHistory(count);

      const result = {
        success: true,
        videos,
        method: 'browser_automation',
        sampled_at: new Date().toISOString()
      };

      console.log(`✅ Sampling completed: ${result.videos?.length || 0} videos`);
      res.json(result);

    } finally {
      try { await browserInstance?.close(); } catch {}
      await releaseBrowserInstance(sessionId);
    }

  } catch (error: any) {
    console.error(`❌ Sampling error for ${req.params.sessionId}:`, error.message);
    res.status(500).json({ error: error.message });
  }
});

// Module-based sampling endpoints (placeholder - not primary focus)
appAuth.post('/modules/foryoupage/sample/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { count = 10, module_type = 'web' } = req.body;

    if (!sessionManager) {
      return res.status(500).json({ error: 'Session manager not initialized' });
    }

    const sessionData = sessionManager.getSession(sessionId);
    if (!sessionData) {
      return res.status(404).json({ error: 'Session not found' });
    }

    console.log(`🎯 Starting For You page sampling (module-based) for session ${sessionId.substring(0, 8)}...`);

    let result;

    if (module_type === 'mobile') {
      console.log('📱 Using Mobile API module...');

      // Load proprietary mobile auth module
      if (!process.env.MOBILE_AUTH_MODULE_URL) {
        throw new Error('MOBILE_AUTH_MODULE_URL environment variable is required');
      }
      const mobileAuth = await moduleLoader.loadModuleFromUrl(process.env.MOBILE_AUTH_MODULE_URL);

      const client = new PublicApiClient(sessionData, mobileAuth);
      result = await client.sampleTimeline(count);
    } else {
      console.log('📡 Using Web API module...');

      // Load proprietary web auth module
      if (!process.env.WEB_AUTH_MODULE_URL) {
        throw new Error('WEB_AUTH_MODULE_URL environment variable is required');
      }
      const webAuth = await moduleLoader.loadModuleFromUrl(process.env.WEB_AUTH_MODULE_URL);

      const client = new WebApiClient(sessionData, webAuth);
      result = await client.getRecommendedFeed(count);
    }

    if (result.success && result.raw) {
      const itemList = result.raw.itemList || result.raw.aweme_list || [];
      console.log(`✅ Module sampling completed: ${itemList.length} videos (raw response)`);
    }
    res.json(result);

  } catch (error: any) {
    console.error(`❌ Module sampling error for ${req.params.sessionId}:`, error.message);
    res.status(500).json({ error: error.message });
  }
});

appAuth.post('/modules/watchhistory/sample/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { count = 10 } = req.body;

    if (!sessionManager) {
      return res.status(500).json({ error: 'Session manager not initialized' });
    }

    const sessionData = sessionManager.getSession(sessionId);
    if (!sessionData) {
      return res.status(404).json({ error: 'Session not found' });
    }

    console.log(`📺 Starting Watch History sampling (module-based) for session ${sessionId.substring(0, 8)}...`);

    // Load web auth module (for base config) and watch history module (for watch history specific methods)
    if (!process.env.WEB_AUTH_MODULE_URL) {
      throw new Error('WEB_AUTH_MODULE_URL environment variable is required');
    }
    if (!process.env.WATCH_HISTORY_MODULE_URL) {
      throw new Error('WATCH_HISTORY_MODULE_URL environment variable is required');
    }
    const webAuth = await moduleLoader.loadModuleFromUrl(process.env.WEB_AUTH_MODULE_URL);
    const watchHistoryAuth = await moduleLoader.loadModuleFromUrl(process.env.WATCH_HISTORY_MODULE_URL);

    // Combine modules: watch history methods override web auth where they exist
    // WebApiClient will use watchHistoryAuth.generateAuthHeaders for watch history requests
    const combinedAuth = { ...webAuth, ...watchHistoryAuth };

    const client = new WebApiClient(sessionData, combinedAuth as any);
    const result = await client.getWatchHistory(count);

    if (result.success && result.raw) {
      const itemList = result.raw.aweme_list || result.raw.itemList || [];
      console.log(`✅ Module sampling completed: ${itemList.length} videos (raw response)`);
    }
    res.json(result);

  } catch (error: any) {
    console.error(`❌ Module sampling error for ${req.params.sessionId}:`, error.message);
    res.status(500).json({ error: error.message });
  }
});

// Deprecated: Use /playwright/foryoupage/sample instead
appAuth.post('/scrape/:sessionId', async (req, res) => {
  console.log('⚠️  /scrape endpoint is deprecated, use /playwright/foryoupage/sample instead');
  res.status(410).json({
    error: 'Endpoint deprecated',
    message: 'Use /playwright/foryoupage/sample/:sessionId instead'
  });
});

// Container management endpoints
appAuth.post('/containers/create', async (req, res) => {
  try {
    const { proxy } = req.body;

    const response = await fetch(`${BROWSER_MANAGER_URL}/assign/temp-${Date.now()}`, {
      method: 'POST'
    });

    if (!response.ok) {
      throw new Error(`Failed to create container: ${response.statusText}`);
    }

    const data = await response.json();
    res.json({
      containerId: data.container.containerId,
      ip: data.container.ip,
      cdpUrl: data.container.cdpUrl,
      status: data.container.status
    });
  } catch (error: any) {
    console.error('Failed to create container:', error.message);
    res.status(500).json({ error: error.message });
  }
});

appAuth.delete('/containers/:containerId', async (req, res) => {
  try {
    const { containerId } = req.params;

    const response = await fetch(`${BROWSER_MANAGER_URL}/destroy/${containerId}`, {
      method: 'DELETE'
    });

    if (!response.ok) {
      throw new Error(`Failed to delete container: ${response.statusText}`);
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error('Failed to delete container:', error.message);
    res.status(500).json({ error: error.message });
  }
});

appAuth.get('/containers', async (req, res) => {
  try {
    const response = await fetch(`${BROWSER_MANAGER_URL}/stats`);

    if (!response.ok) {
      throw new Error(`Failed to get containers: ${response.statusText}`);
    }

    const stats = await response.json();
    res.json({
      total: stats.total,
      available: stats.available,
      assigned: stats.assigned,
      poolSize: stats.poolSize,  // z-1: Pass through poolSize for borgcube
      containers: []
    });
  } catch (error: any) {
    console.error('Failed to get containers:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// XORDI INTEGRATION ENDPOINTS
// Request Construction Outside, Signing Inside TEE
// ============================================================================

/**
 * Execute TikTok API request with authentication in TEE
 * - Receives pre-constructed request packet from Xordi (NO secrets)
 * - Retrieves TEE-encrypted cookies from Xordi DB
 * - Decrypts cookies in TEE
 * - Generates security headers via Python subprocess
 * - Executes signed request to TikTok
 * - Returns response (public video metadata)
 */
// v1.2.1.1.9 T1 / v2.5 phase-2 step-1: TEE-side inbound concurrency cap.
// Symmetric safety-net to xordi-api's outbound semaphore. Implementation
// extracted to lib/inbound-semaphore.ts; this file just calls
// tryAcquireInbound / releaseInbound.

appDataCustomer.post('/api/tiktok/execute', async (req, res) => {
  try {
    const { sec_user_id, wireguard_bucket, ipfoxy_session, request } = req.body;

    // 1. Verify Xordi API key
    const apiKey = req.header('X-Api-Key');
    const allowedKeys = (process.env.XORDI_API_KEY || '').split(',').filter(k => k);

    if (!apiKey || !allowedKeys.includes(apiKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    // ── v1.2.1.1.9 T1: inbound concurrency cap, fail-fast ───────────────────
    // Placed AFTER auth check (so bad keys don't consume slots) and BEFORE
    // the cookie-fetch + crypto work (so a slot is held only during real work).
    const acquireResult = tryAcquireInbound();
    if (!acquireResult.acquired) {
      return res.status(503).json({
        error: 'tee_busy',
        message: 'TEE inbound concurrency limit reached',
        retryable: true,
        retry_after_seconds: acquireResult.retryAfterSeconds,
      });
    }

    // ── v1.2.1.1.9 T2-min: cancellation propagation ─────────────────────────
    // v1.2.1.1.10 HOTFIX (2026-04-28): the original v1.2.1.1.9 plumbing was:
    //   req.on('close', () => { if (!res.writableEnded) ac.abort(); });
    // That fired prematurely on Express POSTs because IncomingMessage emits
    // 'close' once the request body stream is fully consumed by body-parsers,
    // BEFORE the response is sent. Result: every cookie axios.get aborted with
    // CanceledError ("canceled" in TEE logs), every /api/tiktok/execute returned
    // 500 'Failed to retrieve session data', watch_history at 0%.
    //
    // For now: keep the AbortController declaration (so signal: ac.signal stays
    // valid in the axios calls below — passing a never-aborted signal is a no-op
    // for axios). The cancellation feature is gone until we re-design with the
    // right event (likely res.on('close') with !writableEnded guard, but that
    // needs a verification cycle in this exact Node 18.20.8 / Express 4 / Phala
    // gateway stack before re-enabling).
    const ac = new AbortController();

    try {
    // 2. Validate endpoint against whitelist (Trust Enforcement)
    const ALLOWED_ENDPOINTS = {
      read_only: [
        '/aweme/v1/feed/',              // Mobile API: For You feed
        '/aweme/v1/user/',              // Mobile API: User profile
        '/aweme/v1/search/item/',       // Mobile API: Search
        '/api/recommend/item_list/',    // Web API: For You feed (working implementation)
        '/tiktok/watch/history/list/v1/' // Web API: Watch history (working implementation)
      ],
      authenticated: [
        '/aweme/v1/watch/history/'      // Mobile API: Watch history (experimental)
      ],
      write_operations: [
        '/aweme/v1/commit/item/digg/',  // Mobile API: Like video
        '/aweme/v1/commit/follow/user/' // Mobile API: Follow user
      ]
    };

    const allAllowed = [
      ...ALLOWED_ENDPOINTS.read_only,
      ...ALLOWED_ENDPOINTS.authenticated,
      ...ALLOWED_ENDPOINTS.write_operations
    ];

    // Extract base path (before query string) for whitelist check
    const baseEndpoint = request.endpoint.split('?')[0];

    if (!allAllowed.includes(baseEndpoint)) {
      return res.status(403).json({
        error: 'Endpoint not whitelisted',
        endpoint: baseEndpoint,
        message: 'Only pre-approved TikTok API endpoints are allowed'
      });
    }

    // 3. Get session data - try local session manager first, then Xordi DB
    let sessionData: any = null;
    let cookies: any[] = [];

    // Try local session manager first (for immediate post-auth use)
    const localSession = sessionManager?.getSession(sec_user_id);

    if (localSession && localSession.cookies) {
      sessionData = localSession;
      cookies = localSession.cookies;
    } else {
      // Retrieve TEE-encrypted cookies from Xordi DB

      const xordiApiUrl = process.env.XORDI_API_URL || 'http://xordi-private-api:3001';
      const xordiApiKey = process.env.XORDI_API_KEY;

      if (!xordiApiKey) {
        return res.status(500).json({ error: 'XORDI_API_KEY not configured' });
      }

      try {
        const cookiesResponse = await axios.get(
          `${xordiApiUrl}/api/enclave/get-encrypted-cookies/${sec_user_id}`,
          {
            headers: {
              'X-Api-Key': xordiApiKey
            },
            // v1.2.1.1.9 T2-min: propagate xordi-api abort to TEE-side cookie fetch.
            signal: ac.signal,
            // v1.2.1.1.9 T2-min Fix-1: explicit fail-fast timeout. Cookie fetch is a
            // single SELECT against tiktok_users; <100ms in practice. 15s is well
            // above legitimate variance, well below downstream bounds (xordi pool
            // 10s connect + 30s statement = 40s worst case; Phala gateway kill
            // ~43s; signal fires when xordi-api outer axios gives up at 45s).
            // Belt-and-suspenders against AUTH-FAILURE-ROOT-CAUSE.md RC#1.
            timeout: 15000
          }
        );

        if (!cookiesResponse.data.success) {
          throw new Error('Failed to retrieve encrypted cookies from Xordi');
        }

        // Decrypt cookies IN TEE (fallback handles pre-migration cookies)
        const encryptedHex = cookiesResponse.data.tee_encrypted_cookies;
        cookies = teeCrypto.decryptCookiesWithFallback(encryptedHex);

        // Build session data structure
        sessionData = {
          cookies,
          tokens: {
            device_id: cookiesResponse.data.device_id,
            install_id: cookiesResponse.data.install_id
          },
          user: {
            sec_user_id
          }
        };

      } catch (error: any) {
        console.error('Failed to retrieve/decrypt cookies:', error.message);
        return res.status(500).json({ error: 'Failed to retrieve session data' });
      }
    }

    if (!sessionData || !cookies || cookies.length === 0) {
      return res.status(404).json({ error: 'No session data available for user' });
    }

    // XORDI-V3-L FIX: Extract fresh msToken from decrypted cookies
    // Override any stale msToken that was baked into the request URL by DirectTikTokAPI
    const freshMsToken = cookies.find((c: any) => c.name === 'msToken')?.value || '';

    if (freshMsToken && request.endpoint) {
      try {
        const url = new URL(request.endpoint, 'https://www.tiktok.com');
        if (url.searchParams.has('msToken')) {
          const oldMsToken = url.searchParams.get('msToken');
          url.searchParams.set('msToken', freshMsToken);
          request.endpoint = url.pathname + url.search;
        }
      } catch (urlError) {
        // Could not parse endpoint as URL, skipping msToken injection
      }
    }

    // 4. Detect API type (web vs mobile)
    const apiType = request.apiType || 'mobile';
    const isWebApi = apiType === 'web';

    // 5. Extract cookies - different filtering for web vs mobile
    let cookieString = '';
    if (cookies && Array.isArray(cookies)) {
      if (isWebApi) {
        // Web API: Use all cookies
        cookieString = cookies.map((c: any) => `${c.name}=${c.value}`).join('; ');
      } else {
        // Mobile API: Filter to mobile-only cookies
        const mobileCookieNames = [
          'sessionid', 'sessionid_ss',
          'sid_guard', 'sid_tt',
          'uid_tt', 'uid_tt_ss',
          'msToken',
          'tt_chain_token',
          'sid_ucp_v1', 'ssid_ucp_v1',
          'store-idc', 'store-country-code', 'store-country-code-src',
          'tt-target-idc', 'tt-target-idc-sign',
          'cmpl_token', 'multi_sids',
          'tt_session_tlb_tag'
        ];
        const mobileCookieNameSet = new Set(mobileCookieNames);
        const filteredCookies = cookies.filter((c: any) => mobileCookieNameSet.has(c.name));
        cookieString = filteredCookies.map((c: any) => `${c.name}=${c.value}`).join('; ');
      }
    }

    // 6. Build headers based on API type
    let requestHeaders: any = {
      'Cookie': cookieString
    };

    if (isWebApi) {
      // Determine correct referer based on endpoint (matches v2.4 stable behavior)
      const isWatchHistory = request.endpoint.includes('/watch/history/');
      const referer = isWatchHistory
        ? 'https://www.tiktok.com/tpp/watch-history'
        : 'https://www.tiktok.com/foryou';

      // Web API: Browser headers matching working v2.4 implementation
      requestHeaders = {
        ...requestHeaders,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': referer,
        'Origin': 'https://www.tiktok.com',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
      };
    } else {
      // Mobile API: Generate security headers via Python subprocess
      const paramsString = new URLSearchParams(request.params).toString();
      const stub = request.body ? crypto.createHash('md5').update(request.body).digest('hex') : '';

      const headersResponse = await xordiSecurityModule.sendRequest('generateHeaders', {
        params: paramsString,
        cookies: cookieString,
        stub: stub,
        timestamp: Math.floor(Date.now() / 1000)
      });

      if (!headersResponse.success) {
        throw new Error('Failed to generate security headers');
      }

      requestHeaders = {
        ...requestHeaders,
        'X-Gorgon': headersResponse.headers['X-Gorgon'],
        'X-Khronos': headersResponse.headers['X-Khronos'],
        'X-Argus': headersResponse.headers['X-Argus'],
        'X-Ladon': headersResponse.headers['X-Ladon'],
        'User-Agent': `com.zhiliaoapp.musically/${request.params.manifest_version_code || '2023009040'} (Linux; U; Android ${request.params.os_version || '10'}; ${request.params.language || 'en'}_${request.params.region || 'US'}; ${request.params.device_type || 'SM-G973F'}; Build/QP1A.190711.020;tt-ok/3.12.13.4-tiktok)`
      };
    }

    // 7. Execute HTTP request to TikTok (FROM TEE)
    const baseUrl = isWebApi ? 'https://www.tiktok.com' : 'https://api16-normal-c-useast1a.tiktokv.com';

    // Proxy routing: IPFoxy (per-user sticky sessions) or WireGuard (bucket-based)
    const proxyMode = process.env.PROXY_MODE || 'wireguard';
    const disableWireguardRouting = process.env.DISABLE_WIREGUARD_ROUTING === 'true';
    let proxyAgent = null;

    if (proxyMode === 'ipfoxy') {
      if (!ipfoxy_session) {
        return res.status(400).json({ error: 'ipfoxy_session required when PROXY_MODE=ipfoxy' });
      }

      const account = process.env.IPFOXY_ACCOUNT;
      const password = process.env.IPFOXY_PASSWORD;
      const gateway = process.env.IPFOXY_GATEWAY || 'gate-us.ipfoxy.io:58688';

      const ipfoxyUser = `customer-${account}-cc-US-sessid-${ipfoxy_session}-ttl-60`;
      const socksProxy = `socks5://${ipfoxyUser}:${password}@${gateway}`;
      proxyAgent = new SocksProxyAgent(socksProxy);

    } else if (proxyMode === 'wireguard' && wireguard_bucket !== null && wireguard_bucket !== undefined) {
      // WireGuard buckets run on borgcube, connect via external SOCKS5
      const wgHost = process.env.WIREGUARD_HOST || '162.251.235.136';
      const wgBasePort = parseInt(process.env.WIREGUARD_BASE_PORT || '10800');
      const wgUser = process.env.WG_PROXY_USER;
      const wgPass = process.env.WG_PROXY_PASS;

      if (!wgUser || !wgPass) {
        console.error('❌ WG_PROXY_USER/WG_PROXY_PASS not configured');
        return res.status(500).json({ error: 'WireGuard credentials not configured' });
      }

      const port = wgBasePort + wireguard_bucket;
      const socksProxy = `socks5://${wgUser}:${wgPass}@${wgHost}:${port}`;
      proxyAgent = new SocksProxyAgent(socksProxy);

    } else {
      // Direct connection (no proxy)
    }

    // For web API, endpoint already has query string; for mobile API, use params
    const axiosConfig: any = {
      method: request.method,
      url: `${baseUrl}${request.endpoint}`,
      data: request.body,
      headers: requestHeaders,
      timeout: 15000
    };

    // Only add proxy agent if VPN routing is enabled
    if (proxyAgent) {
      axiosConfig.httpAgent = proxyAgent;
      axiosConfig.httpsAgent = proxyAgent;
    }

    // Only add params if not already in URL (mobile API uses params object)
    if (!isWebApi && request.params && Object.keys(request.params).length > 0) {
      axiosConfig.params = request.params;
    }

    // v1.2.1.1.9 T2-min: propagate xordi-api abort to TikTok call.
    // axiosConfig already has timeout: 15000; just add signal for cooperative abort.
    axiosConfig.signal = ac.signal;
    const tiktokResponse = await axios.request(axiosConfig);
    const responseData = tiktokResponse.data;

    // v1.2.1.1.5: surface TikTok-side errors before encryption. Without this,
    // non-zero status_code responses (rate-limit, bad params, expired session)
    // were silently encrypted into encrypted_watch_history as "successful"
    // pages with zero videos — masking real failures and polluting storage.
    const tiktokStatusCode = responseData?.status_code;
    if (typeof tiktokStatusCode === 'number' && tiktokStatusCode !== 0) {
      log.warn('TEE', 'tiktok_status_error', {
        status_code: tiktokStatusCode,
        status_msg: responseData?.status_msg || null,
        bucket: req.body?.wireguard_bucket,
      });
      return res.status(502).json({
        error: 'tiktok_status_error',
        tiktok_status_code: tiktokStatusCode,
        tiktok_status_msg: responseData?.status_msg || null,
      });
    }

    // 8. Return response — optionally encrypt if requested (v1.1.8)
    if (req.body.encrypt_response && teeCrypto.isWatchHistoryKeyReady()) {
      // Extract pagination metadata BEFORE encrypting (borgcube needs these for scrape loop)
      const hasMore = !!(responseData.has_more ?? responseData.hasMore);
      const cursor = responseData.cursor || responseData.max_cursor || null;
      // Encrypt the full response (video data + everything).
      // v1.1.9: async — delegated to worker_threads pool.
      const encryptedHex = await teeCrypto.encryptWatchHistory(responseData);
      // v1.2.1.1.4: include per-page video count as non-encrypted metadata so the
      // orchestrator can populate watch_history_sessions.unique_videos accurately.
      // v1.2.1.1.5: TikTok responses use multiple field names depending on endpoint
      // (aweme_list / itemList / videos). Match crypto-worker.js:91 fallback chain
      // — checking only aweme_list missed the data in many real responses.
      const videoArr = responseData?.aweme_list || responseData?.itemList || responseData?.videos;
      const videosCount = Array.isArray(videoArr) ? videoArr.length : 0;
      return res.json({
        encrypted: encryptedHex,
        has_more: hasMore,
        cursor: cursor,
        videos_count: videosCount,
      });
    } else if (req.body.encrypt_response && !teeCrypto.isWatchHistoryKeyReady()) {
      // encrypt_response requested but DStack key not available
      // In production (DStack socket exists but key failed): hard-fail 503
      // In dev/staging (no DStack at all): fall through to plaintext
      const dstackSocketExists = fs.existsSync('/var/run/dstack.sock');
      if (dstackSocketExists) {
        return res.status(503).json({ error: 'Watch history encryption key not initialized' });
      }
      log.warn('TEE', 'encrypt_response_no_dstack', { reason: 'returning_plaintext' });
    }
    // Default: return plaintext (normal path, or dev fallback when no DStack)
    res.json(tiktokResponse.data);

    } finally {
      // v1.2.1.1.9 T1: release the inbound slot. Fires on every body exit path
      // (success / 4xx / 5xx return / thrown error → outer catch). Integer
      // decrement is event-loop-atomic; cannot throw.
      releaseInbound();
    }

  } catch (error: any) {
    // v1.2.1.1.3 — capture safe diagnostic fields so we can distinguish where
    // the abort came from (TikTok RST vs proxy drop vs WG tunnel reset).
    // SAFE FIELDS ONLY — do NOT include error.config / error.request /
    // error.response (those carry cookies, X-Bogus, auth headers).
    log.error('TEE', 'tiktok_request_failed', {
      message: error.message,
      code: error.code,
      syscall: error.syscall,
      address: error.address,
      port: error.port,
      cause_code: error.cause?.code,
      cause_message: error.cause?.message,
      bucket: req.body?.wireguard_bucket,
    });
    res.status(500).json({
      error: error.message,
      code: error.code,
    });
  }
});

// ============================================================================
// WATCH HISTORY ENCRYPTION/DECRYPTION (v1.1.8)
// ============================================================================

/**
 * Decrypt TEE-encrypted watch history data
 * Called by borgcube when a 3P app requests watch history for an authorized user.
 * borgcube pre-authorizes the 3P app before proxying here.
 */
appDataCustomer.post('/api/enclave/decrypt-watch-history', async (req, res) => {
  try {
    // Auth: same XORDI_API_KEY as /api/tiktok/execute
    const apiKey = req.header('X-Api-Key');
    const allowedKeys = (process.env.XORDI_API_KEY || '').split(',').filter((k: string) => k);
    if (!apiKey || !allowedKeys.includes(apiKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    // Guard: watch history key must be DStack-derived (no fallback)
    if (!teeCrypto.isWatchHistoryKeyReady()) {
      return res.status(503).json({ error: 'Watch history decryption key not initialized (DStack required)' });
    }

    const { encrypted_data, audit_context } = req.body;
    if (!encrypted_data || typeof encrypted_data !== 'string') {
      return res.status(400).json({ error: 'encrypted_data (hex string) is required' });
    }

    // Decrypt (v1.1.9: async — worker_threads pool)
    const decrypted = await teeCrypto.decryptWatchHistory(encrypted_data);

    // Audit log (local)
    log.ok('TEE', 'watch_history_decrypted', {
      sec_user_id: audit_context?.sec_user_id,
      app_name: audit_context?.app_name,
      request_id: audit_context?.request_id,
    });

    // Fire-and-forget audit write-back to borgcube (if configured)
    const xordiApiUrl = process.env.XORDI_API_URL || process.env.BORGCUBE_API_URL;
    if (xordiApiUrl && audit_context) {
      axios.post(`${xordiApiUrl}/api/internal/write-audit-log`, {
        operation: 'decrypt_watch_history',
        sec_user_id: audit_context.sec_user_id,
        app_name: audit_context.app_name,
        request_id: audit_context.request_id,
        event_timestamp: new Date().toISOString(),
      }, {
        headers: { 'X-Api-Key': (process.env.XORDI_API_KEY || '').split(',')[0] || '' },
        timeout: 5000,
      }).catch((err: any) => {
        log.warn('TEE', 'audit_writeback_failed', { error: err.message });
      });
    }

    return res.json({ data: decrypted });

  } catch (error: any) {
    log.error('TEE', 'watch_history_decrypt_endpoint_fail', { error: error.message });
    return res.status(500).json({ error: error.message });
  }
});

/**
 * Decrypt all watch history for a user (v2 — TEE-pull architecture)
 * Instead of borgcube pushing encrypted blobs in the request body,
 * the TEE pulls them from borgcube using the manifest + page endpoints.
 * This avoids body size limits and reduces borgcube→TEE round-trips to one.
 */
appDataCustomer.post('/api/enclave/decrypt-watch-history-v2', async (req, res) => {
  try {
    // Auth
    const apiKey = req.header('X-Api-Key');
    const allowedKeys = (process.env.XORDI_API_KEY || '').split(',').filter((k: string) => k);
    if (!apiKey || !allowedKeys.includes(apiKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    // Guard: watch history key must be DStack-derived
    if (!teeCrypto.isWatchHistoryKeyReady()) {
      return res.status(503).json({ error: 'Watch history decryption key not initialized (DStack required)' });
    }

    const { sec_user_id, audit_context } = req.body;
    if (!sec_user_id) {
      return res.status(400).json({ error: 'sec_user_id is required' });
    }

    const xordiApiUrl = process.env.XORDI_API_URL || process.env.BORGCUBE_API_URL;
    const xordiApiKey = (process.env.XORDI_API_KEY || '').split(',')[0];
    if (!xordiApiUrl) {
      return res.status(500).json({ error: 'XORDI_API_URL not configured' });
    }

    // 1. Fetch manifest from borgcube
    // 30s absorbs xordi-api load variance; 10s was firing under contention.
    const manifestResp = await axios.get(
      `${xordiApiUrl}/api/enclave/get-encrypted-watch-history-manifest/${sec_user_id}`,
      { headers: { 'X-Api-Key': xordiApiKey }, timeout: 30000 }
    );

    if (!manifestResp.data?.pages?.length) {
      return res.json({ success: true, videos: [], total_count: 0, pages_decrypted: 0, pages_failed: 0 });
    }

    const pages = manifestResp.data.pages;
    log.ok('TEE', 'watch_history_v2_manifest', { sec_user_id, total_pages: pages.length });

    // 2. Fetch and decrypt pages in parallel batches of 10
    const BATCH_SIZE = 10;
    const allVideos: any[] = [];
    const seenIds = new Set<string>();
    let pagesFailed = 0;
    let totalRawVideos = 0;

    for (let i = 0; i < pages.length; i += BATCH_SIZE) {
      const batch = pages.slice(i, i + BATCH_SIZE);
      const results = await Promise.allSettled(
        batch.map((page: any) =>
          axios.get(
            `${xordiApiUrl}/api/enclave/get-encrypted-watch-history-page/${sec_user_id}/${page.id}`,
            { headers: { 'X-Api-Key': xordiApiKey }, timeout: 30000 }
          )
        )
      );

      // v1.2.0: collect successfully-fetched hexes, then do one batch
      // decrypt-and-dedup call so main thread pays O(1) structured-clone
      // cost instead of O(n pages). Fetch failures are still counted here
      // per-page to preserve the existing log.warn semantics.
      const hexesToDecrypt: string[] = [];
      for (const result of results) {
        if (result.status === 'rejected') {
          pagesFailed++;
          log.warn('TEE', 'watch_history_v2_page_fetch_failed', { error: (result as any).reason?.message });
          continue;
        }
        const encryptedHex = result.value.data?.encrypted_hex;
        if (!encryptedHex) {
          pagesFailed++;
          continue;
        }
        hexesToDecrypt.push(encryptedHex);
      }

      if (hexesToDecrypt.length > 0) {
        try {
          const batchResult = await teeCrypto.decryptAndDedupWatchHistory(
            hexesToDecrypt,
            Array.from(seenIds)
          );
          totalRawVideos += batchResult.totalRawVideos;
          pagesFailed += batchResult.pagesFailed;
          for (const id of batchResult.newlyAddedIds) seenIds.add(id);
          for (const v of batchResult.newVideos) allVideos.push(v);
        } catch (batchErr: any) {
          pagesFailed += hexesToDecrypt.length;
          log.error('TEE', 'watch_history_v2_batch_decrypt_fail', { error: batchErr.message });
        }
      }
    }

    // 3. Audit log
    log.ok('TEE', 'watch_history_v2_complete', {
      sec_user_id,
      pages_decrypted: pages.length - pagesFailed,
      pages_failed: pagesFailed,
      total_videos: allVideos.length,
      deduplicated_from: totalRawVideos,
    });

    // Fire-and-forget audit write-back
    if (xordiApiUrl && audit_context) {
      axios.post(`${xordiApiUrl}/api/internal/write-audit-log`, {
        operation: 'decrypt_watch_history_v2',
        sec_user_id: audit_context.sec_user_id || sec_user_id,
        app_name: audit_context.app_name,
        request_id: audit_context.request_id,
        event_timestamp: new Date().toISOString(),
      }, {
        headers: { 'X-Api-Key': xordiApiKey },
        timeout: 5000,
      }).catch((err: any) => {
        log.warn('TEE', 'audit_writeback_failed', { error: err.message });
      });
    }

    return res.json({
      success: true,
      videos: allVideos,
      total_count: allVideos.length,
      pages_decrypted: pages.length - pagesFailed,
      pages_failed: pagesFailed,
    });

  } catch (error: any) {
    log.error('TEE', 'watch_history_v2_endpoint_fail', { error: error.message });
    return res.status(500).json({ error: error.message });
  }
});

/**
 * Encrypt watch history data (for plaintext → encrypted migration)
 * Called by borgcube migration script to encrypt existing plaintext watch history.
 * Sunset after Phase 4a completes (all plaintext deleted).
 */
appDataBulk.post('/api/enclave/encrypt-watch-history', async (req, res) => {
  try {
    // Auth
    const apiKey = req.header('X-Api-Key');
    const allowedKeys = (process.env.XORDI_API_KEY || '').split(',').filter((k: string) => k);
    if (!apiKey || !allowedKeys.includes(apiKey)) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    // Guard: watch history key must be DStack-derived (no fallback)
    if (!teeCrypto.isWatchHistoryKeyReady()) {
      return res.status(503).json({ error: 'Watch history encryption key not initialized (DStack required)' });
    }

    const { data } = req.body;
    if (!data) {
      return res.status(400).json({ error: 'data field is required' });
    }

    // v1.1.9: async — worker_threads pool
    const encryptedHex = await teeCrypto.encryptWatchHistory(data);

    log.ok('TEE', 'watch_history_encrypted_for_migration', {
      data_size: JSON.stringify(data).length,
    });

    return res.json({ success: true, encrypted: encryptedHex });

  } catch (error: any) {
    log.error('TEE', 'watch_history_encrypt_endpoint_fail', { error: error.message });
    return res.status(500).json({ error: error.message });
  }
});

// ============================================================================

// ============================================================================
// MIGRATION ENDPOINT (v2.4 → perf branch cookie migration)
// ============================================================================

/**
 * Process ALL pending cookie migrations
 * Loops through all users with plaintext cookies, encrypts with TEE key,
 * stores in tee_encrypted_cookies, clears temp column.
 *
 * POST /migrate/process-pending
 * Requires X-Migration-Key header matching MIGRATION_TRIGGER_KEY env var
 */
appDataBulk.post('/migrate/process-pending', async (req, res) => {
  // Auth: require migration trigger key
  const triggerKey = req.header('X-Migration-Key');
  const expectedKey = process.env.MIGRATION_TRIGGER_KEY;

  if (!expectedKey || triggerKey !== expectedKey) {
    return res.status(401).json({ error: 'Invalid or missing X-Migration-Key' });
  }

  const xordiApiUrl = process.env.XORDI_API_URL || 'http://xordi-private-api:3001';
  const xordiApiKey = process.env.XORDI_API_KEY;

  if (!xordiApiKey) {
    return res.status(500).json({ error: 'XORDI_API_KEY not configured' });
  }

  // Guard: If DStack socket exists but DStack failed to init, refuse to encrypt
  const dstackSocketExists = fs.existsSync('/var/run/dstack.sock');
  if (dstackSocketExists && !teeCrypto.isDStackKey()) {
    return res.status(503).json({ error: 'DStack socket present but key not initialized' });
  }

  let totalSuccess = 0;
  let totalFailed = 0;
  let batchCount = 0;

  try {
    // Loop until no more pending users
    while (true) {
      batchCount++;

      // Get next batch of users (100 at a time)
      const pendingResponse = await axios.get(
        `${xordiApiUrl}/api/enclave/migrate/pending`,
        { headers: { 'X-Api-Key': xordiApiKey } }
      );

      const pendingUsers = pendingResponse.data.users || [];

      // Exit loop when no more pending
      if (pendingUsers.length === 0) {
        console.log(`✅ Migration complete after ${batchCount} batches`);
        break;
      }

      console.log(`🔄 Batch ${batchCount}: Processing ${pendingUsers.length} users...`);

      for (const user of pendingUsers) {
        try {
          // Parse plaintext cookies (already in array format)
          const cookies = user._migration_cookies_plaintext;

          // Encrypt with TEE key
          const encryptedHex = teeCrypto.encryptCookies(cookies);

          // Store encrypted cookies and clear temp column
          await axios.post(
            `${xordiApiUrl}/api/enclave/migrate/complete`,
            {
              sec_user_id: user.sec_user_id,
              tee_encrypted_cookies: encryptedHex
            },
            { headers: { 'X-Api-Key': xordiApiKey } }
          );

          totalSuccess++;
        } catch (err: any) {
          totalFailed++;
          console.error(`❌ ${user.sec_user_id}: ${err.message}`);
        }
      }

      console.log(`   Batch ${batchCount} done: ${totalSuccess} success, ${totalFailed} failed so far`);
    }

    res.json({
      success: true,
      processed: totalSuccess,
      failed: totalFailed,
      batches: batchCount
    });

  } catch (error: any) {
    console.error('Migration processing failed:', error.message);
    res.status(500).json({
      error: error.message,
      processed_before_error: totalSuccess,
      failed_before_error: totalFailed
    });
  }
});

/**
 * POST /migrate/verify-encryption
 * Classifies each user's cookies by which key can decrypt them.
 * Auth: X-Migration-Key header.
 */
appDataBulk.post('/migrate/verify-encryption', async (req, res) => {
  const triggerKey = req.header('X-Migration-Key');
  const expectedKey = process.env.MIGRATION_TRIGGER_KEY;

  if (!expectedKey || triggerKey !== expectedKey) {
    return res.status(401).json({ error: 'Invalid or missing X-Migration-Key' });
  }

  const xordiApiUrl = process.env.XORDI_API_URL || 'http://xordi-private-api:3001';
  const xordiApiKey = process.env.XORDI_API_KEY;

  if (!xordiApiKey) {
    return res.status(500).json({ error: 'XORDI_API_KEY not configured' });
  }

  let totalSampled = 0;
  let encryptedWithFallback = 0;
  let encryptedWithDstack = 0;
  let decryptionFailedBoth = 0;
  let offset = 0;

  try {
    while (true) {
      const response = await axios.get(
        `${xordiApiUrl}/api/enclave/migrate/all-encrypted-users?offset=${offset}`,
        { headers: { 'X-Api-Key': xordiApiKey } }
      );

      const users = response.data.users || [];
      if (users.length === 0) break;

      for (const user of users) {
        totalSampled++;
        const hex = user.tee_encrypted_cookies;

        if (teeCrypto.canDecryptWithFallback(hex)) {
          encryptedWithFallback++;
        } else {
          try {
            teeCrypto.decryptCookies(hex);
            encryptedWithDstack++;
          } catch (e) {
            decryptionFailedBoth++;
          }
        }
      }

      offset += users.length;
    }

    res.json({
      total_sampled: totalSampled,
      encrypted_with_fallback: encryptedWithFallback,
      encrypted_with_dstack: encryptedWithDstack,
      decryption_failed_both: decryptionFailedBoth,
      dstack_key_active: teeCrypto.isDStackKey()
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /migrate/upgrade-to-tee-key
 * Re-encrypts all fallback-encrypted cookies with the DStack-derived key.
 * Self-paginating: processes all users in batches of 50 internally.
 * Auth: X-Migration-Key header.
 * Precondition: DStack key must be active.
 */
appDataBulk.post('/migrate/upgrade-to-tee-key', async (req, res) => {
  const triggerKey = req.header('X-Migration-Key');
  const expectedKey = process.env.MIGRATION_TRIGGER_KEY;

  if (!expectedKey || triggerKey !== expectedKey) {
    return res.status(401).json({ error: 'Invalid or missing X-Migration-Key' });
  }

  if (!teeCrypto.isDStackKey()) {
    return res.status(503).json({ error: 'DStack key not initialized — cannot re-encrypt' });
  }

  const xordiApiUrl = process.env.XORDI_API_URL || 'http://xordi-private-api:3001';
  const xordiApiKey = process.env.XORDI_API_KEY;

  if (!xordiApiKey) {
    return res.status(500).json({ error: 'XORDI_API_KEY not configured' });
  }

  let totalProcessed = 0;
  let reEncrypted = 0;
  let alreadyDstack = 0;
  let failedBothKeys = 0;
  const failedUsers: string[] = [];
  let batchCount = 0;
  let offset = 0;

  try {
    while (true) {
      batchCount++;

      const response = await axios.get(
        `${xordiApiUrl}/api/enclave/migrate/all-encrypted-users?offset=${offset}`,
        { headers: { 'X-Api-Key': xordiApiKey } }
      );

      const users = response.data.users || [];
      if (users.length === 0) break;

      console.log(`🔄 Re-encryption batch ${batchCount}: ${users.length} users (offset ${offset})...`);

      for (const user of users) {
        totalProcessed++;
        const hex = user.tee_encrypted_cookies;

        try {
          // Try fallback key first
          if (teeCrypto.canDecryptWithFallback(hex)) {
            const plaintext = teeCrypto._decryptWithFallbackKey(hex);
            const reEncryptedHex = teeCrypto.encryptCookies(plaintext);

            await axios.post(
              `${xordiApiUrl}/api/enclave/migrate/complete`,
              { sec_user_id: user.sec_user_id, tee_encrypted_cookies: reEncryptedHex },
              { headers: { 'X-Api-Key': xordiApiKey } }
            );

            reEncrypted++;
          } else {
            // Try current (DStack) key — already migrated
            try {
              teeCrypto.decryptCookies(hex);
              alreadyDstack++;
            } catch (e) {
              failedBothKeys++;
              failedUsers.push(user.sec_user_id);
              console.error(`❌ ${user.sec_user_id}: both keys failed`);
            }
          }
        } catch (err: any) {
          failedBothKeys++;
          failedUsers.push(user.sec_user_id);
          console.error(`❌ ${user.sec_user_id}: ${err.message}`);
        }
      }

      offset += users.length;
      console.log(`   Batch ${batchCount}: ${reEncrypted} re-encrypted, ${alreadyDstack} already DStack, ${failedBothKeys} failed`);
    }

    res.json({
      total_processed: totalProcessed,
      re_encrypted: reEncrypted,
      already_dstack: alreadyDstack,
      failed_both_keys: failedBothKeys,
      failed_users: failedUsers,
      batches: batchCount
    });
  } catch (error: any) {
    console.error('Re-encryption failed:', error.message);
    res.status(500).json({
      error: error.message,
      total_processed: totalProcessed,
      re_encrypted: reEncrypted,
      already_dstack: alreadyDstack,
      failed_both_keys: failedBothKeys,
      failed_users: failedUsers
    });
  }
});

// ============================================================================
// TEE-TO-TEE MIGRATION ENDPOINTS
// ============================================================================

/**
 * POST /migrate/encrypt-incoming
 * Accepts plaintext cookies from the old TEE, encrypts with local DStack key.
 * Called by the old TEE during TEE-to-TEE migration.
 * Auth: X-Migration-Key header.
 * Precondition: DStack key must be initialized.
 */
appDataBulk.post('/migrate/encrypt-incoming', async (req, res) => {
  const triggerKey = req.header('X-Migration-Key');
  const expectedKey = process.env.MIGRATION_TRIGGER_KEY;

  if (!expectedKey || triggerKey !== expectedKey) {
    return res.status(401).json({ error: 'Invalid or missing X-Migration-Key' });
  }

  if (!teeCrypto.isDStackKey()) {
    return res.status(503).json({ error: 'DStack key not initialized' });
  }

  try {
    const { sec_user_id, cookies } = req.body;

    if (!sec_user_id || !cookies) {
      return res.status(400).json({ error: 'Missing sec_user_id or cookies' });
    }

    const encryptedHex = teeCrypto.encryptCookies(cookies);

    res.json({
      success: true,
      encrypted_hex: encryptedHex,
      sec_user_id
    });
  } catch (error: any) {
    console.error('encrypt-incoming failed:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /migrate/verify-decrypt
 * Accepts an encrypted hex blob, attempts decryption, returns success/failure.
 * Used by the old TEE to verify the new TEE can decrypt re-encrypted cookies.
 * Auth: X-Migration-Key header.
 * Precondition: DStack key must be initialized.
 */
appDataBulk.post('/migrate/verify-decrypt', async (req, res) => {
  const triggerKey = req.header('X-Migration-Key');
  const expectedKey = process.env.MIGRATION_TRIGGER_KEY;

  if (!expectedKey || triggerKey !== expectedKey) {
    return res.status(401).json({ error: 'Invalid or missing X-Migration-Key' });
  }

  if (!teeCrypto.isDStackKey()) {
    return res.status(503).json({ error: 'DStack key not initialized' });
  }

  try {
    const { encrypted_hex, sec_user_id } = req.body;

    if (!encrypted_hex || !sec_user_id) {
      return res.status(400).json({ error: 'Missing encrypted_hex or sec_user_id' });
    }

    try {
      teeCrypto.decryptCookies(encrypted_hex);
      res.json({ success: true, can_decrypt: true, sec_user_id });
    } catch (decryptError) {
      res.json({ success: true, can_decrypt: false, sec_user_id });
    }
  } catch (error: any) {
    console.error('verify-decrypt failed:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /migrate/tee-to-tee-single
 * Processes a single user: decrypts with old DStack key, sends plaintext to new TEE
 * for re-encryption, verifies both directions, returns result to Borgcube.
 * Auth: X-Migration-Key header.
 * Precondition: DStack key must be initialized.
 * Env required: MIGRATION_TARGET_TEE_URL, MIGRATION_TARGET_API_KEY
 */
appDataBulk.post('/migrate/tee-to-tee-single', async (req, res) => {
  const triggerKey = req.header('X-Migration-Key');
  const expectedKey = process.env.MIGRATION_TRIGGER_KEY;

  if (!expectedKey || triggerKey !== expectedKey) {
    return res.status(401).json({ error: 'Invalid or missing X-Migration-Key' });
  }

  if (!teeCrypto.isDStackKey()) {
    return res.status(503).json({ error: 'DStack key not initialized' });
  }

  const targetTeeUrl = process.env.MIGRATION_TARGET_TEE_URL;
  const targetApiKey = process.env.MIGRATION_TARGET_API_KEY;

  if (!targetTeeUrl || !targetApiKey) {
    return res.status(500).json({ error: 'MIGRATION_TARGET_TEE_URL or MIGRATION_TARGET_API_KEY not configured' });
  }

  try {
    const { sec_user_id, encrypted_hex } = req.body;

    if (!sec_user_id || !encrypted_hex) {
      return res.status(400).json({ error: 'Missing sec_user_id or encrypted_hex' });
    }

    // Step 1: Decrypt with old (local) DStack key
    let plaintext: any;
    try {
      plaintext = teeCrypto.decryptCookies(encrypted_hex);
    } catch (decryptError: any) {
      return res.json({
        success: false,
        sec_user_id,
        error: `Decryption failed with current key: ${decryptError.message}`
      });
    }

    // Step 2: Send plaintext to new TEE for re-encryption
    const encryptResponse = await axios.post(
      `${targetTeeUrl}/migrate/encrypt-incoming`,
      { sec_user_id, cookies: plaintext },
      {
        headers: { 'X-Migration-Key': targetApiKey },
        timeout: 30000
      }
    );

    if (!encryptResponse.data.success || !encryptResponse.data.encrypted_hex) {
      return res.json({
        success: false,
        sec_user_id,
        error: `New TEE encrypt-incoming failed: ${encryptResponse.data.error || 'no encrypted_hex returned'}`
      });
    }

    const newEncryptedHex = encryptResponse.data.encrypted_hex;

    // Step 3: Verify new TEE can decrypt the new blob
    const verifyResponse = await axios.post(
      `${targetTeeUrl}/migrate/verify-decrypt`,
      { sec_user_id, encrypted_hex: newEncryptedHex },
      {
        headers: { 'X-Migration-Key': targetApiKey },
        timeout: 30000
      }
    );

    const newTeeCanDecrypt = verifyResponse.data.can_decrypt === true;

    // Step 4: Verify old TEE CANNOT decrypt the new blob (key isolation)
    let oldTeeCannotDecrypt = false;
    try {
      teeCrypto.decryptCookies(newEncryptedHex);
      // If we get here, old TEE CAN decrypt — key isolation failed
      oldTeeCannotDecrypt = false;
    } catch (e) {
      // Expected: AES-GCM auth tag mismatch proves different keys
      oldTeeCannotDecrypt = true;
    }

    res.json({
      success: true,
      sec_user_id,
      new_encrypted_hex: newEncryptedHex,
      verification: {
        new_tee_can_decrypt: newTeeCanDecrypt,
        old_tee_cannot_decrypt: oldTeeCannotDecrypt
      }
    });
  } catch (error: any) {
    console.error(`tee-to-tee-single failed for ${req.body?.sec_user_id}:`, error.message);
    res.status(500).json({
      success: false,
      sec_user_id: req.body?.sec_user_id,
      error: error.message
    });
  }
});

// ============================================================================

const startTime = Date.now();

// v3-s: Debug screenshot endpoint (with API key auth)
appAuth.get('/debug/screenshot/:token', (req, res) => {
  if (process.env.ENABLE_DEBUG_SCREENSHOTS !== 'true') {
    return res.status(404).json({ error: 'Debug screenshots disabled' });
  }

  // Require API key auth
  const apiKey = req.header('X-Api-Key');
  const allowedKeys = (process.env.XORDI_API_KEY || '').split(',').filter((k: string) => k);
  if (!apiKey || !allowedKeys.includes(apiKey)) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  const { token } = req.params;
  const screenshot = debugScreenshots.get(token);

  if (!screenshot) {
    return res.status(404).json({ error: 'Screenshot not found or expired' });
  }

  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Content-Disposition',
    `inline; filename="debug-${screenshot.authSessionId.substring(0, 8)}-${screenshot.reason}.png"`);
  res.send(screenshot.buffer);
});

// v3-w: List all active debug screenshots
appAuth.get('/debug/screenshots', (req, res) => {
  if (process.env.ENABLE_DEBUG_SCREENSHOTS !== 'true') {
    return res.json({ enabled: false, count: 0, screenshots: [] });
  }

  // Require API key auth
  const apiKey = req.header('X-Api-Key');
  const allowedKeys = (process.env.XORDI_API_KEY || '').split(',').filter((k: string) => k);
  if (!apiKey || !allowedKeys.includes(apiKey)) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  const baseUrl = process.env.DEBUG_SCREENSHOT_BASE_URL
    || `${req.protocol}://${req.get('host')}`;
  const now = Date.now();

  const screenshots = Array.from(debugScreenshots.entries()).map(([token, ss]) => ({
    token,
    url: `${baseUrl}/debug/screenshot/${token}`,
    authSessionId: ss.authSessionId,
    step: ss.step,
    reason: ss.reason,
    pageUrl: ss.url,
    pageTitle: ss.title,
    timestamp: new Date(ss.timestamp).toISOString(),
    ageMs: now - ss.timestamp,
    expiresInMs: DEBUG_SCREENSHOT_TTL_MS - (now - ss.timestamp)
  }));

  res.json({
    enabled: true,
    ttlMs: DEBUG_SCREENSHOT_TTL_MS,
    count: screenshots.length,
    screenshots
  });
});

// z-4: Get all screenshots for a specific auth session
appAuth.get('/debug/screenshots/:authSessionId', (req, res) => {
  const apiKey = req.headers['x-api-key'] as string;
  const allowedKeys = (process.env.XORDI_API_KEY || '').split(',').filter((k: string) => k);
  if (!apiKey || !allowedKeys.includes(apiKey)) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  const { authSessionId } = req.params;
  const baseUrl = process.env.DEBUG_SCREENSHOT_BASE_URL
    || `${req.protocol}://${req.get('host')}`;

  const screenshots = Array.from(debugScreenshots.entries())
    .filter(([_, ss]) => ss.authSessionId === authSessionId)
    .sort((a, b) => a[1].step - b[1].step)
    .map(([token, ss]) => ({
      token,
      url: `${baseUrl}/debug/screenshot/${token}`,
      step: ss.step,
      reason: ss.reason,
      pageUrl: `${new URL(ss.url).hostname}${new URL(ss.url).pathname}`,
      timestamp: new Date(ss.timestamp).toISOString()
    }));

  res.json({ authSessionId, count: screenshots.length, screenshots });
});

app.get('/health', async (req, res) => {
  let bmHealthy = false;
  let bmPool = 0;
  try {
    const bmResp = await fetch(`${BROWSER_MANAGER_URL}/stats`, {
      signal: AbortSignal.timeout(3000)
    });
    if (bmResp.ok) {
      const stats = await bmResp.json() as any;
      bmHealthy = true;
      bmPool = stats.poolSize || 0;
    }
  } catch {}

  const status = bmHealthy ? 'healthy' : 'degraded';
  res.status(bmHealthy ? 200 : 503).json({
    status,
    browser_pool: bmHealthy ? bmPool : 0,
    instance_id: process.env.INSTANCE_ID || 'main',
    uptime: (Date.now() - startTime) / 1000,
    sessions: sessionManager?.getSessionCount() || 0,
    dstack: !!getDstackSDK(),
    dstackInitialized: !!getDstackSDK(),
    encryption: !!getEncryptionKey(),
    cookieEncryption: teeCrypto.isDStackKey() ? 'dstack' : 'fallback',
    watchHistoryEncryption: teeCrypto.isWatchHistoryKeyReady() ? 'dstack' : 'unavailable',
    timestamp: new Date().toISOString()
  });
});

// Readiness check - can accept requests
app.get('/ready', async (req, res) => {
  try {
    // Check if browser-manager is reachable and has capacity
    const bmUrl = process.env.BROWSER_MANAGER_URL || 'http://browser-manager:3001';
    const response = await axios.get(`${bmUrl}/stats`, { timeout: 5000 });

    const { available, total, authSlotsAvailable } = response.data;

    if (available > 0 || (authSlotsAvailable !== undefined && authSlotsAvailable > 0)) {
      res.json({
        status: 'ready',
        instance_id: process.env.INSTANCE_ID || 'main',
            capacity: {
          containers_available: available,
          containers_total: total,
          auth_slots_available: authSlotsAvailable
        }
      });
    } else {
      res.status(503).json({
        status: 'not_ready',
        reason: 'no_available_capacity',
        instance_id: process.env.INSTANCE_ID || 'main'
      });
    }
  } catch (error: any) {
    res.status(503).json({
      status: 'not_ready',
      reason: 'browser_manager_unavailable',
      error: error.message,
      instance_id: process.env.INSTANCE_ID || 'main'
    });
  }
});

// TEE identity + attestation data (public — no auth required)
app.get('/tee-info', async (req, res) => {
  try {
    const dstackSDK = getDstackSDK();
    if (!dstackSDK) {
      return res.status(503).json({ error: 'DStack not initialized' });
    }
    const info = await dstackSDK.info();
    res.json({
      app_id: info.app_id,
      instance_id: info.instance_id,
      compose_hash: info.compose_hash,
      tcb_info: info.tcb_info,
      dstack_sdk_version: (() => { try { return require('./package.json').dependencies['@phala/dstack-sdk']; } catch { return 'unknown'; } })(),
      // v1.2.1 — Which process answered: 'auth', 'data', or 'all' (legacy single-process).
      // Callers that pool both URLs can use this to verify they hit the intended process.
      mode: MODE
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to get TEE info', details: err.message });
  }
});

const PORT = process.env.PORT || 3000;

async function startServer(): Promise<void> {
  // v1.2.1 — initDStack is called in BOTH modes. Cookie + watch-history keys
  // are derived identically in both processes (DStack platform guarantees
  // deterministic key derivation per app_id). The data process needs the
  // watch-history key for crypto; the auth process technically doesn't use
  // it, but initDStack also sets the cookie key which cookie helpers rely on.
  // Keeping initDStack unconditional also keeps the startup contract simple.
  await initDStack();

  // v1.2.1 — Auth-only bootstrap: SessionManager, AuthSessionManager, the
  // enclave module loader, and the Xordi security module are all used only
  // by auth routes (browser orchestration, QR/portal flows, /scrape, etc).
  // Skipping them on the data process saves a few hundred ms of startup +
  // frees memory from unused state. If TOKSCOPE_MODE=all (legacy), these
  // still init because isAuth is true.
  if (isAuth) {
    sessionManager = new SessionManager();
    sessionManager.initialize();

    authSessionManager = new AuthSessionManager({
      // Pass destroyAuthContainer as a callback — the lib doesn't
      // know about browser-manager URLs; server.ts owns that.
      destroyContainer: destroyAuthContainer
    });
    // Auxiliary cleanup that used to be inline in removeAuthSession:
    // when a session is removed, drop its screenshot-step counter too.
    authSessionManager.on('session_removed', (authSessionId: string) => {
      authScreenshotSteps.delete(authSessionId);
    });

    // v2.5 phase-3 step-1: register the SSE event-stream endpoint.
    // Subscribes to AuthSessionManager events for a given authSessionId
    // and pushes them to the connected client. Today no auth-flow code
    // emits qr_ready / scan_detected / auth_complete / failed yet —
    // those wires get added in step 2. The endpoint is harmless until
    // emits arrive (just streams nothing).
    registerSseChannel(appAuth, authSessionManager);

    console.log('🔐 Auth session manager initialized');

    moduleLoader = new EnclaveModuleLoader();
    console.log('🔒 Proprietary module loader initialized');

    // Initialize Xordi security module (Python subprocess)
    await xordiSecurityModule.initialize();
    console.log('🔐 Xordi security module initialized');

    // Cleanup expired auth sessions periodically
    setInterval(async () => {
      try {
        await authSessionManager?.cleanupExpired();
      } catch (e: any) {
        console.error('Auth session cleanup failed:', e.message);
      }
    }, 60000); // Every minute
  }

  // v1.1.9: event-loop-lag monitor. Catches regressions of the v1.1.8 bug
  // where synchronous crypto on the main thread starved auth orchestration.
  // p99_ms > 50 over a 60s window is a red flag — investigate before it
  // cascades into auth failures. Uses perf_hooks.monitorEventLoopDelay for
  // an efficient kernel-level histogram (no setInterval polling overhead).
  try {
    const { monitorEventLoopDelay } = require('node:perf_hooks');
    const elDelay = monitorEventLoopDelay({ resolution: 20 });
    elDelay.enable();
    setInterval(() => {
      const p99 = Number((elDelay.percentile(99) / 1e6).toFixed(1));
      const max = Number((elDelay.max / 1e6).toFixed(1));
      log.ok('TEE', 'event_loop_lag', { p99_ms: p99, max_ms: max });
      elDelay.reset();
    }, 60_000).unref();
  } catch (e: any) {
    log.warn('TEE', 'event_loop_lag_init_failed', { err: e.message });
  }

  // T1: Heartbeat every 5 minutes
  setInterval(() => {
    const uptimeSec = Math.round((Date.now() - startTime) / 1000);
    const hours = Math.floor(uptimeSec / 3600);
    const mins = Math.floor((uptimeSec % 3600) / 60);
    const uptimeStr = `${hours}h${mins}m`;
    const bmStats = fetch(`${BROWSER_MANAGER_URL}/stats`).then(r => r.json()).catch(() => ({ total: 0, poolSize: 0, assigned: 0 }));
    bmStats.then((stats: any) => {
      log.ok('HEALTH', 'heartbeat', {
        uptime: uptimeStr,
        pool_total: stats.poolSize || stats.total || 0,
        pool_idle: (stats.poolSize || stats.total || 0) - (stats.assigned || 0),
        auth_active: sessionManager?.getSessionCount() || 0
      });
    }).catch(() => {});
  }, 5 * 60 * 1000);

  app.listen(PORT, () => {
    console.log(`🚀 Multi-User TCB Server running on port ${PORT}`);
    console.log(`📊 Session timeout: ${Math.round(3600000 / 60000)} minutes`);
    console.log(`🔐 Auth session timeout: ${Math.round(120000 / 1000)} seconds`);
    log.ok('HEALTH', 'startup_ok', { port: PORT, version: 'v1.1.3NX' });
  });
}

startServer().catch(console.error);