// File: tokscope-enclave/lib/scan-watcher.ts
//
// In-page MutationObserver that watches TikTok's QR login page for the
// "scanned, confirm on phone" DOM indicator and fires a single Node
// callback when it appears. The DOM update IS the contract — TikTok
// HAS to render the indicator visually for the user to see, so the
// indicator is by definition in the DOM regardless of whatever
// invisible mechanism TikTok uses internally (sealed polling, WS,
// WASM payload).
//
// The exact selector for TikTok's indicator is discovered during
// Phase 4 iteration via debug access on PROD2 (DOM diff before/after
// a real scan — see "Scan-signal discovery" section in
// RELEASE-v2.5.md). For the initial Phase 3 ship, this module uses
// best-guess candidates and fires on any match. A follow-up iteration
// replaces the placeholders with the real selector after a debug-
// access DOM diff.
//
// Robustness: scanWatcher emits 'scan_detected' as a UX/telemetry
// signal only — the canonical auth-complete signal is the URL
// transition / cookie arrival check (which lives in
// waitForLoginCompletion in server.ts). If the scan-detected signal
// breaks because TikTok changes its DOM, auth still completes via the
// URL detection — the user just doesn't get the early "scan detected"
// notification.
//
// This module's only responsibility: attach the observer + call back
// once when a candidate matches. It deliberately does NOT call
// updateAuthSession or interact with AuthSessionManager directly — it
// takes a callback so the caller can wire the emit however it wants.

import type { Page } from 'playwright';

export interface ScanWatcherOptions {
  /**
   * Set of placeholder selector candidates. The watcher fires on the
   * first match across all candidates. After Phase 4 DOM-diff
   * discovery, prune this list to the actual selector(s) TikTok uses.
   *
   * Default: a conservative best-guess set (text match for "Confirm on
   * your phone" + similar phrases). Override via `selectors:` if the
   * caller wants tighter control.
   */
  selectors?: ScanSelectorCandidate[];
}

export type ScanSelectorCandidate =
  | { kind: 'text'; substring: string; caseSensitive?: boolean }
  | { kind: 'querySelector'; selector: string };

const DEFAULT_CANDIDATES: ScanSelectorCandidate[] = [
  // Best-guess text matches. TikTok's exact copy is unknown until
  // Phase 4 discovery. These cover the obvious variants — most
  // login-confirmation flows surface phrasing similar to one of these.
  { kind: 'text', substring: 'Confirm on your phone', caseSensitive: false },
  { kind: 'text', substring: 'confirm in your phone', caseSensitive: false },
  { kind: 'text', substring: 'check your phone', caseSensitive: false },
  { kind: 'text', substring: 'open your phone', caseSensitive: false },
  // Some login flows label the post-scan state "scanned" with a
  // checkmark-style affordance.
  { kind: 'text', substring: 'scanned', caseSensitive: false },
];

/**
 * Attach the scan-watcher to a Playwright page. Calls `onScanDetected`
 * exactly once when any selector candidate matches in the page DOM.
 * Subsequent matches are ignored (the observer disconnects on first
 * match).
 *
 * Idempotent at the page level: if attachScanWatcher is called twice
 * on the same page (e.g. retry after a navigation), the in-page code
 * checks a flag and short-circuits.
 *
 * Errors during attach are swallowed and logged to the console — the
 * scan-watcher is best-effort, not a correctness gate. URL-based
 * auth-complete detection in waitForLoginCompletion is the
 * correctness layer.
 */
export async function attachScanWatcher(
  page: Page,
  onScanDetected: () => void,
  options: ScanWatcherOptions = {}
): Promise<void> {
  const candidates = options.selectors ?? DEFAULT_CANDIDATES;

  // 1. Expose a callback the in-page JS can invoke. Wrap the user's
  //    callback so an exception in onScanDetected doesn't propagate
  //    back into the browser context.
  try {
    await page.exposeFunction('__scanWatcherDetected', () => {
      try {
        onScanDetected();
      } catch (e) {
        // Swallow — calling code should log if it cares.
      }
    });
  } catch (e: any) {
    // If the function is already exposed (idempotent re-attach), the
    // call throws. That's fine — the existing exposure still works.
    if (!String(e?.message ?? '').includes('has been already registered')) {
      console.warn(`scan-watcher: exposeFunction failed: ${e.message}`);
      return;
    }
  }

  // 2. Inject the MutationObserver into the page. Runs in the browser
  //    context — the function body cannot reference Node types or
  //    closures. Pass selector candidates as the second arg so they
  //    serialize across.
  try {
    await page.evaluate((cands: ScanSelectorCandidate[]) => {
      // Idempotency guard: if a previous attach already installed the
      // watcher on this page, don't double-install.
      if ((window as any).__scanWatcherActive) return;
      (window as any).__scanWatcherActive = true;

      let fired = false;

      const matches = (): boolean => {
        const bodyText = document.body?.innerText ?? '';
        for (const c of cands) {
          if (c.kind === 'text') {
            const haystack = c.caseSensitive ? bodyText : bodyText.toLowerCase();
            const needle = c.caseSensitive ? c.substring : c.substring.toLowerCase();
            if (haystack.includes(needle)) return true;
          } else if (c.kind === 'querySelector') {
            try {
              if (document.querySelector(c.selector)) return true;
            } catch {
              // invalid selector; ignore
            }
          }
        }
        return false;
      };

      const fire = () => {
        if (fired) return;
        fired = true;
        observer.disconnect();
        const cb = (window as any).__scanWatcherDetected;
        if (typeof cb === 'function') cb();
      };

      const observer = new MutationObserver(() => {
        if (matches()) fire();
      });

      // Watch the whole body for any DOM change. Coarse but cheap on
      // a login page; if TikTok ships a heavily-mutating layout, we
      // could narrow to the QR container, but that requires knowing
      // its selector — same problem as the indicator.
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        characterData: true,
      });

      // Initial check in case the indicator is already in the DOM at
      // attach time (rare but possible if the QR was scanned before
      // we got the observer in).
      if (matches()) fire();
    }, candidates);
  } catch (e: any) {
    console.warn(`scan-watcher: evaluate failed: ${e.message}`);
  }
}
