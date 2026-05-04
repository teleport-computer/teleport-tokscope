// File: tokscope-enclave/lib/scan-watcher.ts
//
// Future home of the in-page MutationObserver that watches TikTok's QR
// page for the "scanned, confirm on phone" indicator. The DOM update IS
// the contract — see "Scan-signal discovery" in RELEASE-v2.5.md.
//
// Phase 3 (push-based auth) implements this with multiple selector
// candidates (text match, aria-live, common classes) and a
// page.exposeFunction('onScanDetected') hook. The actual selector for
// TikTok's indicator is discovered during Phase 4 iteration via debug
// access (DOM diff before/after a scan), so initial Phase 3 ships with
// best-guess candidates and a follow-up iteration replaces them.
//
// Also watches for: framenavigated to /foryou or /home (canonical
// auth-complete signal — correctness gate regardless of DOM detection),
// sessionid cookie arrival, captcha/expiry.
//
// Currently a placeholder.

export {};
