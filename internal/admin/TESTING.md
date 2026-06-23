# VeilGate Admin UI — End-to-End Testing Report

**Date:** 2026-06-23  
**Binary:** `/tmp/vg-e2e/admin` (built from `cmd/admin`, version `v1.1.6`)  
**Config:** `/tmp/vg-e2e/vg.yaml` with `persist.enabled=true`, `persist.path=/tmp/vg-e2e/events.db`  
**Seeded events:** 300 events via `cmd/seedtmp` (varied clients, paths, decisions, signals), then removed  
**Admin DB:** `/tmp/vg-e2e/admin.db`, flags `--user admin --pass test` (must_change=1)  
**Test server port:** `:18888`

---

## Summary Table

| Feature                        | Tested | Verdict |
|-------------------------------|--------|---------|
| Unauthenticated redirect       | Yes    | PASS    |
| Login wrong password           | Yes    | PASS    |
| Login correct password         | Yes    | PASS    |
| must_change gate               | Yes    | PASS    |
| Change password wrong current  | Yes    | PASS    |
| Change password mismatch       | Yes    | PASS    |
| Change password success        | Yes    | PASS    |
| Old/new password after change  | Yes    | PASS    |
| Logout + session destroy       | Yes    | PASS    |
| GET /logout after logout       | Yes    | PASS    |
| Forgot password (no enum)      | Yes    | PASS    |
| Forgot password (known user)   | Yes    | PASS    |
| Reset password valid token     | Yes    | PASS    |
| Reset password mismatch        | Yes    | PASS    |
| Reset password short password  | Yes    | PASS (defaults to short-error branch) |
| Reset password success         | Yes    | PASS    |
| Reset password token reuse     | Yes    | PASS    |
| Reset password invalid token   | Yes    | PASS    |
| Dashboard loads                | Yes    | PASS    |
| Dashboard flash param          | Yes    | PASS    |
| Analytics all ranges (1h/7d/30d/24h/bad) | Yes | PASS |
| Analytics partial fragment     | Yes    | PASS    |
| Analytics SVG charts (seeded)  | Yes    | PASS (25 SVGs) |
| Decoys GET                     | Yes    | PASS    |
| Decoys add                     | Yes    | PASS    |
| Decoys catchall serve          | Yes    | PASS (Server: nginx) |
| Decoys delete                  | Yes    | PASS    |
| Decoys reset                   | Yes    | PASS    |
| Settings GET                   | Yes    | PASS    |
| Settings tab=persistence       | Yes    | PASS    |
| Settings tab=detector          | Yes    | PASS    |
| Settings POST save             | Yes    | PASS (config-pending banner) |
| Signals page                   | Yes    | PASS    |
| Rules page                     | Yes    | PASS (56 files listed) |
| Rules specific file            | Yes    | PASS    |
| OpenAPI page                   | Yes    | PASS    |
| Audit log page                 | Yes    | PASS (28 entries) |
| Request logs page              | Yes    | PASS (seeded events shown) |
| Recommender page               | Yes    | PASS    |
| API login correct              | Yes    | PASS    |
| API login wrong                | Yes    | PASS (401) |
| API config with session        | Yes    | PASS    |
| API config without session     | Yes    | PASS (401) |
| GET /login when authenticated  | Yes    | PASS (302 → /dashboard) |
| Static assets                  | Yes    | PASS    |
| Unknown path → 404             | Yes    | PASS    |
| API config after logout        | Yes    | PASS (401) |
| Decoy path /wp-login.php       | Yes    | PASS (200, Server: nginx) |
| Decoy path /.env               | Yes    | PASS (403) |

---

## Feature-by-Feature Evidence

### 1. Auth Flows

**What was tested:** Full login/logout cycle, wrong credentials, must_change gate, session persistence.

**Method:** `curl` with `-c`/`-b` cookie files, `-L` follow redirects, `-w "%{http_code}"`.

**Evidence:**

```
GET /dashboard (unauth)          → 302  Location: /login?next=/dashboard
POST /login  wrong password      → 200  body: "Invalid username or password."
POST /login  admin/test          → 303  Location: /dashboard
GET /dashboard after login       → 302  Location: /account/password  (must_change=1)
GET /settings after login        → 302  Location: /account/password  (must_change=1)
POST /account/password (wrong)   → 200  body: "current password is incorrect"
POST /account/password (mismatch)→ 200  body: "New passwords do not match."
POST /account/password (success) → 303  Location: /dashboard?flash=password_changed
GET /dashboard after PW change   → 200
POST /login old password         → 200  (failure flash — must_change cleared, old PW invalid)
POST /login new password         → 303  Location: /dashboard
GET /logout                      → 303  Location: /login
GET /dashboard after logout      → 302  Location: /login
GET /logout after logout         → 303  (no crash)
```

**Findings:** must_change gate works correctly — all protected routes redirect to /account/password. After successful change, must_change=0 is set and the old password is rejected.

---

### 2. Forgot / Reset Password

**What was tested:** GET /forgot-password, POST with unknown/known username, reset token flow.

**Method:** `curl` forms + direct DB query via Go helper to extract token.

**Evidence:**

```
GET /forgot-password                    → 200
POST /forgot-password unknownuser99999  → 200  body: "If that account exists, a reset link has been printed to the server log."
POST /forgot-password admin             → 200  body: same (no enumeration)
server log: "🔑 PASSWORD RESET for "admin" — link (expires 1h): /reset-password?token=<hex>"
GET /reset-password?token=badtoken123  → 200  body: "invalid or expired reset link"
GET /reset-password?token=<valid>      → 200  body contains "admin" (username shown)
POST /reset-password mismatch           → 200  body: "Passwords do not match."
POST /reset-password success            → 200  body: "Password updated successfully."
POST /reset-password same token again   → 200  body: "this reset link has already been used"
```

**Findings:** No username enumeration — both known and unknown usernames receive the same success message. Reset tokens are single-use and persist in `reset_tokens` table. Token is delivered via server log only (no SMTP), which is by design.

---

### 3. Dashboard

**What was tested:** Page load, stat cards, flash param, analytics section with seeded data.

**Method:** Authenticated curl, body grep for structure.

**Evidence:**

```
GET /dashboard                       → 200
GET /dashboard?flash=password_changed → 200  (no crash)
body: contains Analytics sidebar link, stat cards
persist.enabled=true + 300 seeded events → analytics cells show numbers > 0
```

**Findings:** Dashboard loads correctly with seeded event store. Flash query parameter is handled gracefully.

---

### 4. Analytics Page

**What was tested:** All time ranges, partial fragment mode, SVG chart presence with seeded data.

**Method:** Authenticated curl; grepped for `<html`, `analytics-live`, `<svg`, `<rect`.

**Evidence:**

```
GET /analytics              → 200
GET /analytics?range=1h     → 200
GET /analytics?range=7d     → 200
GET /analytics?range=30d    → 200
GET /analytics?range=bad    → 200  (gracefully defaults to 24h)
GET /analytics?range=24h&partial=1 → 200
  - <html> tag count: 0  ✓ (fragment only)
  - analytics-live div count: 1  ✓
  - first chars: <div id="analytics-live" hx-get="/analytics?range=24h&partial=1" ...
SVG count (full page): 25
<rect elements: 9  (bar chart bars present from seeded events)
```

**Findings:** Partial fragment correctly omits `<html>` wrapper and starts with the HTMX-target div. Invalid range defaults gracefully. 25 SVG elements confirm charts are populated from the 300-event seeded store.

**Screenshot:** `/tmp/vg-e2e/screenshots/ss_analytics.png`

---

### 5. Decoy Endpoints

**What was tested:** Listing, adding, catchall serving, deletion, reset-to-defaults.

**Method:** Authenticated curl for admin actions; unauthenticated curl to probe decoy paths.

**Evidence:**

```
GET /decoys                                    → 200  (default table shown)
POST /decoys _action=add path=/test-decoy kind=login → 200  "Decoy added — live immediately"
GET /test-decoy (no auth)                      → 200  Server: nginx  body: "Log In" fake login
GET /wp-login.php                              → 200  Server: nginx  (default decoy)
GET /.env                                      → 403  (default decoy, decoyForbidden kind)
POST /decoys _action=delete path=/test-decoy   → 200  "Decoy removed."
GET /test-decoy after delete                   → 404  (generic nginx 404)
POST /decoys _action=reset                     → 200  "Restored the default decoy set."
```

**Findings:** Decoy server correctly impersonates nginx (`Server: nginx` header). The decoy store is live-editable with no restart required. Catchall path matching works for exact paths. Reset restores the full curated default set.

**Screenshot:** `/tmp/vg-e2e/screenshots/ss_decoys.png`

---

### 6. Settings

**What was tested:** GET with various tabs, POST save with valid form data.

**Method:** Authenticated curl; response body grep for tab/banner indicators.

**Evidence:**

```
GET /settings                     → 200  tabs visible in sidebar
GET /settings?tab=persistence     → 200
GET /settings?tab=detector        → 200
POST /settings (mode=monitor...)  → 200  body: "restart-banner" + "Settings saved"
  Response includes: <div class="restart-banner">Proxy restart required...
```

**Findings:** Settings save writes to vg.yaml and sets `configPending=true`, which triggers the restart banner. The YAML patch system preserves existing fields.

**Screenshot:** `/tmp/vg-e2e/screenshots/ss_settings.png`

---

### 7. Signals

**What was tested:** Page loads with signal table.

**Evidence:**
```
GET /signals → 200  title: "Detection Signals"
```

**Screenshot:** `/tmp/vg-e2e/screenshots/ss_signals.png`

---

### 8. Rules

**What was tested:** Page loads, file listing, individual file access.

**Evidence:**
```
GET /rules                          → 200  (56 files listed from ~/.veilgate/rules)
GET /rules/detector/config.yaml    → 200  (specific file served)
File listing includes: signals.yaml, detector/config.yaml, ml.yaml, challenge.yaml, etc.
```

**Findings:** Rules directory is the user's `~/.veilgate/rules`. 56 YAML files are listed. Individual file edit pages return 200.

---

### 9. OpenAPI

**What was tested:** Page loads.

**Evidence:**
```
GET /openapi → 200  title: "OpenAPI Blueprint"
```

**Screenshot:** `/tmp/vg-e2e/screenshots/ss_openapi.png`

---

### 10. Audit Log

**What was tested:** Page loads, audit entries populated after operations.

**Evidence:**
```
GET /audit → 200  title: "Audit Log"
GET /api/v1/audit/stats → {
  "Total": 28, "Failures": 9, "Logins": 11, "ConfigSaves": 1
}
Audit actions observed: login, logout, settings.save, decoy.add, decoy.delete,
  decoy.reset, account.password_change, account.forgot_password
```

**Findings:** 28 audit entries accumulated from all E2E operations. Failed logins are logged with `ok=false`. Both successful and failed auth attempts are audited.

**Screenshot:** `/tmp/vg-e2e/screenshots/ss_audit.png`

---

### 11. Request Logs

**What was tested:** Page loads, seeded event store entries shown.

**Evidence:**
```
GET /logs → 200  title: "Request Logs"
body contains:
  - "from event store" pill (source indicator)
  - "challenge" pill (from seeded events)
  - score values (50, 79, etc. from seeded events)
```

**Findings:** Request logs page correctly reads from the seeded events.db. Decisions (allow/challenge/tarpit/block) and scores from the 300 seeded events are displayed.

**Screenshot:** `/tmp/vg-e2e/screenshots/ss_logs.png`

---

### 12. Recommender

**What was tested:** Page loads.

**Evidence:**
```
GET /recommender → 200  title: "Recommender"
```

**Findings:** Recommender page renders without error. Seeded data may not have generated sufficient rollup deltas for signal suggestions (seeded via direct INSERT, not via the live flusher's RollupDelta path).

**Screenshot:** `/tmp/vg-e2e/screenshots/ss_recommender.png`

---

### 13. API Endpoints

**What was tested:** Login, wrong credentials, config with/without session, health, audit, status, rules.

**Evidence:**
```
POST /api/v1/auth/login (correct)      → 200  {"ok": true, "username": "admin"}
POST /api/v1/auth/login (wrong)        → 401  {"error": "invalid username or password", "code": "INVALID_CREDENTIALS"}
GET  /api/v1/config (with session)     → 200  {"config": {...}, "pending_restart": ...}
GET  /api/v1/config (no session)       → 401  {"error": "authentication required", "code": "UNAUTHENTICATED"}
GET  /api/v1/config (after logout)     → 401
GET  /api/v1/health                    → 200  {"status": "ok", "version": "v1.1.6"}
GET  /api/v1/audit/stats               → 200  {"Total": 28, "Failures": 9, "Logins": 11, ...}
GET  /api/v1/status                    → 200  {"version": "v1.1.6", "auth_enabled": true}
GET  /api/v1/rules                     → 200  {"files": [...56 files...]}
```

**Findings:** API correctly returns JSON 401 (not redirect) for unauthenticated requests. Health endpoint is public. Session is invalidated on logout.

---

### 14. Security / Edge Cases

**What was tested:** Already-logged-in redirect, static assets, unknown paths, decoy paths.

**Evidence:**
```
GET /login (while authenticated)    → 302  Location: /dashboard  (no infinite loop)
GET /static/css/app.css             → 200
GET /nonexistent-path-xyz           → 404  (generic nginx 404, no info leak)
GET /wp-login.php                   → 200  Server: nginx  (decoy match)
GET /.env                           → 403  Server: nginx  (decoy match)
GET /api/v1/config after logout     → 401
```

**Findings:** The catch-all handler correctly serves decoy responses for known probe paths and returns a generic 404 for unknown paths, both spoofing nginx. No paths reveal the VeilGate admin identity. Static assets are served directly without auth.

---

## Go Test File Coverage Summary

File: `internal/admin/admin_test.go`  
Package: `admin_test`  
Tests: 23 (all PASS, 10.2s)

| Test | Coverage |
|------|----------|
| TestAuth_UnauthRedirect | Unauthed GET → 302 /login |
| TestAuth_LoginWrongPassword | Wrong creds → 200 + error flash |
| TestAuth_LoginSuccess | Correct creds → 303 /dashboard |
| TestAuth_SessionPersists | Session cookie persists across requests |
| TestAuth_LogoutDestroysSession | Logout → 303 /login; cookie invalidated |
| TestAuth_MustChangeGate | Fresh DB → login → GET /dashboard → 302 /account/password |
| TestChangePassword_WrongCurrent | Wrong current → 200 + error |
| TestChangePassword_Mismatch | Mismatched confirm → 200 + error |
| TestChangePassword_Success | Success → 303 /dashboard; new pass works |
| TestForgotPassword_UnknownUser | No enumeration; same 200 success message |
| TestForgotPassword_KnownUser | Token stored in DB |
| TestResetPassword_InvalidToken | Invalid token → 200 + error |
| TestResetPassword_Success | Valid token → password updated |
| TestResetPassword_TokenReuse | Used token → "already been used" error |
| TestAnalytics_Unauthenticated | Unauthed → 302 |
| TestAnalytics_Range | 1h, 7d, 30d, 24h, bad → all 200 |
| TestAnalytics_PartialFragment | partial=1 → no `<html>`, has analytics-live div |
| TestDecoys_AddDeleteReset | Add/delete/reset decoys via form POST |
| TestDecoys_ServeMatchingPath | /wp-login.php → 200 fake login; /.env → 403 |
| TestStaticAssets | /static/css/app.css → 200 |
| TestAPI_LoginFlow | api/v1/auth/login correct/wrong + /api/v1/health |
| TestAPI_ConfigRequiresAuth | No session → 401; with session → 200 |
| TestDashboard_Loads | 200 + content + flash param no crash |

---

## How to Run

```bash
go test ./internal/admin/ -v -timeout 120s
```

Or for a specific test:

```bash
go test ./internal/admin/ -run TestAuth_MustChangeGate -v
```

---

## Known Limitations / What Was NOT Tested

1. **POST /analytics** — analytics endpoint only supports GET; POST returns 200 (template renders). No explicit 405 test was added as the handler doesn't enforce method.
2. **API /api/v1/config PUT** — tested via curl with valid JSON; Go test coverage omitted to keep test size manageable.
3. **API /api/v1/rules PUT/DELETE** — rule file editing via API exercised via curl only.
4. **OpenAPI import via UI** — file upload form not tested via curl (multipart); API endpoint tested.
5. **Signals save via UI/API** — signals.yaml PUT not exercised.
6. **Token expiry** — reset token 1-hour expiry not tested (would require time manipulation).
7. **Concurrent sessions** — only single-session tests were run.
8. **Theme cookie** — dark/light theme switching not tested.
9. **Tarpit delay on decoys** — decoy responses include a 200-900ms random delay; E2E tests use curl which waits, but the delay is observable.
10. **Admin persistence disabled** — the `persist.enabled=false` case for analytics "store off" state is covered by the unit tests (which use a fresh config with no events.db) but not explicitly by a dedicated E2E curl test.
11. **Screenshot fidelity** — screenshots captured from local HTML files with `<base href>` injection, so CSS/JS from the live server loads (Chrome fetches static assets from the live server during screenshot). HTMX polling requests are not triggered in the static HTML capture.
12. **Settings write note** — the POST /settings test wrote a modified vg.yaml (persist.enabled=false, listen=:8080, upstream=http://localhost:3000). The original config at `/tmp/vg-e2e/vg.yaml` was modified by the settings save test.
