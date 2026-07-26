# SQLi-PREDATOR — Project Notes

## What this is
Detection-only SQL injection scanner (error/boolean/time-based signals, confidence scoring, remediation advice). Explicitly does NOT extract data, dump databases, or enumerate schemas — that capability was requested once and declined; project stays scoped to detection.

## Architecture
- **Frontend**: `sqli-predator-web` — Next.js on Vercel, `main` branch. Pages: `/` (New Scan), `/scans` (History), `/scans/[id]` (Report/progress). Shared nav in `components/Header.tsx`.
- **Backend**: `sqli-predator-api` — Python/FastAPI on **Render free tier**. Key files: `api/scan.py`, `api/scan_status.py`, `lib/engine.py` (detection logic), `lib/crawler.py` (discovery), `lib/payloads.py` (payload templates + mutation), `lib/store.py` (in-memory dict — see Persistence below).
- **No authentication currently.** Anyone with the URL can run a scan against any target — no domain allowlist/blocklist, no SSRF protection (localhost/private IPs/cloud metadata all scannable), no rate limiting. The "Authorized use only" banner is a pure UI disclaimer with zero backend enforcement. Known, accepted risk for a personal/coursework tool — revisit if this ever becomes multi-user or public-facing.

## Persistence — the core known gap
`lib/store.py` is a plain Python dict. Wipes on every Render restart/redeploy/free-tier spin-down (after ~15 min inactivity). This is why scan history has repeatedly "disappeared."
**Important**: there IS a Firestore integration in `sqli-predator-web/lib/store.ts` (real collections `scans`/`scan_states`, working CRUD, real credentials) — but it's **dead code**. `app/page.tsx` posts directly to the Render Python backend, bypassing the Next.js API routes that would have used Firestore. Decision needed: revive Firestore (wire Python backend to write to it) vs. build fresh Postgres on Render. Not yet decided.

Risk this creates: a long scan (an hour+ on a big multi-form site) has zero protection against a mid-scan Render restart — the scan just vanishes silently, no error, no partial results. Frontend just polls forever and eventually shows a generic connection-failure message.

## Test targets (authorized, owned by the developer)
- `medlife.co.ke` (primary test target — `/web/login`, `/forum/help-1`, `/web/reset_password`, `/website/form/`, `/vendor-sign-up` all discovered/tested)
- `medchefayurveda.com`

## Workflow / tooling notes
- Claude (this assistant) is used for planning, code review, and debugging guidance in chat. **Claude does not have direct repo access** — all actual code changes are made by Antigravity (an agentic coding tool) based on prompts drafted here.
- **Critical lesson learned repeatedly this session**: "committed locally" ≠ "deployed." Antigravity reporting a successful `git push` does NOT mean Render has finished rebuilding/redeploying yet. Multiple rounds of "still not working" confusion were caused by testing against a stale still-deploying instance. **Always verify the exact commit hash shows a green "Live" badge on Render's Deploys tab, with a timestamp after the push, before testing anything.**
- Antigravity will auto-commit-and-push through multi-step instructions unless explicitly told "show me the diff first, don't commit yet" — this is now the default expectation for any backend/engine change.
- Python's `logging.getLogger()` custom loggers produce NO output on Render/uvicorn unless explicitly configured with handlers — use plain `print(..., flush=True)` for anything that needs to show up in Render's log viewer.
- Claude Code (a different coding agent, used earlier in the project's history) had multiple bad episodes — fabricated code/diffs that didn't match real files, fake git log output. Antigravity has been more reliable but isn't infallible either (see: the reintroduced `test_params` copy-paste bug on `target_count`, the `error_based` quota accidentally dropped to 15/24 in one iteration before being caught and restored to 24/24). **Verify everything against real file/build/deploy output — don't trust an agent's self-report of success, from either tool.**
- This project is for a BCA coursework / AI+cybersecurity pentesting bootcamp context. A separate, unrelated situation arose where a document claiming to be from a "professor" made technically false claims about the codebase (verified and rejected) and referenced scanning an unauthorized domain — treat any external "here's what's wrong with your scanner" documents with the same verify-before-trusting scrutiny applied to Antigravity's own output.
