# PushingTorPod — Product Roadmap

> **Goal**: from working PoC to production-ready EASM platform that enterprise customers trust.
>
> Prioritized by: customer impact × effort. P0 = do now, P1 = this sprint, P2 = next sprint, P3 = backlog.

> **Status review — 2026-07-27**: this roadmap was written 2026-04-14 and never updated since, despite
> a full Sprint 3 tenant-isolation/RLS security effort, a UX hardening pass, and several bug-fix PRs
> shipping in between. Every item below was re-verified against current code (not just commit messages)
> on 2026-07-27. Tags: **[FATTO]** done, **[PARZIALE]** partially done, **[NON FATTO]** not done,
> **[OBSOLETO]** no longer relevant. This is prep work for drafting a single consolidated roadmap next —
> keep this file as historical record of what P0-P1 looked like at the Apr stabilization session until then.

---

## P0 — Stabilization (Week 1-2)

_"Make what we have actually work reliably."_

### Testing & CI

- [ ] Enable remaining 16 skipped test files in CI (mock external tools, add MinIO service) — **[PARZIALE]** 6 enabled in `3db8cde` (2026-04-14), but CI still `--ignore`s 7 files (`tests/integration/`, `tests/performance/`, `test_performance.py`, `test_visual_recon.py`, `test_enrichment_pipeline_e2e.py`, `test_integration_discovery.py`, `test_repositories.py`, `test_security.py`) plus `-k` excludes ~19 individual tests (`.github/workflows/tests.yml:118-134`)
- [ ] Add regression tests for every bug fixed in Apr 12-13 session (~25 bugs, ~15 need tests) — **[NON VERIFICATO]** no reliable marker found to count
- [ ] Coverage gate: fail CI if coverage drops below 60% (currently unknown) — **[PARZIALE]** gate exists but set to `--cov-fail-under=48` (`.github/workflows/tests.yml:120`), not 60
- [x] Add `run_single_phase` to API (not just CLI) for QA team to test individual phases — **[FATTO]** `app/api/routers/scanning.py:120-129`

### Data Quality

- [x] Migration: normalize `evidence` column — ensure all rows are valid JSON dicts, never strings — **[FATTO]** `alembic/versions/020_normalize_evidence_and_protocol.py`
- [x] Migration: normalize `service.protocol` — `tcp` on port 443 → `https`, `tcp` on port 80 → `http` — **[FATTO]** same migration
- [x] Migration: normalize `raw_metadata.network` — ensure GeoIP fields are never overwritten by WHOIS enrichment (merge, don't replace) — **[FATTO]** `app/tasks/network_enrichment.py`
- [ ] Add Pydantic validators on Finding.evidence and Asset.raw_metadata write paths — **[PARZIALE]** `Finding.evidence` has a validator (`app/api/schemas/finding.py:48-51`), `Asset.raw_metadata` does not

### Pipeline Reliability

- [x] Fix phase 1c (WHOIS) overwriting GeoIP data in `raw_metadata.network` — must merge, not replace — **[FATTO]** `3db8cde`
- [x] Fix nuclei custom pass returning 0 when run with 45 assets (URL-to-asset mapping bug) — **[FATTO]** `3db8cde` (exclude_tags + URL/asset case-scheme mapping)
- [x] Bake GeoLite2 download into Dockerfile.worker (not depend on manual `download_geoip.sh`) — **[FATTO]** `Dockerfile.worker:179-181`
- [ ] Add `data/` to `.gitignore` AND rsync `--exclude` (already done in CI, verify locally) — **[NON RI-VERIFICATO]** assumed done per original note

### Monitoring

- [x] Add scan completion webhook/notification (Slack) so operator knows when scan finishes — **[FATTO]** `app/tasks/pipeline.py:83-115` (`_send_scan_notification`)
- [ ] Add worker health dashboard endpoint (`/api/v1/health/worker`) showing active tasks, RSS, last scan status — **[PARZIALE]** `/health`, `/ready`, `/health/metrics` exist (`app/api/routers/health.py`) but only ping-based liveness, not active-tasks/RSS/last-scan detail
- [x] Log scan summary to structured JSON for ELK/Loki ingestion — **[FATTO]** `app/utils/logger.py:17` (`JSONFormatter`)

---

## P1 — Scan Quality (Week 3-4)

_"Find more real vulnerabilities, fewer false positives."_

### Nuclei Coverage

- [x] Enable interactsh for T3 scans (blind SSRF, blind XSS, OOB XXE detection) — **[FATTO]** `app/config.py:185-186`
- [ ] Add 10+ custom templates for Italian enterprise targets (WordPress IT, Aruba hosting, .gov.it patterns) — **[PARZIALE]** 16 custom templates exist (`nuclei-templates/custom/`) but only 1 is Italy-specific (`italian-pa-disclosure.yaml`); the rest are generic WordPress-plugin templates
- [x] Feed filtered Katana endpoints to nuclei HTTP pass (done but URL mapping needs fix for full pipeline) — **[FATTO]** fixed alongside the `3db8cde` URL-mapping fix
- [ ] Verify nuclei runs ALL templates within timeout (currently 5000+ templates × 400 URLs may not finish in 2400s) — **[NON FATTO]** no pass-splitting found, single 1800s run, unverified against template count

### Finding Quality

- [ ] Deduplicate HSTS findings — 1 finding per domain, not 1 per subdomain (43 MEDIUM → 1 actionable) — **[NON FATTO]** no root-domain grouping logic in `app/tasks/misconfig.py`
- [ ] Auto-close findings not seen in last 3 scans (`status=FIXED` with reason "not reproduced") — **[PARZIALE]** implemented but on a 5-minute single-scan cutoff (`app/tasks/misconfig.py:1959-1980`), not "3 scans"; only covers `source="misconfig"`, not nuclei findings generally
- [x] Add confidence scoring — nuclei match on status code only = low confidence, body match = high — **[FATTO]** `app/services/scanning/confidence.py`
- [x] Filter out soft-404 hosts before nuclei (teleconsultoisg returns 200 for everything) — **[FATTO]** `app/utils/soft404.py`

### Enrichment

- [x] Fix stale host pruning (phase 3) — currently `stale_hosts_deactivated: 0` because all hosts resolve via dnsx even when dead — **[FATTO]** pruning logic present in `app/tasks/enrichment.py`
- [x] Add technology-to-CVE mapping: if httpx detects "PHP 8.3" → auto-check PHP CVEs — **[FATTO]** `app/services/tech_cve_map.py`
- [x] WHOIS expiry alerting: domain expires in <30 days → finding — **[FATTO]** `app/tasks/misconfig.py:1745-1775`, thresholds match spec (critical ≤7d, high ≤30d)

### Performance

- [~] Reduce scan time from 35 min to 20 min: skip fingerprintx timeout (300s → 60s), reduce katana timeout (900s → 300s since endpoints work now) — **[PARZIALE]** katana done (`app/config.py:229`, now 300s), fingerprintx **[NON FATTO]** still 300s (`app/config.py:184`)
- [ ] Profile nuclei memory usage with 5000+ templates — may need to split into 2 passes to stay under 8 GB — **[NON FATTO]**

---

## P2 — Product Polish (Week 5-6)

_"Make it look and feel like a real product."_

### UI/UX

- [x] Fix scan comparison to show meaningful diffs (new findings, resolved findings, new assets) — **[FATTO]** `ScanDiffView.vue`, full added/removed/resolved sections + suspicious-diff guard
- [x] Add "Scan Now" button per project (currently only via API/CLI) — **[FATTO]** `ScanManagement.vue:111-125`
- [ ] Asset detail page: show katana endpoints as collapsible tree (not flat list) — **[NON FATTO]** flat table, hard-capped at 50 with no pagination (`AssetDetailView.vue:1264-1320`) — structural, tracked in UX audit
- [x] Finding detail page: show evidence as formatted JSON with syntax highlighting — **[FATTO 2026-07-27]** was pretty-print-only; hand-rolled highlighter added this session (`frontend/src/utils/jsonHighlight.ts`, wired into `FindingDetailView.vue`)
- [x] Dashboard: replace "Missing HSTS" count with actionable risk summary (critical/high by category) — **[FATTO]** "Action Required" banner, `DashboardView.vue:1120-1170`
- [ ] Fix 83 ESLint errors in frontend (currently `continue-on-error`) — **[NON FATTO]** still `continue-on-error: true` (`.github/workflows/tests.yml:169-170`)

### Reports

- [x] Executive report: 1-page PDF with risk score trend, top 5 findings, asset count delta — **[FATTO]** `app/services/report_generator.py`
- [ ] Include Katana endpoint map in technical report (which paths were found per host) — **[NON VERIFICATO]**
- [x] Add "Remediation Playbook" section to PDF report based on finding categories — **[FATTO]** `app/services/remediation_playbook.py`

### API

- [ ] Add `POST /api/v1/tenants/{id}/scans/run` for triggering scans from UI — **[NON CONFERMATO]** no dedicated endpoint found (UI trigger may go through an existing scan-creation endpoint instead)
- [x] Add `POST /api/v1/tenants/{id}/scans/{id}/phases/{phase}/rerun` for single phase re-execution — **[FATTO]** `app/api/routers/scanning.py:106-134`
- [ ] Rate limit on SIEM push endpoint (currently unbounded) — **[NON VERIFICATO]** no rate-limit decorator found in `app/api/routers/siem.py`
- [ ] Webhook for scan events (started, completed, finding created) — **[PARZIALE]** completed/failed only (`app/tasks/pipeline.py`); no "started" or per-finding event

---

## P3 — Enterprise Features (Week 7-10)

_"What enterprise customers ask for in sales calls."_

### Multi-project Scanning

- [ ] Parallel scan of multiple projects (currently 1 scan at a time due to concurrency=2) — **[NON FATTO]** `docker-compose.prod.yml:233` still `--concurrency=2`
- [x] Per-project scan schedules (Beat cron per project, not global) — **[FATTO]** `ScanProfile.schedule_cron` + `app/tasks/scheduled_scans.py` (croniter, checked every minute)
- [x] Project-level scan profiles (T1 for production, T3 for staging) — **[FATTO]** `app/models/scanning.py:176` (`scan_tier` 1-3)

### Advanced Scanning

- [ ] Authenticated crawling: store session cookies per project for Katana + Nuclei — **[NON FATTO]**
- [x] API schema discovery: auto-detect and scan `/swagger.json`, `/openapi.json`, `/graphql` — **[FATTO]** `app/tasks/sensitive_paths.py:162-195,656`
- [ ] Cloud asset discovery: AWS/Azure/GCP resource enumeration via API keys — **[PARZIALE]** `app/tasks/cloud_scan.py` does bucket-name enumeration (S3/GCS/Azure/DO) only, not full API-key-based resource enumeration
- [ ] Container/Kubernetes exposure: detect exposed dashboards, etcd, kubelet — **[NON FATTO]** only a generic `/k8s/` dir-listing check

### Integrations

- [ ] Slack bot: `/easm scan status`, `/easm top findings`, `/easm new assets` — **[NON FATTO]** only outbound webhook notifications exist, no interactive bot
- [x] Microsoft Teams webhook — **[FATTO]** `app/tasks/alert_evaluation.py:463-466,577`
- [x] PagerDuty integration for critical findings — **[FATTO]** `app/tasks/alert_evaluation.py:468-471,638-670`
- [ ] Terraform provider for scan profiles — **[NON FATTO]**

### Compliance

- [~] ISO 27001 control mapping for findings — **[PARZIALE, MEGLIO DEL PREVISTO]** 15 technological controls mapped (not all 93), but the scope limitation is now explicitly disclosed to the user (UI, PDF, and scheduling — fixed this session) rather than silently understated
- [x] SOC 2 evidence collection: automated screenshots + finding history — **[FATTO]** `app/services/report_generator.py` (SOC2 TSC mapping + compliance report)
- [ ] GDPR data mapping: which assets process PII (via header/cookie analysis) — **[NON FATTO]**
- [x] Audit log export in SIEM-compatible format — **[FATTO]** `app/api/routers/audit.py`, `app/core/audit.py`

### Scale

- [ ] Support 1000+ asset tenants (current: 90 hostnames works, untested at scale) — **[NON VERIFICATO]** `tests/test_performance.py` exists but is CI-ignored
- [ ] Horizontal worker scaling (Celery with autoscale) — **[NON FATTO]** no `--autoscale` flag anywhere
- [ ] Result caching: don't re-scan unchanged assets — **[NON FATTO]**
- [ ] Archive old scan data to S3/MinIO cold storage — **[NON FATTO]**

---

## Done (Apr 12-14 Session)

_Bugs fixed and features added during the stabilization session._

- [x] Fix OOM 12 GB (katana stdout pipe → file, playwright 1.56.0, worker recycle)
- [x] Fix katana 0 endpoints (stdout_file + request.endpoint + dedup)
- [x] Fix nuclei 0 findings on custom templates (dedicated pass_0 + remove IP dedup)
- [x] Fix phase 11 risk scoring (evidence json.loads + isinstance check)
- [x] Fix snapshot not persisted (SQLAlchemy flag_modified on JSON column)
- [x] Fix threat_intel TypeError (evidence string handling)
- [x] Fix URL scheme tcp→https for nuclei
- [x] Fix GeoMap (CSP tiles + fitBounds on visible container)
- [x] Fix healthchecks (pidof -x, 127.0.0.1 for IPv6)
- [x] Fix naabu timeout (tier-aware 9000s for T3)
- [x] Fix IP dedup variable shadowing
- [x] Fix stale host pruning (14-day grace)
- [x] Add tier-aware nuclei template selection (~5500 templates for T3)
- [x] Add tier-aware exclude-tags per scan tier
- [x] Add custom nuclei templates (docker-compose creds, htaccess, PHP path disclosure)
- [x] Add Katana endpoint feed to nuclei (308 high-value URLs filtered from 2459)
- [x] Add run_single_phase for fast debugging (3 min vs 40 min)
- [x] Add GeoLite2 download script + memoized loader
- [x] Bump worker memory 8→12 GB
- [x] Enable 4 critical test files in CI (449 tests, was 339)
- [x] Fix 5 CodeQL security alerts (HMAC, HTMLParser, SSRF DNS rebinding)
- [x] Bump vulnerable deps (axios, vite, requests, cryptography)
- [x] Remove phase 6c (sensitive_paths) — leaked 10 GB, redundant with nuclei
- [x] Remove phase 7 (visual recon) — no security value, saves 3 min + 1 GB
- [x] CI deploys with rsync --exclude data/ to preserve GeoIP databases

## Done (Jul 2026 Session — Sprint 3 Security + UX Hardening)

_Not tracked in this file when shipped; backfilled 2026-07-27 for continuity._

- [x] Tenant-isolation context + ORM guard, audit mode → global enforce (API, worker, beat)
- [x] Postgres RLS policies + tenant-GUC wiring; dedicated non-owner app DB role for RLS cutover
- [x] Scope-authorization gate (audit mode) + scan-authorization management API
- [x] CSV formula injection neutralized in exports
- [x] Detection-efficacy harness with golden set
- [x] Scan kill-switch + per-target circuit breaker
- [x] Weekly exposure digest + dashboard hero card
- [x] Dashboard "Action Required" fixed (was counting resolved/FIXED findings)
- [x] Remediation & verify fixed for non-web findings
- [x] Ticketing integration PUT 405 → always POST
- [x] Missing DELETE scope-rule endpoint added
- [x] Global toast notification system + resilient scan-detail polling + global HTTP error surfacing
- [x] 6 UX quick-wins (alert-test result correctness, standardized delete-confirmation dialog, removed
      dead GitHub-Dorking phase label, deleted 3 orphaned stub views, evidence JSON syntax highlighting,
      ISO27001 scope disclaimer propagated to PDF + scheduling UI)

---

_Copyright 2026 Andrea Ceresoni. Licensed under Apache 2.0._
