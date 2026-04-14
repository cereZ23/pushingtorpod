# PushingTorPod — Product Roadmap

> **Goal**: from working PoC to production-ready EASM platform that enterprise customers trust.
>
> Prioritized by: customer impact × effort. P0 = do now, P1 = this sprint, P2 = next sprint, P3 = backlog.

---

## P0 — Stabilization (Week 1-2)

_"Make what we have actually work reliably."_

### Testing & CI

- [ ] Enable remaining 16 skipped test files in CI (mock external tools, add MinIO service)
- [ ] Add regression tests for every bug fixed in Apr 12-13 session (~25 bugs, ~15 need tests)
- [ ] Coverage gate: fail CI if coverage drops below 60% (currently unknown)
- [ ] Add `run_single_phase` to API (not just CLI) for QA team to test individual phases

### Data Quality

- [ ] Migration: normalize `evidence` column — ensure all rows are valid JSON dicts, never strings
- [ ] Migration: normalize `service.protocol` — `tcp` on port 443 → `https`, `tcp` on port 80 → `http`
- [ ] Migration: normalize `raw_metadata.network` — ensure GeoIP fields are never overwritten by WHOIS enrichment (merge, don't replace)
- [ ] Add Pydantic validators on Finding.evidence and Asset.raw_metadata write paths

### Pipeline Reliability

- [ ] Fix phase 1c (WHOIS) overwriting GeoIP data in `raw_metadata.network` — must merge, not replace
- [ ] Fix nuclei custom pass returning 0 when run with 45 assets (URL-to-asset mapping bug)
- [ ] Bake GeoLite2 download into Dockerfile.worker (not depend on manual `download_geoip.sh`)
- [ ] Add `data/` to `.gitignore` AND rsync `--exclude` (already done in CI, verify locally)

### Monitoring

- [ ] Add scan completion webhook/notification (Slack) so operator knows when scan finishes
- [ ] Add worker health dashboard endpoint (`/api/v1/health/worker`) showing active tasks, RSS, last scan status
- [ ] Log scan summary to structured JSON for ELK/Loki ingestion

---

## P1 — Scan Quality (Week 3-4)

_"Find more real vulnerabilities, fewer false positives."_

### Nuclei Coverage

- [ ] Enable interactsh for T3 scans (blind SSRF, blind XSS, OOB XXE detection)
- [ ] Add 10+ custom templates for Italian enterprise targets (WordPress IT, Aruba hosting, .gov.it patterns)
- [ ] Feed filtered Katana endpoints to nuclei HTTP pass (done but URL mapping needs fix for full pipeline)
- [ ] Verify nuclei runs ALL templates within timeout (currently 5000+ templates × 400 URLs may not finish in 2400s)

### Finding Quality

- [ ] Deduplicate HSTS findings — 1 finding per domain, not 1 per subdomain (43 MEDIUM → 1 actionable)
- [ ] Auto-close findings not seen in last 3 scans (`status=FIXED` with reason "not reproduced")
- [ ] Add confidence scoring — nuclei match on status code only = low confidence, body match = high
- [ ] Filter out soft-404 hosts before nuclei (teleconsultoisg returns 200 for everything)

### Enrichment

- [ ] Fix stale host pruning (phase 3) — currently `stale_hosts_deactivated: 0` because all hosts resolve via dnsx even when dead
- [ ] Add technology-to-CVE mapping: if httpx detects "PHP 8.3" → auto-check PHP CVEs
- [ ] WHOIS expiry alerting: domain expires in <30 days → finding

### Performance

- [ ] Reduce scan time from 35 min to 20 min: skip fingerprintx timeout (300s → 60s), reduce katana timeout (900s → 300s since endpoints work now)
- [ ] Profile nuclei memory usage with 5000+ templates — may need to split into 2 passes to stay under 8 GB

---

## P2 — Product Polish (Week 5-6)

_"Make it look and feel like a real product."_

### UI/UX

- [ ] Fix scan comparison to show meaningful diffs (new findings, resolved findings, new assets)
- [ ] Add "Scan Now" button per project (currently only via API/CLI)
- [ ] Asset detail page: show katana endpoints as collapsible tree (not flat list)
- [ ] Finding detail page: show evidence as formatted JSON with syntax highlighting
- [ ] Dashboard: replace "Missing HSTS" count with actionable risk summary (critical/high by category)
- [ ] Fix 83 ESLint errors in frontend (currently `continue-on-error`)

### Reports

- [ ] Executive report: 1-page PDF with risk score trend, top 5 findings, asset count delta
- [ ] Include Katana endpoint map in technical report (which paths were found per host)
- [ ] Add "Remediation Playbook" section to PDF report based on finding categories

### API

- [ ] Add `POST /api/v1/tenants/{id}/scans/run` for triggering scans from UI
- [ ] Add `POST /api/v1/tenants/{id}/scans/{id}/phases/{phase}/rerun` for single phase re-execution
- [ ] Rate limit on SIEM push endpoint (currently unbounded)
- [ ] Webhook for scan events (started, completed, finding created)

---

## P3 — Enterprise Features (Week 7-10)

_"What enterprise customers ask for in sales calls."_

### Multi-project Scanning

- [ ] Parallel scan of multiple projects (currently 1 scan at a time due to concurrency=2)
- [ ] Per-project scan schedules (Beat cron per project, not global)
- [ ] Project-level scan profiles (T1 for production, T3 for staging)

### Advanced Scanning

- [ ] Authenticated crawling: store session cookies per project for Katana + Nuclei
- [ ] API schema discovery: auto-detect and scan `/swagger.json`, `/openapi.json`, `/graphql`
- [ ] Cloud asset discovery: AWS/Azure/GCP resource enumeration via API keys
- [ ] Container/Kubernetes exposure: detect exposed dashboards, etcd, kubelet

### Integrations

- [ ] Slack bot: `/easm scan status`, `/easm top findings`, `/easm new assets`
- [ ] Microsoft Teams webhook
- [ ] PagerDuty integration for critical findings
- [ ] Terraform provider for scan profiles

### Compliance

- [ ] ISO 27001 control mapping for findings
- [ ] SOC 2 evidence collection: automated screenshots + finding history
- [ ] GDPR data mapping: which assets process PII (via header/cookie analysis)
- [ ] Audit log export in SIEM-compatible format

### Scale

- [ ] Support 1000+ asset tenants (current: 90 hostnames works, untested at scale)
- [ ] Horizontal worker scaling (Celery with autoscale)
- [ ] Result caching: don't re-scan unchanged assets
- [ ] Archive old scan data to S3/MinIO cold storage

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

---

_Copyright 2026 Andrea Ceresoni. Licensed under Apache 2.0._
