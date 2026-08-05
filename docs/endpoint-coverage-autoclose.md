# Endpoint coverage-aware auto-close (Traccia B)

How exposed-endpoint findings are scanned, tracked, and safely auto-closed — and how to operate,
monitor, and roll back the feature.

## Why

`http_stock` scans **base URLs only**. Deep, path/query-specific findings (an exposed panel at
`/admin`, a CVE at `/api/x`) are produced by a **dedicated endpoint pass** and must only be
auto-closed when we can prove *that exact endpoint* was re-scanned and the detector no longer fires.
Closing on host-level absence alone would false-`FIXED` real, still-present endpoint findings.

## Architecture

```
Katana endpoints ─▶ http_endpoint pass (nuclei, endpoint-sensitive templates)
                      │  writes per-endpoint coverage + findings WITH provenance
                      ▼
   scan_endpoint_coverage(asset_id, endpoint_shape_hash, policy_hash, status)
   findings(endpoint_shape_hash, origin_policy_hash, last_detected_scan_run_id, fingerprint*)
                      ▼
   coverage-aware consumer (phase 10)  ──shadow by default──▶  WOULD_CLOSE decision
                      │  gated by a SEPARATE per-tenant flag
                      ▼
              real close: OPEN → FIXED (+ audit)
```

- **Endpoint identity** — `endpoint_shape_hash` = SHA-256 over the versioned canonical
  `(scheme, effective port, path)`. Never stores a URL (confidentiality-at-rest).
- **Provenance** — an endpoint finding carries `endpoint_shape_hash` **and** `origin_policy_hash`
  (FK to the `http_endpoint` `scan_policy`) **and** `last_detected_scan_run_id`, written atomically.
- **Fingerprint** — `compute_finding_fingerprint` appends `endpoint_shape_hash` **only** for endpoint
  findings, so the same detector/matcher on two paths cannot collapse into one finding. Host/base
  findings keep the historic (endpoint-less) fingerprint byte-for-byte.

## Feature flags

Two **independent** flags (both default OFF; empty allowlist = **no tenant**, never a wildcard):

| Setting | Purpose |
|---|---|
| `nuclei_http_endpoint_enabled` + `nuclei_http_endpoint_tenant_ids` | run the endpoint **pass** (scan + write coverage/provenance) |
| `nuclei_endpoint_autoclose_enabled` + `nuclei_endpoint_autoclose_tenant_ids` | **really close** (OPEN→FIXED) on a WOULD_CLOSE decision |

Set in `docker-compose.prod.yml` (worker env). Values are JSON lists — use `"[3]"`, not `"3"`
(a bare value may not parse as `list[int]` → allowlist silently empty).

The coverage-aware consumer runs in **shadow for every tenant** regardless of the auto-close flag —
it always persists miss-streaks and computes WOULD_CLOSE, but only *closes* for allow-listed tenants.

## Eligibility — when a finding closes

A finding is auto-closed only on a positively-decided **WOULD_CLOSE** (default threshold: 2
consecutive eligible misses). Fail-closed everywhere. For an **endpoint** finding, ALL must hold:

1. discovery is healthy enough to authorise closing (`auto_close_allowed`);
2. **complete provenance** — both `endpoint_shape_hash` and `origin_policy_hash` set;
3. an **exact** `scan_endpoint_coverage` row `(asset, shape, origin_policy_hash)` exists this run with
   `pass = http_endpoint` and status **COVERED**;
4. the detector is applicable in that policy's intact catalog;
5. the finding was **not detected** this run.

Anything else → **ineligible** → streak reset (never frozen). In particular: coverage PARTIAL/FAILED,
**policy drift** (finding's `origin_policy_hash` ≠ this run's coverage policy), a shape mismatch, or
**incomplete provenance** → ineligible. Endpoint findings **never** fall back to asset-level coverage.

Concurrency: open findings are row-locked (`SELECT … FOR UPDATE`); an out-of-order (older-started)
run that reaches a finding after a newer one is a no-op (`stale_skip`). The close is a conditional
`UPDATE … WHERE status='open'` with a rowcount check → idempotent (a re-run closes nothing twice);
the audit line is emitted **after commit** for rows that actually changed (no false/double audit).

## Audit & metrics

- **Audit** (durable, URL-free) per real close:
  `coverage auto-close REAL: run=<id> finding=<id> asset=<id> source=<src> shape=<hash> origin_policy=<hash>`
- **Metric**: phase-10 stats `coverage_auto_closed` (0 while shadow). The summary log line reports
  `would_close` and `closed` per run.

## Rollout & validation

Shipped incrementally: `#126` origin-homogeneous batching · `#127` completion-vs-unresponsive
separation · `#128` shape-aware fingerprint + provenance · `#129` endpoint-aware shadow consumer ·
`#130` real-nuclei finding attribution fix · `#131` real close behind the separate flag ·
`#132` config-only cutover enabling real close for Curci (tenant 3).

Validated end-to-end on an **isolated authorized probe** (dedicated test tenant + a controlled
internal endpoint serving a private token): create (finding with full provenance, COVERED) → two
eligible misses → WOULD_CLOSE (shadow) → negative (policy-drift → ineligible, streak reset) → smoke
with the flag OFF (WOULD_CLOSE reported, `closed=0`) → real **OPEN→FIXED** with the flag ON. Then
confirmed by **three clean production shadow runs** on Curci (`would_close=0`, no spurious
candidates) before the cutover.

## Operational runbook

### Enable for a tenant (cutover)
1. Confirm ≥2–3 recent **shadow** runs for the tenant with no spurious WOULD_CLOSE candidates.
2. Config-only PR: add the tenant to `nuclei_endpoint_autoclose_tenant_ids` and set
   `nuclei_endpoint_autoclose_enabled: "true"` in `docker-compose.prod.yml`.
3. CI green → merge at **scanner stopped** → deploy. Verify live env + services healthy.
4. Do **not** launch extra scans to force a close (inflates load, compresses the miss window). Let
   scheduled scans run.

### At the first `closed > 0`, verify ALL of:
- `would_close == closed` (no silent divergence);
- exact endpoint coverage **COVERED** in **both** eligible runs;
- **same shape** and **same policy** across those runs;
- the finding was **not detected** in the miss runs;
- audit line **complete and URL-free**;
- correct **re-open** if the detector reappears in a later run.

### Rollback (immediate, on any unexpected close / mismatch / incomplete audit)
Set `NUCLEI_ENDPOINT_AUTOCLOSE_ENABLED: "false"` (or empty the allowlist) → deploy. The consumer
instantly reverts to **pure shadow** (closes nothing). App defaults are `false`/`[]`, so every
non-allow-listed tenant is unaffected at all times.

## Key code

- `app/services/scanning/endpoint_pass.py` — batching + conservative per-batch verdict.
- `app/services/scanning/http_endpoint_orchestrator.py` — the pass, coverage/provenance writes, finding attribution.
- `app/services/endpoint_identity.py` — `endpoint_shape_hash`.
- `app/services/dedup.py` — shape-aware `compute_finding_fingerprint`.
- `app/services/coverage_autoclose.py` — `shadow_auto_close` (shadow + gated real close).
- `app/services/discovery_health.py` — `auto_close_allowed` gate.
- `app/tasks/pipeline_phases/detection.py` — phase-9 pass wiring + phase-10 consumer wiring.
- `app/config.py` — the two flag pairs.
