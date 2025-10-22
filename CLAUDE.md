# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an **External Attack Surface Management (EASM)** platform design built around ProjectDiscovery tooling (Subfinder, HTTPX, Naabu, Katana, DNSX, TLSX, Uncover, Nuclei, Notify). The system is designed for multi-tenant, continuous reconnaissance with UI and API.

**Key Design Goals:**
- Continuous discovery of domains, subdomains, exposed IPs, and technologies
- Enrichment and prioritization (TLS, ports, HTTP technologies, known exposures)
- Targeted scanning with Nuclei (curated templates)
- Alerting on new attack surfaces or critical vulnerabilities
- Historical tracking and trends per tenant, asset, and CVE

## Architecture Overview

The platform follows a pipeline architecture:

```
Seeds → uncover → subfinder → dnsx (resolved) →
  ├─ httpx (web attrs) ─┐
  ├─ naabu (open ports) ├─→ merge assets → katana (crawl) → nuclei (filtered templates)
  └─ tlsx (cert intel) ─┘
→ JSON normalization → DB (assets, exposures, findings) → scoring → notify
```

**Core Components:**
1. **Ingestion & Seeds**: Root domains, ASNs, IP ranges, OSINT via `uncover`
2. **Discovery**: Passive via `subfinder`, DNS via `dnsx`, optional permutations
3. **Enrichment**: HTTP (`httpx`), ports (`naabu`), TLS (`tlsx`), crawling (`katana`)
4. **Vulnerability Scanning**: `nuclei` with severity gates and rate limiting
5. **Storage**: PostgreSQL (metadata, findings), MinIO/S3 (raw artifacts)
6. **Queue System**: Redis + Celery (scheduler/workers)
7. **API Backend**: FastAPI with JWT multi-tenant authentication
8. **UI**: Vue.js (dashboard, timeline, diff between runs)
9. **Alerting**: `notify` → Slack/Email/Webhook with severity policies
10. **Scheduler**: Celery Beat for daily runs and 15-30min watchers on critical assets

## Data Model

PostgreSQL schema (minimal):
- `tenants(id, name, slug, contact_policy)`
- `assets(id, tenant_id, type, identifier, first_seen, last_seen, risk_score)`
  - type: 'domain', 'subdomain', 'ip', 'url', 'service'
- `services(id, asset_id, port, proto, product, version, tls_fingerprint, last_seen)`
- `findings(id, asset_id, source, template_id, name, severity, cvss, evidence, first_seen, last_seen, status)`
  - source: 'nuclei', 'manual'
  - status: 'open', 'suppressed', 'fixed'
- `events(id, asset_id, kind, payload, created_at)`
  - kind: 'new_asset', 'open_port', 'new_cert', 'new_path'

**Risk Scoring Example:**
```
score = max_severity_weight + (is_new_asset? 10:0) + (exp_tls? 8:0) + (internet_exposed_login? 6:0)
```

## ProjectDiscovery Tool Chain

**Discovery Phase:**
```bash
# OSINT seed collection
uncover -q 'org:"ACME Corp"' -e shodan,censys -silent | tee seeds.txt

# Subdomain enumeration
subfinder -dL roots.txt -all -recursive -silent -o subdomains.txt

# DNS resolution with records
dnsx -l subdomains.txt -a -aaaa -cname -mx -resp -silent -o resolved.txt
```

**Enrichment Phase:**
```bash
# HTTP probing with tech detection
httpx -l resolved.txt -mc 200,301,302,403 -server -tech-detect -title \
  -follow-redirects -json -o httpx.json

# Port scanning
naabu -l resolved.txt -top-ports 1000 -rate 8000 -json -o naabu.json

# TLS intelligence
tlsx -l resolved.txt -cn -sans -issuer -exp -alpn -ja3 -json -o tlsx.json

# Web crawling
katana -uL <(jq -r '.[].url' httpx.json) -js-crawl -silent -json -o katana.json
```

**Vulnerability Scanning Phase:**
```bash
# Nuclei with severity filtering and rate limiting
nuclei -l <(jq -r '.[].url' httpx.json) \
  -t cves/ -t exposed-panels/ -t misconfiguration/ \
  -severity critical,high,medium -rl 300 -bs 50 -c 50 \
  -json -o nuclei.json
```

**Alerting Phase:**
```bash
# Alert on critical findings
cat nuclei.json | jq -cr '. | select(.severity=="critical")' | \
  notify -provider-config notify.conf
```

## API Endpoints (FastAPI)

Key endpoints to implement:
- `POST /tenants/{t}/seeds` - Add root domains, ASNs
- `GET /tenants/{t}/assets?changed_since=...` - Query assets with delta
- `GET /tenants/{t}/findings?severity>=high&status=open` - Query findings
- `POST /tenants/{t}/suppressions` - Manage false positive patterns
- `GET /tenants/{t}/risk/scorecard` - Risk overview

## UI Components (Vue.js)

Essential widgets:
- **Attack Surface Map**: Hierarchical view of domains → subdomains → services
- **Delta View**: New assets/ports in last 24h/7d
- **Findings Board**: Filterable by severity, service, template, tenant
- **TLS Hygiene**: Expiring certs, weak ciphers, mismatches
- **Tech Radar**: Technology stack from Wappalyzer/httpx for patch prioritization

## Deployment

**PoC with Docker Compose:**
- Services: `api` (FastAPI), `worker` (Celery), `beat`, `db` (Postgres), `redis`, `minio`, `ui`
- Container "runner" with ProjectDiscovery tools + volume `templates/` for Nuclei

## Security & Compliance Considerations

- Per-tenant scoping with explicit exclusions
- Global throttling to prevent aggressive scanning
- Comprehensive logging and audit trail
- Rate limiting for external APIs (Shodan, Censys, etc.)
- Tenant isolation for API keys and OSINT provider credentials

## Development Notes

**When implementing this system:**
- All reconnaissance commands should be idempotent and composable
- Use JSON output format from all tools for consistent parsing
- Implement proper error handling for API rate limits
- Store raw tool outputs in MinIO/S3 for forensics and re-processing
- Normalize data from different tools into unified asset records
- Implement severity gates before running Nuclei to avoid excessive scanning
- Use Celery task chains for pipeline orchestration
- Ensure proper tenant isolation at database and API levels
