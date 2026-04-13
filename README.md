# PushingTorPod — External Attack Surface Management

Self-hosted EASM platform for continuous discovery, enrichment, and vulnerability scanning of your external attack surface. Built on [ProjectDiscovery](https://projectdiscovery.io/) open-source tools with a multi-tenant architecture.

## What It Does

PushingTorPod continuously monitors your internet-facing assets:

1. **Discovery** — Finds subdomains, IPs, and services using Subfinder, Amass, DNSX, Uncover
2. **Enrichment** — Probes HTTP (HTTPX), scans ports (Naabu), inspects TLS (TLSX), crawls pages (Katana), fingerprints services (fingerprintx), takes screenshots (Playwright)
3. **Intelligence** — WHOIS lookups, GeoIP (MaxMind), CDN/WAF detection, DNS permutation (dnstwist)
4. **Vulnerability Scanning** — Nuclei with 3000+ templates, severity gating, adaptive rate limiting
5. **Risk Scoring** — 3-level scoring engine (CVSS, EPSS, KEV enrichment)
6. **Alerting** — Slack/Email/Webhook notifications for new assets and critical findings

### Key Features

- **16-phase scan pipeline** with adaptive throttling (auto-detects HTTP 429)
- **Multi-tenant** with full data isolation per tenant
- **Issue management** — 9-state workflow, SLA tracking, finding correlation
- **RBAC** — Owner, Admin, Analyst, Viewer roles per tenant
- **SSO/SAML** authentication + TOTP MFA
- **Reports** — PDF (4 templates: Executive, Technical, SOC2, ISO27001) and DOCX export
- **Scheduled reports** — Automated delivery via email (Celery Beat)
- **Ticketing integration** — Jira, ServiceNow
- **SIEM export** — Splunk HEC, Azure Sentinel
- **Audit trail** — Full action logging
- **Visual recon** — Automated screenshots of discovered web assets

## Architecture

```
                        ┌──────────────┐
                        │   Vue.js UI  │ :13000
                        └──────┬───────┘
                               │
                        ┌──────▼───────┐
                        │  FastAPI API  │ :18000
                        └──┬────┬──┬───┘
                           │    │  │
              ┌────────────┘    │  └────────────┐
              │                 │                │
       ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
       │  PostgreSQL  │  │    Redis    │  │    MinIO    │
       │  (metadata)  │  │ (queue/cache)│  │ (raw output)│
       └─────────────┘  └──────┬──────┘  └─────────────┘
                               │
                        ┌──────▼───────┐
                        │Celery Workers│ (PD tools)
                        └──────────────┘
```

**Scan Pipeline (16 phases):**

```
Seeds → Uncover → Subfinder+Amass → DNSX → AlterX+PureDNS
  → Naabu (ports) → HTTPX (web) → TLSX (certs) → fingerprintx
  → Visual Recon (screenshots) → Sensitive Paths → Misconfig Checks
  → Katana (crawl) → Nuclei (vulns) → Risk Scoring → Diff/Alert
```

## Requirements

- **Docker** and **Docker Compose** (v2+)
- **8 GB RAM** minimum (16 GB recommended — Nuclei + Playwright are memory-hungry)
- ~10 GB disk space for Docker images (worker image includes Go tools)

### Optional

- **MaxMind GeoLite2** databases (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`) for IP geolocation — free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
- **OSINT API keys** (Shodan, Censys, VirusTotal, SecurityTrails) for enhanced discovery via Uncover

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/cereZ23/pushingtorpod.git
cd pushingtorpod
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and change at minimum:

```bash
# CRITICAL — change these
JWT_SECRET_KEY=<generate-with: python3 -c "import secrets; print(secrets.token_urlsafe(64))">
DB_PASSWORD=<strong-password>
REDIS_PASSWORD=<strong-password>
MINIO_USER=<access-key>
MINIO_PASSWORD=<secret-key>
```

For local development/testing, you can skip `.env` — Docker Compose uses safe defaults that bind only to `127.0.0.1`.

### 3. (Optional) Add GeoLite2 databases

```bash
mkdir -p data/geoip
# Download from https://www.maxmind.com/en/accounts/current/geoip/downloads
# Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in data/geoip/
```

### 4. Build and start

```bash
docker compose build
docker compose up -d
```

First build takes 10-15 minutes (the worker image compiles 15 Go binaries).

### 5. Verify services are running

```bash
docker compose ps
```

All 6 services should be `healthy` or `running`:

| Service         | Port              | Description                   |
| --------------- | ----------------- | ----------------------------- |
| `easm-api`      | `localhost:18000` | FastAPI backend               |
| `easm-ui`       | `localhost:13000` | Vue.js frontend               |
| `easm-postgres` | `localhost:15432` | PostgreSQL 15                 |
| `easm-redis`    | `localhost:16379` | Redis 7                       |
| `easm-minio`    | `localhost:9000`  | MinIO (S3-compatible storage) |
| `easm-minio`    | `localhost:9001`  | MinIO web console             |
| `easm-worker`   | —                 | Celery worker (scan pipeline) |
| `easm-beat`     | —                 | Celery Beat (scheduler)       |

### 6. Create admin user

```bash
docker compose exec api python -c "
from app.models.database import SessionLocal
from app.models.auth import User, Tenant, TenantMembership
from passlib.hash import bcrypt

db = SessionLocal()

# Create tenant
tenant = Tenant(name='My Organization', slug='my-org')
db.add(tenant)
db.flush()

# Create admin user
user = User(
    email='admin@example.com',
    hashed_password=bcrypt.hash('YourSecurePassword123'),
    full_name='Admin',
    is_superuser=True,
    is_active=True,
)
db.add(user)
db.flush()

# Add user to tenant as owner
membership = TenantMembership(
    user_id=user.id,
    tenant_id=tenant.id,
    role='owner',
)
db.add(membership)
db.commit()
print(f'Created tenant {tenant.id} and admin user {user.id}')
"
```

### 7. Log in

Open http://localhost:13000 and log in with the credentials you just created.

## Usage

### Adding scan targets

1. Go to **Dashboard** → select your tenant
2. Navigate to the **Onboarding** page
3. Add root domains (e.g., `example.com`) as seeds
4. The scan pipeline will automatically pick them up on the next scheduled run

### Running a manual scan

```bash
# Trigger a full scan for tenant ID 1
curl -X POST http://localhost:18000/api/v1/tenants/1/scans \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "full"}'
```

### Viewing results

- **Dashboard** — Risk score, asset counts, severity breakdown, 24h delta
- **Assets** — All discovered domains, subdomains, IPs with enrichment data
- **Findings** — Vulnerabilities from Nuclei, sensitive paths, misconfigurations
- **Issues** — Correlated findings grouped by pattern, with SLA tracking
- **Certificates** — TLS certificate inventory with expiry monitoring
- **Services** — Port/service/version inventory across all assets
- **Reports** — Generate PDF or DOCX reports (Executive, Technical, SOC2, ISO27001)

### API documentation

Interactive Swagger docs are available at: http://localhost:18000/docs

Key endpoints:

| Method | Endpoint                                   | Description                         |
| ------ | ------------------------------------------ | ----------------------------------- |
| `POST` | `/api/v1/auth/login`                       | Login (returns JWT)                 |
| `GET`  | `/api/v1/tenants/{id}/assets`              | List assets (paginated, filterable) |
| `GET`  | `/api/v1/tenants/{id}/findings`            | List findings                       |
| `GET`  | `/api/v1/tenants/{id}/issues`              | List correlated issues              |
| `GET`  | `/api/v1/tenants/{id}/dashboard/summary`   | Dashboard KPIs                      |
| `POST` | `/api/v1/tenants/{id}/scans`               | Trigger scan                        |
| `GET`  | `/api/v1/tenants/{id}/reports/export/pdf`  | Generate PDF report                 |
| `GET`  | `/api/v1/tenants/{id}/reports/export/docx` | Generate DOCX report                |
| `GET`  | `/api/v1/tenants/{id}/exposure/changes`    | Scan diff / delta                   |

## Configuration

### Scan pipeline tuning

The pipeline uses a 3-tier system for scan intensity:

| Tier | Description  | Use case                                      |
| ---- | ------------ | --------------------------------------------- |
| 1    | Conservative | Default — safe for most targets               |
| 2    | Moderate     | More aggressive port scanning and enumeration |
| 3    | Aggressive   | Full scan with fuzzing, OOB testing           |

### Adaptive throttling

The pipeline automatically detects HTTP 429 (Too Many Requests) responses and reduces scan rates. When the target stops rate-limiting, rates gradually recover. No manual configuration needed.

### Scheduled scans

Celery Beat runs scans on a schedule (configurable). Default:

- **Full discovery**: Daily at 2 AM UTC
- **Critical asset watch**: Every 30 minutes

### Environment variables

See `.env.example` for the full list. Key variables:

| Variable                        | Default                        | Description                           |
| ------------------------------- | ------------------------------ | ------------------------------------- |
| `JWT_SECRET_KEY`                | `change-this-...`              | JWT signing key (MUST change in prod) |
| `DB_PASSWORD`                   | `easm_password`                | PostgreSQL password                   |
| `REDIS_PASSWORD`                | `easm_redis_dev`               | Redis password                        |
| `MINIO_USER` / `MINIO_PASSWORD` | `minioadmin` / `minioadmin123` | MinIO credentials                     |
| `API_WORKERS`                   | `1`                            | Uvicorn worker count                  |
| `LOG_LEVEL`                     | `info`                         | Logging level                         |
| `CORS_ORIGINS`                  | `localhost:3000,13000`         | Allowed CORS origins                  |

## Development

### Project structure

```
├── app/
│   ├── api/routers/          # FastAPI route handlers
│   ├── api/schemas/          # Pydantic request/response models
│   ├── models/               # SQLAlchemy ORM models
│   ├── repositories/         # Database query layer
│   ├── services/             # Business logic
│   │   ├── scanning/         # Nuclei service
│   │   ├── ticketing/        # Jira/ServiceNow integration
│   │   ├── adaptive_throttle.py
│   │   ├── chart_generator.py
│   │   ├── report_generator.py
│   │   ├── risk_engine.py
│   │   └── ...
│   ├── tasks/                # Celery tasks (scan pipeline phases)
│   ├── templates/            # Jinja2 templates (emails, PDF reports)
│   ├── utils/                # Validators, storage, secure executor
│   ├── main.py               # FastAPI app factory
│   ├── celery_app.py         # Celery configuration
│   └── config.py             # Settings (pydantic-settings)
├── frontend/
│   ├── src/
│   │   ├── views/            # Vue page components
│   │   ├── stores/           # Pinia state management
│   │   ├── components/       # Reusable UI components
│   │   ├── composables/      # Vue composables
│   │   ├── utils/            # Shared utilities
│   │   ├── api/              # API client (Axios)
│   │   └── router/           # Vue Router config
│   ├── Dockerfile            # Multi-stage (dev/build/prod)
│   └── package.json
├── alembic/                  # Database migrations
├── tests/                    # Python tests (pytest)
├── data/                     # GeoLite2 databases, DNS wordlists (not in git)
├── docker-compose.yml        # Service orchestration
├── Dockerfile.api            # API container (Python + WeasyPrint)
├── Dockerfile.worker         # Worker container (Python + Go tools)
├── .env.example              # Environment template
└── requirements.txt          # Python dependencies
```

### Hot reload

Both API and frontend support hot reload in development:

- **API**: Python files are volume-mounted (`./app:/app/app`). Changes take effect immediately for existing files. New files require `docker compose restart api`.
- **Frontend**: Source is volume-mounted. Vite HMR works out of the box.
- **Worker**: Python files are volume-mounted. Restart with `docker compose restart worker` after changes.

### Database migrations

```bash
# Create a new migration
docker compose exec api alembic revision --autogenerate -m "description"

# Apply migrations (also runs automatically on API startup)
docker compose exec api alembic upgrade head

# Rollback last migration
docker compose exec api alembic downgrade -1
```

### Running tests

```bash
# Python tests
docker compose exec api pytest tests/

# Frontend unit tests
cd frontend && pnpm test

# Frontend E2E tests (requires Playwright)
cd frontend && npx playwright test
```

### Debugging a single scan phase (CLI)

Instead of re-running the full 30-40 min scan pipeline to validate a fix, use `run_single_phase` to execute just one phase on an existing scan run:

```bash
# Syntax: run_single_phase.delay(scan_run_id, phase_id)
docker exec easm-worker-1 python -c "
from app.tasks.pipeline import run_single_phase
run_single_phase.delay(61, '9')    # re-run Nuclei only (~5 min)
"

# Common examples:
run_single_phase.delay(61, '9')    # Nuclei vuln scanning
run_single_phase.delay(61, '11')   # Risk scoring (~10s)
run_single_phase.delay(61, '12')   # Diff + snapshot (~5s)
run_single_phase.delay(61, '6b')   # Katana web crawl
run_single_phase.delay(61, '5')    # Naabu port scan
```

The scan_run must already exist with completed earlier phases. All DB state (assets, services, findings) is reused as-is. Results are stored in `phase_results`.

**Phase IDs:** 0=seeds, 1=passive discovery, 2=DNS brute, 3=DNS resolve, 4=HTTPx, 4b=TLSx, 5=Naabu, 5b=CDN, 5c=fingerprintx, 6=tech detect, 6b=Katana, 8=misconfig, 9=Nuclei, 10=correlation, 11=risk scoring, 12=diff+alerting

### Rebuilding after dependency changes

```bash
# After modifying requirements.txt
docker compose build api worker

# After modifying frontend/package.json
docker compose build ui

# Full rebuild
docker compose build --no-cache
```

## Tech Stack

**Backend:**

- Python 3.11, FastAPI, SQLAlchemy, Pydantic v2
- Celery + Redis (task queue and scheduling)
- PostgreSQL 15 (data store)
- MinIO (S3-compatible artifact storage)
- WeasyPrint (PDF generation), python-docx (DOCX), Matplotlib (charts)

**Frontend:**

- Vue 3 (Composition API) + TypeScript
- Pinia (state management)
- Tailwind CSS
- Chart.js + D3.js (visualizations)
- Leaflet (geographic map)
- Axios (HTTP client)

**Security tools (in worker container):**

- Subfinder, Amass — subdomain enumeration
- DNSX — DNS resolution and records
- HTTPX — HTTP probing and tech detection
- Naabu — port scanning
- TLSX — TLS certificate analysis
- Katana — web crawling
- Nuclei — vulnerability scanning (3000+ templates)
- Uncover — OSINT search (Shodan, Censys, etc.)
- AlterX + PureDNS — DNS permutation bruteforce
- fingerprintx — service fingerprinting
- cdncheck — CDN/WAF detection
- dnstwist — domain typosquatting detection
- Playwright + Chromium — visual reconnaissance screenshots

## Troubleshooting

### Worker OOM (Out of Memory)

If Nuclei or Playwright get killed (exit code -9), increase worker memory in `docker-compose.yml`:

```yaml
worker:
  deploy:
    resources:
      limits:
        memory: 8G # Increase as needed
```

### Scans returning 0 results

Check if your IP is being rate-limited/blocked by the target. The pipeline logs HTTP 429 counts — look for `Adaptive throttle` messages:

```bash
docker compose logs worker | grep -i "throttle\|429"
```

### API not starting

Check migration status:

```bash
docker compose logs api | grep -i "migration\|error"
docker compose exec api alembic current
```

### Frontend can't reach API

Ensure `VITE_API_BASE_URL` matches your API port:

```bash
# In docker-compose.yml, ui service
VITE_API_BASE_URL: http://localhost:18000
```

### Rebuilding a single service

```bash
docker compose build api && docker compose up -d api
docker compose build worker && docker compose up -d worker
```

## License

Proprietary — All Rights Reserved.
