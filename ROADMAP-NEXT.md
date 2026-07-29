# PushingTorPod — Roadmap consolidato (2026-07)

> Roadmap unico e forward-looking, scritto il **2026-07-27**. Sostituisce i due file
> storici `ROADMAP.md` (apr, P0-P3) e `docs/ROADMAP.md` (apr, "NimbusGuard" sprint 1-8),
> che restano come archivio. Ogni voce qui è basata sui due audit del 2026-07-27
> (frontend/UX + backend/pipeline/sicurezza), verificati contro il codice — non sui
> commit message. Riferimenti `file:line` dove noti.

## Stato attuale (verificato)

Piattaforma EASM funzionante: pipeline di scan solida, UI completa, multi-tenant con
isolamento hard (tenant-guard enforce su API/worker/beat, RLS Postgres, ruolo DB non-owner).
Change detection e digest settimanale attivi. Report PDF (executive/technical/ISO/SOC2) con
remediation playbook. Integrazioni Slack/Teams/PagerDuty (outbound).

**Gap che contano** (dettaglio nelle sezioni P0/P1): backup solo locale, secrets su file
Fernet, DOCX di compliance che degrada silenziosamente, sistema di toast adottato da 1 view
su 38, 92 errori ESLint soppressi in CI.

## Fatto di recente

- **PR #39 (2026-07)** — 6 UX quick-win: correttezza test-notifica, dialog di conferma
  eliminazione unificato, evidence JSON con highlight XSS-safe, disclaimer ISO nel PDF +
  scheduling, rimozione fase "GitHub Dorking" morta e 3 view stub.
- **Sprint 3 sicurezza (lug)** — tenant isolation enforce, RLS + tenant-GUC, ruolo DB
  dedicato, scan-authorization API, scope-gate, kill-switch + circuit breaker, CSV
  injection fix, detection-efficacy harness.
- **Retention** — digest settimanale esposizione + hero card dashboard.

---

## P0 — Rischio / correttezza (fare adesso)

_Cose che possono causare perdita dati, incidenti, o vendere un artefatto sbagliato._

- [x] **Espansione CIDR scansionava il netblock del PROVIDER** — **[FATTO, PR #50]** la fase 1c faceva
  WHOIS su ogni IP risolto ed espandeva il netblock in tutti i /32; ma quel netblock è del **provider
  di hosting**, non del target → un dominio (itsright.it) esplodeva in **792 IP di altri clienti del
  provider** (fuori scope, rallenta tutto). Fix: espandere solo netblock il cui **org WHOIS matcha il
  target** (token dai domini radice), non "non è un cloud noto". Follow-up: disattivare gli IP morti
  già creati per i tenant esistenti. **Dedup finding network/servizio per IP FATTO (PR #51)**: FTP/SSH
  su host che condividono lo stesso IP ora collassano in 1 (fase 10, i duplicati passano a suppressed).

- [ ] **Backup off-site** — oggi `scripts/backup.sh` fa solo `pg_dump` locale via cron,
  retention 7 giorni, **nessun upload S3/MinIO**. Un guasto del box = perdita totale.
  → aggiungere upload verso MinIO/S3 con retention 30gg e restore testato.
- [x] **DOCX di compliance degrada in silenzio** — ~~`report_generator.py:872-874`~~ **[FATTO,
  PR #39]** `generate_docx` ora alza `ValueError` invece del downgrade silenzioso; `/export/docx`
  risponde 400 per soc2/iso27001; la delivery schedulata forza PDF (contenuto corretto) con
  warning; la UI di scheduling disabilita DOCX per i tipi compliance.
- [ ] **Secrets fuori dal filesystem** — `app/utils/secrets.py` usa un `SecretManager`
  custom (file Fernet + env), non Vault/Docker secrets. Accettabile per il PoC, rischioso
  con dati cliente reali. → migrazione a Docker secrets (minimo) o Vault.

## P1 — Qualità prodotto (prossimo)

_Consistenza UX, salute del codice, qualità dei finding._

- [x] **Rollout del sistema di toast** — **[FATTO, PR #40]** 10 view settings/form migrate dai
  banner inline al toast store (success→`toast.success`, errori load/azione→`toast.error`),
  validazione form tenuta inline. Restano le view read-only (solo `error` di load) → follow-up.
- [x] **Paginazione lista endpoint asset** — **[FATTO, PR #41]** `AssetDetailView` ora ha
  ricerca su path/method + paginazione client-side (50/pagina, Prev/Next) invece del cap fisso
  a 50: tutti gli endpoint sono raggiungibili.
- [x] **ESLint ratchet** — **[FATTO, PR #42]** Scoperta: i "92 errori" non erano violazioni ma
  **parse error** — il frontend non aveva *nessun* config ESLint, quindi il linter era morto e
  `continue-on-error` li ingoiava. Aggiunto `.eslintrc.cjs` (vue3-essential + ts-recommended,
  `no-undef` off per TS), script `lint:ci`, e tolto `continue-on-error`: ora gli errori bloccano.
  Violazioni reali col config: 0 errori, 7 warning `no-explicit-any`. **[BURNDOWN FATTO, PR #44]**
  i 7 `(f as any).campo` erano cast inutili (i campi erano già sul tipo `Finding`) → rimossi →
  **lint ora 0 errori, 0 warning** (baseline pristina per il ratchet).
- [x] **Dedup finding HSTS** — **[FATTO, PR #43]** aggiunto `dedup_scope="root_domain"` al
  decoratore `@register`; HDR-004 lo usa: le finding HSTS di tutti i subdomain sotto lo stesso
  registrable domain (via `tldextract`, nuovo `app/utils/domains.py`) collassano in **1 finding
  per dominio** con gli host affetti in evidence (43 MEDIUM → 1 azionabile). 18 test.
- [ ] **Auto-close finding stale** — oggi cutoff a 5 minuti su singolo scan
  (`misconfig.py:1959-1980`) e solo `source=misconfig`, non "non visto negli ultimi 3 scan"
  né i finding nuclei. → estendere a N-scan e a tutte le sorgenti.
- [ ] **Audit loading-state** — solo ~11/38 view hanno spinner/skeleton; un terzo lampeggia
  vuoto al primo render. → skeleton coerente view per view.

## P2 — Feature / scala (backlog)

- [~] **Scan paralleli** — **[PARZIALE, PR #45]** `--concurrency=2` → `3` così i task leggeri
  (rerun single-phase, alert, digest) non restano FIFO-bloccati dietro uno scan pesante in corso.
  Tradeoff OOM accettato (12G, storia OOM a conc.2); mitigato da `worker_max_tasks_per_child`.
  Se l'OOM si ripresenta → coda `quick` dedicata (Opzione A). Autoscale/parallelismo pieno resta backlog.
- [ ] **Webhook per-evento** — oggi solo fine-scan; niente "started" né per-finding critico.
- [ ] **`POST scans/run` dedicato** (trigger da UI senza passare da endpoint generici) e
  **rate limit sull'endpoint SIEM push** (oggi illimitato).
- [~] **Performance scan** — **[PARZIALE, PR #46 + #48]** misconfig andava in timeout di fase
  (1800s) su tenant con molti IP: EXP-011 probava le porte sensibili **serialmente** per asset
  (681 IP × 3s ≈ 34 min). #46: pre-warm concorrente dei probe (cache per-processo) → ~1-2 min.
  #48 (principio *scan solo i vivi*): misconfig ora **scarta gli IP morti** (CIDR-expanded,
  `is_active` ma zero righe Service = nessuna porta aperta) → non li scansiona affatto, alla fonte.
  Resta: `fingerprintx` timeout 300s (`config.py:184`, target 60s); profiling memoria nuclei.
- [x] **Copertura nuclei — completa** — **[FATTO, PR #47 + #49]** Al timeout il subprocess veniva
  SIGKILLato e **tutto l'output del pass buttato** (findings: []) — perdita **silenziosa** di vuln.
  - #47: l'executor conserva l'output parziale nell'eccezione (vale per **tutti** i tool), nuclei
    recupera i finding già emessi + segna `truncated`, la fase espone `coverage_complete`.
  - #49 (la garanzia vera): `scan_urls_batched` spezza i target in lotti che rientrano nel timeout;
    un lotto che tronca viene **rispezzato e ritentato** (parziale scartato per non duplicare) fino
    a entrare → **ogni template gira su ogni target vivo**. Solo un singolo target genuinamente
    non-scannabile o l'esaurimento del budget di fase lascia un residuo, ed è **visibile**.
  Combinato con lo scan-solo-vivi (nuclei filtra già http-live; misconfig #48 scarta IP morti) il
  set è realistico e rientra. Resta minore: template custom davvero Italy-specific (oggi 1 su 16).
- [ ] **Feature enterprise** (grandi, su richiesta): authenticated crawling, k8s/etcd exposure,
  Slack bot interattivo, Terraform provider, GDPR PII mapping, ISO 27001 completo (15/93 → 93),
  NIS2/AgID mapping, SSO SAML end-to-end, RBAC per progetto, white-label, multi-region.
- [ ] **Scala** — 1000+ asset per tenant (non testato), result caching (skip asset invariati),
  archiviazione cold storage.

---

## Verifica end-to-end sospesa

I 4 item non guidati end-to-end in PR #39 (test-notifica, modale conferma, fase rimossa,
disclaimer PDF) restano da esercitare contro un backend che monti **questo** clone con dati
di test — l'ambiente locale attuale ha l'API di un altro clone con RLS che non espone i dati
alla membership di test. Coperti da `vue-tsc` + 2/6 guidati nel browser (incluso l'XSS).

---

_Copyright 2026 Andrea Ceresoni. Licensed under Apache 2.0._
