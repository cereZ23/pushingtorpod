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
- **Arco UX/qualità (28-29 lug, PR #39-54)** — 6 UX quick-win, toast rollout (10 view),
  paginazione endpoint, config ESLint (era assente → lint morto) + lint a 0, dedup HSTS,
  concurrency 2→3, fix DOCX compliance.
- **Arco qualità-scan "scan solo i vivi" (PR #46-54)** — misconfig probe paralleli (30min→~1min)
  + skip IP morti; nuclei salva output parziale al timeout + **batching** (ogni template su ogni
  target vivo, validato T3: 9→27 finding, `coverage_complete=True`); discovery non espande più il
  **netblock del provider** (fine dei 792 IP di terzi); **disattivazione IP morti** post-naabu;
  **dedup finding per IP** (network FTP/SSH + SSL cipher, SNI-safe); **fix conteggi dashboard**
  incoerenti ("3 high" fantasma → allineati OPEN+attivi su ~12 query/11 file).
- **Gestione tenant per superuser (31 lug)** — chiarito il modello (superuser piattaforma → crea
  il *cliente* + owner; amministra per-tenant via switch). Nuova pagina **Tenants** superuser-only
  (`/admin/tenants`, endpoint `GET /api/v1/tenants/overview`) con owner + conteggi utenti/asset e
  "Manage" (entra nel tenant → Users); banner "Managing users for: X" + selettore inline in Users.
  Bug collaterali fixati: onboarding 500 su validazione (ValueError non serializzabile, #57), 500
  RLS su `seeds` senza tenant context (#58), login 401 mascherato da "No refresh token" (#59).
- **Arco qualità finding / audit imbuto EASM (31 lug, PR #62-69)** — audit dell'imbuto (nostro vs
  reference ProjectDiscovery) → **piano a 5 pilastri anti-FP/FN**. Fatti:
  - **#1 loop discovery** (#66): i SAN dei certificati (tlsx) rientrano come asset SUBDOMAIN in-scope
    (`_upsert_hostname_assets`; terzi su cert condivisi esclusi) — prima si buttavano via.
  - **#2 esposizione vs igiene** (#67): ogni finding ha un `tier` (`finding_tier`); board con tab
    Exposures|Hygiene|All, default Exposures → l'igiene (header/cipher/SPF) non seppellisce il segnale.
  - **#3 deep-ID (parziale)** (#68): identificazione appliance dai certificati (serial Fortinet nel CN
    → FortiGate-100D + serial, come Shodan); check `DEV-001` + CLI `scripts/fortifind.py`.
  - **#4 loop segna-FP** (#69): bottone "Mark false positive" → soppressione **permanente** (l'upsert
    nuclei non tocca lo status, misconfig riapre solo i FIXED → i FP non tornano).
  - Pulizia rumore: rimosso "No SCT" (falso positivo su ogni cert, #63) + **cancellati 117** finding
    SCT da tutti i tenant in prod; asset-detail finding host-level + conteggi coerenti (#62); cloud
    provider "(estimated)" (#65); nuovo **EXP-012** per cluster di porte non-web non identificate (#64).
- **Health engine nuclei — detection canary (1 ago, PR #71)** — primo passo del pilastro #5.
  Sappiamo che nuclei *gira* ma non se *rileva* ciò che deve. Canary: `nuclei -dast` contro un
  target noto (Google Firing Range → `reflected-xss`, **provato live**) → verifica che il template
  atteso scatti, altrimenti engine-health rosso. `evaluate_canary` (puro) + task self-contained
  (scarica i fuzzing-templates se assenti) + `GET/POST /health/scan-engine` (superuser) + cache Redis.
- **Vuln-scan performance + affidabilità scan (1-2 ago, PR #89-92)** — arco nato dal vivo mentre
  uno scan T2 falliva a 60 min:
  - **Pruning host morti prima di nuclei (#89)** — il wall-clock del vuln-scan era dominato dalla
    *tassa di timeout* di nuclei su host morti-ma-prima-vivi (soft-404 becca solo i 200; i 5xx/timeout
    passavano e ognuno costava ~`-mhe 50 × -timeout 10s` ≈ 500s di socket appesi → FAILED a 60 min).
    `detect_dead_hosts` (probe root+/robots https+http) instrada i morti nella **pass leggera
    SSL/takeover** (fuori dal loop CVE), preservando cert/takeover. **Provato dal vivo**: da FAILED-a-
    60min a **pass da 6-34s / 0 errori**. Flag `nuclei_prune_dead_hosts`.
  - **Watchdog stale-scan (#92)** — reaper Celery Beat (ogni 5 min) che auto-**FAILa** gli scan
    `RUNNING` fermi oltre *budget-tier + grace* (heartbeat = ultimo PhaseResult, no migration). Chiude
    lo **zombie** lasciato quando un worker muore a metà (deploy/OOM) — il `time_limit` interno non
    scatta senza processo vivo. Soglia generosa (mai reare uno scan lungo-ma-vivo). Config +8 test.
  - **Fix Duration timezone (#90)** — il backend serializza datetime **naive senza `Z`** → il browser
    li leggeva come ora locale → Duration gonfiata dell'offset UTC (uno scan di 31 min mostrato "2h27m"
    in CEST). `parseApiDate` (naive→UTC) nel formatter condiviso + durate ScanDetail. Corregge durate
    e orari in tutta l'app, senza toccare l'API.
  - **Messaggio Test-alert chiaro (#91)** — "Failed: webhook" (sembrava un 500) ora riporta il
    *perché* + segnala l'URL placeholder del seed-defaults.
  - Chiarito **`xss-fuzz`**: NON è una falla né il DAST — è un template `http/vulnerabilities/generic/`
    (tag `xss,vuln`, no `fuzzing:`, gira senza `-dast`), detection XSS legittima su T2. Gating DAST intatto.
- **Robustezza pipeline: PARTIAL first-class + bulk-retest + rischio servizio (1 ago, PR #82-87)** —
  arco "scanner correctness":
  - **PARTIAL first-class (#82, #86, #87)**: `PhaseStatus.PARTIAL` (no migration, VARCHAR) con
    `completed_at`; criterio unico `_classify_phase_outcome` (coverage nuclei / flag `partial` /
    contatori standard `items_total|succeeded|failed|skipped`); **0/N riusciti → FAILED** (non
    COMPLETED); `skipped` **informativo** (esclusioni volontarie non degradano la fase, solo i
    fallimenti reali). Propagazione: rollup scan-level (`completeness`+`partial_phases`), notifica
    "partial coverage", API + banner UI ambra. Contatori `items_*` adottati in **DNS/HTTPX/TLSx/Naabu/
    DAST/misconfig** (failed = errore reale del tool, non "trovato nulla").
  - **Bulk retest sbloccato (#83)**: `/findings/{finding_id:int}/retest` con converter `:int` →
    `bulk/retest` non è più catturata dalla parametrica (order-independent).
  - **Rischio servizio spiegabile e persistito (#84, #85, #86)**: `calculate_service_risk` riusa i
    primitivi di asset/finding (`compute_finding_score`/`HIGH_RISK_PORTS`/`_get_risk_level`);
    **correlazione finding↔servizio via `matched_at`/porta** (SSH non eredita più la CVE del web a
    piena gravità; altri finding = contesto ridotto 0.5×). **Persistito** su `Service` (colonne
    risk_score/level/components, migration 023, calcolo in fase 11 batch) → API **sort/filter globale**
    (`sort_by=risk_score` NULL-last, `min_risk_level` validato→422) **prima** della paginazione; UI:
    colonna Risk + breakdown `risk_components` espandibile + dropdown filtro. Backfill al prossimo scan.
- **DAST attivo end-to-end + Scan Authorizations (1 ago, PR #73-75)** — fase **9d `_phase_9d_dast`**
  (`katana -f qurl` → `nuclei -dast -fa`), gated **hard**: T3 **+** ScanAuthorization attiva (finestra
  `valid_from/until` verificata) **+** `dast_enabled` off di default; immagine worker con
  `projectdiscovery/fuzzing-templates` (i bundle non hanno SQLi/XSS). UI: descrizioni per-tier +
  badge "DAST" su T3, progresso scan. Nuova pagina **Scan Authorizations** (store + view +
  nav Configuration + rotta `settings/scan-authorizations`), create/revoke **admin-only**.
- **Inferenza version→CVE — fase 9e (1 ago, PR #76)** — *il differenziatore*: fingerprintiamo già
  product/version e arricchiamo i CVE con EPSS/KEV, ma non trasformavamo il fingerprint **in** CVE
  (dipendevamo solo dal match template nuclei → "0 CVE" su host reali). Ora `cve_inference.py` (puro,
  mappa curata product→CPE + parsing NVD 2.0) + fase 9e: per ogni servizio cerca i CVE noti (NVD via
  CPE, **cache Redis per-CPE** cross-run, coppie distinte cap + rate-limit) → finding **presumptive**
  con EPSS/KEV. Trova CVE senza template nuclei e funziona **anche su host che filtrano i probe**.
- **Il tier di default (T1) ora trova le CVE (1 ago, PR #77)** — l'exclude-tags di nuclei droppava
  `sqli,xss,ssrf,ssti,rce` sul T1, che però sono anche i **CVE matcher version/path-based** (benigni,
  senza payload) → causa vera dello "0 CVE" sul default. Fix: exclude-tags **config-driven**
  (`nuclei_exclude_tags_t1/t2/t3`, reversibile da env), T1 tiene esclusi solo i payload-sender veri
  (`intrusive,fuzz,dos,bruteforce,upload` — la protezione contro il blacklist Azure resta) e ammette
  i CVE matcher. Test che blinda l'invariante.
- **Porte DB/admin scoperte su ogni tier (1 ago, PR #79)** — la top-1000 di naabu **manca**
  redis 6379/mongo 27017/memcached 11211/kibana 5601/rabbitmq 15672 (validato sul worker), e il
  `top_ports` per-tier era codice morto. Fix: unione `-tp` + `-p <naabu_sensitive_ports>` (naabu fonde
  i due, validato) → un datastore esposto (finding EASM top-value) ora si vede su T1/T2/T3 e nel rescan.
- **Pagina Technologies navigabile + icone (1 ago, PR #78, #80)** — card cliccabili → lista Services
  **filtrata per tecnologia** (search esteso all'array JSON `http_technologies`, così jQuery/Bootstrap/
  Analytics atterrano su liste piene); icona brand (CDN simple-icons) con **fallback monogram colorato**
  (mai più quadrati vuoti / lettere nude). *Nota: se la rete del viewer blocca jsdelivr si vedono i
  monogram; icone brand garantite = self-host `simple-icons` inline (follow-up).*
- **Fix UX gestione tenant (30 lug)** — bug RBAC vero: due `currentTenantId` separati (dati vs
  permessi) → dopo login/switch un admin non-superuser perdeva le voci admin finché non ricaricava.
  Unificato il source-of-truth (auth deriva dal tenant store). + switcher chiaro (mono-tenant
  statico, badge/CTA superuser, toast a switch, niente più push forzato a `/`), empty-state
  "Nessun workspace" (`NoTenantState.vue`) al posto del "No tenant selected" nudo, refetch tenant
  dopo onboard, clear-before-refetch sulle liste (niente flash del tenant precedente).

---

## P0 — Rischio / correttezza (fare adesso)

_Cose che possono causare perdita dati, incidenti, o vendere un artefatto sbagliato._

- [ ] **Auto-close coverage-aware (consumer per-detector)** — _in corso, ~85%._ Il ledger `scan_coverage`
  oggi **osserva ma non decide** (nessun consumer lo legge → nessun falso FIXED possibile). Fondazione in
  prod: scan-policy identity + rule resolver + detector catalog + coverage ledger (#95); pass-wiring dei 4
  pass nuclei (#96); fix contratto producer→wiring — un fallimento restituito come dict
  (`{"status":"failed"}`/`no_urls`/`None`) non diventa più COVERED (#97).
  **Il vecchio auto-close tenant-wide resta INTATTO finché il consumer non è completo e validato.**
  Fail-closed ovunque: "meglio un falso open che un falso fixed". Ordine approvato:
  1. **Gate #1** — scan piccolo in prod + verifica ledger reale (COVERED/PARTIAL/FAILED con `policy_hash`
     coerenti). `scan_coverage` era vuota perché nessuno scan era girato dopo il deploy del wiring.
  2. **P-B catalogo osservazionale** — chiamare `persist_catalog` nei 4 pass. **Vincolo single-snapshot**:
     revision, manifest, catalogo e coverage devono derivare dallo **stesso** snapshot delle regole
     (resolve snapshot → revision → manifest → enumera detector dallo stesso snapshot → persist_policy →
     persist_catalog → record_pass_coverage). Mai rileggere il filesystem separatamente tra policy e
     catalogo (race se i template cambiano durante l'emissione).
  3. **P-A misconfig → ledger** — misconfig NON è nuclei-template-based: policy-identity propria basata sul
     **digest canonico dei controlli attivi**.
  4. **P-C streak + marker** — migrazione su `Finding`: `eligible_miss_streak`, `last_eligible_run_id`,
     `last_eligible_miss_at` (diagnostica) e `last_detected_scan_run_id` (marker esplicito di rilevazione,
     preferito a `last_seen < run.started_at`). Update atomico sotto lock (no doppio incremento su
     retry/worker concorrenti). Una run **non eleggibile azzera** lo streak (conservativo: ritarda una
     chiusura, mai la inventa).
  5. **Consumer fail-closed** — chiude un finding solo se: discovery sana + asset COVERED nel pass corretto
     + detector applicabile alla policy + finding non rilevato nel run + **2 miss eleggibili consecutivi**.
  6. **Spegnere il vecchio auto-close tenant-wide** (solo dopo consumer completo e validato).
  - Prereq scoperti (non costruiti in fase di piano): `persist_catalog` non era mai chiamato (catalogo vuoto
    → condizione "detector applicabile" non valutabile); `Finding` non aveva campo streak/run-di-rilevazione.

- [x] **Espansione CIDR scansionava il netblock del PROVIDER** — **[FATTO, PR #50]** la fase 1c faceva
  WHOIS su ogni IP risolto ed espandeva il netblock in tutti i /32; ma quel netblock è del **provider
  di hosting**, non del target → un dominio (itsright.it) esplodeva in **792 IP di altri clienti del
  provider** (fuori scope, rallenta tutto). Fix: espandere solo netblock il cui **org WHOIS matcha il
  target** (token dai domini radice), non "non è un cloud noto".
  - **[FATTO, PR #53]** disattivazione IP morti (zero porte aperte) post-naabu → self-clean dei
    tenant esistenti (cere: ~792 IP → disattivati al prossimo scan).
  - **[FATTO, PR #51]** dedup finding network per IP (FTP/SSH su host stesso-IP → 1, in fase 10).
  - **[FATTO, PR #54]** dedup finding SSL server-config per IP (weak cipher/TLS-version → 1);
    i finding cert-specific (scaduto/self-signed/mismatch) restano per-host (SNI-safe).

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

- [x] **Conteggi finding incoerenti tra endpoint** — **[FATTO, PR #52]** il banner "Action Required"
  mostrava "3 high" assenti dalla lista: `get_tenant_dashboard.findings_by_severity` contava **tutti gli
  stati su tutti gli asset** (i 3 high erano fixed/soppressi su IP morti). Canonico = **OPEN + asset
  attivi** (come la lista findings). Allineati ~12 query in 11 file (dashboard, tenants, risk_summary,
  exposure, findings/stats, reports, report_generator, finding_repository, asset_detail, assets) —
  aggiunto `is_active` e/o `status=OPEN` dove mancava.

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
- [ ] **Qualità EASM — pilastri #3 (pesante) e #5** (dal piano a 5 pilastri, PR #62-69):
  - **#3 deep service-ID**: probe protocollo-specifici (fgfm/541, RDP-NTLM su porte non-standard come
    1042/1043) + **`nmap -sV` di secondo passaggio** sugli Unknown vivi dietro firewall → identificare
    i servizi come fa nmap a mano (oggi restano "Unknown" e non generano finding mirati).
  - **#5 verifica + recall**: canary nuclei **fatto** (PR #71); restano — indicatore UI superuser,
    pannello coverage (`coverage_complete`/`truncated`) nello scan-detail, schedule beat giornaliero,
    e gate di **ri-verifica attiva** sui finding high-value prima di mostrarli.
  - Follow-up #1: route i 4 upsert-asset inline (fasi 1/2/3, crt.sh) via `_upsert_hostname_assets`;
    `run_dnsx` same-run sui nuovi SAN così si arricchiscono nello stesso scan.
  - Follow-up #3: estendere `device_fingerprint` a più vendor (Palo Alto, SonicWall, Cisco ASA) col
    serial/model nel cert.
- [~] **DAST attivo (nuclei -dast) + dashboard OWASP Top 10** — **[FASE DAST FATTA, PR #73-75]**
  `katana -f qurl` → `nuclei -dast -fa -t fuzzing-templates` trova vuln vere (reflected-XSS su Firing
  Range, provato live). Fatto: (1) immagine worker con **`projectdiscovery/fuzzing-templates`** (i
  bundle hanno solo template base, **niente SQLi/XSS**); (2) fase **`_phase_9d_dast`** gated **T3 +
  ScanAuthorization attiva + `dast_enabled`** off di default + rate-limit; (3) UI tier + pagina Scan
  Authorizations. **Limite onesto**: **signal-based** → prende XSS-riflesso, SQLi error-based, SSRF via
  OAST; **non** blind/UNION/DOM/logica (serve ZAP/Burp — backlog). **Resta**: la **dashboard OWASP Top
  10** (classificatore finding→A01-A10 + 10 card + filtro `?owasp=`), con A04/A09 onestamente vuoti da
  esterno — da costruire quando ci sono dati DAST reali. Follow-up gated: pannello per-run con scope +
  ack, banner `dast_skipped` friendly nello ScanDetail, scope-matching reale delle authorization.
- [ ] **Detection quality — follow-up (dopo PR #76-79)** — piccoli, alto rapporto valore/sforzo:
  - **#4 rumore `info`**: i finding `info` di service-detection non dovrebbero contare come "findings"
    nei conteggi/board (default board già su Exposures, ma i contatori li includono).
  - **version→CVE**: allargare la mappa curata `_PRODUCT_CPE` (oggi ~20 prodotti) e valutare una
    `nvd_api_key` in prod per togliere il rate-limit anonimo (6s/coppia).
  - **porte**: verificare al primo scan reale che i datastore esposti emergano (redis/mongo) e, se
    utile, un finding `EXP` dedicato "datastore esposto senza auth".
- [ ] **Follow-up robustezza pipeline / rischio (dopo PR #82-87)**:
  - **PARTIAL per-target fine-grained** per i tool batch (dnsx/httpx/naabu/tlsx): oggi il `failed` è
    tutto-o-niente sul run (i runner non tracciano l'errore per-target). Per un partial granulare
    servirebbe far riportare ai runner gli errori per-host (come già fa misconfig e nuclei via
    `coverage_complete`).
  - **Backfill rischio servizio**: i servizi esistenti hanno risk NULL finché la fase 11 del prossimo
    scan non gira. Opzionale: comando/endpoint di **recalc on-demand** per popolarli subito.
  - **Precisione correlazione**: `matched_at` è best-effort (porta esplicita o default di schema); i
    finding senza URL restano contesto asset-level (documentato in `finding_scope`).
- [ ] **Tuning volume vuln-scan T2 (dopo il pruning #89) — da validare su tenant grande**: anche col
  pruning, un sito *grande* in T2 fa tanto lavoro (host vivi × endpoint katana × template, batch
  sequenziali, budget ~54 min) e può sfiorare il budget → troncamento. Leve, **una alla volta e
  misurate** (durata fase 9 ↓, `coverage_complete` resta True, conteggio finding invariato):
  1. **`nuclei_max_endpoints_per_host` 200 → ~75 (tier-aware)** — taglio di volume maggiore, rischio
     recall basso (lo shape-dedup già collassa `/id=1..N`); tenere 200 per T3.
  2. **`-timeout` 10 → 6s (T1/T2)** — riduce l'attesa sugli host vivi-ma-lenti; T3 resta 10s.
  3. **(se serve) batching 2× parallelo** — ora sicuro *dopo* il pruning (niente più socket appesi);
     gate basso, monitorando i 429 via adaptive-throttle.
  Non urgente: il pruning ha già reso i T2 correnti veloci; serve solo se un tenant davvero grande
  resta lungo. NON fare per primo: alzare `-c`/rate o abbassare `-mhe` (regressione documentata).
- [x] **Watchdog stale-scan** — **[FATTO, PR #92]** reaper beat auto-FAIL degli scan zombie (worker
  morto a metà). Fase B futura: colonna `ScanRun.heartbeat_at` timbrata intra-nuclei per reaping più
  veloce (oggi soglia generosa = budget-tier + grace, ~90 min per T2).

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
