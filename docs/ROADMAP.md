# NimbusGuard — Roadmap to Production

**Stato attuale**: MVP funzionante. Pipeline scan solida, UI completa, 90% backend reale.
**Obiettivo**: SaaS vendibile a CISO italiani (500-5000 dipendenti).
**Stima**: 8 settimane per "vendibile", 16 settimane per "enterprise-ready".

> **Revisione stato — 2026-07-27**: questo file è stato scritto il 18 aprile 2026 e mai più aggiornato,
> nonostante un intero sprint di sicurezza (tenant isolation, RLS, kill-switch), un digest di retention e
> un hardening UX siano stati completati nel frattempo. Ogni voce sotto è stata riverificata contro il
> codice attuale il 2026-07-27 (non solo i commit message). Tag: **[FATTO]**, **[PARZIALE]**, **[NON FATTO]**,
> **[NON VERIFICATO]** (non controllato in questo passaggio, non significa "non fatto"). Questo è lavoro
> preparatorio per scrivere insieme un roadmap unico consolidato — nel frattempo questo file resta come
> riferimento storico del piano di aprile.

---

## Sprint 1 — Fix the Lies (settimana 1)

Tutto ciò che dice "funziona" nella UI ma non funziona va fixato o rimosso.

- [x] **Alert test endpoint**: mandare notifica vera (Slack/email/webhook) invece di fake 200 OK — **[FATTO 2026-07-27]** il backend invia davvero da tempo (`alert_policies.py:496-590`), ma il frontend ignorava la risposta e mostrava sempre "successo"; corretto questa sessione (`AlertPolicies.vue`)
- [x] **Scan diff/snapshot**: popolare snapshot su scan esistenti con migration script, oppure mostrare messaggio utile — **[FATTO]** snapshot creato al volo (`scan_compare_service.py:102-111`), empty-state azionabile in `ScanDiffView.vue:881-901`
- [x] **GitHub dorking (phase 1b)**: o implementare o rimuovere dalla UI — **[FATTO 2026-07-27]** il backend l'aveva già rimossa dalla pipeline (`1a2be48`), ma l'etichetta era rimasta orfana in `ScanDetail.vue`; rimossa questa sessione
- [x] **Compliance ISO 27001**: aggiungere disclaimer "Beta — X/93 controlli mappati" oppure completare il mapping — **[FATTO]** disclaimer esplicito su scope (15 controlli tecnologici) presente nella UI on-demand da prima; questa sessione propagato anche al PDF generato e alla UI di scheduling, dove mancava

**Deliverable**: zero feature fake visibili all'utente. — **quasi centrato**: nessuna feature finta rimane visibile senza etichetta; il mapping ISO resta parziale ma ora è dichiarato ovunque, non solo nella UI on-demand.

---

## Sprint 2 — Security Hardening (settimana 2-3)

Senza questo non puoi gestire dati di clienti.

- [x] **Rate limiting API**: 60 req/min per utente — **[FATTO]** `app/main.py:354` (`@limiter.limit("60/minute")`)
- [x] **Rate limiting scan trigger**: max 1 scan running per progetto — **[FATTO]** guard su `ScanRun.status` in `app/api/routers/projects.py:567,1403,1541`
- [ ] **Secrets**: migrare da .env a Docker secrets o HashiCorp Vault — **[PARZIALE]** `app/utils/secrets.py` ha un `SecretManager` custom (backend file Fernet-encrypted + env), non un'integrazione Vault/Docker secrets reale
- [ ] **SMTP/Slack token rotation**: documentare procedura — **[NON VERIFICATO]**
- [x] **API key per tenant**: permettere accesso programmatico senza JWT — **[FATTO]** modello `APIKey` (`app/models/auth.py:132-151`), `generate_api_key`/`verify_api_key` (`app/core/security.py:240`), audit log sull'uso
- [x] **CORS hardening**: verificare whitelist origin — **[FATTO]** whitelist + controllo esplicito su wildcard (`app/config.py:52,373`)
- [x] **Audit log completeness**: ogni azione admin deve essere loggata — **[FATTO]** `app/core/audit.py`, `app/api/routers/audit.py`

**Deliverable**: superare un penetration test base. — la parte di secrets management resta il gap più concreto verso "enterprise-ready" (Vault/Docker secrets, non file Fernet locale).

---

## Sprint 3 — Change Detection (settimana 3-4)

Questo è il valore #1 per un CISO. "Cosa è cambiato dalla settimana scorsa?"

- [x] **API**: `GET /tenants/{t}/changes?since=7d` — **[FATTO]** `app/api/routers/dashboard.py:531-532`, `app/api/routers/exposure.py:427-428`
- [x] **Dashboard widget**: "5 nuovi subdomain, 2 nuovi critical" con trend arrow — **[FATTO]** commit `28cc090`, hero card dashboard
- [x] **Email digest**: report settimanale automatico — **[FATTO]** commit `65697cc`, `app/services/exposure_digest.py` + `app/tasks/exposure_digest.py` (lunedì 08:00, opt-in via `weekly_digest_enabled`)
- [ ] **Webhook on change**: trigger su nuovo asset/finding critico — **[NON FATTO]** esiste solo il webhook di fine-scan, nessun trigger per singolo evento

**Deliverable**: il CISO apre la dashboard e in 10 secondi sa se c'è qualcosa di nuovo. — **centrato per 3 voci su 4**; manca solo il webhook per-evento.

---

## Sprint 4 — Report & Compliance (settimana 4-5)

Per vendere a enterprise serve documentazione che il CISO possa dare al board.

- [ ] **Completare ISO 27001**: mappare tutti i 93 controlli Annex A — **[NON FATTO]** fermo a 15 controlli tecnologici, ma ora dichiarato ovunque (v. Sprint 1)
- [ ] **Aggiungere NIS2**: mapping specifico per direttiva europea — **[NON FATTO]**
- [ ] **Aggiungere AgID**: linee guida ABSC per PA italiana — **[NON FATTO]**
- [x] **PDF executive report**: logo aziendale personalizzabile, grafici trend, confronto periodo — **[FATTO]** (v. Reports in ROADMAP.md); logo personalizzabile non riverificato puntualmente
- [ ] **Export compliance evidence**: ZIP con finding + remediation per ogni controllo — **[NON VERIFICATO]**
- [x] **Scheduled report delivery**: verificare che l'invio email funzioni end-to-end — **[FATTO, MA CON BUG SCOPERTO]** `app/tasks/report_delivery.py` funziona e usa lo stesso generator dell'on-demand; **però** un report ISO27001/SOC2 richiesto in DOCX viene silenziosamente declassato al template "executive" generico (`report_generator.py:872-874`), perdendo tutto il mapping Annex A — bug strutturale da fixare, non incluso nei quick-win di questa sessione

**Deliverable**: report PDF che il CISO porta in CDA. — **il PDF va bene, il DOCX per i report di compliance no** (downgrade silenzioso, vedi sopra).

---

## Sprint 5 — Onboarding & UX (settimana 5-6)

Primo impatto = prima impressione. Deve funzionare in 2 minuti.

- [ ] **Wizard onboarding**: dominio → scan automatico → risultati — **[NON VERIFICATO]**
- [ ] **Empty state su ogni pagina**: spiegare cosa fare, non mostrare tabelle vuote — **[PARZIALE]** qualità molto variabile tra le view (es. `ScanDiffView.vue` ha un empty-state azionabile; altre no) — dettaglio completo nell'audit UX del 2026-07-27
- [ ] **Dashboard ridisegnata**: risk score grande, trend 30 giorni, top 5 findings, prossimo scan — **[PARZIALE]** il banner "Action Required" con riepilogo rischio esiste (`DashboardView.vue:1120-1170`); lo spec completo (trend 30gg, prossimo scan) non riverificato
- [ ] **Notifiche in-app**: bell icon con "Scan completato", "3 nuovi critical" — **[NON FATTO]** esiste solo un sistema di toast temporanei (scompaiono dopo qualche secondo), non un centro notifiche persistente con bell icon
- [ ] **Tenant switcher**: se utente è su più tenant, switch rapido — **[NON VERIFICATO]**
- [ ] **Dark mode fix**: verificare tutti i componenti — **[NON VERIFICATO]** (dark: classes presenti diffusamente, ma non auditate esaustivamente)

**Deliverable**: demo in 2 minuti senza spiegazioni. — copertura reale non verificata a fondo in questo passaggio; il gap più chiaro è l'assenza di un centro notifiche persistente.

---

## Sprint 6 — Scale & Reliability (settimana 6-7)

Per gestire più di 1 cliente.

- [ ] **Load test**: simulare 10 tenant × 500 asset × scan concorrenti — **[NON FATTO]** nessun artefatto locust/load-test trovato
- [x] **Database indexing**: verificare query slow su tabelle grandi — **[FATTO]** `alembic/versions/016_add_missing_indexes.py` (2026-03-15, precede entrambi i roadmap)
- [ ] **Worker autoscaling**: scale workers basato su coda Redis — **[NON FATTO]**
- [ ] **Backup automatico**: pg_dump giornaliero su S3/MinIO con retention 30 giorni — **[PARZIALE]** `scripts/backup.sh` fa pg_dump locale via cron, retention 7 giorni, **nessun upload S3/MinIO**
- [x] **Health monitoring**: /health endpoint con check DB + Redis + worker alive — **[FATTO]** `app/api/routers/health.py`
- [x] **Error tracking**: Sentry integration per API + worker — **[FATTO]** `app/utils/logger.py:175-193` (`setup_sentry`, integrazioni Celery/SQLAlchemy/Redis)
- [ ] **Log aggregation**: stdout JSON → Loki/CloudWatch — **[PARZIALE]** formato JSON pronto, invio effettivo a Loki/CloudWatch non verificato

**Deliverable**: sistema che regge 10 clienti senza intervento manuale. — **il backup è il gap più rischioso**: nessuna copia fuori dal server locale.

---

## Sprint 7 — Go-to-Market (settimana 7-8)

- [ ] **Landing page**: easm.securekt.com con pricing, demo, signup — **[NON VERIFICATO]** (fuori perimetro codice)
- [ ] **Self-service signup**: registrazione → tenant → progetto → primo scan — **[NON VERIFICATO]**
- [ ] **Stripe integration**: billing mensile — **[NON VERIFICATO]**
- [ ] **Demo video**: aggiornare con UI attuale — **[NON VERIFICATO]**
- [x] **Documentazione utente**: API docs (Swagger già c'è) — **[FATTO]** FastAPI auto-docs su `/docs`; guida setup/FAQ non verificate
- [ ] **Terms of service + Privacy policy** — **[NON VERIFICATO]**

**Deliverable**: un cliente può comprare e usare senza parlare con nessuno. — voci di business/marketing, non verificabili da codice; solo gli API docs sono confermati.

---

## Sprint 8 — Enterprise Features (settimana 9-16)

Per clienti enterprise (>1000 dipendenti, >5000€/mese).

- [ ] **SSO SAML**: completare flow — **[PARZIALE]** migration `010_add_user_sso_fields` suggerisce solo groundwork iniziale, flow completo non verificato
- [ ] **RBAC granulare**: permessi per progetto — **[NON VERIFICATO]**
- [ ] **API key management**: create/revoke/rotate da UI — **[NON VERIFICATO]** (il modello backend esiste, v. Sprint 2)
- [ ] **SLA monitoring** — **[NON VERIFICATO]**
- [ ] **White-label** — **[NON VERIFICATO]**
- [ ] **Multi-region** — **[NON VERIFICATO]**
- [ ] **SOC 2 Type II** — **[NON VERIFICATO]**

_Sprint 8 ha ricevuto una copertura più leggera in questa revisione — utile un passaggio dedicato se diventa priorità._

---

## Priorità per Impatto

```
                    IMPATTO BUSINESS
                    ↑
                    |
    Sprint 3        |  Sprint 7
    (Change Det.)   |  (Go-to-Market)
                    |
    Sprint 1        |  Sprint 4
    (Fix Lies)      |  (Compliance)
                    |
    ─────────────────────────────→ EFFORT
                    |
    Sprint 2        |  Sprint 6
    (Security)      |  (Scale)
                    |
    Sprint 5        |  Sprint 8
    (UX)            |  (Enterprise)
```

**Se hai solo 2 settimane**: Sprint 1 + Sprint 3 (fix lies + change detection). — **entrambi sostanzialmente fatti** ad oggi.
**Se hai solo 4 settimane**: + Sprint 2 + Sprint 5 (security + UX). — Sprint 2 quasi fatto (manca secrets management vero); Sprint 5 il meno verificato.
**Se vuoi vendere**: tutti gli 8 sprint. — gap principali oggi: backup off-site (Sprint 6), secrets Vault (Sprint 2), DOCX compliance downgrade (Sprint 4), centro notifiche persistente (Sprint 5).

---

## KPI per Sprint

| Sprint | KPI                                | Target             | Stato 2026-07-27 |
| ------ | ---------------------------------- | ------------------ | ---------------- |
| 1      | Feature fake visibili              | 0                  | Raggiunto |
| 2      | Vulnerabilità note                 | 0 critical, 0 high | Non ri-scansionato in questa revisione |
| 3      | Tempo per capire "cosa è cambiato" | < 10 sec           | Probabile, non misurato |
| 4      | Controlli ISO mappati              | 93/93              | 15/93 |
| 5      | Tempo onboarding nuovo utente      | < 2 min            | Non verificato |
| 6      | Uptime sotto carico (10 tenant)    | > 99.5%            | Nessun load test eseguito |
| 7      | Conversion rate landing → signup   | > 5%               | N/A (fuori perimetro codice) |
| 8      | Enterprise pilot chiusi            | ≥ 2                | Non tracciato qui |
