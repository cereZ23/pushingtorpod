# NimbusGuard — Roadmap to Production

**Stato attuale**: MVP funzionante. Pipeline scan solida, UI completa, 90% backend reale.
**Obiettivo**: SaaS vendibile a CISO italiani (500-5000 dipendenti).
**Stima**: 8 settimane per "vendibile", 16 settimane per "enterprise-ready".

---

## Sprint 1 — Fix the Lies (settimana 1)

Tutto ciò che dice "funziona" nella UI ma non funziona va fixato o rimosso.

- [ ] **Alert test endpoint**: mandare notifica vera (Slack/email/webhook) invece di fake 200 OK
- [ ] **Scan diff/snapshot**: popolare snapshot su scan esistenti con migration script, oppure mostrare messaggio utile ("Lancia 2 scan per vedere il diff")
- [ ] **GitHub dorking (phase 1b)**: o implementare o rimuovere dalla UI. Zero stub visibili all'utente
- [ ] **Compliance ISO 27001**: aggiungere disclaimer "Beta — 20/93 controlli mappati" oppure completare il mapping

**Deliverable**: zero feature fake visibili all'utente.

---

## Sprint 2 — Security Hardening (settimana 2-3)

Senza questo non puoi gestire dati di clienti.

- [ ] **Rate limiting API**: 60 req/min per utente, 5 scan concorrenti per tenant
- [ ] **Rate limiting scan trigger**: max 1 scan running per progetto (già nel codice, verificare enforcement)
- [ ] **Secrets**: migrare da .env a Docker secrets o HashiCorp Vault
- [ ] **SMTP/Slack token rotation**: documentare procedura
- [ ] **API key per tenant**: permettere accesso programmatico senza JWT
- [ ] **CORS hardening**: verificare whitelist origin
- [ ] **Audit log completeness**: ogni azione admin deve essere loggata

**Deliverable**: superare un penetration test base.

---

## Sprint 3 — Change Detection (settimana 3-4)

Questo è il valore #1 per un CISO. "Cosa è cambiato dalla settimana scorsa?"

- [ ] **API**: `GET /tenants/{t}/changes?since=7d` — nuovi asset, nuovi finding, asset rimossi
- [ ] **Dashboard widget**: "5 nuovi subdomain, 2 nuovi critical" con trend arrow
- [ ] **Email digest**: report settimanale automatico "Ecco cosa è cambiato"
- [ ] **Webhook on change**: trigger su nuovo asset/finding critico

**Deliverable**: il CISO apre la dashboard e in 10 secondi sa se c'è qualcosa di nuovo.

---

## Sprint 4 — Report & Compliance (settimana 4-5)

Per vendere a enterprise serve documentazione che il CISO possa dare al board.

- [ ] **Completare ISO 27001**: mappare tutti i 93 controlli Annex A (anche "non applicabile")
- [ ] **Aggiungere NIS2**: mapping specifico per direttiva europea
- [ ] **Aggiungere AgID**: linee guida ABSC per PA italiana
- [ ] **PDF executive report**: logo aziendale personalizzabile, grafici trend, confronto periodo
- [ ] **Export compliance evidence**: ZIP con finding + remediation per ogni controllo
- [ ] **Scheduled report delivery**: verificare che l'invio email funzioni end-to-end

**Deliverable**: report PDF che il CISO porta in CDA.

---

## Sprint 5 — Onboarding & UX (settimana 5-6)

Primo impatto = prima impressione. Deve funzionare in 2 minuti.

- [ ] **Wizard onboarding**: dominio → scan automatico → risultati. Zero configurazione
- [ ] **Empty state su ogni pagina**: spiegare cosa fare, non mostrare tabelle vuote
- [ ] **Dashboard ridisegnata**: risk score grande, trend 30 giorni, top 5 findings, prossimo scan
- [ ] **Notifiche in-app**: bell icon con "Scan completato", "3 nuovi critical"
- [ ] **Tenant switcher**: se utente è su più tenant, switch rapido
- [ ] **Dark mode fix**: verificare tutti i componenti

**Deliverable**: demo in 2 minuti senza spiegazioni.

---

## Sprint 6 — Scale & Reliability (settimana 6-7)

Per gestire più di 1 cliente.

- [ ] **Load test**: simulare 10 tenant × 500 asset × scan concorrenti
- [ ] **Database indexing**: verificare query slow su tabelle grandi (findings, assets)
- [ ] **Worker autoscaling**: scale workers basato su coda Redis
- [ ] **Backup automatico**: pg_dump giornaliero su S3/MinIO con retention 30 giorni
- [ ] **Health monitoring**: /health endpoint con check DB + Redis + worker alive
- [ ] **Error tracking**: Sentry integration per API + worker
- [ ] **Log aggregation**: stdout JSON → Loki/CloudWatch

**Deliverable**: sistema che regge 10 clienti senza intervento manuale.

---

## Sprint 7 — Go-to-Market (settimana 7-8)

- [ ] **Landing page**: easm.securekt.com con pricing, demo, signup
- [ ] **Self-service signup**: registrazione → tenant → progetto → primo scan
- [ ] **Stripe integration**: billing mensile (299€/mese starter, 799€ pro)
- [ ] **Demo video**: aggiornare con UI attuale (script già pronto in docs/)
- [ ] **Documentazione utente**: guida setup, FAQ, API docs (Swagger già c'è)
- [ ] **Terms of service + Privacy policy**: obbligatori per SaaS

**Deliverable**: un cliente può comprare e usare senza parlare con nessuno.

---

## Sprint 8 — Enterprise Features (settimana 9-16)

Per clienti enterprise (>1000 dipendenti, >5000€/mese).

- [ ] **SSO SAML**: completare flow (backend esiste, testare con Okta/Azure AD)
- [ ] **RBAC granulare**: permessi per progetto, non solo per tenant
- [ ] **API key management**: create/revoke/rotate da UI
- [ ] **SLA monitoring**: uptime scan, tempo medio remediation
- [ ] **White-label**: logo/colori personalizzabili per MSSP
- [ ] **Multi-region**: deploy EU/US per data residency
- [ ] **SOC 2 Type II**: preparare evidence per certificazione propria

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

**Se hai solo 2 settimane**: Sprint 1 + Sprint 3 (fix lies + change detection).
**Se hai solo 4 settimane**: + Sprint 2 + Sprint 5 (security + UX).
**Se vuoi vendere**: tutti gli 8 sprint.

---

## KPI per Sprint

| Sprint | KPI                                | Target             |
| ------ | ---------------------------------- | ------------------ |
| 1      | Feature fake visibili              | 0                  |
| 2      | Vulnerabilità note                 | 0 critical, 0 high |
| 3      | Tempo per capire "cosa è cambiato" | < 10 sec           |
| 4      | Controlli ISO mappati              | 93/93              |
| 5      | Tempo onboarding nuovo utente      | < 2 min            |
| 6      | Uptime sotto carico (10 tenant)    | > 99.5%            |
| 7      | Conversion rate landing → signup   | > 5%               |
| 8      | Enterprise pilot chiusi            | ≥ 2                |
