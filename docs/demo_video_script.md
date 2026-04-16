# NimbusGuard — Video Demo Script (3 minuti)

**Formato:** screencast con voce narrante, 1080p, 30fps.
**Target:** CISO italiano, 500-5000 dipendenti, team security 2-5 persone.
**Tono:** professionale ma concreto, zero buzzword, massimo dimostrazione pratica.

---

## SCENA 1 — Problema (0:00 – 0:25)

**Video:** mappa Italia con puntini rossi che si moltiplicano. Sovraimpressione screenshot news data breach italiani (2024-2025).

**Voice-over:**

> "Il 73% degli attacchi a grandi organizzazioni parte da asset esposti dimenticati. Subdomain abbandonati, porte aperte, certificati scaduti, plugin WordPress con CVE critici. Il tuo team di 3 persone non puo' tenere traccia di 500 asset manualmente."

**Text on screen:**

- "500+ asset medi in un'azienda enterprise"
- "Nuovi domini creati ogni settimana"
- "CVE pubblicati ogni ora"

---

## SCENA 2 — Soluzione (0:25 – 0:45)

**Video:** logo NimbusGuard che si compone animato. Transition a dashboard EASM.

**Voice-over:**

> "NimbusGuard e' un EASM italiano che scopre, monitora e ti dice **come fixare** ogni asset esposto. Un click per iniziare, remediation in italiano per il tuo team."

**Text on screen:**

- "EASM 100% italiano"
- "ISO 27001, NIS2, AgID ready"
- "Self-hosted o SaaS"

---

## SCENA 3 — Onboarding (0:45 – 1:15)

**Video:** pagina `/register`. Digita email, password, "IFO Roma", domini "ifo.it, ire.it". Click Start.

**Voice-over:**

> "Due minuti per iniziare. Email, dominio, password. Il nostro motore parte subito: discovery subdomain, port scan, fingerprinting, vulnerability scan con 8000+ template nuclei piu' i nostri custom italiani."

**Text on screen:**

- "0 configurazione"
- "Scan completo in 30 minuti"

---

## SCENA 4 — Findings reali (1:15 – 1:45)

**Video:** dashboard scan completato. Banner rosso "3 CRITICAL require attention". Click su "Magento Mass Importer Remote Auth Bypass — CVE-2020-5777". Mostra EPSS 91%.

**Voice-over:**

> "In 30 minuti, su un cliente reale, NimbusGuard ha trovato Magento esposto con un RCE pubblico. EPSS al 91% — probabilita' di essere sfruttato nei prossimi 30 giorni. Docker-compose con password in chiaro. WordPress Ultimate Member con privilege escalation non patchato."

**Text on screen:**

- "3 CRITICAL trovati"
- "EPSS 91% = attivamente sfruttato"
- "docker-compose.yml exposed"

---

## SCENA 5 — Remediation Playbook (1:45 – 2:20)

**Video:** click "Come sistemarlo". Espande step-by-step. Scroll mostra comandi nginx, wp-cli, verify curl.

**Voice-over:**

> "Ecco il nostro vantaggio competitivo: ogni finding ha un **playbook italiano** step-by-step. Comando nginx da copiare. Verifica curl. Template email al team dev. Il tuo junior fixa critici senza chiamare il consulente."

**Text on screen:**

- "Playbook italiano per ogni finding"
- "Copy-paste commands"
- "MTTR ridotto del 60%"

---

## SCENA 6 — Compliance & Scale (2:20 – 2:45)

**Video:** pagina `/compliance/iso27001`. Mostra 11/15 controlli clean. Poi schedulazione scan — "Weekly Monday 2AM". Poi integration Slack webhook.

**Voice-over:**

> "Mapping automatico a ISO 27001 Annex A — evidence pronta per l'audit. Scan schedulati via cron. Alert su Slack e webhook. Per l'enterprise: multi-tenant, SSO SAML, RBAC, API REST."

**Text on screen:**

- "ISO 27001:2022 mapping"
- "NIS2 Perimetro Cibernetico"
- "SAML SSO, RBAC, SIEM"

---

## SCENA 7 — Call to Action (2:45 – 3:00)

**Video:** logo NimbusGuard centered. URL easm.securekt.com. Email contatto. QR code demo.

**Voice-over:**

> "NimbusGuard. EASM italiano, per team italiani. Prenota una demo su easm.securekt.com. Oppure installa self-hosted con Docker Compose in 15 minuti."

**Text on screen:**

- "easm.securekt.com"
- "demo@pushingtorpod.it"
- "Self-hosted o SaaS da 299€/mese"

---

## Recording notes

1. **Pre-seed il DB** con scan reale su IFO prima del recording (Magento + WP findings gia' presenti)
2. **Zoom level 110%** per leggibilita' su YouTube/LinkedIn
3. **Browser in modalita' incognito** per hide bookmarks personali
4. **Dark mode frontend** (look piu' professionale, gia' supportato)
5. **Mouse highlight** (app Presentify o tool simile)
6. **Registra audio separatamente** e mixa in post — audio pulito e' decisivo
7. **Music:** soft electronic low-key, -20dB sotto voce (suggerisco "Corporate Tech" da epidemicsound.com)
8. **Export:** MP4 1080p30 H.264, under 50MB (limite LinkedIn/Twitter)
9. **Thumbnail:** screenshot dashboard con findings + logo overlay

## Distribution

- LinkedIn post (organic + sponsored)
- YouTube (SEO: "EASM italiano", "Attack Surface Management")
- Embed in landing page
- Send in sales email outreach
