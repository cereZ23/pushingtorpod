# NimbusGuard — Brand Guide

## Nome

**NimbusGuard** (un token, no spazio, no dash)

- "Nimbus" = nuvola/aura protettiva (latino)
- "Guard" = guardiano/protezione (inglese)
- Messaggio: protezione che circonda e si adatta

Pronunciation: /'nim-bus-gard/

## Tagline

**Italian EASM. Secured.**
(oppure: "Superficie d'attacco, sotto controllo.")

## Colori

```
Primary Dark   #0f1729   Background scuro, navbar, footer
Primary Blue   #141e33   Secondary dark
Accent Cyan    #00b4d8   CTA primary, logo, links
Accent Orange  #f59e0b   Warning, CRITICAL alerts
Success Green  #10b981   Risk score ok, clean controls
Danger Red     #dc2626   CRITICAL findings
Text Primary   #f8fafc   Su dark bg
Text Gray      #94a3b8   Subtext, metadata
Text Dark      #1e293b   Su light bg
```

## Tipografia

- **Headings**: Inter Bold / Helvetica-Bold (fallback)
- **Body**: Inter Regular / Helvetica (fallback)
- **Code/Mono**: JetBrains Mono / Menlo (fallback)

## Logo (SVG)

Forma: cerchio cyan con gradient + guard shield al centro.

```svg
<svg width="64" height="64" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <!-- Nimbus (aura) -->
  <defs>
    <radialGradient id="nimbus" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#00b4d8" stop-opacity="0.4"/>
      <stop offset="70%" stop-color="#00b4d8" stop-opacity="0.1"/>
      <stop offset="100%" stop-color="#00b4d8" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <circle cx="32" cy="32" r="30" fill="url(#nimbus)"/>
  <!-- Guard shield -->
  <path d="M32 12 L48 20 L48 34 C48 42 40 50 32 52 C24 50 16 42 16 34 L16 20 Z"
        fill="#00b4d8" stroke="#0f1729" stroke-width="2"/>
  <!-- Checkmark -->
  <path d="M24 32 L30 38 L42 24" stroke="#0f1729" stroke-width="3"
        fill="none" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
```

## Logo wordmark

```
 ┌─────┐
 │  ◉  │  NimbusGuard
 └─────┘
```

Logo + wordmark layout:

- Icon 40x40 px
- Gap 12 px
- Wordmark "NimbusGuard" in Helvetica-Bold 24px, color Primary Dark (on light) or Text Primary (on dark)

## Do's

- Sempre logo cyan (#00b4d8) su sfondo scuro (#0f1729)
- Minimum clearspace: 20% logo dimension
- Solid fill, no outline

## Don'ts

- No stretch/distorsione
- No gradienti diversi dal brand
- No rotazione
- Non mischiare con altri loghi
- No lowercase "nimbusguard" o "Nimbus Guard"

## Voice & tone

- **Autorevole** ma non arrogante
- **Concreto** (numeri, dimostrazioni, no buzzword)
- **Italiano-first** (localizzazione = moat)
- **Technical-friendly** (scrivere per CISO, non per marketing)

Parole da EVITARE:

- "Rivoluzionario", "disruptive", "next-gen"
- "AI-powered" (salvo quando e' vero)
- "Best-in-class"
- "Game-changer"

Parole da PREFERIRE:

- "Verificato sul cliente X"
- "MTTR ridotto del Y%"
- "ISO 27001 Annex A.8.8"
- "Evidence per audit"

## Domini

- Primary: `nimbusguard.it`
- Alt: `nimbusguard.com`, `nimbusguard.io`
- Product: `easm.securekt.com` (current staging)

## Email signatures

```
Andrea Ceresoni
Founder, NimbusGuard

[M] +39 XXX XXX XXXX
[W] https://nimbusguard.it
[E] andrea@nimbusguard.it
```

## Social media

- LinkedIn: /company/nimbusguard
- Twitter/X: @nimbusguard_it
- GitHub: /nimbusguard (prodotto open-source a release pubblica)
- YouTube: NimbusGuard (demo + tutorial)
