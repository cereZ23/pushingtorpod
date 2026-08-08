# Guida utente

Questa guida spiega come usare la piattaforma EASM, avviare e interpretare gli scan, leggere la
copertura degli endpoint e comprendere il ciclo di vita dei finding. È rivolta a owner, admin,
analyst e viewer del tenant; alcune azioni dipendono dal proprio ruolo.

## 1. Concetti principali

| Termine | Significato |
|---|---|
| **Tenant** | Workspace isolato dell'organizzazione. Dati e permessi sono separati dagli altri tenant. |
| **Project** | Raggruppa il perimetro da monitorare, i seed e gli scan. |
| **Seed** | Punto di partenza autorizzato, ad esempio un dominio. |
| **Asset** | Elemento scoperto nel perimetro: dominio, sottodominio, indirizzo IP o servizio. |
| **Scan run** | Una singola esecuzione di uno scan, identificata da un ID. |
| **Tier** | Livello di profondità e impatto dello scan: T1, T2 o T3. |
| **Finding** | Evidenza di una vulnerabilità, esposizione o configurazione errata. |
| **Endpoint** | Percorso HTTP specifico, per esempio `/admin` o `/api/users`. |
| **Coverage** | Prova persistita di ciò che è stato effettivamente verificato durante uno scan. |

## 2. Ruoli e permessi

Il ruolo è assegnato per tenant.

| Ruolo | Consultazione | Avvio/modifica | Gestione utenti |
|---|:---:|:---:|:---:|
| **Viewer** | Sì | No | No |
| **Analyst** | Sì | Sì | No |
| **Admin** | Sì | Sì | Sì |
| **Owner** | Sì | Sì | Sì |

Un superuser della piattaforma può amministrare più tenant. Per la descrizione completa dei ruoli,
vedere [Gestione tenant e utenti](tenant-management.md).

## 3. Creare e selezionare un progetto

Nella pagina **Scan Management**:

1. selezionare un progetto dalla colonna **Projects**;
2. verificare nome, descrizione e seed;
3. usare **New Project** per creare un nuovo perimetro, se il ruolo lo consente;
4. usare **Edit** per aggiornare un progetto esistente;
5. usare **Trigger Scan** per avviare uno scan manuale.

Prima di avviare uno scan, verificare sempre che seed e scope appartengano al perimetro autorizzato.
La piattaforma elimina dalla selezione gli endpoint fuori scope, ma l'autorizzazione del perimetro
rimane responsabilità dell'organizzazione.

## 4. Scegliere il tier corretto

### T1 — Safe Continuous

Adatto al monitoraggio frequente e non intrusivo:

- ricognizione e verifica dei servizi più comuni;
- template sicuri, con severità prioritaria;
- scansione HTTP delle base URL;
- pass dedicato sugli endpoint profondi con i soli detector pertinenti;
- Interactsh/OAST pubblico disabilitato.

È il tier consigliato per la scansione continua.

### T2 — Extended

Adatto a verifiche più approfondite:

- superficie di porte e servizi più ampia;
- più detector applicabili rispetto a T1;
- verifica dedicata degli endpoint con catalogo T2;
- durata e numero di richieste generalmente superiori a T1;
- Interactsh/OAST pubblico disabilitato.

Usarlo quando serve maggiore copertura e il tempo di esecuzione più lungo è accettabile.

### T3 — Aggressive

Livello ad alto impatto, da usare solo con autorizzazione esplicita:

- superficie completa prevista dal profilo;
- funzionalità intrusive o attive solo quando abilitate esplicitamente;
- DAST/fuzzing soltanto con relativo flag e autorizzazione allo scan;
- OAST soltanto con un server Interactsh configurato esplicitamente;
- mai utilizzo implicito del servizio Interactsh pubblico.

T3 non deve essere trattato come una semplice estensione automatica di T2. Se le capability
richieste non sono abilitate, i detector che ne dipendono vengono esclusi in modo conservativo.

> I numeri dei template non sono costanti: dipendono dalla versione del catalogo Nuclei, dal tier,
> dalla severità e dalle capability abilitate. La piattaforma registra la policy effettiva dello scan.

## 5. Capire la lista degli scan

La tabella degli scan mostra:

- **ID** — identificativo univoco del run;
- **Status** — stato dell'esecuzione;
- **Tier** — T1, T2, T3 oppure Unknown per run legacy;
- **Trigger** — Manual, Scheduled, API, Retest o un'etichetta descrittiva;
- **Started** — data e ora di avvio;
- **Duration** — durata complessiva;
- **Actions** — apertura del dettaglio e azioni consentite.

Il tier e il trigger sono snapshot del run: restano quelli realmente eseguiti anche se il profilo
viene modificato successivamente.

### Stati principali

| Stato | Significato |
|---|---|
| **Pending** | Run creato e in attesa del worker. |
| **Running** | Scan in esecuzione. |
| **Completed** | Pipeline terminata; eventuali endpoint non verificabili sono dichiarati separatamente. |
| **Completed with limitations** | Pipeline terminata, ma una parte prevista non ha prova completa. |
| **Failed** | Errore che ha impedito il completamento operativo. |
| **Cancelled** | Run annullato. |

**Completed with limitations non significa automaticamente che tutto lo scan sia fallito.** Aprire
il dettaglio per identificare la fase o la verifica interessata.

## 6. Leggere il dettaglio dello scan

Il dettaglio contiene tre aree principali.

### Informazioni del run

Mostra stato, tier, trigger, orari, durata e l'eventuale errore generale.

### Scan result

La card **Scan result** riassume la decisione del backend. Il frontend visualizza i dati persistiti e
non ricalcola autonomamente outcome o copertura.

Per la verifica degli endpoint mostra:

| Campo | Significato |
|---|---|
| **Selected** | Endpoint scelti dal selettore dopo scope, deduplica e limiti del profilo. |
| **Verified** | Endpoint completamente verificati dal catalogo applicabile. |
| **Not verifiable** | Endpoint raggiunti dal processo ma non verificabili completamente, ad esempio perché l'origine non risponde. |
| **Failed** | Endpoint il cui batch ha avuto un errore operativo. |
| **Skipped** | Endpoint pianificati ma non eseguiti. Include quelli non raggiunti dal budget. |
| **Coverage %** | `Verified / Selected`; è `—` quando non esistono endpoint selezionati. |

Possibili stati:

- **All endpoints verified** — tutti gli endpoint selezionati hanno prova completa;
- **Verified with limitations** — lo scan è operativamente concluso, ma alcune origini non erano
  verificabili;
- **Verification incomplete** — budget, timeout o troncamento hanno impedito di completare il
  lavoro previsto;
- **Verification failed** — errore strutturale, di esecuzione o persistenza;
- **No endpoints to verify** — nessun endpoint applicabile in quel run;
- **Endpoint verification off** — pass non abilitato;
- **Not available** — run legacy senza dati sufficienti; la UI non inventa una copertura.

Le limitazioni possono includere origine non responsiva, budget insufficiente, timeout, output
troncato, cambiamento del catalogo, parsing incompleto, errore di scrittura, esecuzione o
configurazione. In caso di dati incoerenti la piattaforma usa i conteggi del ledger come fonte
autorevole e segnala esplicitamente l'incoerenza.

### Phase Progress

La timeline delle fasi mostra lo stato delle singole attività. Una fase può essere completata,
parziale, fallita o saltata. Alcune fasi sono condizionali e possono risultare saltate senza indicare
un problema.

## 7. Perché gli endpoint profondi non riducono la completezza

Lo scan HTTP è diviso intenzionalmente:

1. il pass stock verifica le base URL;
2. il pass endpoint analizza gli URL profondi scoperti dal crawler;
3. sugli endpoint vengono eseguiti soltanto i detector classificati come dipendenti da path/query.

Questo evita di moltiplicare migliaia di template host-level per migliaia di URL, mantenendo la
verifica utile sugli endpoint profondi.

Esempio:

- `https://example.com/` viene verificato dal pass stock;
- `https://example.com/admin` viene verificato dal pass endpoint con i detector pertinenti;
- un finding su `/admin` può essere chiuso automaticamente solo se quello stesso endpoint viene
  ricoperto da una policy compatibile e il detector non scatta più.

L'assenza del finding a livello host non viene mai usata come prova che un endpoint profondo sia
stato corretto.

## 8. Finding e ciclo di vita

Aprendo un finding si visualizzano stato corrente, severità, evidenze, remediation e la card di
verifica lifecycle.

La card può mostrare:

- ultimo run che ha rilevato il finding;
- scope della coverage (**Endpoint** o **Host**);
- tier della policy di origine, quando disponibile;
- numero di miss consecutivi eleggibili;
- soglia richiesta prima dell'auto-close;
- cronologia degli eventi.

### Eventi della timeline

| Evento | Significato |
|---|---|
| **Detected** | Il detector ha rilevato nuovamente il problema; lo streak dei miss torna a zero. |
| **Eligible miss** | Il detector non ha prodotto il finding e la copertura richiesta è stata provata. |
| **Would close** | È stata raggiunta la soglia di miss; in shadow indica cosa verrebbe chiuso. |
| **Automatically fixed** | Il finding è passato da OPEN a FIXED tramite auto-close. |
| **Reopened** | Il detector ha rilevato nuovamente un finding precedentemente FIXED, oppure un utente lo ha riaperto. |
| **Miss reset** | Un miss precedente non è più eleggibile, per esempio per coverage o policy non compatibile. |

I run precedenti all'introduzione della timeline possono mostrare **history not available**. La
piattaforma non ricostruisce eventi storici che non può provare.

## 9. Come funziona l'auto-close

Un finding non viene chiuso perché semplicemente “non compare” nello scan successivo. Per maturare
un miss eleggibile devono essere vere tutte le condizioni di sicurezza, tra cui:

- discovery sufficientemente sana;
- coverage completa dello scope corretto;
- detector presente nel catalogo della policy;
- policy compatibile con quella che ha originato il finding;
- finding non rilevato nel run corrente.

Per gli endpoint profondi è richiesta la prova dello stesso endpoint. Per impostazione corrente la
chiusura richiede miss eleggibili consecutivi; un nuovo rilevamento o un run ineleggibile azzera lo
streak. Se il finding ricompare dopo essere stato auto-chiuso, viene riaperto e l'evento è registrato.

### Shadow e chiusura reale

- In **shadow** la piattaforma calcola e registra la decisione, ma non modifica lo stato del finding.
- In modalità reale, abilitata dagli operatori per tenant e tier certificati, una decisione
  **Would close** può effettuare la transizione atomica `OPEN → FIXED` con audit persistente.

L'utente non deve interpretare un finding `FIXED` come prova generica che l'host sia irraggiungibile:
la timeline indica se la chiusura è automatica e su quale scope è basata.

## 10. Operational Dashboard

La voce **Operational Dashboard** apre `/operations` e offre una vista aggregata della salute degli
scan.

### Periodo

È possibile selezionare **7, 30 o 90 giorni**. Il cambio periodo aggiorna i dati senza ricaricare la
pagina. Le richieste obsolete vengono ignorate: un cambio rapido di periodo o tenant non può
sovrascrivere la vista corrente con dati precedenti.

### Scan outcomes

Mostra scan completati, completati con limitazioni, falliti e cancellati. I cancellati sono separati
dal totale degli outcome terminali.

### Endpoint verification

Mostra endpoint selezionati, verificati, non verificabili, falliti, saltati e percentuale di
copertura. I dati non sono la somma indiscriminata di tutti gli scan del periodo: per evitare di dare
più peso ai progetti scansionati più spesso, il backend utilizza l'ultimo run terminale applicabile
per progetto e tier.

### Finding lifecycle

Mostra:

- **Automatically fixed** — finding distinti auto-chiusi nel periodo;
- **Reopened** — finding distinti riaperti nel periodo;
- **Awaiting confirmation** — finding attualmente aperti con un miss eleggibile, ancora sotto la
  soglia di chiusura.

### By tier

La tabella confronta T1 e T2 usando lo stesso contratto dei totali. T3 non compare finché non viene
certificato per questo utilizzo. Un'attività lifecycle senza attribuzione tier verificabile resta nel
totale e non viene assegnata arbitrariamente a T1 o T2.

### Stati della dashboard

- **Loading** — richiesta in corso;
- **Empty** — nessuna attività nel periodo;
- **Error** — impossibile caricare i dati;
- **Incomplete data** — risposta priva di un blocco tier garantito; la UI non sostituisce il dato con
  zero.

## 11. Interactsh e OAST

Interactsh consente ai detector OAST di confermare vulnerabilità tramite una callback esterna, utile
per classi come SSRF o alcune RCE blind.

Per proteggere riservatezza e controllo del traffico:

- il servizio Interactsh pubblico non viene usato implicitamente;
- quando nessun server autorizzato è configurato, Nuclei viene eseguito con OAST disabilitato;
- i detector che dipendono dalla callback vengono esclusi dal catalogo capace di autorizzare
  auto-close;
- un eventuale Interactsh self-hosted deve essere configurato esplicitamente dagli operatori.

Con OAST disabilitato alcuni detector vengono comunque caricati da Nuclei, ma non possono completare
il match previsto. Per questo il numero “templates loaded” può essere maggiore del catalogo dei
detector effettivamente capaci di produrre finding.

Questa scelta è conservativa: può ridurre la detection OAST finché non esiste un server autorizzato,
ma non può trasformare l'assenza di una callback in una falsa remediation.

## 12. Trigger degli scan

| Trigger | Significato |
|---|---|
| **Manual** | Avviato da un utente tramite UI. |
| **Scheduled** | Avviato automaticamente da una schedulazione. |
| **API** | Avviato tramite integrazione/API. |
| **Retest** | Verifica mirata successiva a un finding o intervento. |
| **Custom/Unknown** | Run legacy o etichetta descrittiva non riconducibile con certezza a un tipo. |

La UI distingue il tipo del trigger dall'etichetta libera. Un testo personalizzato non viene
interpretato automaticamente come “manuale”.

## 13. Risoluzione dei problemi

### Lo scan è Completed ma alcuni endpoint sono Not verifiable

Lo scan ha terminato il lavoro operativo; una o più origini non hanno risposto in modo sufficiente.
Gli endpoint interessati restano non autorizzanti per l'auto-close. Non è necessario considerare
l'intero scan fallito.

### Lo scan è Completed with limitations

Aprire **Scan result** e **Phase Progress**. Budget, timeout, output troncato o errore possono aver
impedito di raggiungere parte del lavoro previsto. I dati incompleti non autorizzano chiusure.

### La coverage mostra `—`

Non esiste un insieme di endpoint selezionati per il calcolo. `—` non significa 100%.

### Un finding non viene auto-chiuso

È il comportamento corretto quando manca una delle prove richieste: endpoint non coperto, policy
cambiata, detector non applicabile, discovery non sana, provenance legacy o miss non consecutivi.
Consultare la card lifecycle per lo stato e lo streak.

### Un finding FIXED ricompare

La piattaforma lo riapre quando il detector lo rileva nuovamente e registra **Reopened** nella
timeline.

### Il tier è Unknown

Il run è legacy o non associato a un profilo con tier dimostrabile. La piattaforma non indovina il
tier retroattivamente.

### La dashboard non mostra dati

Verificare tenant e periodo selezionati. Se la risposta è incompleta o fallisce, la UI mostra un
messaggio esplicito. Riprovare; se il problema persiste, fornire all'amministratore tenant, periodo e
ID degli scan interessati, senza copiare credenziali o token.

## 14. Sicurezza e riservatezza

- Ogni richiesta e aggregazione è tenant-scoped.
- La coverage endpoint persiste un'identità normalizzata, non l'URL in chiaro.
- Timeline e dashboard non espongono URL, hash di policy o dettagli interni sensibili.
- Endpoint fuori scope vengono esclusi prima dell'esecuzione.
- Capability intrusive, DAST e OAST richiedono abilitazione esplicita.
- Legacy, errori e dati incoerenti vengono trattati in modo conservativo: mai copertura o remediation
  inventate.

## 15. Checklist rapida dopo uno scan

1. Verificare **Status**, **Tier** e **Trigger**.
2. Aprire **Scan result** e controllare outcome e coverage endpoint.
3. Se esistono limitazioni, leggere il motivo e i conteggi interessati.
4. Controllare **Phase Progress** per errori o fasi incomplete.
5. Esaminare i nuovi finding e la loro remediation.
6. Per finding auto-chiusi o riaperti, controllare la timeline lifecycle.
7. Usare **Operational Dashboard** per confrontare l'andamento su 7/30/90 giorni.

## 16. Funzioni future

Click-through dalla dashboard verso liste prefiltrate, filtri persistenti nelle URL, trend grafici ed
export sono evoluzioni possibili, ma non fanno parte delle funzioni descritte come disponibili in
questa guida.
