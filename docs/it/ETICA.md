# Politica d'uso etico - OSINT Toolkit

**Uso consentito esclusivamente per test di sicurezza autorizzati e
ricerca.**

Questo toolkit raccoglie e correla informazioni pubbliche su asset
esposti in Internet (DNS, certificati, servizi attivi). I dati sono
tecnicamente pubblici; il limite etico e giuridico non riguarda la loro
*lettura*, ma **contro chi viene puntato lo strumento** e **cosa se ne
fa**.

Eseguire questo software su infrastrutture di cui non si è proprietari o
per le quali non si dispone di **autorizzazione scritta** può integrare
violazioni di:

- **Italia** - L. 547/1993 e art. 615-*ter* c.p. (accesso abusivo a
  sistema informatico), art. 615-*quater* c.p. (detenzione e diffusione
  abusiva di codici di accesso), art. 617-*quater* c.p. (intercettazione
  di comunicazioni informatiche). GDPR art. 6 quando vengono trattati
  dati personali senza base giuridica.
- **Unione Europea** - Direttiva 2013/40/UE (attacchi contro i sistemi
  di informazione) nella trasposizione nazionale. Regolamento 2016/679
  (GDPR) quando i risultati OSINT includono dati personali di persone
  fisiche identificate o identificabili.
- **Stati Uniti** - Computer Fraud and Abuse Act (18 U.S.C. § 1030) per
  accesso non autorizzato; le leggi statali sulla raccolta dati variano.
- **Regno Unito** - Computer Misuse Act 1990.

Questo elenco non costituisce parere legale. La legge applicabile al
caso concreto governa comunque le azioni dell'operatore,
indipendentemente da ciò che il tool consente tecnicamente.

## Garanzie tecniche del toolkit

Le regole non sono solo scritte: il codice le applica.

1. **Cancello di autorizzazione su ogni target.** L'API rifiuta la
   creazione di un `Target` con `authorized_to_scan` diverso da `true`.
   La checkbox nell'interfaccia ricalca un controllo lato server -
   bypassare l'interfaccia non aggira il cancello.
2. **Filtro di scope su ogni scansione.** Gli asset scoperti fuori dai
   `scope_domains` del target vengono scartati prima della
   persistenza. Le fonti passive (CT log, WHOIS) spesso restituiscono
   domini vicini; il filtro assicura che una scansione su "example.com"
   non persista accidentalmente dati su "examplecompany.com".
3. **Passivo per default.** L'enumerazione sottodomini legge solo
   archivi di terze parti (crt.sh, SecurityTrails). Nessun traffico
   viene inviato al target.
4. **Scansione attiva opt-in.** Il flag `OSINT_ENABLE_ACTIVE_SCANNING`
   gattina qualunque chiamata a strumenti attivi (Amass, Subfinder,
   port scanner). Di default è `false` e richiede una scelta consapevole
   per essere abilitato.
5. **Nessuno strumento offensivo incluso.** Il toolkit rileva e usa
   strumenti attivi esterni solo se installati, non li ridistribuisce.

## Responsabilità dell'operatore

Prima di creare un target l'operatore deve poter rispondere **sì** a
tutte queste domande:

- [ ] Ho autorizzazione scritta dal titolare dell'asset, **oppure** sono
      io stesso proprietario, **oppure** gli asset rientrano in un
      programma di bug-bounty i cui termini permettono esplicitamente
      OSINT.
- [ ] L'autorizzazione copre tutti i domini che sto per inserire in
      scope. Se "example.com" è autorizzato ma "example.org" non lo è,
      non aggiungere il secondo.
- [ ] Ho compreso che alcune fonti restituiscono dati riferibili a
      persone fisiche (e-mail di contatto in WHOIS, nomi nei subject dei
      certificati). Tali dati vanno trattati secondo il GDPR e le norme
      sulla privacy applicabili.

## Cosa il toolkit **non** è

- **Non è uno strumento di accesso.** Non sfrutta vulnerabilità, non
  effettua login, non enumera utenti di applicazioni.
- **Non è uno strumento di aggressione verso persone.** Le funzioni
  investigative OSINT (username, breach, metadati immagine) esistono
  per ricerca su account controllati dall'operatore o per investigazioni
  consensuali, non per stalking, doxxing o molestie.
- **Non è un sostituto dell'autorizzazione.** Inserire un IP in una
  casella di scope non rende la scansione lecita.

## Base giuridica sotto il GDPR

Quando il trattamento dei dati coinvolge persone fisiche identificabili,
l'operatore deve individuare una base giuridica valida (art. 6 GDPR).
Nei contesti d'uso tipici del toolkit:

- **Interesse legittimo** (art. 6(1)(f)) - tipico per security testing
  autorizzato condotto dal titolare o da un incaricato. Richiede un
  *legitimate interest assessment* (LIA) documentato.
- **Obbligo legale** (art. 6(1)(c)) - indagini forensi su incarico
  dell'autorità giudiziaria.
- **Consenso** (art. 6(1)(a)) - investigazioni consensuali (es.
  self-doxxing check richiesto dall'interessato).

L'uso del toolkit **senza** una base giuridica identificabile è una
violazione del GDPR, a prescindere dalla qualità tecnica dei risultati
ottenuti.

## Segnalazione di abusi

Se ritieni che questo toolkit venga usato contro di te o contro la tua
infrastruttura senza autorizzazione, apri una issue sul repository. I
manutentori sono interessati a rendere l'abuso più difficile da
ripetere.
