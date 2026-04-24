# Ethical Use Policy

> **This toolkit is intended for authorized security testing, incident response, and research only.**
> Running it against systems, networks, accounts, or people without documented permission is illegal in
> most jurisdictions and is **not a supported use case** of this project.

This document supplements - but does **not override** - the MIT License in [`LICENSE`](./LICENSE).
It is a statement of author intent for how this software should be used, and a pointer to the legal
frameworks that govern misuse. It is not legal advice. If you are unsure whether a specific use is
lawful in your jurisdiction, consult qualified counsel before running any scan.

## Who this is for

The project ships two toolkits:

- **`soc-toolkit`** - defensive workflows run against artifacts you already possess (phishing emails
  routed to your abuse mailbox, log files from your infrastructure, IOCs you are investigating as
  part of incident response). Most of its modules never touch the internet at all.
- **`osint-toolkit`** - reconnaissance against a defined perimeter, using public-source enrichment
  (passive DNS, certificate transparency) by default. Active probing is gated behind an explicit
  configuration flag.

Both toolkits assume the operator is acting in one of the following roles:

1. **Internal defender** - scanning assets owned by their employer, under the scope of their job.
2. **Contracted pentester / red-teamer** - operating under a signed statement of work that names
   the in-scope assets.
3. **Bug bounty researcher** - operating within the published scope and rules of engagement of a
   public or private bounty program.
4. **Researcher / educator** - using sample data, lab environments, or explicitly authorized
   targets (e.g. `scanme.nmap.org`, intentionally vulnerable VMs).

Anything else - curiosity-driven scans of third-party systems, "just seeing what's out there",
passive enumeration of an ex-partner's online footprint, recon against a company you happen to
dislike - is **out of scope** for this project and may be criminal.

## Legal landscape

Unauthorized access to computer systems is criminalized in every jurisdiction this project is
likely to be used from. A non-exhaustive, non-authoritative list of relevant statutes:

- **Italy** - *Legge 23 dicembre 1993, n. 547*, which introduced article **615-ter** of the
  Codice Penale ("Accesso abusivo ad un sistema informatico o telematico"). Penalties range from
  fines to imprisonment up to three years, with aggravating circumstances for systems of public
  interest. Article **617-quater** covers unauthorized interception of communications; article
  **635-bis** covers damage to IT systems.
- **European Union** - **GDPR (Regulation 2016/679)**. Processing personal data scraped or
  enumerated during OSINT requires a lawful basis under **Article 6** (typically 6(1)(f)
  "legitimate interests" for security research, balanced against data subject rights). OSINT that
  surfaces personal data - usernames, emails, breach records - is regulated processing, not a
  license-free activity. Consult Article 6(1)(f) balancing tests and, where applicable, the
  "household exception" (which does **not** cover professional or commercial security work).
- **United States** - **Computer Fraud and Abuse Act (18 U.S.C. § 1030)**. Unauthorized access to
  a "protected computer" (broadly defined) is a federal crime. Recent precedent
  (*Van Buren v. United States*, 2021) narrowed what counts as "exceeding authorized access", but
  did not narrow unauthorized access itself.
- **United Kingdom** - **Computer Misuse Act 1990**. Section 1 (unauthorized access), Section 3
  (unauthorized acts with intent to impair), Section 3A (making/supplying tools for offences -
  read this carefully if distributing builds).
- Many other jurisdictions have analogous statutes (Germany StGB §§202a–202c, France Code pénal
  art. 323-1, Australia Criminal Code Division 477). If you are running scans that cross borders,
  assume the strictest regime applies.

## What this toolkit does and does not do

**Passive by default.** The OSINT toolkit's default subdomain enumeration reads certificate
transparency logs and passive-DNS aggregators - no traffic is ever sent to the target. Running
against `example.com` costs `example.com` nothing. This is the intended mode for the public build.

**Active scanning is gated.** The `enable_active_scanning` configuration flag is the master
switch; individual scan launches additionally require the target to be marked "authorized to
scan" in the UI. Active mode shells out to Amass or Subfinder if installed - neither is bundled.
The confirmation modal requires the operator to type the target name verbatim. These frictions
are intentional: they exist so "I clicked the wrong button" cannot become "I DDoSed a stranger".

**Nothing here is a zero-day, C2, or exploitation framework.** The project ingests evidence and
enriches indicators. It does not deliver payloads.

## Rules of engagement we expect contributors to honor

1. **Scope discipline.** Do not submit features that make it easier to operate outside a defined
   scope (e.g. target-auto-discovery that sweeps arbitrary CIDR ranges with no operator input).
2. **No retaliation / hack-back.** We will not accept features that initiate traffic against
   attacker infrastructure. Analysis yes; retaliation no.
3. **No detection-evasion theatre for attacking others.** OPSEC features that protect a legitimate
   defender from their own alerting are fine. Features whose only use is evading the target's
   defenses while you attack them are not.
4. **Respect rate limits and terms of service** of the APIs we integrate with. If a source says
   "do not use this data for X", we honor that, even if enforcement is unlikely.
5. **Minimize collection.** If a feature can answer the analyst's question with less personal
   data, it should.

## Reporting misuse or vulnerabilities

- **Vulnerability in this toolkit**: email the maintainer (see repository metadata). Do not open a
  public issue for unpatched security bugs.
- **Evidence that someone is misusing this toolkit against you or your organization**: preserve
  logs and contact local law enforcement. The author is not in a position to mediate between
  operators and targets.

---

*This policy applies to the current and all future versions of `sec-toolkit` unless explicitly
superseded. Last reviewed: 2026-04-23.*
