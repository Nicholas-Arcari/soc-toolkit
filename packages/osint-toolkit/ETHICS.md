# Ethical Use Policy - OSINT Toolkit

**For authorized security testing and research only.**

This toolkit collects and correlates publicly available information about
internet-facing assets (DNS, certificates, exposed services). The data is
technically public; the legal and ethical boundaries are not about *reading*
it, they are about **who you point it at** and **what you do with it**.

Running this software against infrastructure you do not own or do not have
written authorization to test may violate:

- **Italy** - L. 547/1993 and art. 615-*ter* c.p. (accesso abusivo a sistema
  informatico), GDPR Art. 6 when personal data is processed without a lawful
  basis.
- **European Union** - Directive 2013/40/EU (attacks against information
  systems) as transposed nationally; GDPR (Regulation 2016/679) when OSINT
  results contain personal data.
- **United States** - Computer Fraud and Abuse Act (18 U.S.C. § 1030) for
  unauthorized access; state-level laws on data collection vary.
- **United Kingdom** - Computer Misuse Act 1990.

This list is not legal advice. Local law governs your actions regardless of
what the tool permits technically.

## What the toolkit enforces

Technical guardrails back the policy:

1. **Authorization gate on every target.** The API refuses to create a
   `Target` without `authorized_to_scan=True`. The checkbox in the UI
   mirrors a server-side check - bypassing the UI does not bypass the gate.
2. **Scope filter on every scan.** Discovered assets outside the target's
   `scope_domains` are discarded before persistence. Passive sources
   routinely leak neighbor domains; the scope filter makes sure "scanning
   example.com" cannot accidentally persist data about "examplecompany.com".
3. **Passive-by-default.** Subdomain enumeration reads only third-party
   records (crt.sh, SecurityTrails). No traffic is sent to the target.
4. **Active scanning is opt-in.** The `OSINT_ENABLE_ACTIVE_SCANNING` flag
   gates any subprocess call into active tools (Amass, Subfinder, port
   scanners). It defaults to False and requires a conscious choice to flip.
5. **No bundled offensive tooling.** The toolkit detects and uses external
   active-scanning tools when installed, rather than redistributing them.

## What you must do

Before creating a target:

- [ ] You have written authorization from the asset owner, **or** you own
      the assets yourself, **or** the assets are explicit bug-bounty scope
      for a program whose terms permit OSINT against them.
- [ ] Your authorization covers the scope domains you are about to enter.
      If "example.com" is authorized but "example.org" is not, do not add
      the latter.
- [ ] You understand that some sources return data related to individuals
      (contact emails in WHOIS, names in certificate subjects). Handle that
      data under your jurisdiction's privacy rules.

## What this toolkit is not

- **Not an access-granting tool.** It does not exploit vulnerabilities, log
  into services, or enumerate users of applications.
- **Not a threat-to-individuals tool.** Investigative OSINT features
  (username / breach / image) exist to research accounts the operator
  controls or to support consented investigations, not to stalk, dox, or
  harass.
- **Not a substitute for authorization.** Putting an IP in a scope box does
  not make the scan legal.

## Reporting abuse

If you believe this toolkit is being used against you or your
infrastructure without authorization, open an issue on the repository - the
maintainers are interested in making misuse harder to repeat.
