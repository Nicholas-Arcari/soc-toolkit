// Per-page contextual help shown by the PageHelp ("?") button. Centralised
// here (keyed by route) so pages don't each carry their own help markup; the
// homepage entry pairs with an auto-generated overview of every page.

export interface PageHelpEntry {
  title: string;
  summary: string;
  steps?: string[];
}

export const PAGE_HELP: Record<string, PageHelpEntry> = {
  "/": {
    title: "Welcome to SOC Toolkit",
    summary:
      "Your blue-team workbench: triage suspicious emails, dig through logs, extract and pivot on indicators, and validate detections — all in one place. Open any page and tap the ? to see how it works.",
  },
  "/phishing": {
    title: "Phishing Analyzer",
    summary:
      "Upload an email (.eml) to get an automated verdict with a 0–100 risk score.",
    steps: [
      "Drop or choose a .eml file.",
      "Read the verdict and risk score.",
      "Review flagged headers (SPF/DKIM/DMARC), URLs and attachments.",
    ],
  },
  "/logs": {
    title: "Log Analyzer",
    summary:
      "Detect brute force, web exploits and suspicious Windows events from a log file.",
    steps: [
      "Pick the log type (or leave Auto).",
      "Upload an auth.log, access.log or Windows export.",
      "Work the alerts — each maps to MITRE ATT&CK and ranks top source IPs.",
    ],
  },
  "/ioc": {
    title: "IOC Extractor",
    summary:
      "Pull indicators (IPs, domains, URLs, hashes, CVEs) out of reports, emails or raw text.",
    steps: [
      "Upload a PDF/.eml/text file or paste text.",
      "Review the extracted IOCs with their surrounding context.",
      "Export to JSON/CSV, or pivot on one in IOC Pivot.",
    ],
  },
  "/ioc-pivot": {
    title: "IOC Pivot",
    summary:
      "Drill one IP or domain across passive sources — certificate transparency, passive DNS, WHOIS, ASN, Shodan — without touching the target.",
    steps: [
      "Enter an IP or domain.",
      "Explore the linked infrastructure across each source.",
    ],
  },
  "/yara": {
    title: "YARA Scanner",
    summary: "Match an uploaded file against a curated YARA rule set.",
    steps: [
      "Upload the file to scan.",
      "Review hits with severity and MITRE technique mapping.",
    ],
  },
  "/sigma": {
    title: "Sigma Detection",
    summary:
      "Validate Sigma rules by evaluating JSON events against the bundled library.",
    steps: [
      "Inspect the loaded rules.",
      "Paste JSON events and evaluate to see which rules fire.",
    ],
  },
  "/misp": {
    title: "MISP Enrichment",
    summary:
      "Extract IOCs from text and flag which ones your MISP instance already knows.",
    steps: [
      "Paste threat-report text.",
      "Review which indicators MISP has seen before.",
    ],
  },
  "/file": {
    title: "File Inspector",
    summary:
      "Check a download or setup statically — it is never executed.",
    steps: [
      "Upload any file (up to 100 MB).",
      "Read the verdict + risk score and the reasons behind it.",
      "Review detected type vs extension, appended data, macros, embedded IOCs and YARA hits.",
    ],
  },
  "/qr": {
    title: "QR Analyzer",
    summary:
      "Decode a QR code from an image and inspect what it really points to. The image is decoded in your browser.",
    steps: [
      "Upload a screenshot or photo of the QR code.",
      "See the decoded payload and its type (URL, Wi-Fi, text…).",
      "Review quishing flags; for links, the destination is checked against threat intel.",
    ],
  },
  "/link": {
    title: "Link Analyzer",
    summary:
      "Unshorten a link and follow its redirects to reveal the real destination, then check it against threat intel.",
    steps: [
      "Paste a URL (a shortener, a tracking link, anything).",
      "Follow the redirect chain to the final destination.",
      "Review the risk flags and the link reputation.",
    ],
  },
  "/news": {
    title: "Security News",
    summary:
      "The latest from curated threat-intel feeds, refreshed periodically. Click a headline to read the full story.",
  },
  "/profile": {
    title: "Your profile",
    summary:
      "Upload a profile picture, track your XP and level, and sign out. XP grows each time you run an analysis or surface a threat.",
  },
  "/settings": {
    title: "API keys",
    summary:
      "Bring your own keys to enable the enrichment integrations. They are stored only in your browser and sent with your own requests — never on the server.",
  },
  "/contact": {
    title: "Contact the developer",
    summary:
      "Hit a bug or a service issue? Send a note and it lands straight in the developer's inbox.",
  },
};
