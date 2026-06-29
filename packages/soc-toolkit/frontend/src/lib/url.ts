const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "rebrand.ly", "cutt.ly", "t.ly", "shorturl.at", "rb.gy",
]);

/** The hostname of a URL, or the raw string if it can't be parsed. */
export function hostFromUrl(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname || rawUrl;
  } catch {
    return rawUrl;
  }
}

/** Heuristic "is this link risky?" flags shared by the QR + link analyzers. */
export function urlRiskFlags(rawUrl: string): string[] {
  const flags: string[] = [];
  try {
    const url = new URL(rawUrl);
    const host = url.hostname.toLowerCase();
    if (url.protocol !== "https:") flags.push("Not HTTPS");
    if (SHORTENERS.has(host)) {
      flags.push("URL shortener - hides the real destination");
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      flags.push("IP address instead of a domain");
    }
    if (host.startsWith("xn--") || host.includes(".xn--")) {
      flags.push("Punycode/IDN domain - possible look-alike");
    }
    if (url.username || url.password) {
      flags.push("Credentials embedded in the URL");
    }
    if ((rawUrl.match(/https?:\/\//gi) ?? []).length > 1) {
      flags.push("Multiple URLs - possible redirect chain");
    }
  } catch {
    flags.push("Malformed URL");
  }
  return flags;
}
