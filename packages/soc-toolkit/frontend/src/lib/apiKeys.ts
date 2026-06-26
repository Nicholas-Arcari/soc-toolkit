// Bring-your-own API keys for SaaS users (no repo / no .env). Stored only in
// the browser; the api client attaches them as X-Api-Key-<id> headers so the
// backend uses them per-request and never persists them. `id` must match the
// backend service name (and the .env *_API_KEY prefix).

export interface ApiKeyService {
  id: string;
  label: string;
  url: string;
}

export const API_KEY_SERVICES: ApiKeyService[] = [
  { id: "virustotal", label: "VirusTotal", url: "https://www.virustotal.com/gui/join-us" },
  { id: "abuseipdb", label: "AbuseIPDB", url: "https://www.abuseipdb.com/register" },
  { id: "shodan", label: "Shodan", url: "https://account.shodan.io/register" },
  { id: "urlscan", label: "URLScan.io", url: "https://urlscan.io/user/signup/" },
  { id: "otx", label: "AlienVault OTX", url: "https://otx.alienvault.com/" },
  { id: "securitytrails", label: "SecurityTrails", url: "https://securitytrails.com/app/signup" },
];

const STORAGE_KEY = "soc-toolkit.apikeys";

export type ApiKeyMap = Record<string, string>;

export function readApiKeys(): ApiKeyMap {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as ApiKeyMap) : {};
  } catch {
    return {};
  }
}

export function writeApiKeys(keys: ApiKeyMap): void {
  // Drop blanks so we never emit empty headers.
  const clean: ApiKeyMap = {};
  for (const [id, value] of Object.entries(keys)) {
    if (value && value.trim()) clean[id] = value.trim();
  }
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(clean));
  } catch {
    // Storage blocked (private mode) - keys just won't persist.
  }
}

export function apiKeyHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [id, value] of Object.entries(readApiKeys())) {
    if (value) headers[`X-Api-Key-${id}`] = value;
  }
  return headers;
}
