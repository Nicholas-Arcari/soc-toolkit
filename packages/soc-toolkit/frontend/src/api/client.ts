import { createApiClient, type IOC, type IOCExtractionResult, type HealthCheck } from "@sec-toolkit/common/api";
import { apiKeyHeaders } from "../lib/apiKeys";
import { recordAnalysis } from "../lib/history";

const api = createApiClient({ baseURL: "/api" });

// Attach the user's own provider keys (entered in Settings, stored only in
// their browser) as X-Api-Key-<service> headers, so the backend uses them for
// this request and falls back to its .env when absent.
api.interceptors.request.use((config) => {
  const extra = apiKeyHeaders();
  if (Object.keys(extra).length > 0) {
    config.headers = config.headers ?? {};
    Object.assign(config.headers as Record<string, string>, extra);
  }
  return config;
});

export type { IOC, IOCExtractionResult, HealthCheck };

export interface PhishingResult {
  verdict: string;
  confidence: number;
  risk_score: number;
  headers: Record<string, unknown>;
  urls: URLResult[];
  attachments: AttachmentResult[];
  indicators: string[];
  recommendations: string[];
}

export interface URLResult {
  url: string;
  domain: string;
  suspicious_patterns: string[];
  malicious: boolean;
  virustotal: Record<string, unknown> | null;
}

export interface AttachmentResult {
  filename: string;
  size: number;
  hashes: { md5: string; sha1: string; sha256: string };
  malicious: boolean;
  suspicious_extension: boolean;
}

export interface LogAlert {
  severity: string;
  message: string;
  source_ip: string | null;
  geo: { country: string; isp: string; abuse_score: number } | null;
  count: number;
  mitre_technique: string | null;
}

export interface LogAnalysisResult {
  log_type: string;
  total_lines: number;
  suspicious_entries: number;
  alerts: LogAlert[];
  top_ips: { ip: string; attempts: number }[];
  timeline: { hour: string; count: number }[];
  summary: string;
}

export async function analyzePhishing(file: File): Promise<PhishingResult> {
  const formData = new FormData();
  formData.append("file", file);
  const response = await api.post<PhishingResult>("/phishing/analyze", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  awardXp("phishing", response.data.indicators?.length ?? 0);
  return response.data;
}

export interface InboxMessage {
  subject: string;
  from: string;
  date: string;
  verdict: string;
  risk_score: number;
  indicators: string[];
}

export interface InboxQuery {
  host: string;
  username: string;
  password: string;
  port?: number;
  folder?: string;
  limit?: number;
}

export async function triageInbox(query: InboxQuery): Promise<InboxMessage[]> {
  const response = await api.post<{ messages: InboxMessage[] }>(
    "/phishing/inbox",
    query,
  );
  return response.data.messages;
}

export async function analyzeLogs(
  file: File,
  logType: string = "auto"
): Promise<LogAnalysisResult> {
  const formData = new FormData();
  formData.append("file", file);
  const response = await api.post<LogAnalysisResult>(
    `/logs/analyze?log_type=${logType}`,
    formData,
    { headers: { "Content-Type": "multipart/form-data" } }
  );
  awardXp("logs", response.data.alerts.length);
  return response.data;
}

export async function extractIOCs(file: File): Promise<IOCExtractionResult> {
  const formData = new FormData();
  formData.append("file", file);
  const response = await api.post<IOCExtractionResult>("/ioc/extract", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  awardXp("ioc", response.data.total_iocs);
  return response.data;
}

export async function exportReport(
  data: Record<string, unknown>,
  reportType: string,
  format: string
): Promise<Blob> {
  const response = await api.post(
    "/reports/export",
    { data, report_type: reportType, format },
    { responseType: "blob" }
  );
  return response.data;
}

export async function healthCheck(): Promise<HealthCheck> {
  const response = await api.get<HealthCheck>("/health");
  return response.data;
}

export interface CertificateRow {
  subdomain: string;
  issuer: string;
  not_before: string;
  not_after: string;
  cert_id: number | string;
  active: boolean;
}

export interface PassiveDNSRow {
  value: string;
  query?: string;
  record_type: string;
  first_seen: string;
  last_seen: string;
  organizations?: string[];
  source: string;
}

export interface WhoisRecord {
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  updated_date?: string;
  name_servers?: string[];
  emails?: string[];
  status?: string[];
  registrant_name?: string;
  registrant_org?: string;
  country?: string;
}

export interface WhoisHistoryRow {
  registrar: string;
  contact_email: string;
  creation_date: string;
  expiration_date: string;
  updated_date: string;
  name_servers: string[];
  status: string;
  source: string;
}

export interface ASNRecord {
  asn?: string;
  asn_description?: string;
  country?: string;
  cidr?: string;
  registry?: string;
  source?: string;
}

export interface ShodanRecord {
  ip?: string;
  os?: string;
  organization?: string;
  isp?: string;
  country?: string;
  city?: string;
  open_ports?: number[];
  vulns?: string[];
  hostnames?: string[];
  last_update?: string;
  error?: string;
}

export interface PivotSections {
  certificates?: CertificateRow[];
  passive_dns?: PassiveDNSRow[];
  whois?: WhoisRecord;
  whois_history?: WhoisHistoryRow[];
  subdomains?: string[];
  asn?: ASNRecord;
  reverse_dns?: string[];
  shodan?: ShodanRecord;
}

export interface PivotResult {
  target: string;
  target_type: string;
  summary: Record<string, unknown>;
  pivot: PivotSections;
  error?: string | null;
}

export async function pivotOSINT(type: string, value: string): Promise<PivotResult> {
  const response = await api.post<PivotResult>("/osint/pivot", { type, value });
  awardXp("ioc-pivot", response.data.error ? 0 : 1);
  return response.data;
}

export interface YaraMatch {
  rule: string;
  namespace: string;
  tags: string[];
  metadata: Record<string, unknown>;
}

export interface YaraScanResult {
  filename: string;
  size: number;
  match_count: number;
  matches: YaraMatch[];
}

export async function scanYara(file: File): Promise<YaraScanResult> {
  const formData = new FormData();
  formData.append("file", file);
  const response = await api.post<YaraScanResult>("/yara/scan", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  awardXp("yara", response.data.match_count);
  return response.data;
}

export interface SigmaRuleSummary {
  id: string;
  title: string;
  level: string;
  tags: string[];
  description: string;
  logsource: Record<string, string>;
}

export interface SigmaRuleList {
  rule_count: number;
  rules: SigmaRuleSummary[];
}

export interface SigmaMatch {
  rule_id: string;
  title: string;
  level: string;
  tags: string[];
  description: string;
  event: Record<string, unknown>;
}

export interface SigmaEvaluationResult {
  event_count: number;
  match_count: number;
  matches: SigmaMatch[];
}

export async function listSigmaRules(): Promise<SigmaRuleList> {
  const response = await api.get<SigmaRuleList>("/sigma/rules");
  return response.data;
}

export async function evaluateSigma(
  events: Record<string, unknown>[],
): Promise<SigmaEvaluationResult> {
  const response = await api.post<SigmaEvaluationResult>("/sigma/evaluate", { events });
  awardXp("sigma", response.data.match_count);
  return response.data;
}

export type SigmaBackend = "splunk" | "lucene" | "kql";

export interface SigmaBackendList {
  backends: SigmaBackend[];
}

export interface SigmaCompileResult {
  backend: SigmaBackend;
  rule_id: string;
  title: string;
  level: string;
  query: string;
}

export async function listSigmaBackends(): Promise<SigmaBackendList> {
  const response = await api.get<SigmaBackendList>("/sigma/backends");
  return response.data;
}

export async function compileSigmaRule(
  ruleId: string,
  backend: SigmaBackend,
): Promise<SigmaCompileResult> {
  const response = await api.post<SigmaCompileResult>("/sigma/compile", {
    rule_id: ruleId,
    backend,
  });
  return response.data;
}

export interface MISPEventRef {
  event_id?: string | number;
  uuid?: string;
  info?: string;
  threat_level_id?: string | number;
  org?: string;
  date?: string;
  attribute_category?: string;
  attribute_type?: string;
  to_ids?: boolean;
}

export interface MISPLookupResult {
  found?: boolean;
  event_count?: number;
  to_ids?: boolean;
  events?: MISPEventRef[];
  error?: string;
}

export interface MISPEnrichmentResponse {
  extracted_count: number;
  iocs: IOC[];
  misp: {
    known_count: number;
    results: Record<string, MISPLookupResult>;
    summary: Record<string, { checked: number; known: number }>;
  };
}

export async function enrichWithMISP(text: string): Promise<MISPEnrichmentResponse> {
  const response = await api.post<MISPEnrichmentResponse>("/misp/enrich", { text });
  awardXp("misp", response.data.misp.known_count);
  return response.data;
}

export async function lookupMISP(value: string, kind: string): Promise<MISPLookupResult> {
  const response = await api.post<MISPLookupResult>("/misp/lookup", { value, kind });
  return response.data;
}

export async function uploadAvatar(file: File): Promise<void> {
  const formData = new FormData();
  formData.append("file", file);
  await api.post("/auth/avatar", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
}

export async function removeAvatar(): Promise<void> {
  await api.delete("/auth/avatar");
}

// Gamification. Fire-and-forget so it can never block or break an analysis;
// on success it pings the auth context (window event) to refresh XP/level.
// Silently no-ops when auth is disabled or the user isn't logged in.
export function awardXp(action: string, findings = 0): void {
  recordAnalysis(action, findings);
  api
    .post("/auth/xp", { action, findings })
    .then(() => window.dispatchEvent(new CustomEvent("sectk:user-updated")))
    .catch(() => {});
}

export interface NewsItem {
  title: string;
  link: string;
  source: string;
  published: string | null;
  summary: string;
}

export interface NewsResponse {
  count: number;
  items: NewsItem[];
}

export async function fetchNews(limit = 40): Promise<NewsResponse> {
  const response = await api.get<NewsResponse>(`/news?limit=${limit}`);
  return response.data;
}

export interface FileInspectionReport {
  filename: string;
  size: number;
  extension: string;
  detected_type: string;
  type_mismatch: boolean;
  suspicious_extension: boolean;
  double_extension: boolean;
  macros: boolean;
  trailing_bytes: number;
  hashes: { md5: string; sha1: string; sha256: string };
  embedded: { urls: string[]; ips: string[]; script_markers: string[] };
  yara_matches: {
    rule: string;
    namespace: string;
    tags: string[];
    metadata: Record<string, unknown>;
  }[];
  virustotal: Record<string, unknown> | null;
  malwarebazaar: Record<string, unknown> | null;
  verdict: string;
  risk_score: number;
  reasons: string[];
}

export async function inspectFile(file: File): Promise<FileInspectionReport> {
  const formData = new FormData();
  formData.append("file", file);
  const response = await api.post<FileInspectionReport>("/file/scan", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  awardXp("file", response.data.reasons?.length ?? 0);
  return response.data;
}

export interface UrlCheckResult {
  url: string;
  domain: string;
  suspicious_patterns: string[];
  malicious: boolean;
  virustotal: Record<string, unknown> | null;
  urlscan?: Record<string, unknown> | null;
}

export async function checkUrl(url: string): Promise<UrlCheckResult | null> {
  const response = await api.post<{ url: string; results: UrlCheckResult[] }>(
    "/phishing/check-url",
    { url },
  );
  return response.data.results[0] ?? null;
}

export interface RedirectHop {
  url: string;
  status: number;
}

export interface RedirectTrace {
  input: string;
  final_url: string;
  hops: number;
  chain: RedirectHop[];
  blocked: boolean;
  error: string | null;
}

export async function traceUrl(url: string): Promise<RedirectTrace> {
  const response = await api.post<RedirectTrace>("/link/trace", { url });
  return response.data;
}

export async function redeemLicense(key: string): Promise<void> {
  await api.post("/auth/redeem-license", { key });
}

export async function verifyEmail(token: string): Promise<void> {
  await api.post("/auth/verify", { token });
}

export default api;
