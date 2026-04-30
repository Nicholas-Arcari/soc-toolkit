import { createApiClient, type IOC, type IOCExtractionResult, type HealthCheck } from "@sec-toolkit/common/api";

const api = createApiClient({ baseURL: "/api" });

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
  return response.data;
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
  return response.data;
}

export async function extractIOCs(file: File): Promise<IOCExtractionResult> {
  const formData = new FormData();
  formData.append("file", file);
  const response = await api.post<IOCExtractionResult>("/ioc/extract", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
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
  return response.data;
}

export async function lookupMISP(value: string, kind: string): Promise<MISPLookupResult> {
  const response = await api.post<MISPLookupResult>("/misp/lookup", { value, kind });
  return response.data;
}

export default api;
