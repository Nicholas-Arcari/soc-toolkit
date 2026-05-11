import { createApiClient } from "@sec-toolkit/common/api";

const api = createApiClient({ baseURL: "/api" });

export interface HealthCheck {
  status: string;
  version: string;
  toolkit: string;
  configured_apis: string[];
  active_scanning_enabled: boolean;
}

export interface Target {
  id: number;
  name: string;
  owner_email: string;
  scope_domains: string[];
  authorized_to_scan: boolean;
  active: boolean;
  created_at: string;
}

export interface TargetCreateInput {
  name: string;
  owner_email?: string;
  scope_domains: string[];
  authorized_to_scan: boolean;
}

export interface SubdomainRow {
  fqdn: string;
  source: string;
  first_seen: string;
  last_seen: string;
}

export interface SubdomainEnumResult {
  scan_id: number;
  target_id: number;
  status: string;
  summary: {
    discovered_total: number;
    new: number;
    updated: number;
    sources: Record<string, number>;
  };
  subdomains: string[];
}

export async function healthCheck(): Promise<HealthCheck> {
  const response = await api.get<HealthCheck>("/health");
  return response.data;
}

export async function listTargets(includeInactive = false): Promise<Target[]> {
  const response = await api.get<Target[]>("/targets", {
    params: { include_inactive: includeInactive },
  });
  return response.data;
}

export async function getTarget(id: number): Promise<Target> {
  const response = await api.get<Target>(`/targets/${id}`);
  return response.data;
}

export async function createTarget(input: TargetCreateInput): Promise<Target> {
  const response = await api.post<Target>("/targets", input);
  return response.data;
}

export async function deleteTarget(id: number): Promise<void> {
  await api.delete(`/targets/${id}`);
}

export async function runSubdomainEnum(targetId: number): Promise<SubdomainEnumResult> {
  const response = await api.post<SubdomainEnumResult>(
    `/scans/targets/${targetId}/subdomain-enum`
  );
  return response.data;
}

export interface ActiveScanSummary {
  tool: string;
  discovered_total: number;
  new: number;
  stderr_tail: string[];
}

export interface ActiveScanResult {
  scan_id: number;
  target_id: number;
  status: string;
  summary: ActiveScanSummary;
  discovered: string[];
}

export async function runActiveScan(
  targetId: number,
  confirmation: string,
): Promise<ActiveScanResult> {
  const response = await api.post<ActiveScanResult>(
    `/scans/targets/${targetId}/active-scan`,
    { confirmation },
  );
  return response.data;
}

export async function listSubdomains(targetId: number): Promise<SubdomainRow[]> {
  const response = await api.get<SubdomainRow[]>(`/scans/targets/${targetId}/subdomains`);
  return response.data;
}

export interface DNSDomainSummary {
  domain: string;
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  txt_count: number;
  spf: string | null;
  dmarc: string | null;
}

export interface DNSMappingSummary {
  domains_checked: number;
  findings_created: number;
  domains: DNSDomainSummary[];
}

export interface DNSMappingResult {
  scan_id: number;
  target_id: number;
  status: string;
  summary: DNSMappingSummary;
}

export async function runDNSMapping(targetId: number): Promise<DNSMappingResult> {
  const response = await api.post<DNSMappingResult>(
    `/scans/targets/${targetId}/dns-mapping`,
  );
  return response.data;
}

export interface ServiceDiscoverySummary {
  hosts_checked?: number;
  services_new?: number;
  services_updated?: number;
  cves_seen?: string[];
  skipped?: boolean;
  reason?: string;
  note?: string;
}

export interface ServiceDiscoveryResult {
  scan_id: number;
  target_id: number;
  status: string;
  summary: ServiceDiscoverySummary;
}

export async function runServiceDiscovery(
  targetId: number,
): Promise<ServiceDiscoveryResult> {
  const response = await api.post<ServiceDiscoveryResult>(
    `/scans/targets/${targetId}/service-discovery`,
  );
  return response.data;
}

export interface ServiceRow {
  subdomain_id: number;
  ip: string;
  port: number;
  banner: string;
  cves: string[];
  first_seen: string;
  last_seen: string;
}

export async function listServices(targetId: number): Promise<ServiceRow[]> {
  const response = await api.get<ServiceRow[]>(`/scans/targets/${targetId}/services`);
  return response.data;
}

export type FindingStatus = "open" | "acknowledged" | "resolved" | "false_positive";

export interface FindingRow {
  id: number;
  severity: string;
  category: string;
  description: string;
  status: FindingStatus;
  note: string;
  created_at: string;
  resolved_at: string | null;
}

export async function listFindings(targetId: number): Promise<FindingRow[]> {
  const response = await api.get<FindingRow[]>(`/scans/targets/${targetId}/findings`);
  return response.data;
}

export async function updateFinding(
  targetId: number,
  findingId: number,
  patch: { status?: FindingStatus; note?: string },
): Promise<FindingRow> {
  const response = await api.patch<FindingRow>(
    `/scans/targets/${targetId}/findings/${findingId}`,
    patch,
  );
  return response.data;
}

export type ExportKind =
  | "subdomains.csv"
  | "services.csv"
  | "findings.csv"
  | "report.json";

/**
 * Absolute URL for the export endpoint - anchor/download attributes need
 * a real URL, not an axios call. The axios baseURL prefix is re-applied
 * here so the relative `/api` stays consistent between XHR and anchor
 * downloads.
 */
export function exportUrl(targetId: number, kind: ExportKind): string {
  const base = api.defaults.baseURL ?? "/api";
  return `${base}/scans/targets/${targetId}/export/${kind}`;
}

// --- Investigate (Phase D) ---

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  meta?: Record<string, string>;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

export interface EntityGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface UsernameHit {
  platform: string;
  category: string;
  url: string;
  status: "present" | "absent" | "inconclusive";
  http_status: number;
  note?: string;
}

export interface UsernameSearchResponse {
  username: string;
  checked: number;
  present_count: number;
  hits: UsernameHit[];
  graph: EntityGraph;
}

export interface BreachRecord {
  name: string;
  title: string;
  domain: string;
  breach_date: string;
  pwn_count: number;
  data_classes: string[];
  verified?: boolean;
  sensitive?: boolean;
  description?: string;
}

export interface BreachSearchResponse {
  query: string;
  kind: "email" | "domain";
  available: boolean;
  note?: string;
  breaches: BreachRecord[];
  graph: EntityGraph;
}

export interface ImageMetadataResponse {
  filename: string;
  format: string;
  size_px: [number, number];
  size_bytes: number;
  exif: Record<string, string>;
  gps: { latitude: number; longitude: number; altitude?: number | null } | null;
  note?: string;
  graph: EntityGraph;
}

export async function investigateUsername(username: string): Promise<UsernameSearchResponse> {
  const response = await api.post<UsernameSearchResponse>("/investigate/username", { username });
  return response.data;
}

export async function investigateBreaches(query: string): Promise<BreachSearchResponse> {
  const response = await api.post<BreachSearchResponse>("/investigate/breaches", { query });
  return response.data;
}

export async function investigateImage(file: File): Promise<ImageMetadataResponse> {
  const form = new FormData();
  form.append("file", file);
  const response = await api.post<ImageMetadataResponse>("/investigate/image", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return response.data;
}

export default api;
