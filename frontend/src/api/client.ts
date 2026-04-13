import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  headers: {
    "Content-Type": "application/json",
  },
});

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

export interface IOC {
  type: string;
  value: string;
  context: string | null;
  enrichment: Record<string, unknown> | null;
  malicious: boolean | null;
}

export interface IOCExtractionResult {
  source: string;
  total_iocs: number;
  iocs: IOC[];
  stats: Record<string, number>;
}

export interface HealthCheck {
  status: string;
  version: string;
  configured_apis: string[];
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

export default api;
