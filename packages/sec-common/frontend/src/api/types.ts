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
