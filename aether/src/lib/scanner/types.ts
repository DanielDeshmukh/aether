export interface Finding {
  id: string;
  category: string;
  title: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  detail: string;
  attack_vector: string;
  detected_threat: string;
  evidence_snippet: string;
  provided_solution: string;
  evidence: Record<string, unknown>;
}

export interface PortScanResult {
  host: string;
  ports: { port: number; state: string }[];
  open_ports: number[];
  error?: string;
}

export interface HeaderAuditResult {
  final_url: string;
  status_code: number | null;
  headers: Record<string, string>;
  findings: Finding[];
  error?: string;
}

export interface AuditResult {
  target_url: string;
  tested_params: string[];
  base_response: { url?: string; status_code?: number; headers?: Record<string, string> };
  findings: Finding[];
  profiles: { profile_type: string; label: string; summary: string; details: Record<string, unknown> }[];
  error?: string;
}

export interface HeuristicResult {
  target_url: string;
  findings: Finding[];
  profiles: { profile_type: string; label: string; summary: string; details: Record<string, unknown> }[];
}

export interface TechStackResult {
  target_url: string;
  final_url?: string;
  title?: string;
  headers?: Record<string, string>;
  scripts?: string[];
  meta?: { name: string | null; content: string | null }[];
  frameworks?: string[];
  error?: string;
}

export interface InitialPlan {
  steps: { label: "THOUGHT" | "OBSERVE" | "PLAN"; message: string }[];
}

export interface FinalVerdict {
  threat_level: "low" | "medium" | "high" | "critical";
  risk_impact: string;
  remediation_steps: string[];
}

export interface VulnerabilityRow {
  id: string;
  scan_id: string;
  session_id: string;
  attack_vector: string;
  detected_threat: string;
  provided_solution: string;
  severity: string;
  category: string;
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
  is_fixed: boolean;
}

export interface ScanResults {
  tech_stack: TechStackResult | null;
  port_scan: PortScanResult | null;
  header_audit: HeaderAuditResult | null;
  audit_engine: AuditResult | null;
}
