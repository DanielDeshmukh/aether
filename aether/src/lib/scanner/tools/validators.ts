import { createHash } from "crypto";
import type { Finding } from "../types";

const BLOCKED_NETWORKS = [
  { base: "127.0.0.0", mask: 8 },
  { base: "10.0.0.0", mask: 8 },
  { base: "172.16.0.0", mask: 12 },
  { base: "192.168.0.0", mask: 16 },
  { base: "169.254.0.0", mask: 16 },
  { base: "0.0.0.0", mask: 8 },
  { base: "100.64.0.0", mask: 10 },
  { base: "198.18.0.0", mask: 15 },
];

function ipToLong(ip: string): number {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isInBlockedRange(ip: string): boolean {
  const ipLong = ipToLong(ip);
  for (const { base, mask } of BLOCKED_NETWORKS) {
    const baseLong = ipToLong(base);
    const maskLong = ~((1 << (32 - mask)) - 1) >>> 0;
    if ((ipLong & maskLong) === (baseLong & maskLong)) return true;
  }
  return false;
}

export function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
    const hostname = parsed.hostname;
    if (!hostname) return false;
    if (hostname === "169.254.169.254") return false;
    const blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1"];
    if (blocked.includes(hostname)) return false;
    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

export function findingId(prefix: string, ...parts: string[]): string {
  const digest = createHash("sha1").update(parts.join(":")).digest("hex").slice(0, 12);
  return `${prefix}:${digest}`;
}

export function coerceSeverity(v: unknown): string {
  const valid = new Set(["Low", "Medium", "High", "Critical"]);
  if (typeof v === "string") {
    const capped = v.trim().charAt(0).toUpperCase() + v.trim().slice(1).toLowerCase();
    if (valid.has(capped)) return capped;
  }
  return "Low";
}

export function buildVulnerabilityRow(raw: Record<string, unknown>, scanId: string, sessionId: string): Record<string, unknown> {
  return {
    id: raw.id || crypto.randomUUID(),
    scan_id: scanId,
    session_id: sessionId,
    attack_vector: raw.attack_vector || raw.category || "Web Application Surface",
    detected_threat: raw.detected_threat || raw.title || "Potential Hunt Signal",
    provided_solution: raw.provided_solution || raw.solution || "Apply standard security hardening per OWASP guidelines.",
    severity: coerceSeverity(raw.severity),
    category: raw.category || "general",
    title: raw.title || "Untitled Vulnerability",
    detail: raw.detail || "Analysis in progress.",
    evidence: typeof raw.evidence === "object" && raw.evidence !== null ? raw.evidence : {},
    is_fixed: raw.is_fixed || false,
  };
}
