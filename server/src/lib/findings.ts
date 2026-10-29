import type { Finding, Severity, FindingStatus } from "@shared/types.js";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

let counter = 0;
export function nextId(prefix = "F"): string {
  counter += 1;
  return `${prefix}-${Date.now().toString(36)}-${counter}`;
}

export interface FindingInput {
  testId: string;
  controlArea: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  description: string;
  remediation: string;
  affectedOperation?: string;
  references?: string[];
  evidence?: Finding["evidence"];
  cvss?: Finding["cvss"];
  cwe?: string[];
  cve?: string[];
}

export function makeFinding(input: FindingInput): Finding {
  return {
    id: nextId(),
    testId: input.testId,
    controlArea: input.controlArea,
    title: input.title,
    severity: input.severity,
    status: input.status,
    description: input.description,
    remediation: input.remediation,
    affectedOperation: input.affectedOperation,
    references: input.references ?? [],
    evidence: input.evidence,
    cvss: input.cvss,
    cwe: input.cwe,
    cve: input.cve,
  };
}

/** Truncate a body for evidence capture. */
export function snippet(text: string | undefined, max = 1500): string | undefined {
  if (!text) return undefined;
  return text.length > max ? text.slice(0, max) + "\n…(truncated)" : text;
}
