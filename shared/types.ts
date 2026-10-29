// Shared types used by both the Fastify server and the React web client.

export type HttpMethod = "POST" | "GET";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus = "pass" | "fail" | "warn" | "info" | "manual";

export type TestMode = "auto" | "assisted" | "guided";

/**
 * The central request abstraction. Every security test derives variants from a
 * single base request so authenticated / operation-specific endpoints work.
 * Captures the full HTTP request: method, url, all headers (authorization,
 * Origin, Content-Type, User-Agent, custom...) and the GraphQL JSON body.
 */
export interface GraphQLRequest {
  method: HttpMethod;
  url: string;
  headers: Record<string, string>;
  operationName?: string;
  query: string;
  variables?: Record<string, unknown>;
  /** Original raw HTTP text, if the request was pasted. */
  raw?: string;
}

export interface Cvss {
  score: number; // 0.0 - 10.0 (CVSS 3.1 base)
  vector: string; // e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
}

export interface Evidence {
  /** Human-readable note describing what proves the finding. */
  note?: string;
  /** The exact probe request that was sent. */
  request?: {
    method: HttpMethod;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  /** The server response that proves the finding. */
  response?: {
    status?: number;
    headers?: Record<string, string>;
    bodySnippet?: string;
  };
  /** Any extra artifact, e.g. a generated CSRF PoC HTML snippet. */
  artifact?: string;
}

export interface Finding {
  id: string;
  testId: string;
  controlArea: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  description: string;
  evidence?: Evidence;
  affectedOperation?: string;
  remediation: string;
  cvss?: Cvss;
  cwe?: string[];
  cve?: string[];
  references: string[];
}

export interface TestResult {
  testId: string;
  controlArea: string;
  title: string;
  mode: TestMode;
  status: FindingStatus;
  findings: Finding[];
  /** Milliseconds the test took. */
  durationMs?: number;
  /** For guided/assisted tests that need more input before a verdict. */
  needsInput?: boolean;
}

export interface HostGeo {
  host: string;
  ip?: string;
  isPrivate?: boolean;
  country?: string;
  lat?: number;
  lon?: number;
  /** Why this host surfaced: the base target, or a reflected/SSRF/redirect host. */
  source: "target" | "cors" | "redirect" | "ssrf";
}

export interface ScanSummary {
  totalTests: number;
  passed: number;
  failed: number;
  warned: number;
  manual: number;
  bySeverity: Record<Severity, number>;
  byControlArea: Record<string, { passed: number; failed: number; total: number }>;
  securityScore: number; // 0 - 100
  endpointsDiscovered: number;
}

export interface ScanResult {
  id: string;
  target: string;
  startedAt: string;
  finishedAt?: string;
  fingerprint?: string;
  results: TestResult[];
  findings: Finding[];
  hosts: HostGeo[];
  summary: ScanSummary;
}

/** SSE event streamed from the server while a scan runs. */
export type ScanEvent =
  | { type: "start"; scanId: string; total: number; target: string }
  | { type: "test-start"; testId: string; title: string; controlArea: string }
  | { type: "test-result"; result: TestResult; summary: ScanSummary }
  | { type: "host"; host: HostGeo }
  | { type: "done"; scan: ScanResult }
  | { type: "error"; message: string };

// ---- Analyzer ----

export interface SchemaStat {
  types: number;
  queries: number;
  mutations: number;
  subscriptions: number;
  deprecated: number;
}

export interface SchemaReport {
  ok: boolean;
  error?: string;
  stats?: SchemaStat;
  findings: Finding[];
  /** Operations extracted from a pasted JS bundle, if provided. */
  extractedOperations?: string[];
}

// ---- Proxy ----

export interface ProxyEvent {
  id: string;
  at: string;
  method: string;
  operationName?: string;
  operationType?: string;
  depth: number;
  fieldCount: number;
  aliasCount: number;
  batchSize: number;
  complexity: number;
  status?: number;
  flagged: boolean;
  flags: string[];
}

// ---- Advisor ----

export interface Recommendation {
  id: string;
  title: string;
  severity: Severity;
  rationale: string;
  references: string[];
  cwe?: string[];
}
