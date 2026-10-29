// Maps vulnerability classes to CWE, a defensible CVSS 3.1 base, remediation and references.
// CVEs are intentionally NOT hard-coded to findings — they are only attached at runtime when
// a fingerprinted engine/version matches a known advisory (see knownCvesForFingerprint).

import type { Cvss, Severity } from "@shared/types.js";

export interface VulnClass {
  key: string;
  title: string;
  severity: Severity;
  cwe: string[];
  cvss: Cvss;
  remediation: string;
  references: string[];
}

const OWASP = "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html";

export const VULN_CLASSES: Record<string, VulnClass> = {
  introspection: {
    key: "introspection",
    title: "Introspection enabled in production",
    severity: "medium",
    cwe: ["CWE-200"],
    cvss: { score: 5.3, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" },
    remediation:
      "Disable introspection in production (e.g. Apollo: introspection:false), or restrict it to trusted roles/environments.",
    references: [OWASP, "https://graphql.org/learn/introspection/"],
  },
  fieldSuggestions: {
    key: "fieldSuggestions",
    title: "Field suggestions leak schema",
    severity: "low",
    cwe: ["CWE-200"],
    cvss: { score: 3.7, vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" },
    remediation:
      "Disable 'Did you mean' field suggestions in production (e.g. graphql-js: set a custom validation rule or disable suggestions) so the schema cannot be reconstructed.",
    references: [OWASP],
  },
  devTools: {
    key: "devTools",
    title: "GraphQL development tools exposed",
    severity: "medium",
    cwe: ["CWE-200", "CWE-16"],
    cvss: { score: 5.3, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" },
    remediation: "Disable GraphiQL / Playground / Voyager and any schema explorer in production.",
    references: [OWASP],
  },
  noAuth: {
    key: "noAuth",
    title: "Protected operation accessible without authentication",
    severity: "high",
    cwe: ["CWE-306"],
    cvss: { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" },
    remediation: "Require and verify authentication server-side for every protected query, mutation and subscription.",
    references: [OWASP],
  },
  tokenHandling: {
    key: "tokenHandling",
    title: "Invalid tokens accepted",
    severity: "high",
    cwe: ["CWE-287", "CWE-345"],
    cvss: { score: 8.1, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" },
    remediation: "Reject expired, malformed, tampered and unsigned tokens; validate signature, algorithm, issuer and expiry.",
    references: [OWASP, "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
  },
  bola: {
    key: "bola",
    title: "Broken object-level authorization (BOLA/IDOR)",
    severity: "high",
    cwe: ["CWE-639"],
    cvss: { score: 8.1, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" },
    remediation: "Enforce per-object ownership/authorization checks in every resolver, not only in the UI.",
    references: [OWASP, "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
  },
  missingAuthz: {
    key: "missingAuthz",
    title: "Missing or client-side authorization",
    severity: "high",
    cwe: ["CWE-862", "CWE-285"],
    cvss: { score: 8.1, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" },
    remediation: "Enforce authorization server-side at the resolver/field level for every operation and nested field.",
    references: [OWASP],
  },
  overFetch: {
    key: "overFetch",
    title: "Sensitive field over-fetch",
    severity: "high",
    cwe: ["CWE-200", "CWE-213"],
    cvss: { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" },
    remediation: "Apply field-level authorization; never expose secret fields (password/token/apiKey) through the schema.",
    references: [OWASP],
  },
  injection: {
    key: "injection",
    title: "Injection via GraphQL argument",
    severity: "critical",
    cwe: ["CWE-89", "CWE-74"],
    cvss: { score: 9.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
    remediation: "Use parameterized queries / safe APIs; validate and sanitize all inputs before backend use.",
    references: [OWASP, "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"],
  },
  xss: {
    key: "xss",
    title: "Reflected input (potential XSS)",
    severity: "medium",
    cwe: ["CWE-79"],
    cvss: { score: 6.1, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" },
    remediation: "Encode output in the consuming client; validate and sanitize inputs server-side.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
  },
  depthDos: {
    key: "depthDos",
    title: "No query depth limit (DoS)",
    severity: "high",
    cwe: ["CWE-770", "CWE-400"],
    cvss: { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
    remediation: "Enforce a maximum query depth and reject queries that exceed it.",
    references: [OWASP],
  },
  complexityDos: {
    key: "complexityDos",
    title: "No query complexity/cost limit (DoS)",
    severity: "high",
    cwe: ["CWE-770", "CWE-400"],
    cvss: { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
    remediation: "Add query cost analysis with a per-request budget; reject over-budget queries.",
    references: [OWASP, "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#query-cost-analysis"],
  },
  pagination: {
    key: "pagination",
    title: "Unbounded result size",
    severity: "medium",
    cwe: ["CWE-770"],
    cvss: { score: 5.3, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" },
    remediation: "Enforce maximum page sizes and sane defaults on list fields.",
    references: [OWASP],
  },
  batching: {
    key: "batching",
    title: "Unbounded batching / aliasing",
    severity: "high",
    cwe: ["CWE-770", "CWE-799"],
    cvss: { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
    remediation: "Limit operations per request and alias counts; apply rate limiting per operation, not per request.",
    references: [OWASP, "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#batching-attacks"],
  },
  errorLeak: {
    key: "errorLeak",
    title: "Verbose errors leak internals",
    severity: "medium",
    cwe: ["CWE-209"],
    cvss: { score: 5.3, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" },
    remediation: "Return generic error messages in production; strip stack traces, DB and file-path details.",
    references: [OWASP],
  },
  cors: {
    key: "cors",
    title: "Permissive CORS with credentials",
    severity: "high",
    cwe: ["CWE-942", "CWE-346"],
    cvss: { score: 7.1, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N" },
    remediation: "Allowlist trusted origins; never reflect arbitrary Origin together with Access-Control-Allow-Credentials:true.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"],
  },
  csrf: {
    key: "csrf",
    title: "Cross-site request forgery on GraphQL",
    severity: "high",
    cwe: ["CWE-352"],
    cvss: { score: 8.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" },
    remediation:
      "Reject simple content types (form-encoded/text/plain) and GET for state changes; require a CSRF token or custom header and SameSite cookies.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
  },
  ssrf: {
    key: "ssrf",
    title: "Server-side request forgery",
    severity: "high",
    cwe: ["CWE-918"],
    cvss: { score: 8.6, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N" },
    remediation: "Allowlist outbound hosts; block localhost/private/metadata ranges; resolve and re-validate after redirects.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
  },
  transport: {
    key: "transport",
    title: "Insecure transport",
    severity: "medium",
    cwe: ["CWE-319"],
    cvss: { score: 5.9, vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" },
    remediation: "Force HTTPS and HSTS; redirect or reject plaintext HTTP.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
  },
  config: {
    key: "config",
    title: "Debug / development configuration in production",
    severity: "medium",
    cwe: ["CWE-16", "CWE-489"],
    cvss: { score: 5.3, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" },
    remediation: "Disable debug mode, tracing and verbose errors; ship a hardened production config.",
    references: [OWASP],
  },
  dataExposure: {
    key: "dataExposure",
    title: "Excessive data / internal metadata exposure",
    severity: "medium",
    cwe: ["CWE-200", "CWE-213"],
    cvss: { score: 5.3, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" },
    remediation: "Return only what the requester needs; remove internal identifiers and implementation metadata.",
    references: [OWASP],
  },
};

export function vuln(key: keyof typeof VULN_CLASSES): VulnClass {
  return VULN_CLASSES[key];
}

/**
 * Known CVE advisories keyed by a fingerprint substring. Only used when the engine
 * fingerprint actually matches — never fabricated onto generic findings.
 */
const CVE_BY_FINGERPRINT: { match: RegExp; cves: string[]; note: string }[] = [
  {
    match: /graphql-ruby/i,
    cves: ["CVE-2022-31178"],
    note: "graphql-ruby error handling advisory — verify the running version.",
  },
  {
    match: /hasura/i,
    cves: ["CVE-2021-45905"],
    note: "Hasura GraphQL Engine advisory — verify the running version.",
  },
];

export function knownCvesForFingerprint(fingerprint: string | undefined): { cves: string[]; note: string }[] {
  if (!fingerprint) return [];
  return CVE_BY_FINGERPRINT.filter((e) => e.match.test(fingerprint)).map((e) => ({ cves: e.cves, note: e.note }));
}
