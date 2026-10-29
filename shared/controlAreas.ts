// The 16 control areas and the 61-test catalog metadata.
// Numbering follows the "GraphQL Security Test Checklist" PDF.

import type { TestMode } from "./types.js";

export interface TestMeta {
  id: string; // e.g. "T01"
  area: string; // control area key
  title: string;
  mode: TestMode;
}

export interface ControlAreaMeta {
  key: string;
  name: string;
  tests: TestMeta[];
}

export const CONTROL_AREAS: ControlAreaMeta[] = [
  {
    key: "discovery",
    name: "Schema Discovery & Attack Surface",
    tests: [
      { id: "T01", area: "discovery", title: "Endpoint discovery across common paths", mode: "auto" },
      { id: "T02", area: "discovery", title: "Introspection enabled in production", mode: "auto" },
      { id: "T03", area: "discovery", title: "Deprecated / hidden / undocumented schema elements", mode: "auto" },
      { id: "T04", area: "discovery", title: "Field suggestions leak schema on invalid fields", mode: "auto" },
      { id: "T05", area: "discovery", title: "GraphiQL / Playground / Voyager dev tools exposed", mode: "auto" },
    ],
  },
  {
    key: "auth",
    name: "Authentication & Token Security",
    tests: [
      { id: "T06", area: "auth", title: "Protected operations accessible without authentication", mode: "auto" },
      { id: "T07", area: "auth", title: "Authentication bypass via alternate operations", mode: "assisted" },
      { id: "T08", area: "auth", title: "Expired / malformed / tampered tokens accepted", mode: "auto" },
      { id: "T09", area: "auth", title: "Brute-force / credential-stuffing protection", mode: "assisted" },
      { id: "T10", area: "auth", title: "Token scope enforcement", mode: "assisted" },
    ],
  },
  {
    key: "authz",
    name: "Authorization & Access Control",
    tests: [
      { id: "T11", area: "authz", title: "BOLA / IDOR via object ID swap", mode: "assisted" },
      { id: "T12", area: "authz", title: "Privileged operation as low-privileged account", mode: "assisted" },
      { id: "T13", area: "authz", title: "Resolver-level authorization enforced server-side", mode: "assisted" },
      { id: "T14", area: "authz", title: "Client-supplied role / ownership tampering", mode: "assisted" },
      { id: "T15", area: "authz", title: "Nested / related cross-tenant object access", mode: "assisted" },
      { id: "T16", area: "authz", title: "Alias / fragment / alternate structure authz bypass", mode: "auto" },
    ],
  },
  {
    key: "fieldauthz",
    name: "Field-Level Authorization",
    tests: [
      { id: "T17", area: "fieldauthz", title: "Sensitive fields accessible across roles", mode: "assisted" },
      { id: "T18", area: "fieldauthz", title: "Restricted fields via nested objects", mode: "assisted" },
      { id: "T19", area: "fieldauthz", title: "Over-fetch: append sensitive fields to a known query", mode: "auto" },
    ],
  },
  {
    key: "input",
    name: "Input Validation & Injection",
    tests: [
      { id: "T20", area: "input", title: "Invalid type / format / length / range / missing values", mode: "auto" },
      { id: "T21", area: "input", title: "Malformed / duplicate / conflicting inputs", mode: "auto" },
      { id: "T22", area: "input", title: "SQL / NoSQL / command / LDAP / XPath injection markers", mode: "auto" },
      { id: "T23", area: "input", title: "Custom scalar validation with malicious values", mode: "auto" },
    ],
  },
  {
    key: "mutation",
    name: "Mutation Security",
    tests: [
      { id: "T24", area: "mutation", title: "Exposed mutation review", mode: "auto" },
      { id: "T25", area: "mutation", title: "Unexpected fields accepted in mutation input", mode: "auto" },
      { id: "T26", area: "mutation", title: "Restricted-field mutation (role/ownership/status/limits)", mode: "assisted" },
      { id: "T27", area: "mutation", title: "Replay / idempotency of sensitive mutations", mode: "assisted" },
    ],
  },
  {
    key: "dos",
    name: "Resource Consumption & Denial of Service",
    tests: [
      { id: "T28", area: "dos", title: "Deeply nested query depth limit", mode: "auto" },
      { id: "T29", area: "dos", title: "Query complexity / cost limit (fields, fragments, circular)", mode: "auto" },
      { id: "T30", area: "dos", title: "Pagination / max result limit (first: 999999)", mode: "auto" },
      { id: "T31", area: "dos", title: "Long-running query server-side timeout", mode: "auto" },
      { id: "T32", area: "dos", title: "Rate limiting on repeated expensive queries", mode: "auto" },
      { id: "T33", area: "dos", title: "Array batching operation cap", mode: "auto" },
      { id: "T34", area: "dos", title: "Alias-based repetition of expensive/sensitive ops", mode: "auto" },
    ],
  },
  {
    key: "exposure",
    name: "Data Exposure & Error Handling",
    tests: [
      { id: "T35", area: "exposure", title: "Over-returned / sensitive data in responses", mode: "auto" },
      { id: "T36", area: "exposure", title: "Internal fields / metadata / implementation details", mode: "auto" },
      { id: "T37", area: "exposure", title: "Stack traces / DB / file paths in error messages", mode: "auto" },
      { id: "T38", area: "exposure", title: "Resolver / backend error leakage", mode: "auto" },
      { id: "T39", area: "exposure", title: "User / object enumeration via errors", mode: "auto" },
    ],
  },
  {
    key: "subscription",
    name: "Subscription Security",
    tests: [
      { id: "T40", area: "subscription", title: "Unauthenticated subscription to protected events", mode: "guided" },
      { id: "T41", area: "subscription", title: "Cross-tenant event subscription", mode: "guided" },
      { id: "T42", area: "subscription", title: "Permission revocation mid-subscription", mode: "guided" },
      { id: "T43", area: "subscription", title: "Connection / message flooding limits", mode: "guided" },
    ],
  },
  {
    key: "logic",
    name: "Business Logic & Workflow",
    tests: [
      { id: "T44", area: "logic", title: "Workflow step skip / reorder", mode: "guided" },
      { id: "T45", area: "logic", title: "Price / quantity / limit parameter tampering", mode: "guided" },
      { id: "T46", area: "logic", title: "Business limit bypass via multiple accounts/sessions", mode: "guided" },
      { id: "T47", area: "logic", title: "Stale / replayed workflow state reuse", mode: "guided" },
    ],
  },
  {
    key: "upload",
    name: "File Upload Security",
    tests: [
      { id: "T48", area: "upload", title: "File type / size enforcement & code execution", mode: "guided" },
      { id: "T49", area: "upload", title: "Cross-user uploaded file access", mode: "guided" },
    ],
  },
  {
    key: "ssrf",
    name: "SSRF & URL-Based Inputs",
    tests: [
      { id: "T50", area: "ssrf", title: "URL/host args reach localhost / private / metadata", mode: "assisted" },
      { id: "T51", area: "ssrf", title: "SSRF filter bypass (redirects / encoding / DNS)", mode: "assisted" },
    ],
  },
  {
    key: "config",
    name: "Production Config & Transport",
    tests: [
      { id: "T52", area: "config", title: "Debug mode / verbose / dev features enabled", mode: "auto" },
      { id: "T53", area: "config", title: "HTTP to HTTPS enforcement", mode: "auto" },
    ],
  },
  {
    key: "corscsrf",
    name: "CORS & CSRF",
    tests: [
      { id: "T54", area: "corscsrf", title: "CORS reflects arbitrary Origin with credentials", mode: "auto" },
      { id: "T55", area: "corscsrf", title: "Cross-site state change (form-encoded / GET CSRF)", mode: "auto" },
    ],
  },
  {
    key: "extapi",
    name: "External API & Resolver Dependencies",
    tests: [
      { id: "T56", area: "extapi", title: "External data validated before use", mode: "guided" },
      { id: "T57", area: "extapi", title: "Malformed / excessive upstream responses handled", mode: "guided" },
    ],
  },
  {
    key: "logging",
    name: "Logging, Monitoring & Audit",
    tests: [
      { id: "T58", area: "logging", title: "Security events are logged", mode: "guided" },
      { id: "T59", area: "logging", title: "Secrets not written to logs", mode: "guided" },
      { id: "T60", area: "logging", title: "Abnormal activity detection / monitoring", mode: "guided" },
      { id: "T61", area: "logging", title: "Audit traceability for sensitive mutations", mode: "guided" },
    ],
  },
];

export const ALL_TESTS: TestMeta[] = CONTROL_AREAS.flatMap((a) => a.tests);

export const AREA_NAME: Record<string, string> = Object.fromEntries(
  CONTROL_AREAS.map((a) => [a.key, a.name])
);

export function testMeta(id: string): TestMeta | undefined {
  return ALL_TESTS.find((t) => t.id === id);
}
