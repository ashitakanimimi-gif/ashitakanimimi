import type { Finding, Recommendation, ScanResult } from "@shared/types.js";
import { sortFindings, severityRank } from "../../lib/findings.js";
import { knownCvesForFingerprint, VULN_CLASSES } from "./knowledgeBase.js";

const BASELINE: Recommendation[] = [
  {
    id: "base-introspection",
    title: "Disable introspection and field suggestions in production",
    severity: "medium",
    rationale: "Prevents attackers from mapping the full schema and attack surface.",
    references: [VULN_CLASSES.introspection.references[0]],
    cwe: ["CWE-200"],
  },
  {
    id: "base-depth-cost",
    title: "Enforce query depth and cost/complexity limits",
    severity: "high",
    rationale: "Bounds resource consumption and prevents nested/aliased/batched DoS.",
    references: [VULN_CLASSES.complexityDos.references[0]],
    cwe: ["CWE-770"],
  },
  {
    id: "base-authz",
    title: "Enforce authentication and authorization in every resolver",
    severity: "high",
    rationale: "Stops BOLA/IDOR and privilege escalation via alternate query structures.",
    references: [VULN_CLASSES.bola.references[0]],
    cwe: ["CWE-862", "CWE-639"],
  },
  {
    id: "base-persisted",
    title: "Use persisted queries / an operation allowlist",
    severity: "medium",
    rationale: "Blocks arbitrary and abusive queries, shrinking the attack surface.",
    references: [VULN_CLASSES.complexityDos.references[0]],
  },
  {
    id: "base-rate",
    title: "Apply per-client and per-operation rate limiting",
    severity: "medium",
    rationale: "Limits brute force, scraping, and alias/batch amplification.",
    references: [VULN_CLASSES.batching.references[0]],
    cwe: ["CWE-770"],
  },
  {
    id: "base-errors",
    title: "Return generic errors; never leak stack traces or secrets",
    severity: "medium",
    rationale: "Prevents information disclosure through verbose errors and logs.",
    references: [VULN_CLASSES.errorLeak.references[0]],
    cwe: ["CWE-209"],
  },
  {
    id: "base-cors-csrf",
    title: "Lock down CORS and require CSRF protection for state changes",
    severity: "high",
    rationale: "Prevents credentialed cross-origin and cross-site request forgery.",
    references: [VULN_CLASSES.csrf.references[0]],
    cwe: ["CWE-352", "CWE-942"],
  },
  {
    id: "base-tls",
    title: "Force HTTPS/HSTS for all GraphQL traffic",
    severity: "medium",
    rationale: "Protects tokens and data in transit.",
    references: [VULN_CLASSES.transport.references[0]],
    cwe: ["CWE-319"],
  },
];

export function buildRecommendations(scan: ScanResult): Recommendation[] {
  const recs: Recommendation[] = [];
  const seenTitles = new Set<string>();

  // Finding-derived recommendations first (prioritized by severity).
  for (const f of sortFindings(scan.findings.filter((x) => x.status === "fail" || x.status === "warn"))) {
    const key = f.remediation.slice(0, 60);
    if (seenTitles.has(key)) continue;
    seenTitles.add(key);
    recs.push({
      id: `fix-${f.id}`,
      title: f.remediation,
      severity: f.severity,
      rationale: `${f.title} — observed on ${f.affectedOperation ?? scan.target}.`,
      references: f.references,
      cwe: f.cwe,
    });
  }

  // Baseline recommendations, skipping ones already covered.
  for (const b of BASELINE) {
    if ([...seenTitles].some((t) => b.title.toLowerCase().includes(t.toLowerCase().slice(0, 20)))) continue;
    recs.push(b);
  }

  return recs.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

/** Attach known CVEs to findings when the fingerprint matches a known advisory. */
export function enrichWithCves(scan: ScanResult): ScanResult {
  const matches = knownCvesForFingerprint(scan.fingerprint);
  if (matches.length === 0) return scan;
  const cves = matches.flatMap((m) => m.cves);
  const note = matches.map((m) => m.note).join(" ");
  const enriched: Finding[] = scan.findings.map((f) => ({
    ...f,
    cve: [...new Set([...(f.cve ?? []), ...cves])],
    description: f.description + ` (Engine fingerprint matched a known advisory: ${note})`,
  }));
  return { ...scan, findings: enriched };
}
