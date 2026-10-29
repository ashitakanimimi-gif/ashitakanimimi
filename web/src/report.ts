import type { ScanResult, Finding, Recommendation } from "@shared/types.js";
import { AREA_NAME } from "@shared/controlAreas.js";

function esc(s: string): string {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!));
}

function groupByArea(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!map.has(f.controlArea)) map.set(f.controlArea, []);
    map.get(f.controlArea)!.push(f);
  }
  return map;
}

export function buildMarkdown(scan: ScanResult, recs: Recommendation[]): string {
  const s = scan.summary;
  const lines: string[] = [];
  lines.push(`# GraphQL Security Report`);
  lines.push("");
  lines.push(`- **Target:** ${scan.target}`);
  if (scan.fingerprint) lines.push(`- **Engine fingerprint:** ${scan.fingerprint}`);
  lines.push(`- **Date:** ${scan.startedAt}`);
  lines.push(`- **Security score:** ${s.securityScore}/100`);
  lines.push(`- **Results:** ${s.passed} passed · ${s.failed} failed · ${s.warned} warnings · ${s.manual} manual`);
  lines.push(
    `- **Severity:** critical ${s.bySeverity.critical} · high ${s.bySeverity.high} · medium ${s.bySeverity.medium} · low ${s.bySeverity.low}`
  );
  lines.push("");

  if (recs.length) {
    lines.push(`## Prioritized recommendations`);
    for (const r of recs) lines.push(`- **[${r.severity.toUpperCase()}]** ${r.title} — ${r.rationale}`);
    lines.push("");
  }

  lines.push(`## Findings (evidence workpaper)`);
  const byArea = groupByArea(scan.findings);
  for (const [key, fs] of byArea) {
    lines.push("");
    lines.push(`### ${AREA_NAME[key] ?? key}`);
    for (const f of fs) {
      lines.push("");
      lines.push(`#### [${f.severity.toUpperCase()}] ${f.title} (${f.testId}) — ${f.status}`);
      lines.push("");
      lines.push(f.description);
      if (f.cvss) lines.push(`- **Criticality:** ${f.severity} · CVSS ${f.cvss.score} \`${f.cvss.vector}\``);
      if (f.cwe?.length) lines.push(`- **CWE:** ${f.cwe.join(", ")}`);
      if (f.cve?.length) lines.push(`- **CVE:** ${f.cve.join(", ")}`);
      if (f.affectedOperation) lines.push(`- **Affected operation:** ${f.affectedOperation}`);
      lines.push(`- **Recommendation:** ${f.remediation}`);
      if (f.evidence?.request) {
        lines.push("");
        lines.push(`**Evidence — request**`);
        lines.push("```http");
        lines.push(`${f.evidence.request.method} ${f.evidence.request.url}`);
        for (const [k, v] of Object.entries(f.evidence.request.headers ?? {})) lines.push(`${k}: ${v}`);
        if (f.evidence.request.body) lines.push(`\n${f.evidence.request.body}`);
        lines.push("```");
      }
      if (f.evidence?.response) {
        lines.push(`**Evidence — response (HTTP ${f.evidence.response.status ?? "?"})**`);
        lines.push("```");
        lines.push(f.evidence.response.bodySnippet ?? "");
        lines.push("```");
      }
      if (f.evidence?.artifact) {
        lines.push(`**Proof-of-concept**`);
        lines.push("```html");
        lines.push(f.evidence.artifact);
        lines.push("```");
      }
      if (f.references.length) lines.push(`- References: ${f.references.join(" , ")}`);
    }
  }
  return lines.join("\n");
}

export function buildHtml(scan: ScanResult, recs: Recommendation[]): string {
  const s = scan.summary;
  const sevColor: Record<string, string> = {
    critical: "#ff2d55",
    high: "#ff7a1a",
    medium: "#f2c53d",
    low: "#4c8dff",
    info: "#9ba1ac",
  };
  const findingHtml = (f: Finding) => `
    <div class="f" style="border-left-color:${sevColor[f.severity]}">
      <div class="fh"><span class="sev" style="color:${sevColor[f.severity]}">${f.severity.toUpperCase()}</span>
      <strong>${esc(f.title)}</strong> <span class="id">${f.testId} · ${f.status}</span></div>
      <p>${esc(f.description)}</p>
      <div class="meta">
        ${f.cvss ? `<span class="tag">CVSS ${f.cvss.score}</span>` : ""}
        ${(f.cwe ?? []).map((c) => `<span class="tag">${c}</span>`).join("")}
        ${(f.cve ?? []).map((c) => `<span class="tag cve">${c}</span>`).join("")}
        ${f.affectedOperation ? `<span class="tag">op: ${esc(f.affectedOperation)}</span>` : ""}
      </div>
      <p class="fix"><b>Fix:</b> ${esc(f.remediation)}</p>
      ${f.evidence?.request ? `<div class="lab">Evidence — request</div><pre>${esc(f.evidence.request.method + " " + f.evidence.request.url + "\n" + Object.entries(f.evidence.request.headers ?? {}).map(([k, v]) => k + ": " + v).join("\n") + (f.evidence.request.body ? "\n\n" + f.evidence.request.body : ""))}</pre>` : ""}
      ${f.evidence?.response ? `<div class="lab">Evidence — response (HTTP ${f.evidence.response.status ?? "?"})</div><pre>${esc(f.evidence.response.bodySnippet ?? "")}</pre>` : ""}
      ${f.evidence?.artifact ? `<div class="lab">Proof-of-concept</div><pre>${esc(f.evidence.artifact)}</pre>` : ""}
      ${f.references.length ? `<div class="refs">${f.references.map((r) => `<a href="${esc(r)}">${esc(r)}</a>`).join("<br>")}</div>` : ""}
    </div>`;

  const byArea = groupByArea(scan.findings);
  const areas = [...byArea.entries()]
    .map(([key, fs]) => `<h2>${esc(AREA_NAME[key] ?? key)}</h2>${fs.map(findingHtml).join("")}`)
    .join("");

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>GraphQL Security Report — ${esc(scan.target)}</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#0a0a0b;color:#eceef2;margin:0;padding:40px;line-height:1.55}
    .wrap{max-width:960px;margin:0 auto}
    h1{font-size:34px;margin:0 0 8px}h2{margin-top:36px;border-bottom:1px solid #2a2a31;padding-bottom:8px}
    .sum{display:flex;gap:18px;flex-wrap:wrap;margin:20px 0}
    .tile{background:#141416;border:1px solid #2a2a31;border-radius:12px;padding:14px 18px;min-width:120px}
    .tile .k{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#9a9aa3}
    .tile .v{font-size:30px;font-weight:800}
    .f{background:#141416;border:1px solid #2a2a31;border-left:3px solid #666;border-radius:9px;padding:14px 16px;margin:12px 0}
    .fh{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.sev{font-weight:800;font-size:12px}
    .id{color:#6c6c76;font-size:12px;margin-left:auto}
    .meta{margin:8px 0}.tag{display:inline-block;border:1px solid #2a2a31;border-radius:999px;padding:2px 8px;font-size:11px;margin-right:6px;color:#19d2e5}
    .tag.cve{color:#ff5f87}
    .fix{color:#37d39b}.lab{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#9a9aa3;margin-top:10px}
    pre{background:#060607;border:1px solid #2a2a31;border-radius:8px;padding:10px;overflow:auto;font-size:12px}
    .refs a{color:#ff5f87;font-size:12px}
    ul{padding-left:18px}
  </style></head><body><div class="wrap">
  <h1>GraphQL Security Report</h1>
  <div>${esc(scan.target)}${scan.fingerprint ? " · " + esc(scan.fingerprint) : ""} · ${esc(scan.startedAt)}</div>
  <div class="sum">
    <div class="tile"><div class="k">Score</div><div class="v">${s.securityScore}</div></div>
    <div class="tile"><div class="k">Failed</div><div class="v">${s.failed}</div></div>
    <div class="tile"><div class="k">Warnings</div><div class="v">${s.warned}</div></div>
    <div class="tile"><div class="k">Critical</div><div class="v">${s.bySeverity.critical}</div></div>
  </div>
  ${recs.length ? `<h2>Prioritized recommendations</h2><ul>${recs.map((r) => `<li><b style="color:${sevColor[r.severity]}">[${r.severity.toUpperCase()}]</b> ${esc(r.title)} — ${esc(r.rationale)}</li>`).join("")}</ul>` : ""}
  <h2 style="border:none">Evidence workpaper</h2>
  ${areas || "<p>No failing or warning findings.</p>"}
  </div></body></html>`;
}
