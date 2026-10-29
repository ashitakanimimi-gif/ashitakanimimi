import React, { useMemo } from "react";
import { useApp } from "../store.js";
import { AREA_NAME, CONTROL_AREAS } from "@shared/controlAreas.js";
import type { Finding, ScanResult, Recommendation } from "@shared/types.js";
import { FindingCard } from "../components/FindingCard.js";
import { SeverityBadge } from "../components/common.js";
import { StatTile, scoreColor } from "../components/charts.js";
import { buildMarkdown, buildHtml } from "../report.js";

export function ReportPage({ go }: { go: (t: string) => void }) {
  const { scan, liveResults, liveSummary, base } = useApp();

  const findings: Finding[] = useMemo(() => {
    if (scan) return scan.findings;
    return liveResults.flatMap((r) => r.findings).filter((f) => f.status !== "info");
  }, [scan, liveResults]);

  const summary = scan?.summary ?? liveSummary;
  const recs: Recommendation[] = (scan as any)?.recommendations ?? [];

  const byArea = useMemo(() => {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      if (!map.has(f.controlArea)) map.set(f.controlArea, []);
      map.get(f.controlArea)!.push(f);
    }
    return map;
  }, [findings]);

  if (!summary) {
    return (
      <div className="content">
        <h1 className="page-title">Report</h1>
        <div className="empty">
          No results yet. <a onClick={() => go("scanner")}>Run a scan</a> to generate a report.
        </div>
      </div>
    );
  }

  const scanForExport: ScanResult = (scan as ScanResult) ?? {
    id: "live",
    target: base?.url ?? "",
    startedAt: new Date().toISOString(),
    results: liveResults,
    findings,
    hosts: [],
    summary,
  };

  const download = (name: string, content: string, type: string) => {
    const blob = new Blob([content], { type });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");

  return (
    <div className="content">
      <div className="spread">
        <div>
          <h1 className="page-title">Report</h1>
          <p className="page-sub">
            {scanForExport.target} {scan?.fingerprint ? `· ${scan.fingerprint}` : ""} · {new Date(scanForExport.startedAt).toLocaleString()}
          </p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => download(`graphql-security-report-${stamp}.md`, buildMarkdown(scanForExport, recs), "text/markdown")}>
            Export Markdown
          </button>
          <button className="btn primary" onClick={() => download(`graphql-security-report-${stamp}.html`, buildHtml(scanForExport, recs), "text/html")}>
            Export HTML
          </button>
        </div>
      </div>

      <div className="dash-grid mb">
        <div className="span-3">
          <div className="stat-tile">
            <div className="k">Security score</div>
            <div className="v" style={{ color: scoreColor(summary.securityScore) }}>{summary.securityScore}</div>
          </div>
        </div>
        <div className="span-3"><StatTile label="Failed" value={summary.failed} tone="accent" /></div>
        <div className="span-3"><StatTile label="Warnings" value={summary.warned} /></div>
        <div className="span-3"><StatTile label="Manual / guided" value={summary.manual} /></div>
      </div>

      {recs.length > 0 && (
        <div className="card mb">
          <h3>Prioritized recommendations</h3>
          {recs.map((r) => (
            <div key={r.id} className="spread" style={{ padding: "10px 0", borderBottom: "1px solid var(--border)" }}>
              <div style={{ flex: 1 }}>
                <div className="row" style={{ gap: 8 }}>
                  <SeverityBadge severity={r.severity} />
                  <strong style={{ fontSize: 14 }}>{r.title}</strong>
                </div>
                <div className="muted" style={{ fontSize: 13, marginTop: 4 }}>{r.rationale}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      <h3 className="muted" style={{ letterSpacing: "0.16em", textTransform: "uppercase", fontSize: 12, margin: "8px 0 16px" }}>
        Evidence workpaper — by control area
      </h3>

      {CONTROL_AREAS.map((area) => {
        const fs = byArea.get(area.key);
        if (!fs || fs.length === 0) return null;
        return (
          <div key={area.key} className="mb">
            <h3 style={{ fontFamily: "var(--font-display)", fontSize: 18, marginBottom: 12 }}>{AREA_NAME[area.key]}</h3>
            {fs.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        );
      })}

      {findings.length === 0 && <div className="empty">No failing or warning findings — nothing to report. 🎉</div>}
    </div>
  );
}
