import React, { useState } from "react";
import type { Finding } from "@shared/types.js";
import { SeverityBadge, StatusPill, CvssBadge, CodeBlock, Tag } from "./common.js";

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(finding.severity === "critical" || finding.severity === "high");
  const ev = finding.evidence;
  return (
    <div className={`finding ${finding.severity}`}>
      <div className="f-head">
        <SeverityBadge severity={finding.severity} />
        <StatusPill status={finding.status} />
        <span className="f-title">{finding.title}</span>
        <span style={{ marginLeft: "auto" }} className="dim mono">
          {finding.testId}
        </span>
      </div>
      <div className="f-desc">{finding.description}</div>

      <div className="f-meta">
        {finding.cvss && <CvssBadge score={finding.cvss.score} vector={finding.cvss.vector} />}
        {finding.cwe?.map((c) => (
          <Tag key={c} kind="cwe">
            {c}
          </Tag>
        ))}
        {finding.cve?.map((c) => (
          <Tag key={c} kind="cve">
            {c}
          </Tag>
        ))}
        {finding.affectedOperation && <span className="dim mono">op: {finding.affectedOperation}</span>}
      </div>

      <div className="f-section">
        <div className="lab">Recommendation / fix</div>
        <div className="f-fix">{finding.remediation}</div>
      </div>

      {(ev || finding.references.length > 0) && (
        <div className="f-section">
          <button className="btn ghost" style={{ padding: "6px 12px", fontSize: 10 }} onClick={() => setOpen((o) => !o)}>
            {open ? "Hide evidence" : "Show evidence"}
          </button>
        </div>
      )}

      {open && ev && (
        <>
          {ev.note && (
            <div className="f-section">
              <div className="lab">Evidence</div>
              <div className="muted" style={{ fontSize: 13 }}>
                {ev.note}
              </div>
            </div>
          )}
          {ev.request && (
            <div className="f-section">
              <div className="lab">Request</div>
              <CodeBlock>
                {`${ev.request.method} ${ev.request.url}\n` +
                  Object.entries(ev.request.headers ?? {})
                    .map(([k, v]) => `${k}: ${v}`)
                    .join("\n") +
                  (ev.request.body ? `\n\n${ev.request.body}` : "")}
              </CodeBlock>
            </div>
          )}
          {ev.response && (
            <div className="f-section">
              <div className="lab">Response {ev.response.status != null ? `(HTTP ${ev.response.status})` : ""}</div>
              <CodeBlock>{ev.response.bodySnippet ?? "(no body)"}</CodeBlock>
            </div>
          )}
          {ev.artifact && (
            <div className="f-section">
              <div className="lab">Proof-of-concept</div>
              <CodeBlock>{ev.artifact}</CodeBlock>
            </div>
          )}
        </>
      )}

      {open && finding.references.length > 0 && (
        <div className="f-section">
          <div className="lab">References</div>
          {finding.references.map((r) => (
            <div key={r}>
              <a href={r} target="_blank" rel="noreferrer" style={{ fontSize: 12.5 }}>
                {r}
              </a>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
