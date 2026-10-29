import React from "react";
import type { Severity, FindingStatus } from "@shared/types.js";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge ${severity}`}>{severity}</span>;
}

export function StatusPill({ status }: { status: FindingStatus }) {
  return <span className={`status-pill ${status}`}>{status}</span>;
}

export function CvssBadge({ score, vector }: { score: number; vector?: string }) {
  return (
    <span className="badge cvss" title={vector}>
      CVSS {score.toFixed(1)}
    </span>
  );
}

export function CodeBlock({ children }: { children: React.ReactNode }) {
  return <pre className="code">{children}</pre>;
}

export function Tag({ kind, children }: { kind: "cwe" | "cve"; children: React.ReactNode }) {
  return <span className={`badge ${kind}`}>{children}</span>;
}
