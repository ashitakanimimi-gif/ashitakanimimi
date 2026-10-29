import React from "react";
import {
  RadialBarChart,
  RadialBar,
  PolarAngleAxis,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Cell,
  Tooltip,
  ResponsiveContainer,
  LabelList,
} from "recharts";
import type { ScanSummary, HostGeo, Severity, ScanResult } from "@shared/types.js";

const SEV_COLOR: Record<Severity, string> = {
  critical: "#ff2d55",
  high: "#ff7a1a",
  medium: "#f2c53d",
  low: "#4c8dff",
  info: "#9ba1ac",
};

export function StatTile({ label, value, tone }: { label: string; value: React.ReactNode; tone?: "accent" | "ok" }) {
  return (
    <div className="stat-tile">
      <div className="k">{label}</div>
      <div className={`v ${tone ?? ""}`}>{value}</div>
    </div>
  );
}

export function RadialGauge({
  value,
  label,
  index,
  gradient,
}: {
  value: number;
  label: string;
  index?: string;
  gradient: [string, string];
}) {
  const id = `grad-${label.replace(/\s/g, "")}`;
  const data = [{ name: label, value: Math.max(0, Math.min(100, value)) }];
  return (
    <div className="gauge" style={{ width: 170, height: 170 }}>
      <ResponsiveContainer width={170} height={170}>
        <RadialBarChart innerRadius="74%" outerRadius="100%" data={data} startAngle={90} endAngle={-270}>
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor={gradient[0]} />
              <stop offset="100%" stopColor={gradient[1]} />
            </linearGradient>
          </defs>
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar background={{ fill: "#232329" }} dataKey="value" cornerRadius={20} fill={`url(#${id})`} isAnimationActive />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="center">
        <div className="big">{Math.round(value)}%</div>
      </div>
      {index && <div className="num">{index}</div>}
      <div className="label">{label}</div>
    </div>
  );
}

export function SeverityBars({ summary }: { summary: ScanSummary | null }) {
  const sevs: Severity[] = ["critical", "high", "medium", "low", "info"];
  const data = sevs.map((s) => ({ name: s, count: summary?.bySeverity[s] ?? 0, fill: SEV_COLOR[s] }));
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ top: 16, right: 8, bottom: 0, left: -18 }}>
        <XAxis dataKey="name" tick={{ fill: "#9a9aa3", fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis allowDecimals={false} tick={{ fill: "#6c6c76", fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip
          cursor={{ fill: "rgba(255,255,255,0.04)" }}
          contentStyle={{ background: "#141416", border: "1px solid #2a2a31", borderRadius: 8, fontSize: 12 }}
          labelStyle={{ color: "#fff", textTransform: "uppercase" }}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} barSize={30} isAnimationActive>
          {data.map((d) => (
            <Cell key={d.name} fill={d.fill} />
          ))}
          <LabelList dataKey="count" position="top" fill="#9a9aa3" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function ControlAreaProgress({
  summary,
  areaName,
}: {
  summary: ScanSummary | null;
  areaName: (key: string) => string;
}) {
  if (!summary) return <div className="empty">Run a scan to populate control-area coverage.</div>;
  const rows = Object.entries(summary.byControlArea)
    .map(([key, v]) => ({ key, name: areaName(key), pct: v.total ? Math.round((v.passed / v.total) * 100) : 0, ...v }))
    .sort((a, b) => b.pct - a.pct)
    .slice(0, 8);
  if (rows.length === 0) return <div className="empty">No results yet.</div>;
  return (
    <div>
      {rows.map((r, i) => (
        <div className="prog-row" key={r.key}>
          <div className="rank">{String(i + 1).padStart(2, "0")}</div>
          <div>
            <div className="lab">
              {r.name} <span className="dim">({r.passed}/{r.total} pass)</span>
            </div>
            <div className="track">
              <div className="fill" style={{ width: `${r.pct}%` }} />
            </div>
          </div>
          <div className="pct">{r.pct}%</div>
        </div>
      ))}
    </div>
  );
}

export function GeoMap({ hosts }: { hosts: HostGeo[] }) {
  const plotted = hosts.filter((h) => typeof h.lat === "number" && typeof h.lon === "number");
  return (
    <div>
      <div className="geo-wrap">
        {plotted.length === 0 && (
          <div className="geo-empty">
            No geolocated hosts to plot.
            <br />
            Local/private targets aren&apos;t geolocated, and external IP lookup is off by default.
          </div>
        )}
        {plotted.map((h, i) => {
          const x = ((h.lon! + 180) / 360) * 100;
          const y = ((90 - h.lat!) / 180) * 100;
          return (
            <div
              key={i}
              className={`geo-point ${h.source === "target" ? "" : "cors"}`}
              style={{ left: `${x}%`, top: `${y}%` }}
              title={`${h.host} (${h.source})`}
            />
          );
        })}
      </div>
      <div className="mt" style={{ fontSize: 12 }}>
        {hosts.map((h, i) => (
          <div key={i} className="spread" style={{ padding: "4px 0", borderBottom: "1px solid var(--border)" }}>
            <span className="mono">{h.host}</span>
            <span className="dim">
              {h.source}
              {h.isPrivate ? " · private/local" : h.country ? ` · ${h.country}` : " · public"}
            </span>
          </div>
        ))}
        {hosts.length === 0 && <span className="dim">No hosts observed yet.</span>}
      </div>
    </div>
  );
}

export function ScanTimeline({ history, onPick }: { history: ScanResult[]; onPick: (s: ScanResult) => void }) {
  if (history.length === 0) return <div className="empty">Completed scans will appear here as a timeline.</div>;
  return (
    <div className="timeline">
      {history
        .slice()
        .reverse()
        .map((s) => (
          <div className="tl-item" key={s.id} onClick={() => onPick(s)}>
            <div className="t-when">{new Date(s.startedAt).toLocaleString()}</div>
            <div className="t-score" style={{ color: scoreColor(s.summary.securityScore) }}>
              {s.summary.securityScore}
            </div>
            <div className="t-target">{s.target}</div>
          </div>
        ))}
    </div>
  );
}

export function scoreColor(score: number): string {
  if (score >= 80) return "#37d39b";
  if (score >= 55) return "#f2c53d";
  if (score >= 30) return "#ff7a1a";
  return "#ff2d55";
}
