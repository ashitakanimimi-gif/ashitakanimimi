import React from "react";
import { useApp } from "../store.js";
import { StatTile, RadialGauge, SeverityBars, ControlAreaProgress, GeoMap, ScanTimeline, scoreColor } from "../components/charts.js";
import { AREA_NAME } from "@shared/controlAreas.js";

export function DashboardPage({ go }: { go: (tab: string) => void }) {
  const { liveSummary, liveHosts, history, running, progress, scan, loadHistory, base } = useApp();
  const summary = liveSummary;

  const passedPct = summary
    ? Math.round((summary.passed / Math.max(1, summary.passed + summary.failed + summary.warned)) * 100)
    : 0;
  const score = summary?.securityScore ?? 0;

  const areaName = (k: string) => AREA_NAME[k] ?? k;

  return (
    <div className="content">
      <div className="spread">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-sub">
            Live security posture for <span className="mono">{base?.url ?? "no target set"}</span>
            {scan?.fingerprint ? ` · ${scan.fingerprint}` : ""}.
          </p>
        </div>
        <div className="row">
          <button className="btn" onClick={() => go("target")}>
            Set target
          </button>
          <button className="btn primary" onClick={() => go("scanner")}>
            Run scan ▶
          </button>
        </div>
      </div>

      {running && (
        <div className="banner">
          Scanning… {progress.done}/{progress.total} tests {progress.current ? `· ${progress.current}` : ""}
          <div className="progress-line">
            <div className="bar" style={{ width: `${progress.total ? (progress.done / progress.total) * 100 : 0}%` }} />
          </div>
        </div>
      )}

      {!summary && !running && (
        <div className="empty">
          No scan data yet. Define a target on the <a onClick={() => go("target")}>Target</a> page, then run a scan.
        </div>
      )}

      <div className="dash-grid">
        {/* KPI row */}
        <div className="span-3">
          <StatTile label="Tests run" value={summary ? summary.passed + summary.failed + summary.warned + summary.manual : 0} />
        </div>
        <div className="span-3">
          <StatTile label="Failed" value={summary?.failed ?? 0} tone="accent" />
        </div>
        <div className="span-3">
          <StatTile label="Critical findings" value={summary?.bySeverity.critical ?? 0} tone="accent" />
        </div>
        <div className="span-3">
          <StatTile label="Endpoints found" value={summary?.endpointsDiscovered ?? 0} />
        </div>

        {/* Gauges */}
        <div className="span-5">
          <div className="card" style={{ height: "100%" }}>
            <h3>Posture</h3>
            <div className="gauges">
              <RadialGauge value={score} label="Security score" index="01" gradient={[scoreColor(score), "#ff1e56"]} />
              <RadialGauge value={passedPct} label="Tests passed" index="02" gradient={["#19d2e5", "#ff1e56"]} />
            </div>
          </div>
        </div>

        {/* Severity bars */}
        <div className="span-7">
          <div className="card" style={{ height: "100%" }}>
            <h3>Findings by severity</h3>
            <SeverityBars summary={summary} />
          </div>
        </div>

        {/* Control-area progress */}
        <div className="span-7">
          <div className="card">
            <h3>Control-area pass rate</h3>
            <ControlAreaProgress summary={summary} areaName={areaName} />
          </div>
        </div>

        {/* Geo */}
        <div className="span-5">
          <div className="card">
            <h3>Hosts observed</h3>
            <GeoMap hosts={liveHosts} />
          </div>
        </div>

        {/* Timeline */}
        <div className="span-12">
          <div className="card">
            <h3>Scan timeline</h3>
            <ScanTimeline history={history} onPick={loadHistory} />
          </div>
        </div>
      </div>
    </div>
  );
}
