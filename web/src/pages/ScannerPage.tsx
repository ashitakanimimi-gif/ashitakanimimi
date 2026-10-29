import React, { useMemo, useState } from "react";
import { useApp } from "../store.js";
import { CONTROL_AREAS } from "@shared/controlAreas.js";
import { AuthAckModal } from "../components/AuthAckModal.js";
import { StatusPill } from "../components/common.js";
import { FindingCard } from "../components/FindingCard.js";

export function ScannerPage({ go }: { go: (t: string) => void }) {
  const { base, run, running, liveResults, options, setOptions, progress, error, abort } = useApp();
  const allIds = useMemo(() => CONTROL_AREAS.flatMap((a) => a.tests.map((t) => t.id)), []);
  const [selected, setSelected] = useState<Set<string>>(new Set(allIds));
  const [ackOpen, setAckOpen] = useState(false);
  const [openArea, setOpenArea] = useState<string | null>(null);

  const toggleArea = (key: string, on: boolean) => {
    const area = CONTROL_AREAS.find((a) => a.key === key)!;
    setSelected((prev) => {
      const next = new Set(prev);
      for (const t of area.tests) on ? next.add(t.id) : next.delete(t.id);
      return next;
    });
  };
  const toggleTest = (id: string, on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      on ? next.add(id) : next.delete(id);
      return next;
    });

  const resultById = useMemo(() => new Map(liveResults.map((r) => [r.testId, r])), [liveResults]);

  const startRun = () => {
    setAckOpen(false);
    void run([...selected]);
  };

  return (
    <div className="content">
      <div className="spread">
        <div>
          <h1 className="page-title">Scanner</h1>
          <p className="page-sub">
            61 tests across 16 control areas. Select what to run against{" "}
            <span className="mono">{base?.url ?? "— no target —"}</span>.
          </p>
        </div>
        <div className="row">
          {running ? (
            <button className="btn" onClick={abort}>
              Stop ■
            </button>
          ) : (
            <button
              className="btn primary"
              disabled={!base || selected.size === 0}
              onClick={() => setAckOpen(true)}
            >
              Run {selected.size} tests ▶
            </button>
          )}
        </div>
      </div>

      {!base && (
        <div className="banner">
          No target set. <a onClick={() => go("target")}>Define a target request</a> first.
        </div>
      )}
      {error && <div className="banner" style={{ borderColor: "var(--sev-critical)" }}>{error}</div>}
      {running && (
        <div className="banner">
          Running… {progress.done}/{progress.total} {progress.current ? `· ${progress.current}` : ""}
          <div className="progress-line">
            <div className="bar" style={{ width: `${progress.total ? (progress.done / progress.total) * 100 : 0}%` }} />
          </div>
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: "1.3fr 1fr", gap: 24, alignItems: "start" }}>
        {/* Test selection */}
        <div>
          <div className="spread mb">
            <h3 className="muted" style={{ letterSpacing: "0.16em", textTransform: "uppercase", fontSize: 12 }}>
              Control areas
            </h3>
            <div className="row">
              <button className="btn ghost" style={{ padding: "6px 12px", fontSize: 10 }} onClick={() => setSelected(new Set(allIds))}>
                Select all
              </button>
              <button className="btn ghost" style={{ padding: "6px 12px", fontSize: 10 }} onClick={() => setSelected(new Set())}>
                Clear
              </button>
            </div>
          </div>

          {CONTROL_AREAS.map((area) => {
            const count = area.tests.filter((t) => selected.has(t.id)).length;
            const isOpen = openArea === area.key;
            return (
              <div className="area-group" key={area.key}>
                <div className="area-head">
                  <label className="check" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={count === area.tests.length}
                      ref={(el) => el && (el.indeterminate = count > 0 && count < area.tests.length)}
                      onChange={(e) => toggleArea(area.key, e.target.checked)}
                    />
                    <span className="a-name">{area.name}</span>
                  </label>
                  <div className="a-counts">
                    <span className="dim">
                      {count}/{area.tests.length}
                    </span>
                    <button
                      className="btn ghost"
                      style={{ padding: "4px 10px", fontSize: 10 }}
                      onClick={() => setOpenArea(isOpen ? null : area.key)}
                    >
                      {isOpen ? "–" : "+"}
                    </button>
                  </div>
                </div>
                {isOpen &&
                  area.tests.map((t) => {
                    const r = resultById.get(t.id);
                    return (
                      <div className="test-row" key={t.id}>
                        <label className="check">
                          <input type="checkbox" checked={selected.has(t.id)} onChange={(e) => toggleTest(t.id, e.target.checked)} />
                        </label>
                        <span className="t-id">{t.id}</span>
                        <span className="t-title">{t.title}</span>
                        <span className="t-mode">{t.mode}</span>
                        {r && <StatusPill status={r.status} />}
                      </div>
                    );
                  })}
              </div>
            );
          })}
        </div>

        {/* Options + live results */}
        <div>
          <div className="card mb">
            <h3>Assisted-test options</h3>
            <div className="field">
              <label>IDOR: variable name to swap</label>
              <input type="text" value={options.objectIdField ?? ""} onChange={(e) => setOptions({ ...options, objectIdField: e.target.value })} placeholder="e.g. id" />
            </div>
            <div className="field">
              <label>IDOR: another user&apos;s value</label>
              <input type="text" value={options.objectIdValue ?? ""} onChange={(e) => setOptions({ ...options, objectIdValue: e.target.value })} />
            </div>
            <div className="field">
              <label>SSRF: your callback host</label>
              <input type="text" value={options.callbackHost ?? ""} onChange={(e) => setOptions({ ...options, callbackHost: e.target.value })} placeholder="e.g. abc.oast.site" />
            </div>
            <label className="check" style={{ marginBottom: 10 }}>
              <input type="checkbox" checked={options.enableInjection !== false} onChange={(e) => setOptions({ ...options, enableInjection: e.target.checked })} />
              Enable injection probes (SQLi/XSS markers)
            </label>
            <label className="check">
              <input type="checkbox" checked={!!options.enableBruteForce} onChange={(e) => setOptions({ ...options, enableBruteForce: e.target.checked })} />
              Enable bounded brute-force probe
            </label>
          </div>

          <div className="card">
            <h3>Live findings</h3>
            {liveResults.length === 0 && <div className="empty">Findings appear here as tests complete.</div>}
            {liveResults
              .flatMap((r) => r.findings)
              .filter((f) => f.status === "fail" || f.status === "warn")
              .slice(0, 30)
              .map((f) => (
                <FindingCard key={f.id} finding={f} />
              ))}
            {liveResults.length > 0 && (
              <button className="btn mt" onClick={() => go("report")}>
                View full report ▶
              </button>
            )}
          </div>
        </div>
      </div>

      {ackOpen && <AuthAckModal target={base?.url ?? ""} onConfirm={startRun} onCancel={() => setAckOpen(false)} />}
    </div>
  );
}
