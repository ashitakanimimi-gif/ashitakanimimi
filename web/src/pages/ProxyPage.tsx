import React, { useEffect, useRef, useState } from "react";
import { getProxyConfig, setProxyConfig } from "../api.js";
import type { ProxyEvent } from "@shared/types.js";

export function ProxyPage() {
  const [upstream, setUpstream] = useState("");
  const [saved, setSaved] = useState<string | null>(null);
  const [events, setEvents] = useState<ProxyEvent[]>([]);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    getProxyConfig().then((c) => {
      setSaved(c.upstream);
      if (c.upstream) setUpstream(c.upstream);
      setEvents(c.recent ?? []);
    });
    const es = new EventSource("/api/proxy/events");
    es.onmessage = (m) => {
      try {
        const e = JSON.parse(m.data) as ProxyEvent;
        setEvents((prev) => [...prev.slice(-199), e]);
      } catch {
        /* ignore */
      }
    };
    esRef.current = es;
    return () => es.close();
  }, []);

  const save = async () => {
    const c = await setProxyConfig(upstream.trim() || null);
    setSaved(c.upstream);
  };

  const proxyBase = `${location.origin}/proxy`;

  return (
    <div className="content">
      <h1 className="page-title">Proxy</h1>
      <p className="page-sub">
        Forward GraphQL traffic through the suite to inspect every query&apos;s depth, complexity, aliases and batch size
        in real time. Read-only — traffic is observed, not blocked.
      </p>

      <div className="card mb">
        <h3>Upstream</h3>
        <div className="row">
          <div className="field" style={{ flex: 1, margin: 0 }}>
            <input type="url" value={upstream} onChange={(e) => setUpstream(e.target.value)} placeholder="https://host/graphql" />
          </div>
          <button className="btn primary" onClick={save}>
            Save ▶
          </button>
        </div>
        {saved && (
          <div className="mt muted" style={{ fontSize: 13 }}>
            Point your GraphQL client at <span className="mono" style={{ color: "var(--accent-2)" }}>{proxyBase}</span> — requests are
            forwarded to <span className="mono">{saved}</span>.
          </div>
        )}
      </div>

      <div className="card">
        <h3>Live request feed</h3>
        {events.length === 0 && <div className="empty">Waiting for traffic through the proxy…</div>}
        {events.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ color: "var(--fg-muted)", textAlign: "left" }}>
                  <th style={th}>Time</th>
                  <th style={th}>Operation</th>
                  <th style={th}>Type</th>
                  <th style={th}>Depth</th>
                  <th style={th}>Fields</th>
                  <th style={th}>Aliases</th>
                  <th style={th}>Batch</th>
                  <th style={th}>Cost</th>
                  <th style={th}>Status</th>
                  <th style={th}>Flags</th>
                </tr>
              </thead>
              <tbody>
                {events
                  .slice()
                  .reverse()
                  .map((e) => (
                    <tr key={e.id} style={{ borderTop: "1px solid var(--border)", background: e.flagged ? "color-mix(in srgb, var(--sev-high) 8%, transparent)" : undefined }}>
                      <td style={td} className="dim">{new Date(e.at).toLocaleTimeString()}</td>
                      <td style={td} className="mono">{e.operationName ?? "—"}</td>
                      <td style={td}>{e.operationType}</td>
                      <td style={td}>{e.depth}</td>
                      <td style={td}>{e.fieldCount}</td>
                      <td style={td}>{e.aliasCount}</td>
                      <td style={td}>{e.batchSize}</td>
                      <td style={td}>{e.complexity}</td>
                      <td style={td}>{e.status ?? "—"}</td>
                      <td style={td}>
                        {e.flags.map((f) => (
                          <span key={f} className="status-pill warn" style={{ marginRight: 4 }}>
                            {f}
                          </span>
                        ))}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

const th: React.CSSProperties = { padding: "8px 10px", fontWeight: 600, letterSpacing: "0.04em", fontSize: 11, textTransform: "uppercase" };
const td: React.CSSProperties = { padding: "8px 10px" };
