import React, { useState } from "react";
import { useApp } from "../store.js";
import { sendRepeater } from "../api.js";
import type { GraphQLRequest, HttpMethod } from "@shared/types.js";
import { CodeBlock } from "../components/common.js";

function headersToText(h: Record<string, string>): string {
  return Object.entries(h).map(([k, v]) => `${k}: ${v}`).join("\n");
}
function textToHeaders(t: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of t.split("\n")) {
    const i = line.indexOf(":");
    if (i === -1) continue;
    const k = line.slice(0, i).trim();
    if (k) out[k] = line.slice(i + 1).trim();
  }
  return out;
}

export function RepeaterPage({ go }: { go: (t: string) => void }) {
  const { base } = useApp();
  const [method, setMethod] = useState<HttpMethod>(base?.method ?? "POST");
  const [url, setUrl] = useState(base?.url ?? "");
  const [headers, setHeaders] = useState(headersToText(base?.headers ?? {}));
  const [query, setQuery] = useState(base?.query ?? "");
  const [variables, setVariables] = useState(base?.variables ? JSON.stringify(base.variables, null, 2) : "");
  const [resp, setResp] = useState<any>(null);
  const [prev, setPrev] = useState<any>(null);
  const [metrics, setMetrics] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!base) {
    return (
      <div className="content">
        <h1 className="page-title">Repeater</h1>
        <div className="banner">
          No target set. <a onClick={() => go("target")}>Define a target request</a> first.
        </div>
      </div>
    );
  }

  const send = async () => {
    setErr(null);
    setBusy(true);
    try {
      let vars: Record<string, unknown> | undefined;
      if (variables.trim()) vars = JSON.parse(variables);
      const req: GraphQLRequest = { method, url, headers: textToHeaders(headers), query, variables: vars };
      const out = await sendRepeater(req);
      setPrev(resp);
      setResp(out.response);
      setMetrics(out.metrics);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="content">
      <h1 className="page-title">Repeater</h1>
      <p className="page-sub">Edit and resend the request; inspect the response and query metrics.</p>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 24, alignItems: "start" }}>
        <div className="card">
          <h3>Request</h3>
          <div className="row" style={{ marginBottom: 16 }}>
            <div className="field" style={{ width: 110, margin: 0 }}>
              <label>Method</label>
              <select value={method} onChange={(e) => setMethod(e.target.value as HttpMethod)}>
                <option>POST</option>
                <option>GET</option>
              </select>
            </div>
            <div className="field" style={{ flex: 1, margin: 0 }}>
              <label>URL</label>
              <input type="url" value={url} onChange={(e) => setUrl(e.target.value)} />
            </div>
          </div>
          <div className="field">
            <label>Headers</label>
            <textarea rows={4} value={headers} onChange={(e) => setHeaders(e.target.value)} />
          </div>
          <div className="field">
            <label>Query</label>
            <textarea rows={7} value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <div className="field">
            <label>Variables (JSON)</label>
            <textarea rows={4} value={variables} onChange={(e) => setVariables(e.target.value)} />
          </div>
          <button className="btn primary" onClick={send} disabled={busy}>
            {busy ? "Sending…" : "Send ▶"}
          </button>
        </div>

        <div className="card">
          <h3>Response</h3>
          {err && <div className="banner" style={{ borderColor: "var(--sev-critical)" }}>{err}</div>}
          {!resp && <div className="empty">Send the request to see the response.</div>}
          {resp && (
            <>
              <div className="row mb">
                <span className="status-pill pass">HTTP {resp.status}</span>
                <span className="dim">{resp.durationMs} ms</span>
                {prev && <span className="dim">· prev HTTP {prev.status} / {prev.durationMs} ms</span>}
              </div>
              {metrics && (
                <div className="row mb" style={{ fontSize: 12 }}>
                  <span className="dim">depth {metrics.depth}</span>
                  <span className="dim">· fields {metrics.fieldCount}</span>
                  <span className="dim">· aliases {metrics.aliasCount}</span>
                  <span className="dim">· complexity {metrics.complexity}</span>
                  <span className="dim">· {metrics.operationType}</span>
                </div>
              )}
              <CodeBlock>{resp.bodyText || resp.error || "(empty)"}</CodeBlock>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
