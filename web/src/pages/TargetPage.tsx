import React, { useState } from "react";
import { useApp } from "../store.js";
import { parseRaw } from "../api.js";
import type { GraphQLRequest, HttpMethod } from "@shared/types.js";

const SAMPLE_RAW = `POST http://10.164.3.88:32907/graphql HTTP/1.1
Host: 10.164.3.88:32907
authorization:
content-type: application/json
Origin: https://test.co.ke
User-Agent: Mozilla/5.0

{"operationName":"RequestWhitelistOtp","variables":{"input":{"phoneNumber":"0724657464"}},"query":"mutation RequestWhitelistOtp($input: RequestWhitelistOtpInput!) {\\n  requestWhitelistOtp(input: $input) {\\n    header { requestRefId responseCode __typename }\\n    body { verified message __typename }\\n    __typename\\n  }\\n}"}`;

function headersToText(h: Record<string, string>): string {
  return Object.entries(h)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
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

export function TargetPage({ go }: { go: (t: string) => void }) {
  const { base, setBase } = useApp();
  const [raw, setRaw] = useState("");
  const [method, setMethod] = useState<HttpMethod>(base?.method ?? "POST");
  const [url, setUrl] = useState(base?.url ?? "");
  const [headers, setHeaders] = useState(headersToText(base?.headers ?? { "content-type": "application/json" }));
  const [query, setQuery] = useState(base?.query ?? "");
  const [operationName, setOperationName] = useState(base?.operationName ?? "");
  const [variables, setVariables] = useState(base?.variables ? JSON.stringify(base.variables, null, 2) : "");
  const [msg, setMsg] = useState<string | null>(null);

  const doParse = async (text: string) => {
    setMsg(null);
    try {
      const { request } = await parseRaw(text);
      setMethod(request.method);
      setUrl(request.url);
      setHeaders(headersToText(request.headers));
      setQuery(request.query);
      setOperationName(request.operationName ?? "");
      setVariables(request.variables ? JSON.stringify(request.variables, null, 2) : "");
      setMsg("Parsed raw request into the fields below.");
    } catch (e) {
      setMsg(`Parse error: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const save = () => {
    setMsg(null);
    let vars: Record<string, unknown> | undefined;
    if (variables.trim()) {
      try {
        vars = JSON.parse(variables);
      } catch {
        setMsg("Variables must be valid JSON.");
        return;
      }
    }
    if (!url.trim() || !query.trim()) {
      setMsg("A URL and a GraphQL query/mutation are required.");
      return;
    }
    const req: GraphQLRequest = {
      method,
      url: url.trim(),
      headers: textToHeaders(headers),
      query,
      operationName: operationName.trim() || undefined,
      variables: vars,
    };
    setBase(req);
    setMsg("Target saved. You can now run a scan or open the Repeater.");
  };

  return (
    <div className="content">
      <h1 className="page-title">Target</h1>
      <p className="page-sub">
        Define the base GraphQL request. Every security test derives its probes from this one request, so paste a real
        (authenticated) request to test authenticated and operation-specific endpoints.
      </p>

      <div className="banner">
        Authorized testing only. Set a target you own or are explicitly permitted to test.
      </div>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        <div className="card">
          <h3>Paste raw HTTP request</h3>
          <div className="field">
            <textarea
              rows={12}
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              placeholder="Paste a Burp-style raw HTTP request here…"
            />
          </div>
          <div className="row">
            <button className="btn" onClick={() => doParse(raw)} disabled={!raw.trim()}>
              Parse ▶
            </button>
            <button
              className="btn ghost"
              onClick={() => {
                setRaw(SAMPLE_RAW);
                void doParse(SAMPLE_RAW);
              }}
            >
              Load sample
            </button>
          </div>
        </div>

        <div className="card">
          <h3>Structured request</h3>
          <div className="row" style={{ marginBottom: 16 }}>
            <div className="field" style={{ width: 120, margin: 0 }}>
              <label>Method</label>
              <select value={method} onChange={(e) => setMethod(e.target.value as HttpMethod)}>
                <option>POST</option>
                <option>GET</option>
              </select>
            </div>
            <div className="field" style={{ flex: 1, margin: 0 }}>
              <label>Endpoint URL</label>
              <input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://host/graphql" />
            </div>
          </div>
          <div className="field">
            <label>Headers (one per line, Key: value)</label>
            <textarea rows={5} value={headers} onChange={(e) => setHeaders(e.target.value)} />
          </div>
          <div className="field">
            <label>Operation name (optional)</label>
            <input type="text" value={operationName} onChange={(e) => setOperationName(e.target.value)} />
          </div>
          <div className="field">
            <label>Query / mutation</label>
            <textarea rows={6} value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <div className="field">
            <label>Variables (JSON)</label>
            <textarea rows={4} value={variables} onChange={(e) => setVariables(e.target.value)} />
          </div>
        </div>
      </div>

      {msg && <div className="banner mt">{msg}</div>}

      <div className="row mt">
        <button className="btn primary" onClick={save}>
          Save as target ▶
        </button>
        {base && (
          <>
            <button className="btn" onClick={() => go("scanner")}>
              Go to scanner
            </button>
            <button className="btn ghost" onClick={() => go("repeater")}>
              Open in repeater
            </button>
          </>
        )}
      </div>
    </div>
  );
}
