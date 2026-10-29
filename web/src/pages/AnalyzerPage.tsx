import React, { useState } from "react";
import { analyze } from "../api.js";
import type { SchemaReport } from "@shared/types.js";
import { FindingCard } from "../components/FindingCard.js";
import { StatTile } from "../components/charts.js";
import { CodeBlock } from "../components/common.js";

const SAMPLE_SDL = `type User {
  id: ID!
  email: String!
  password: String
  apiKey: String
  posts: [Post!]!
  role: String @deprecated(reason: "use roles")
}
type Post { id: ID!, title: String!, author: User!, comments: [Comment!]! }
type Comment { id: ID!, text: String!, author: User! }
type Query { me: User, users: [User!]!, post(id: ID!): Post }
type Mutation {
  createPost(title: String!): Post!
  deleteUser(id: ID!): Boolean
  updateUserRole(id: ID!, role: String!): User!
}`;

export function AnalyzerPage() {
  const [schema, setSchema] = useState("");
  const [jsSource, setJsSource] = useState("");
  const [report, setReport] = useState<SchemaReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const run = async () => {
    setErr(null);
    setBusy(true);
    try {
      setReport(await analyze({ schema, jsSource }));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="content">
      <h1 className="page-title">Analyzer</h1>
      <p className="page-sub">
        Statically analyze a schema (SDL or introspection JSON) for risky patterns, and recover operations from a client
        JS bundle — no live target needed.
      </p>

      <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 24, alignItems: "start" }}>
        <div className="card">
          <h3>Schema (SDL or introspection JSON)</h3>
          <div className="field">
            <textarea rows={12} value={schema} onChange={(e) => setSchema(e.target.value)} placeholder="Paste SDL or an introspection result…" />
          </div>
          <div className="row">
            <button className="btn ghost" onClick={() => setSchema(SAMPLE_SDL)}>
              Load sample schema
            </button>
          </div>
        </div>
        <div className="card">
          <h3>JS bundle (recover operations)</h3>
          <div className="field">
            <textarea rows={12} value={jsSource} onChange={(e) => setJsSource(e.target.value)} placeholder="Paste JS source / bundle to extract gql operations…" />
          </div>
        </div>
      </div>

      <div className="row mt">
        <button className="btn primary" onClick={run} disabled={busy || (!schema.trim() && !jsSource.trim())}>
          {busy ? "Analyzing…" : "Analyze ▶"}
        </button>
      </div>

      {err && <div className="banner mt" style={{ borderColor: "var(--sev-critical)" }}>{err}</div>}

      {report && (
        <div className="mt">
          {report.error && <div className="banner" style={{ borderColor: "var(--sev-critical)" }}>Schema error: {report.error}</div>}
          {report.stats && (
            <div className="dash-grid mb">
              <div className="span-3"><StatTile label="Types" value={report.stats.types} /></div>
              <div className="span-3"><StatTile label="Queries" value={report.stats.queries} /></div>
              <div className="span-3"><StatTile label="Mutations" value={report.stats.mutations} tone="accent" /></div>
              <div className="span-3"><StatTile label="Deprecated" value={report.stats.deprecated} /></div>
            </div>
          )}

          {report.findings.length > 0 && (
            <div className="card mb">
              <h3>Schema findings</h3>
              {report.findings.map((f) => (
                <FindingCard key={f.id} finding={f} />
              ))}
            </div>
          )}

          {report.extractedOperations && report.extractedOperations.length > 0 && (
            <div className="card">
              <h3>Extracted operations ({report.extractedOperations.length})</h3>
              {report.extractedOperations.map((op, i) => (
                <div key={i} className="mb">
                  <CodeBlock>{op}</CodeBlock>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
