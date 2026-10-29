import { isObjectType } from "graphql";
import { probe, finding, pass, result, evidenceFrom, infoFinding, type TestDef, type TestContext } from "../testKit.js";
import { setQuery, withOperation, clone } from "../../request/requestModel.js";
import {
  FULL_INTROSPECTION_QUERY,
  INTROSPECTION_NO_DIRECTIVES,
  MINIMAL_INTROSPECTION,
  TYPENAME_QUERY,
  tryBuildSchema,
} from "../../../lib/introspection.js";
import { vuln } from "../../advisor/knowledgeBase.js";
import { looksLikeGraphQL } from "../../../lib/graphqlClient.js";

const COMMON_PATHS = [
  "/graphql",
  "/graphiql",
  "/graphql.php",
  "/graphql/console",
  "/api",
  "/api/graphql",
  "/graphql/api",
  "/graphql/graphql",
  "/v1/graphql",
  "/query",
];

const T01: TestDef = {
  id: "T01",
  area: "discovery",
  title: "Endpoint discovery across common paths",
  mode: "auto",
  async run(ctx) {
    const found: string[] = [];
    let origin: string;
    try {
      origin = new URL(ctx.base.url).origin;
    } catch {
      return result(this, "info", [infoFinding(this, "Base URL could not be parsed; skipping discovery.")]);
    }

    for (const path of COMMON_PATHS) {
      const url = origin + path;
      const req = { ...clone(ctx.base), url, method: "POST" as const, query: TYPENAME_QUERY, variables: undefined, operationName: undefined };
      const res = await probe(req, { timeoutMs: 6000 });
      if (res.status > 0 && (looksLikeGraphQL(res) || /graphiql|playground/i.test(res.bodyText))) {
        found.push(url);
      }
    }

    ctx.state.discoveredEndpoints = found;
    if (found.length === 0) {
      return pass(this, "No additional GraphQL endpoints discovered on common paths.");
    }
    return result(this, "info", [
      infoFinding(
        this,
        `Discovered ${found.length} GraphQL endpoint(s): ${found.join(", ")}. Confirm each is intended to be exposed.`
      ),
    ]);
  },
};

const T02: TestDef = {
  id: "T02",
  area: "discovery",
  title: "Introspection enabled in production",
  mode: "auto",
  async run(ctx) {
    const attempts: { label: string; query: string }[] = [
      { label: "full", query: FULL_INTROSPECTION_QUERY },
      { label: "no-directives", query: INTROSPECTION_NO_DIRECTIVES },
      { label: "minimal", query: MINIMAL_INTROSPECTION },
    ];

    for (const a of attempts) {
      const req = withOperation(ctx.base, a.query, a.label === "minimal" ? undefined : "IntrospectionQuery");
      const res = await probe(req);
      const data = (res.json as any)?.data;
      if (data?.__schema) {
        ctx.state.introspectionEnabled = true;
        const schema = tryBuildSchema(res.json);
        if (schema) {
          ctx.state.schema = schema;
          const q = schema.getQueryType();
          if (q) {
            const noArgField = Object.values(q.getFields()).find((f) => f.args.every((arg) => !("ofType" in (arg.type as any)) || true) && f.args.length === 0);
            ctx.state.sampleQueryField = (noArgField ?? Object.values(q.getFields())[0])?.name;
            // Find a self-referential (cyclic) field for depth testing.
            for (const f of Object.values(q.getFields())) {
              const named = unwrap(f.type);
              if (named && isObjectType(named)) {
                const sub = Object.values(named.getFields()).find((sf) => unwrap(sf.type)?.name === named.name);
                if (sub) {
                  ctx.state.cyclicField = f.name;
                  break;
                }
              }
            }
          }
        }
        const v = vuln("introspection");
        return result(this, "fail", [
          finding(this, {
            title: v.title,
            severity: v.severity,
            status: "fail",
            description: `Schema introspection is enabled (via the ${a.label} query). An attacker can retrieve the full schema, mapping the entire attack surface.`,
            remediation: v.remediation,
            references: v.references,
            cwe: v.cwe,
            cvss: v.cvss,
            evidence: evidenceFrom(req, res, "Response contained __schema data."),
          }),
        ]);
      }
    }

    return pass(this, "Introspection appears to be disabled.");
  },
};

function unwrap(type: any): any {
  let t = type;
  while (t && t.ofType) t = t.ofType;
  return t;
}

const T03: TestDef = {
  id: "T03",
  area: "discovery",
  title: "Deprecated / hidden / undocumented schema elements",
  mode: "auto",
  async run(ctx) {
    if (!ctx.state.schema) {
      return result(this, "info", [
        infoFinding(this, "Introspection disabled — review deprecated/hidden elements manually or via the Analyzer."),
      ]);
    }
    const deprecated: string[] = [];
    for (const type of Object.values(ctx.state.schema.getTypeMap())) {
      if (type.name.startsWith("__")) continue;
      if (isObjectType(type)) {
        for (const f of Object.values(type.getFields())) {
          if (f.deprecationReason) deprecated.push(`${type.name}.${f.name}`);
        }
      }
    }
    if (deprecated.length === 0) return pass(this, "No deprecated schema fields found.");
    const v = vuln("dataExposure");
    return result(this, "warn", [
      finding(this, {
        title: "Deprecated schema fields present",
        severity: "low",
        status: "warn",
        description: `Found ${deprecated.length} deprecated field(s): ${deprecated.slice(0, 15).join(", ")}${deprecated.length > 15 ? "…" : ""}. Deprecated fields often remain reachable and may expose unintended data.`,
        remediation: "Remove or restrict deprecated/unused fields that are no longer required.",
        references: v.references,
        cwe: v.cwe,
      }),
    ]);
  },
};

const T04: TestDef = {
  id: "T04",
  area: "discovery",
  title: "Field suggestions leak schema on invalid fields",
  mode: "auto",
  async run(ctx) {
    const req = withOperation(ctx.base, `{ __nonexistent_field_xyz }`);
    const res = await probe(req);
    const errs = JSON.stringify((res.json as any)?.errors ?? res.bodyText);
    if (/did you mean/i.test(errs)) {
      const v = vuln("fieldSuggestions");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description:
            "The server returns 'Did you mean …' suggestions for invalid fields, letting an attacker reconstruct the schema even when introspection is disabled.",
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, "Error message included field suggestions."),
        }),
      ]);
    }
    return pass(this, "No field suggestions returned for invalid fields.");
  },
};

const T05: TestDef = {
  id: "T05",
  area: "discovery",
  title: "GraphiQL / Playground / Voyager dev tools exposed",
  mode: "auto",
  async run(ctx) {
    const req = { ...clone(ctx.base), method: "GET" as const };
    req.headers = { ...req.headers, accept: "text/html" };
    const res = await probe(req);
    if (/graphiql|graphql playground|graphql-voyager|__ELECTRON|playground-/i.test(res.bodyText)) {
      const v = vuln("devTools");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description: "A GraphQL development/explorer UI (GraphiQL/Playground/Voyager) is served from the endpoint.",
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req as any, res, "HTML response referenced a GraphQL dev tool."),
        }),
      ]);
    }
    return pass(this, "No GraphQL development tools detected at the endpoint.");
  },
};

export const discoveryTests: TestDef[] = [T01, T02, T03, T04, T05];
