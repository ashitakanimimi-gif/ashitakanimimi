import { probe, finding, pass, result, evidenceFrom, infoFinding, type TestDef } from "../testKit.js";
import { withOperation, getHeader } from "../../request/requestModel.js";
import { buildDeepQuery, buildAliasQuery } from "../../../lib/complexity.js";
import { snippet } from "../../../lib/findings.js";
import { vuln } from "../../advisor/knowledgeBase.js";

// Conservative bounds — enough to prove a missing control, not to harm the target.
const DEPTH = 12;
const ALIASES = 100;
const BATCH = 10;
const RATE_BURST = 10;

function depthLimited(body: string): boolean {
  return /(max(imum)? depth|depth limit|query is too deep|exceeds maximum|too complex|query complexity|cost limit|maximum cost)/i.test(
    body
  );
}

const T28: TestDef = {
  id: "T28",
  area: "dos",
  title: "Deeply nested query depth limit",
  mode: "auto",
  async run(ctx) {
    let query: string;
    if (ctx.state.cyclicField) {
      query = buildDeepQuery(ctx.state.cyclicField, DEPTH);
    } else if (ctx.state.introspectionEnabled) {
      // Introspection types are self-nesting — a safe deep probe.
      let inner = "name";
      for (let i = 0; i < DEPTH; i++) inner = `ofType { ${inner} }`;
      query = `{ __type(name: "Query") { fields { type { ${inner} } } } }`;
    } else {
      return result(this, "info", [
        infoFinding(this, "No self-referential field known (introspection disabled). Provide a nestable field to test depth limits."),
      ]);
    }
    const req = withOperation(ctx.base, query);
    const res = await probe(req, { timeoutMs: 15000 });
    if (depthLimited(res.bodyText)) return pass(this, "A depth/complexity limit rejected the deep query.");
    if (res.status === 200 && !(res.json as any)?.errors) {
      const v = vuln("depthDos");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description: `A query nested ${DEPTH} levels deep was accepted without a depth/complexity limit.`,
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, "Deeply nested query accepted."),
        }),
      ]);
    }
    return pass(this, "Deep query did not execute successfully (likely limited or invalid).");
  },
};

const T29: TestDef = {
  id: "T29",
  area: "dos",
  title: "Query complexity / cost limit (fields, fragments, circular)",
  mode: "auto",
  async run(ctx) {
    const field = ctx.state.sampleQueryField ?? "__typename";
    const query = buildAliasQuery(field, ALIASES);
    const req = withOperation(ctx.base, query);
    const res = await probe(req, { timeoutMs: 15000 });
    if (depthLimited(res.bodyText)) return pass(this, "A complexity/cost limit rejected the large query.");
    if (res.status === 200 && !(res.json as any)?.errors) {
      const v = vuln("complexityDos");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: field === "__typename" ? "medium" : v.severity,
          status: "fail",
          description: `A query with ${ALIASES} aliased selections of '${field}' executed without a cost/complexity limit.`,
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, "Large aliased query accepted."),
        }),
      ]);
    }
    return pass(this, "Large query was rejected or errored.");
  },
};

const T30: TestDef = {
  id: "T30",
  area: "dos",
  title: "Pagination / max result limit (first: 999999)",
  mode: "auto",
  async run(ctx) {
    const vars = ctx.base.variables ?? {};
    const pagKey = Object.keys(vars).find((k) => ["first", "last", "limit", "take", "count", "size"].includes(k.toLowerCase()));
    const hasInlinePag = /\b(first|last|limit|take):\s*\d+/i.test(ctx.base.query);
    if (!pagKey && !hasInlinePag) {
      return result(this, "info", [infoFinding(this, "No pagination argument found on the base operation to test.")]);
    }
    let req;
    if (pagKey) {
      req = withOperation(ctx.base, ctx.base.query, ctx.base.operationName, { ...vars, [pagKey]: 999999 });
    } else {
      req = withOperation(ctx.base, ctx.base.query.replace(/\b(first|last|limit|take):\s*\d+/i, "$1: 999999"), ctx.base.operationName, ctx.base.variables);
    }
    const res = await probe(req, { timeoutMs: 15000 });
    const errs = /(maximum|too large|limit|exceeds|max.*page)/i.test(JSON.stringify((res.json as any)?.errors ?? ""));
    if (errs) return pass(this, "A maximum result/page limit rejected the oversized request.");
    if (res.status === 200 && (res.json as any)?.data) {
      const v = vuln("pagination");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description: "Requesting 999999 records was accepted without a maximum page/result limit.",
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, "Oversized page size accepted."),
        }),
      ]);
    }
    return pass(this, "Oversized page request did not succeed.");
  },
};

const T31: TestDef = {
  id: "T31",
  area: "dos",
  title: "Long-running query server-side timeout",
  mode: "auto",
  async run(ctx) {
    const field = ctx.state.sampleQueryField;
    if (!field) return result(this, "info", [infoFinding(this, "No sample query field known to build a heavier query.")]);
    const query = buildAliasQuery(field, 40);
    const req = withOperation(ctx.base, query);
    const res = await probe(req, { timeoutMs: 20000 });
    if (res.durationMs > 10000 && res.status === 200) {
      return result(this, "warn", [
        finding(this, {
          title: "No server-side query timeout observed",
          severity: "medium",
          status: "warn",
          description: `A heavier query took ${res.durationMs} ms and still completed, suggesting no server-side execution timeout.`,
          remediation: "Enforce a server-side execution timeout for GraphQL resolvers/requests.",
          references: vuln("complexityDos").references,
          cwe: ["CWE-400"],
          evidence: evidenceFrom(req, res, `Duration ${res.durationMs} ms.`),
        }),
      ]);
    }
    return pass(this, `Query completed/aborted in ${res.durationMs} ms.`);
  },
};

const T32: TestDef = {
  id: "T32",
  area: "dos",
  title: "Rate limiting on repeated expensive queries",
  mode: "auto",
  async run(ctx) {
    let limited = false;
    let last;
    for (let i = 0; i < RATE_BURST; i++) {
      last = await probe(ctx.base, { timeoutMs: 6000 });
      if (last.status === 429 || /rate limit|too many requests/i.test(last.bodyText)) {
        limited = true;
        break;
      }
    }
    if (limited) return pass(this, `Rate limiting observed within ${RATE_BURST} requests.`);
    return result(this, "warn", [
      finding(this, {
        title: "No rate limiting observed",
        severity: "medium",
        status: "warn",
        description: `Sent ${RATE_BURST} rapid requests with no 429 / rate-limit response.`,
        remediation: "Apply per-client and per-operation rate limiting.",
        references: vuln("batching").references,
        cwe: ["CWE-770"],
      }),
    ]);
  },
};

async function sendBatch(ctx: { base: any }, count: number) {
  const headers: Record<string, string> = { ...ctx.base.headers };
  const ctKey = Object.keys(headers).find((h) => h.toLowerCase() === "content-type");
  if (!ctKey) headers["content-type"] = "application/json";
  else headers[ctKey] = "application/json";
  for (const h of ["host", "Host", "content-length", "Content-Length", "connection", "Connection"]) delete headers[h];
  const op = { query: ctx.base.query, operationName: ctx.base.operationName, variables: ctx.base.variables };
  const body = JSON.stringify(Array.from({ length: count }, () => op));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const res = await fetch(ctx.base.url, { method: "POST", headers, body, signal: controller.signal });
    const text = await res.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      /* */
    }
    return { status: res.status, text, json };
  } catch (e) {
    return { status: 0, text: String(e), json: undefined };
  } finally {
    clearTimeout(timer);
  }
}

const T33: TestDef = {
  id: "T33",
  area: "dos",
  title: "Array batching operation cap",
  mode: "auto",
  async run(ctx) {
    const res = await sendBatch(ctx, BATCH);
    if (Array.isArray(res.json) && res.json.length === BATCH) {
      const v = vuln("batching");
      return result(this, "fail", [
        finding(this, {
          title: "Array query batching is uncapped",
          severity: v.severity,
          status: "fail",
          description: `The server executed a batch of ${BATCH} operations in one request (array response returned). This enables amplification and rate-limit bypass.`,
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: {
            note: "Batched array request returned an array of results.",
            request: { method: "POST", url: ctx.base.url, body: `[ ${BATCH} x operation ]` },
            response: { status: res.status, bodySnippet: snippet(res.text) },
          },
        }),
      ]);
    }
    return pass(this, "Array batching not supported or capped.");
  },
};

const T34: TestDef = {
  id: "T34",
  area: "dos",
  title: "Alias-based repetition of expensive/sensitive ops",
  mode: "auto",
  async run(ctx) {
    const query = buildAliasQuery("__typename", ALIASES);
    const req = withOperation(ctx.base, query);
    const res = await probe(req);
    const data = (res.json as any)?.data;
    if (res.status === 200 && data && Object.keys(data).length >= ALIASES) {
      const v = vuln("batching");
      return result(this, "fail", [
        finding(this, {
          title: "Alias-based repetition is uncapped",
          severity: "medium",
          status: "fail",
          description: `${ALIASES} aliased selections were all executed in one request, enabling per-request rate-limit bypass (e.g. repeating OTP/login/sensitive fields).`,
          remediation: "Cap alias counts and apply rate limiting per resolved field, not per HTTP request.",
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, `${Object.keys(data).length} aliased results returned.`),
        }),
      ]);
    }
    return pass(this, "Alias repetition was rejected or capped.");
  },
};

export const dosTests: TestDef[] = [T28, T29, T30, T31, T32, T33, T34];
