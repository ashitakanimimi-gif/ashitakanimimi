import { probe, finding, pass, result, evidenceFrom, type TestDef } from "../testKit.js";
import { withOrigin, toFormEncoded, toGET } from "../../request/requestModel.js";
import { vuln } from "../../advisor/knowledgeBase.js";

const EVIL_ORIGIN = "https://evil.example";

const T54: TestDef = {
  id: "T54",
  area: "corscsrf",
  title: "CORS reflects arbitrary Origin with credentials",
  mode: "auto",
  async run(ctx) {
    const req = withOrigin(ctx.base, EVIL_ORIGIN);
    const res = await probe(req);
    const acao = res.headers["access-control-allow-origin"];
    const acac = res.headers["access-control-allow-credentials"];
    if (acao && (acao === EVIL_ORIGIN || acao === "*")) {
      const withCreds = acac === "true";
      const v = vuln("cors");
      return result(this, withCreds ? "fail" : "warn", [
        finding(this, {
          title: v.title,
          severity: withCreds ? "high" : "medium",
          status: withCreds ? "fail" : "warn",
          description: `The server reflected Access-Control-Allow-Origin: ${acao}${withCreds ? " together with Access-Control-Allow-Credentials: true" : ""}. ${withCreds ? "Any origin can make credentialed cross-origin requests." : "Wildcard/arbitrary origin is allowed."}`,
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, `ACAO=${acao}, ACAC=${acac ?? "unset"}`),
        }),
      ]);
    }
    return pass(this, "CORS did not reflect an arbitrary origin.");
  },
};

const T55: TestDef = {
  id: "T55",
  area: "corscsrf",
  title: "Cross-site state change (form-encoded / GET CSRF)",
  mode: "auto",
  async run(ctx) {
    // Probe 1: form-encoded content type (bypasses JSON preflight requirement).
    const formReq = toFormEncoded(ctx.base);
    const formRes = await probe(formReq);
    const formOk = formRes.status === 200 && !!(formRes.json as any)?.data && !(formRes.json as any)?.errors;

    // Probe 2: GET method.
    const getReq = toGET(ctx.base);
    const getRes = await probe(getReq);
    const getOk = getRes.status === 200 && !!(getRes.json as any)?.data && !(getRes.json as any)?.errors;

    const isMutation = /mutation/i.test(ctx.base.query);
    if ((formOk || getOk) && isMutation) {
      const v = vuln("csrf");
      const which = formOk && getOk ? "form-encoded POST and GET" : formOk ? "form-encoded POST" : "GET";
      const poc = buildCsrfPoc(ctx.base, getOk ? "GET" : "POST-form");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description: `A state-changing operation executed via ${which}, which can be triggered cross-site without a CSRF token (if cookie auth is used).`,
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          affectedOperation: ctx.base.operationName,
          evidence: {
            note: `Accepted via ${which}.`,
            request: { method: getOk ? "GET" : "POST", url: ctx.base.url },
            response: { status: getOk ? getRes.status : formRes.status },
            artifact: poc,
          },
        }),
      ]);
    }
    if ((formOk || getOk) && !isMutation) {
      return result(this, "warn", [
        finding(this, {
          title: "Query accepted via simple request (GET/form-encoded)",
          severity: "low",
          status: "warn",
          description: "A query executed via GET/form-encoded request. Harmless for reads, but ensure mutations cannot.",
          remediation: vuln("csrf").remediation,
          references: vuln("csrf").references,
          cwe: vuln("csrf").cwe,
        }),
      ]);
    }
    return pass(this, "Operation not accepted via GET or form-encoded request.");
  },
};

function buildCsrfPoc(base: { url: string; query: string; variables?: unknown; operationName?: string }, mode: "GET" | "POST-form"): string {
  if (mode === "GET") {
    const u = new URL(base.url);
    u.searchParams.set("query", base.query);
    if (base.operationName) u.searchParams.set("operationName", base.operationName);
    if (base.variables) u.searchParams.set("variables", JSON.stringify(base.variables));
    return `<!-- GET CSRF PoC -->\n<img src="${u.toString()}">`;
  }
  const fields = [
    `<input type="hidden" name="query" value='${base.query.replace(/'/g, "&#39;")}'>`,
    base.operationName ? `<input type="hidden" name="operationName" value="${base.operationName}">` : "",
    base.variables ? `<input type="hidden" name="variables" value='${JSON.stringify(base.variables).replace(/'/g, "&#39;")}'>` : "",
  ].filter(Boolean);
  return `<!-- Form CSRF PoC -->\n<form action="${base.url}" method="POST" enctype="application/x-www-form-urlencoded">\n  ${fields.join("\n  ")}\n  <input type="submit" value="submit">\n</form>\n<script>document.forms[0].submit()</script>`;
}

export const corsCsrfTests: TestDef[] = [T54, T55];
