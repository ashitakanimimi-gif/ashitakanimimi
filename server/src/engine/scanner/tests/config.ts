import { probe, finding, pass, result, evidenceFrom, infoFinding, type TestDef } from "../testKit.js";
import { vuln } from "../../advisor/knowledgeBase.js";

function isLocalHost(host: string): boolean {
  return /^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)/i.test(host) || /\.local(:\d+)?$/i.test(host);
}

const T52: TestDef = {
  id: "T52",
  area: "config",
  title: "Debug mode / verbose / dev features enabled",
  mode: "auto",
  async run(ctx) {
    const res = await probe(ctx.base);
    const ext = (res.json as any)?.extensions;
    const tracingOn = ext && (ext.tracing || ext.apolloTracing || ext.executionTime);
    const poweredBy = res.headers["x-powered-by"];
    const flags: string[] = [];
    if (tracingOn) flags.push("GraphQL tracing/extensions in response");
    if (poweredBy) flags.push(`X-Powered-By: ${poweredBy}`);
    if (flags.length > 0) {
      const v = vuln("config");
      return result(this, "warn", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "warn",
          description: `Development/verbose features detected: ${flags.join("; ")}.`,
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(ctx.base, res, flags.join("; ")),
        }),
      ]);
    }
    return pass(this, "No debug/tracing/verbose features detected.");
  },
};

const T53: TestDef = {
  id: "T53",
  area: "config",
  title: "HTTP to HTTPS enforcement",
  mode: "auto",
  async run(ctx) {
    let u: URL;
    try {
      u = new URL(ctx.base.url);
    } catch {
      return result(this, "info", [infoFinding(this, "Could not parse URL.")]);
    }
    if (u.protocol === "https:") return pass(this, "Endpoint is served over HTTPS.");
    if (isLocalHost(u.host)) {
      return result(this, "info", [infoFinding(this, "Endpoint is local HTTP — acceptable for a local test target; enforce HTTPS in production.")]);
    }
    const v = vuln("transport");
    return result(this, "fail", [
      finding(this, {
        title: v.title,
        severity: v.severity,
        status: "fail",
        description: "The GraphQL endpoint is reachable over plaintext HTTP. Traffic (including tokens) can be intercepted.",
        remediation: v.remediation,
        references: v.references,
        cwe: v.cwe,
        cvss: v.cvss,
      }),
    ]);
  },
};

export const configTests: TestDef[] = [T52, T53];
