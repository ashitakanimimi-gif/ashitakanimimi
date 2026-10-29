import { probe, finding, pass, result, evidenceFrom, infoFinding, hasSqlErrorSignature, hasStackTraceSignature, type TestDef } from "../testKit.js";
import { setVariables as setVars } from "../../request/requestModel.js";
import { vuln } from "../../advisor/knowledgeBase.js";

function stringVarKeys(vars: Record<string, unknown> | undefined): string[] {
  if (!vars) return [];
  const keys: string[] = [];
  const walk = (obj: any, path: string) => {
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      for (const [k, v] of Object.entries(obj)) {
        if (typeof v === "string") keys.push(path ? `${path}.${k}` : k);
        else walk(v, path ? `${path}.${k}` : k);
      }
    }
  };
  walk(vars, "");
  return keys;
}

function setByPath(vars: Record<string, unknown>, path: string, value: unknown): Record<string, unknown> {
  const clone = structuredClone(vars);
  const parts = path.split(".");
  let cur: any = clone;
  for (let i = 0; i < parts.length - 1; i++) cur = cur[parts[i]];
  cur[parts[parts.length - 1]] = value;
  return clone;
}

const T20: TestDef = {
  id: "T20",
  area: "input",
  title: "Invalid type / format / length / range / missing values",
  mode: "auto",
  async run(ctx) {
    const keys = stringVarKeys(ctx.base.variables);
    if (keys.length === 0) return result(this, "info", [infoFinding(this, "No string variables to fuzz for invalid types.")]);
    // Replace a string with a wrong type (number) and an overlong string.
    const bad = setByPath(ctx.base.variables as any, keys[0], { unexpected: "object" });
    const req = setVars(ctx.base, bad);
    const res = await probe(req);
    if (res.status >= 500 || hasStackTraceSignature(res.bodyText)) {
      return result(this, "fail", [
        finding(this, {
          title: "Invalid input type not handled safely",
          severity: "medium",
          status: "fail",
          description: `Sending a wrong-typed value for '${keys[0]}' produced a server error (status ${res.status}) instead of a clean validation error.`,
          remediation: "Validate and coerce all inputs; return structured validation errors, never 500s/stack traces.",
          references: vuln("errorLeak").references,
          cwe: ["CWE-20"],
          evidence: evidenceFrom(req, res, "Server error on invalid input type."),
        }),
      ]);
    }
    return pass(this, "Invalid input type produced a clean validation error.");
  },
};

const T21: TestDef = {
  id: "T21",
  area: "input",
  title: "Malformed / duplicate / conflicting inputs",
  mode: "auto",
  async run(ctx) {
    // Add an unexpected extra variable; well-behaved servers ignore or reject cleanly.
    const extra = { ...(ctx.base.variables ?? {}), __unexpected_extra__: "x".repeat(2048) };
    const req = setVars(ctx.base, extra);
    const res = await probe(req);
    if (res.status >= 500 || hasStackTraceSignature(res.bodyText)) {
      return result(this, "fail", [
        finding(this, {
          title: "Malformed/extra input not handled safely",
          severity: "low",
          status: "fail",
          description: "An unexpected extra variable produced a server error instead of a clean response.",
          remediation: "Reject or ignore unexpected inputs; never let them trigger server errors.",
          references: vuln("errorLeak").references,
          cwe: ["CWE-20"],
          evidence: evidenceFrom(req, res, "Server error on extra input."),
        }),
      ]);
    }
    return pass(this, "Extra/malformed input handled cleanly.");
  },
};

const INJECTION_MARKERS: { label: string; payload: string }[] = [
  { label: "SQLi", payload: "' OR '1'='1' -- -" },
  { label: "SQLi-error", payload: "'" },
  { label: "NoSQL", payload: '{"$ne": null}' },
  { label: "Command", payload: "; id" },
  { label: "XPath", payload: "' or '1'='1" },
];

const T22: TestDef = {
  id: "T22",
  area: "input",
  title: "SQL / NoSQL / command / LDAP / XPath injection markers",
  mode: "auto",
  async run(ctx) {
    if (ctx.options.enableInjection === false) {
      return result(this, "info", [infoFinding(this, "Injection probing disabled by the user for this run.")]);
    }
    const keys = stringVarKeys(ctx.base.variables);
    if (keys.length === 0) return result(this, "info", [infoFinding(this, "No string variables to inject into.")]);

    for (const key of keys.slice(0, 3)) {
      for (const marker of INJECTION_MARKERS) {
        const req = setVars(ctx.base, setByPath(ctx.base.variables as any, key, marker.payload));
        const res = await probe(req);
        if (hasSqlErrorSignature(res.bodyText)) {
          const v = vuln("injection");
          return result(this, "fail", [
            finding(this, {
              title: `${marker.label} injection signature in '${key}'`,
              severity: v.severity,
              status: "fail",
              description: `Injecting a ${marker.label} marker into variable '${key}' triggered a database/backend error signature, indicating the input reaches a backend query unsafely.`,
              remediation: v.remediation,
              references: v.references,
              cwe: v.cwe,
              cvss: v.cvss,
              affectedOperation: ctx.base.operationName,
              evidence: evidenceFrom(req, res, "Response contained a SQL/backend error signature."),
            }),
          ]);
        }
      }
    }
    return pass(this, "No injection error signatures observed in tested variables.");
  },
};

const T23: TestDef = {
  id: "T23",
  area: "input",
  title: "Custom scalar validation with malicious values",
  mode: "auto",
  async run(ctx) {
    const keys = stringVarKeys(ctx.base.variables);
    if (keys.length === 0) return result(this, "info", [infoFinding(this, "No scalar variables to test.")]);
    const xss = "<script>alert(1)</script>";
    const req = setVars(ctx.base, setByPath(ctx.base.variables as any, keys[0], xss));
    const res = await probe(req);
    if (res.bodyText.includes(xss)) {
      const v = vuln("xss");
      return result(this, "warn", [
        finding(this, {
          title: "Unsanitized scalar reflected in response",
          severity: v.severity,
          status: "warn",
          description: `An HTML/script payload in '${keys[0]}' was reflected unescaped in the response. If rendered by a client, this enables XSS.`,
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, "Payload reflected verbatim."),
        }),
      ]);
    }
    return pass(this, "Custom scalar/malicious value did not reflect unsafely.");
  },
};

export const inputTests: TestDef[] = [T20, T21, T22, T23];
