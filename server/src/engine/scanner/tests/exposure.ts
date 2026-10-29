import { probe, finding, pass, result, evidenceFrom, infoFinding, hasStackTraceSignature, type TestDef } from "../testKit.js";
import { withOperation } from "../../request/requestModel.js";
import { vuln } from "../../advisor/knowledgeBase.js";

const SENSITIVE_KEY = /"(password|passwd|secret|token|api[_-]?key|ssn|credit[_-]?card|cvv|private[_-]?key|hash|salt)"\s*:/i;
const INTERNAL_KEY = /"(stack|stacktrace|__debug|_internal|internalError|trace|sqlMessage|hint|dbError)"\s*:/i;
const LEAK_SIGNATURE = /(\/(usr|home|var|app|src)\/[\w./-]+|[a-z]:\\[\w\\.-]+|postgres|mysql|mongodb|sequelize|prisma|at .+\(.+:\d+:\d+\)|ECONNREFUSED|ENOTFOUND)/i;

const T35: TestDef = {
  id: "T35",
  area: "exposure",
  title: "Over-returned / sensitive data in responses",
  mode: "auto",
  async run(ctx) {
    const res = await probe(ctx.base);
    if (SENSITIVE_KEY.test(res.bodyText)) {
      const v = vuln("dataExposure");
      const match = res.bodyText.match(SENSITIVE_KEY);
      return result(this, "fail", [
        finding(this, {
          title: "Sensitive data returned in response",
          severity: "high",
          status: "fail",
          description: `The base operation's response includes a sensitive key (${match?.[1]}). Return only data the requester needs.`,
          remediation: v.remediation,
          references: v.references,
          cwe: ["CWE-200"],
          affectedOperation: ctx.base.operationName,
          evidence: evidenceFrom(ctx.base, res, `Sensitive key present: ${match?.[1]}`),
        }),
      ]);
    }
    return pass(this, "No obviously sensitive keys in the base response.");
  },
};

const T36: TestDef = {
  id: "T36",
  area: "exposure",
  title: "Internal fields / metadata / implementation details",
  mode: "auto",
  async run(ctx) {
    const res = await probe(ctx.base);
    if (INTERNAL_KEY.test(res.bodyText)) {
      return result(this, "warn", [
        finding(this, {
          title: "Internal metadata exposed in response",
          severity: "medium",
          status: "warn",
          description: "The response contains internal keys (stack/trace/debug/db). Strip implementation detail from client responses.",
          remediation: vuln("dataExposure").remediation,
          references: vuln("dataExposure").references,
          cwe: ["CWE-200"],
          evidence: evidenceFrom(ctx.base, res, "Internal metadata key present."),
        }),
      ]);
    }
    return pass(this, "No internal metadata keys detected.");
  },
};

const T37: TestDef = {
  id: "T37",
  area: "exposure",
  title: "Stack traces / DB / file paths in error messages",
  mode: "auto",
  async run(ctx) {
    const req = withOperation(ctx.base, "{ __this is not valid graphql @@@ }");
    const res = await probe(req);
    if (hasStackTraceSignature(res.bodyText) || LEAK_SIGNATURE.test(res.bodyText)) {
      const v = vuln("errorLeak");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description: "A malformed query produced an error containing a stack trace, database detail, or file path.",
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, "Error response contained internal detail."),
        }),
      ]);
    }
    return pass(this, "Malformed-query errors did not leak internals.");
  },
};

const T38: TestDef = {
  id: "T38",
  area: "exposure",
  title: "Resolver / backend error leakage",
  mode: "auto",
  async run(ctx) {
    // Trigger a resolver-level error: send the base op with a bad variable type.
    const vars = ctx.base.variables ?? {};
    const key = Object.keys(vars)[0];
    const req = withOperation(ctx.base, ctx.base.query, ctx.base.operationName, key ? { ...vars, [key]: { __bad: true } } : { __unexpected: { __bad: true } });
    const res = await probe(req);
    if (hasStackTraceSignature(res.bodyText) || LEAK_SIGNATURE.test(res.bodyText)) {
      const v = vuln("errorLeak");
      return result(this, "fail", [
        finding(this, {
          title: "Resolver/backend error leaks internals",
          severity: v.severity,
          status: "fail",
          description: "A resolver/backend error exposed internal service, resolver, or implementation detail.",
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, "Resolver error leaked internal detail."),
        }),
      ]);
    }
    return pass(this, "Resolver errors did not leak internal detail.");
  },
};

const T39: TestDef = {
  id: "T39",
  area: "exposure",
  title: "User / object enumeration via errors",
  mode: "auto",
  async run(ctx) {
    const res = await probe(ctx.base);
    const errs = JSON.stringify((res.json as any)?.errors ?? "");
    if (/(user (does not exist|not found)|no such user|invalid user|unknown (email|account)|account not found)/i.test(errs)) {
      return result(this, "warn", [
        finding(this, {
          title: "Error messages enable user/object enumeration",
          severity: "medium",
          status: "warn",
          description: "Error messages distinguish existing vs non-existing users/objects, enabling enumeration.",
          remediation: "Return generic, uniform error messages that do not reveal whether a user/object exists.",
          references: vuln("errorLeak").references,
          cwe: ["CWE-204"],
          evidence: evidenceFrom(ctx.base, res, "Enumeration-friendly error message."),
        }),
      ]);
    }
    return pass(this, "No enumeration-friendly error messages observed.");
  },
};

export const exposureTests: TestDef[] = [T35, T36, T37, T38, T39];
