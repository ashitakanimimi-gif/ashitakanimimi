import { probe, finding, pass, result, manual, evidenceFrom, type TestDef } from "../testKit.js";
import { withOperation } from "../../request/requestModel.js";
import { vuln } from "../../advisor/knowledgeBase.js";

const SENSITIVE_FIELDS = ["password", "apiKey", "token", "secret", "ssn", "creditCard"];

/** Insert extra fields into the innermost selection set of a query string. */
function injectFields(query: string, fields: string[]): string | undefined {
  const lastClose = query.lastIndexOf("}");
  if (lastClose === -1) return undefined;
  // Prefer the innermost selection: insert before the closing brace that precedes
  // the final one, so fields land inside a nested object (e.g. `me { ... }`).
  const prevClose = query.lastIndexOf("}", lastClose - 1);
  const insertAt = prevClose === -1 ? lastClose : prevClose;
  return query.slice(0, insertAt) + " " + fields.join(" ") + " " + query.slice(insertAt);
}

const T17: TestDef = {
  id: "T17",
  area: "fieldauthz",
  title: "Sensitive fields accessible across roles",
  mode: "assisted",
  run: async () =>
    manual(
      { id: "T17", area: "fieldauthz", title: "Sensitive fields accessible across roles", mode: "assisted" } as TestDef,
      "Request sensitive/restricted fields using different role tokens and record whether unauthorized roles can read them. Supply a second (lower-privileged) token to automate.",
      vuln("overFetch").remediation,
      vuln("overFetch").references
    ),
};

const T18: TestDef = {
  id: "T18",
  area: "fieldauthz",
  title: "Restricted fields via nested objects",
  mode: "assisted",
  run: async () =>
    manual(
      { id: "T18", area: "fieldauthz", title: "Restricted fields via nested objects", mode: "assisted" } as TestDef,
      "Request restricted fields indirectly through nested/related objects and verify field-level authorization is enforced at every level.",
      vuln("overFetch").remediation,
      vuln("overFetch").references
    ),
};

const T19: TestDef = {
  id: "T19",
  area: "fieldauthz",
  title: "Over-fetch: append sensitive fields to a known query",
  mode: "auto",
  async run(ctx) {
    // Probe each sensitive field on its own — a single unknown field would
    // otherwise invalidate the whole operation and mask a real leak.
    const leaked: { field: string; req: any; res: any }[] = [];
    for (const field of SENSITIVE_FIELDS) {
      const injected = injectFields(ctx.base.query, [field]);
      if (!injected) continue;
      const req = withOperation(ctx.base, injected, ctx.base.operationName, ctx.base.variables);
      const res = await probe(req);
      const dataStr = JSON.stringify((res.json as any)?.data ?? "");
      if (new RegExp(`"${field}"\\s*:`, "i").test(dataStr)) {
        leaked.push({ field, req, res });
      }
    }

    if (leaked.length > 0) {
      const v = vuln("overFetch");
      const last = leaked[leaked.length - 1];
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description: `Appending sensitive field(s) [${leaked.map((l) => l.field).join(", ")}] to the operation returned them in the response.`,
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          affectedOperation: ctx.base.operationName,
          evidence: evidenceFrom(last.req, last.res, `Sensitive fields resolved: ${leaked.map((l) => l.field).join(", ")}`),
        }),
      ]);
    }
    return pass(this, "No appended sensitive fields resolved in the response.");
  },
};

export const fieldAuthzTests: TestDef[] = [T17, T18, T19];
