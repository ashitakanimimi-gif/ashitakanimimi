import { probe, finding, pass, result, manual, evidenceFrom, infoFinding, type TestDef } from "../testKit.js";
import { setVariables as setVars } from "../../request/requestModel.js";
import { vuln } from "../../advisor/knowledgeBase.js";

const T24: TestDef = {
  id: "T24",
  area: "mutation",
  title: "Exposed mutation review",
  mode: "auto",
  async run(ctx) {
    if (ctx.state.schema) {
      const mt = ctx.state.schema.getMutationType();
      if (!mt) return pass(this, "Schema exposes no mutations.");
      const names = Object.keys(mt.getFields());
      return result(this, "warn", [
        finding(this, {
          title: "Mutations exposed by the schema",
          severity: "low",
          status: "warn",
          description: `The schema exposes ${names.length} mutation(s): ${names.slice(0, 25).join(", ")}${names.length > 25 ? "…" : ""}. Confirm each is required and protected.`,
          remediation: "Expose only required mutations; remove or restrict the rest.",
          references: vuln("missingAuthz").references,
          cwe: ["CWE-862"],
        }),
      ]);
    }
    const isMutation = /^\s*mutation\b/.test(ctx.base.query) || ctx.base.query.includes("mutation ");
    return result(this, "info", [
      infoFinding(
        this,
        isMutation
          ? "Base operation is a mutation. Enable introspection analysis or paste the schema to enumerate all mutations."
          : "Introspection disabled — paste the schema in the Analyzer to review exposed mutations."
      ),
    ]);
  },
};

const T25: TestDef = {
  id: "T25",
  area: "mutation",
  title: "Unexpected fields accepted in mutation input",
  mode: "auto",
  async run(ctx) {
    if (!/mutation/i.test(ctx.base.query)) {
      return result(this, "info", [infoFinding(this, "Base operation is not a mutation; set a mutation request to test mass-assignment.")]);
    }
    const vars = ctx.base.variables ?? {};
    // Find the first object-valued variable (the input object) and add a privileged field.
    const inputKey = Object.keys(vars).find((k) => vars[k] && typeof vars[k] === "object");
    if (!inputKey) return result(this, "info", [infoFinding(this, "No object input variable to extend.")]);
    const extended = { ...vars, [inputKey]: { ...(vars[inputKey] as object), isAdmin: true, role: "admin" } };
    const req = setVars(ctx.base, extended);
    const res = await probe(req);
    const errs = JSON.stringify((res.json as any)?.errors ?? "");
    const rejected = /isadmin|role|unknown field|not defined|cannot query|is not defined/i.test(errs);
    if (!rejected && (res.json as any)?.data) {
      return result(this, "warn", [
        finding(this, {
          title: "Mutation input accepted unexpected privileged fields",
          severity: "medium",
          status: "warn",
          description: "Adding isAdmin/role fields to the mutation input did not produce a validation error. Verify the server does not mass-assign unexpected fields.",
          remediation: "Define strict input types; reject or ignore unexpected fields; never mass-assign to privileged attributes.",
          references: vuln("missingAuthz").references,
          cwe: ["CWE-915"],
          affectedOperation: ctx.base.operationName,
          evidence: evidenceFrom(req, res, "No rejection of injected privileged fields."),
        }),
      ]);
    }
    return pass(this, "Unexpected input fields were rejected.");
  },
};

const T26: TestDef = {
  id: "T26",
  area: "mutation",
  title: "Restricted-field mutation (role/ownership/status/limits)",
  mode: "assisted",
  run: async () =>
    manual(
      { id: "T26", area: "mutation", title: "Restricted-field mutation (role/ownership/status/limits)", mode: "assisted" } as TestDef,
      "Attempt to change restricted fields (role, permissions, ownership, status, limits) via mutations with a non-privileged identity and record whether they change.",
      "Enforce server-side authorization on every restricted field; never trust client-supplied privileged values.",
      vuln("missingAuthz").references
    ),
};

const T27: TestDef = {
  id: "T27",
  area: "mutation",
  title: "Replay / idempotency of sensitive mutations",
  mode: "assisted",
  run: async () =>
    manual(
      { id: "T27", area: "mutation", title: "Replay / idempotency of sensitive mutations", mode: "assisted" } as TestDef,
      "Replay sensitive mutations (payments, transfers, OTP issuance) and record whether duplicate processing occurs. NOT replayed automatically to avoid side effects — run deliberately.",
      "Add idempotency keys / nonces and replay protection to sensitive mutations.",
      ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"]
    ),
};

export const mutationTests: TestDef[] = [T24, T25, T26, T27];
