import { probe, finding, pass, result, manual, evidenceFrom, infoFinding, type TestDef } from "../testKit.js";
import { removeHeader, setHeader, setVariables, getHeader, clone } from "../../request/requestModel.js";
import { vuln } from "../../advisor/knowledgeBase.js";

function hasData(res: any): boolean {
  const d = res.json?.data;
  return !!d && Object.values(d).some((v) => v !== null && v !== undefined);
}

const T11: TestDef = {
  id: "T11",
  area: "authz",
  title: "BOLA / IDOR via object ID swap",
  mode: "assisted",
  async run(ctx) {
    const { objectIdField, objectIdValue } = ctx.options;
    if (!objectIdField || objectIdValue === undefined) {
      return manual(
        this,
        "Provide the variable name holding an object reference (e.g. 'id') and an alternate value belonging to another user/tenant. The tool will resend the operation with the swapped reference and compare.",
        vuln("bola").remediation,
        vuln("bola").references
      );
    }
    const swapped = setVariables(ctx.base, { ...(ctx.base.variables ?? {}), [objectIdField]: objectIdValue });
    const res = await probe(swapped);
    if (hasData(res)) {
      const v = vuln("bola");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description: `Swapping '${objectIdField}' to another user's value '${objectIdValue}' returned data, indicating object-level authorization is not enforced.`,
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          affectedOperation: ctx.base.operationName,
          evidence: evidenceFrom(swapped, res, "Data returned for another user's object reference."),
        }),
      ]);
    }
    return pass(this, "Swapped object reference did not return data.");
  },
};

function assistedAuthz(id: string, title: string, guidance: string): TestDef {
  return {
    id,
    area: "authz",
    title,
    mode: "assisted",
    run: async () => manual({ id, area: "authz", title, mode: "assisted" } as TestDef, guidance, vuln("missingAuthz").remediation, vuln("missingAuthz").references),
  };
}

const T12 = assistedAuthz(
  "T12",
  "Privileged operation as low-privileged account",
  "Provide a low-privileged authorization header and attempt a privileged operation. The tool can resend with that identity to confirm it is rejected."
);
const T13 = assistedAuthz(
  "T13",
  "Resolver-level authorization enforced server-side",
  "Confirm authorization is enforced in resolvers, not only the client. Re-run sensitive operations with a non-owner identity and verify rejection."
);
const T14 = assistedAuthz(
  "T14",
  "Client-supplied role / ownership tampering",
  "Add or modify role/permission/ownership fields in variables (e.g. isAdmin:true, role:'admin') and verify they cannot grant access."
);
const T15 = assistedAuthz(
  "T15",
  "Nested / related cross-tenant object access",
  "Traverse to nested/related objects owned by another tenant and verify authorization is enforced at each level."
);

const T16: TestDef = {
  id: "T16",
  area: "authz",
  title: "Alias / fragment / alternate structure authz bypass",
  mode: "auto",
  async run(ctx) {
    const hadAuth = getHeader(ctx.base, "authorization") || getHeader(ctx.base, "cookie");
    if (!hadAuth) {
      return result(this, "info", [
        infoFinding(this, "No credentials on the base request; alias/structure bypass is best tested against a protected operation."),
      ]);
    }
    // Rewrite the operation name and strip credentials; if structure change bypasses a
    // name/credential-based control, data will still return.
    let altQuery = ctx.base.query.replace(/\b(query|mutation)\s+\w+/, "$1 AltOp_bypass");
    if (altQuery === ctx.base.query) altQuery = ctx.base.query;
    const stripped = removeHeader(removeHeader({ ...clone(ctx.base), query: altQuery, operationName: undefined }, "authorization"), "cookie");
    const res = await probe(stripped);
    if (hasData(res)) {
      const v = vuln("missingAuthz");
      return result(this, "fail", [
        finding(this, {
          title: "Authorization bypassed by changing query structure",
          severity: v.severity,
          status: "fail",
          description:
            "Renaming the operation and removing credentials still returned data, suggesting authorization keys off operation name / client state rather than server-side identity.",
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(stripped, res, "Restructured, unauthenticated operation returned data."),
        }),
      ]);
    }
    return pass(this, "Restructured/unauthenticated operation was rejected.");
  },
};

export const authzTests: TestDef[] = [T11, T12, T13, T14, T15, T16];
