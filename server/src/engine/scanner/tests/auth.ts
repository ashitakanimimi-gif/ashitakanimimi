import { probe, finding, pass, result, manual, evidenceFrom, infoFinding, type TestDef } from "../testKit.js";
import { setHeader, removeHeader, getHeader, clone } from "../../request/requestModel.js";
import { vuln } from "../../advisor/knowledgeBase.js";

function responseHasData(res: any): boolean {
  const data = res.json?.data;
  if (!data) return false;
  return Object.values(data).some((v) => v !== null && v !== undefined);
}

function responseLooksAuthError(res: any): boolean {
  const body = (res.bodyText ?? "").toLowerCase();
  return (
    res.status === 401 ||
    res.status === 403 ||
    /unauthorized|unauthenticated|forbidden|not authenticated|access denied|permission/i.test(body)
  );
}

const T06: TestDef = {
  id: "T06",
  area: "auth",
  title: "Protected operations accessible without authentication",
  mode: "auto",
  async run(ctx) {
    const hadAuth = getHeader(ctx.base, "authorization") || getHeader(ctx.base, "cookie");
    const stripped = removeHeader(removeHeader(ctx.base, "authorization"), "cookie");
    const res = await probe(stripped);

    if (!hadAuth) {
      return result(this, "info", [
        infoFinding(
          this,
          "Base request carries no authorization header/cookie, so an unauthenticated baseline can't be compared. Provide an authenticated request to test this properly."
        ),
      ]);
    }

    if (responseHasData(res) && !responseLooksAuthError(res)) {
      const v = vuln("noAuth");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description:
            "The operation returned data when the authorization header/cookie was removed, indicating the endpoint does not require authentication for this operation.",
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          affectedOperation: ctx.base.operationName,
          evidence: evidenceFrom(stripped, res, "Data returned without credentials."),
        }),
      ]);
    }
    return pass(this, "Operation rejected or returned no data without authentication.");
  },
};

const T07: TestDef = {
  id: "T07",
  area: "auth",
  title: "Authentication bypass via alternate operations",
  mode: "assisted",
  run: async () =>
    manual(
      { id: "T07", area: "auth", title: "Authentication bypass via alternate operations", mode: "assisted" } as TestDef,
      "Try reaching protected data through alternate operations, aliases, or public queries/mutations that wrap the same resolvers. Supply those operations and compare authenticated vs anonymous responses.",
      "Ensure every path to sensitive data enforces the same authentication checks.",
      ["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"]
    ),
};

const T08: TestDef = {
  id: "T08",
  area: "auth",
  title: "Expired / malformed / tampered tokens accepted",
  mode: "auto",
  async run(ctx) {
    const authKey = getHeader(ctx.base, "authorization");
    if (!authKey) {
      return result(this, "info", [infoFinding(this, "No authorization header present to tamper with.")]);
    }
    // Tamper: flip the signature/last chars.
    const tampered = authKey.slice(0, -3) + (authKey.endsWith("AAA") ? "BBB" : "AAA");
    const req = setHeader(ctx.base, "authorization", tampered);
    const res = await probe(req);

    if (responseHasData(res) && !responseLooksAuthError(res)) {
      const v = vuln("tokenHandling");
      return result(this, "fail", [
        finding(this, {
          title: v.title,
          severity: v.severity,
          status: "fail",
          description:
            "A tampered authorization token was accepted (data returned, no auth error), indicating the signature/validity of the token is not properly verified.",
          remediation: v.remediation,
          references: v.references,
          cwe: v.cwe,
          cvss: v.cvss,
          evidence: evidenceFrom(req, res, "Data returned with a tampered token."),
        }),
      ]);
    }
    return pass(this, "Tampered token was rejected.");
  },
};

const T09: TestDef = {
  id: "T09",
  area: "auth",
  title: "Brute-force / credential-stuffing protection",
  mode: "assisted",
  async run(ctx) {
    if (!ctx.options.enableBruteForce) {
      return manual(
        this,
        "Enable the bounded brute-force probe (sends a small burst of repeated auth operations) to check for rate limiting, or test manually. Not run by default to avoid locking accounts.",
        "Enforce rate limiting, lockouts and anomaly detection on authentication operations.",
        []
      );
    }
    const burst = 8;
    let limited = false;
    let lastRes: any;
    for (let i = 0; i < burst; i++) {
      lastRes = await probe(ctx.base, { timeoutMs: 5000 });
      if (lastRes.status === 429 || /rate limit|too many/i.test(lastRes.bodyText)) {
        limited = true;
        break;
      }
    }
    if (limited) return pass(this, `Rate limiting observed within ${burst} rapid requests.`);
    const v = vuln("batching");
    return result(this, "warn", [
      finding(this, {
        title: "No rate limiting observed on repeated auth operations",
        severity: "medium",
        status: "warn",
        description: `Sent ${burst} rapid identical operations with no 429 / rate-limit response. Credential-stuffing and brute-force may be possible. Verify lockout thresholds manually.`,
        remediation: "Add rate limiting, exponential backoff and lockouts to authentication flows.",
        references: v.references,
        cwe: ["CWE-307"],
      }),
    ]);
  },
};

const T10: TestDef = {
  id: "T10",
  area: "auth",
  title: "Token scope enforcement",
  mode: "assisted",
  run: async () =>
    manual(
      { id: "T10", area: "auth", title: "Token scope enforcement", mode: "assisted" } as TestDef,
      "Using a token scoped to limited permissions, attempt operations outside that scope and record whether they succeed. Supply the scoped token to automate the comparison.",
      "Enforce token scopes/claims server-side so a token cannot access operations outside its granted permissions.",
      []
    ),
};

export const authTests: TestDef[] = [T06, T07, T08, T09, T10];
