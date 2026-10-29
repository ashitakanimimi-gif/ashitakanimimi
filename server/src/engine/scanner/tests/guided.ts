import { probe, finding, pass, result, manual, evidenceFrom, type TestDef } from "../testKit.js";
import { setVariables as setVars } from "../../request/requestModel.js";
import { vuln } from "../../advisor/knowledgeBase.js";

function guided(id: string, area: string, title: string, guidance: string, remediation: string, refs: string[] = []): TestDef {
  return {
    id,
    area,
    title,
    mode: "guided",
    run: async () => manual({ id, area, title, mode: "guided" } as TestDef, guidance, remediation, refs),
  };
}

// ---- SSRF (assisted; runs a real probe when a callback host is supplied) ----

const T50: TestDef = {
  id: "T50",
  area: "ssrf",
  title: "URL/host args reach localhost / private / metadata",
  mode: "assisted",
  async run(ctx) {
    const cb = ctx.options.callbackHost;
    const vars = ctx.base.variables ?? {};
    const urlKey = Object.keys(vars).find(
      (k) => typeof vars[k] === "string" && /url|uri|host|endpoint|callback|webhook|src|image|avatar/i.test(k)
    );
    if (!cb || !urlKey) {
      return manual(
        { id: "T50", area: "ssrf", title: "URL/host args reach localhost / private / metadata", mode: "assisted" } as TestDef,
        "Provide an out-of-band callback host you control, and ensure the operation has a URL/host variable. The tool will set that variable to your callback and to metadata/localhost targets; watch your listener for a hit.",
        vuln("ssrf").remediation,
        vuln("ssrf").references
      );
    }
    const targets = [`http://${cb}/ssrf-probe`, "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/"];
    const findings = [] as any[];
    for (const t of targets) {
      const req = setVars(ctx.base, { ...vars, [urlKey]: t });
      const res = await probe(req, { timeoutMs: 8000 });
      // We cannot see the OOB hit here; report the attempt + any telltale response.
      if (/instance-id|ami-id|iam\/security|metadata|ec2|computeMetadata/i.test(res.bodyText)) {
        const v = vuln("ssrf");
        findings.push(
          finding(this, {
            title: "SSRF to cloud metadata endpoint",
            severity: v.severity,
            status: "fail",
            description: `Setting '${urlKey}' to ${t} returned cloud-metadata-like content, indicating SSRF.`,
            remediation: v.remediation,
            references: v.references,
            cwe: v.cwe,
            cvss: v.cvss,
            evidence: evidenceFrom(req, res, "Metadata-like content in response."),
          })
        );
      }
    }
    if (findings.length > 0) return result(this, "fail", findings);
    return result(this, "manual", [
      finding(this, {
        title: "SSRF probe sent — check your callback listener",
        severity: "info",
        status: "manual",
        description: `Sent requests setting '${urlKey}' to your callback (${cb}), the AWS metadata IP, and localhost. If your listener received a hit, the endpoint is vulnerable to SSRF.`,
        remediation: vuln("ssrf").remediation,
        references: vuln("ssrf").references,
      }),
    ], { needsInput: true });
  },
};

const T51 = guided(
  "T51",
  "ssrf",
  "SSRF filter bypass (redirects / encoding / DNS)",
  "If a URL allowlist exists, attempt bypasses: open redirects, alternate IP formats (decimal/octal/IPv6), URL encoding, and DNS rebinding to your callback host. Record any that reach internal targets.",
  vuln("ssrf").remediation,
  vuln("ssrf").references
);

// ---- Subscriptions ----
const T40 = guided("T40", "subscription", "Unauthenticated subscription to protected events", "Open a WebSocket subscription to a protected event without credentials and record whether events are delivered.", "Authenticate subscription connections and authorize each subscribed event.");
const T41 = guided("T41", "subscription", "Cross-tenant event subscription", "Subscribe to another tenant's/user's events and record whether you receive them.", "Authorize subscription payloads per user/tenant on every emitted event.");
const T42 = guided("T42", "subscription", "Permission revocation mid-subscription", "After subscribing, revoke/downgrade permissions and verify event delivery stops.", "Re-check authorization on each emitted event, not only at subscribe time.");
const T43 = guided("T43", "subscription", "Connection / message flooding limits", "Open many subscription connections / request many messages and verify connection and message limits apply.", "Enforce connection and message rate/count limits on subscriptions.");

// ---- Business logic ----
const T44 = guided("T44", "logic", "Workflow step skip / reorder", "Skip or reorder required workflow steps (e.g. jump to a checkout/confirm mutation) and verify the business process is enforced server-side.", "Enforce required workflow ordering and state transitions server-side.");
const T45 = guided("T45", "logic", "Price / quantity / limit parameter tampering", "Tamper with prices, quantities, limits, and transaction values in variables and verify business rules are enforced server-side.", "Validate all business parameters server-side; never trust client values.");
const T46 = guided("T46", "logic", "Business limit bypass via multiple accounts/sessions", "Attempt to bypass per-user limits using multiple accounts, sessions, tokens, or concurrent requests.", "Enforce limits across accounts/sessions; detect and block concurrency abuse.");
const T47 = guided("T47", "logic", "Stale / replayed workflow state reuse", "Reuse stale/expired/previously-valid workflow state for sensitive operations and verify it is rejected.", "Invalidate completed/expired state; bind state to a single use.");

// ---- File upload ----
const T48 = guided("T48", "upload", "File type / size enforcement & code execution", "Upload disallowed types/sizes and files that could execute as application code; verify they are rejected and never executed.", "Allowlist types/sizes; store uploads outside the web root; never execute uploaded content.");
const T49 = guided("T49", "upload", "Cross-user uploaded file access", "Access another user's uploaded files via modified references and verify authorization is enforced.", "Authorize access to every uploaded file by owner/tenant.");

// ---- External API deps ----
const T56 = guided("T56", "extapi", "External data validated before use", "Review data received from external APIs used by resolvers and verify it is validated before processing/storage.", "Validate and sanitize all external API data before use.");
const T57 = guided("T57", "extapi", "Malformed / excessive upstream responses handled", "Simulate malformed/excessive responses from upstream APIs and verify they cannot cause injection, exposure, or resource exhaustion.", "Bound and validate upstream responses; apply timeouts and size limits.");

// ---- Logging / monitoring / audit ----
const T58 = guided("T58", "logging", "Security events are logged", "Trigger auth failures, authz failures, and sensitive mutations; verify security events are logged (requires server-side access).", "Log authentication/authorization failures and sensitive operations.");
const T59 = guided("T59", "logging", "Secrets not written to logs", "Review logs and verify passwords, tokens, API keys, and secrets are not logged.", "Redact secrets and sensitive query data from logs.");
const T60 = guided("T60", "logging", "Abnormal activity detection / monitoring", "Generate excessive queries and failed authz attempts; verify abnormal activity is detected and alerted.", "Monitor and alert on abnormal GraphQL activity.");
const T61 = guided("T61", "logging", "Audit traceability for sensitive mutations", "Verify sensitive/privileged operations can be traced to a responsible user and time in audit records.", "Record actor, action, and timestamp for sensitive mutations.");

export const ssrfTests: TestDef[] = [T50, T51];
export const subscriptionTests: TestDef[] = [T40, T41, T42, T43];
export const logicTests: TestDef[] = [T44, T45, T46, T47];
export const uploadTests: TestDef[] = [T48, T49];
export const extApiTests: TestDef[] = [T56, T57];
export const loggingTests: TestDef[] = [T58, T59, T60, T61];
