import type {
  Finding,
  GraphQLRequest,
  HostGeo,
  ScanEvent,
  ScanResult,
  ScanSummary,
  Severity,
  TestResult,
} from "@shared/types.js";
import { AREA_NAME } from "@shared/controlAreas.js";
import { TEST_DEF_BY_ID, ALL_TEST_DEFS } from "./tests/index.js";
import type { ScanOptions, ScanState, TestContext } from "./testKit.js";
import { sendRequest, looksLikeGraphQL } from "../../lib/graphqlClient.js";
import { withOperation } from "../request/requestModel.js";
import { FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION, TYPENAME_QUERY, tryBuildSchema } from "../../lib/introspection.js";
import { isObjectType } from "graphql";

export interface RunScanInput {
  base: GraphQLRequest;
  acknowledged: boolean;
  selectedTestIds?: string[];
  options?: ScanOptions;
  onEvent?: (e: ScanEvent) => void;
}

const SEVERITY_PENALTY: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };

function emptySummary(total: number): ScanSummary {
  return {
    totalTests: total,
    passed: 0,
    failed: 0,
    warned: 0,
    manual: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byControlArea: {},
    securityScore: 100,
    endpointsDiscovered: 0,
  };
}

function updateSummary(summary: ScanSummary, r: TestResult): void {
  if (r.status === "pass") summary.passed++;
  else if (r.status === "fail") summary.failed++;
  else if (r.status === "warn") summary.warned++;
  else if (r.status === "manual") summary.manual++;

  const area = r.controlArea;
  summary.byControlArea[area] ??= { passed: 0, failed: 0, total: 0 };
  summary.byControlArea[area].total++;
  if (r.status === "pass") summary.byControlArea[area].passed++;
  if (r.status === "fail" || r.status === "warn") summary.byControlArea[area].failed++;

  for (const f of r.findings) {
    if (f.status === "fail" || f.status === "warn") summary.bySeverity[f.severity]++;
  }

  // Recompute score from accumulated severity counts (warn = half weight).
  let penalty = 0;
  for (const sev of Object.keys(summary.bySeverity) as Severity[]) {
    penalty += summary.bySeverity[sev] * SEVERITY_PENALTY[sev];
  }
  summary.securityScore = Math.max(0, Math.min(100, Math.round(100 - penalty)));
}

function hostFrom(req: GraphQLRequest): HostGeo | undefined {
  try {
    const u = new URL(req.url);
    const host = u.hostname;
    const isPrivate =
      /^(localhost|127\.|10\.|192\.168\.|169\.254\.|::1|0\.0\.0\.0)/i.test(host) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
      host.endsWith(".local");
    return { host, isPrivate, source: "target" };
  } catch {
    return undefined;
  }
}

/** Fingerprint the engine (graphw00f-lite) from error/behaviour signatures. */
async function fingerprint(base: GraphQLRequest): Promise<string | undefined> {
  const res = await sendRequest(withOperation(base, TYPENAME_QUERY), { timeoutMs: 8000 });
  const body = res.bodyText + JSON.stringify(res.headers);
  const sigs: { re: RegExp; name: string }[] = [
    { re: /apollo|apollographql/i, name: "Apollo Server" },
    { re: /graphql-yoga|yoga/i, name: "GraphQL Yoga" },
    { re: /hasura/i, name: "Hasura" },
    { re: /graphene|django/i, name: "Graphene (Python)" },
    { re: /graphql-ruby/i, name: "graphql-ruby" },
    { re: /HotChocolate|dotnet/i, name: "Hot Chocolate (.NET)" },
    { re: /sangria/i, name: "Sangria (Scala)" },
    { re: /graphql-go|gqlgen/i, name: "gqlgen (Go)" },
  ];
  for (const s of sigs) if (s.re.test(body)) return s.name;
  if (looksLikeGraphQL(res)) return "Generic GraphQL";
  return undefined;
}

/** Populate shared state (schema, sample field, cyclic field) so all tests benefit. */
async function prepareState(base: GraphQLRequest, state: ScanState): Promise<void> {
  for (const q of [FULL_INTROSPECTION_QUERY, MINIMAL_INTROSPECTION]) {
    const res = await sendRequest(withOperation(base, q, q === FULL_INTROSPECTION_QUERY ? "IntrospectionQuery" : undefined));
    const data = (res.json as any)?.data;
    if (data?.__schema) {
      state.introspectionEnabled = true;
      const schema = tryBuildSchema(res.json);
      if (schema) {
        state.schema = schema;
        const qt = schema.getQueryType();
        if (qt) {
          const fields = Object.values(qt.getFields());
          const noArg = fields.find((f) => f.args.length === 0);
          state.sampleQueryField = (noArg ?? fields[0])?.name;
          for (const f of fields) {
            let named: any = f.type;
            while (named?.ofType) named = named.ofType;
            if (named && isObjectType(named)) {
              const sub = Object.values(named.getFields()).find((sf) => {
                let t: any = sf.type;
                while (t?.ofType) t = t.ofType;
                return t?.name === named.name;
              });
              if (sub) {
                state.cyclicField = f.name;
                break;
              }
            }
          }
        }
      }
      return;
    }
  }
}

export async function runScan(input: RunScanInput): Promise<ScanResult> {
  const { base, acknowledged, onEvent } = input;
  if (!acknowledged) {
    throw new Error("Authorization not acknowledged. Confirm you are authorized to test this endpoint.");
  }

  const options: ScanOptions = input.options ?? {};
  const selected = input.selectedTestIds?.length
    ? ALL_TEST_DEFS.filter((t) => input.selectedTestIds!.includes(t.id))
    : ALL_TEST_DEFS;

  const scanId = `scan-${Date.now().toString(36)}`;
  const startedAt = new Date().toISOString();
  const summary = emptySummary(selected.length);
  const results: TestResult[] = [];
  const findings: Finding[] = [];
  const hosts: HostGeo[] = [];

  const emit = (e: ScanEvent) => onEvent?.(e);
  emit({ type: "start", scanId, total: selected.length, target: base.url });

  const targetHost = hostFrom(base);
  if (targetHost) {
    hosts.push(targetHost);
    emit({ type: "host", host: targetHost });
  }

  const state: ScanState = { discoveredEndpoints: [] };
  const fp = await fingerprint(base);
  state.fingerprint = fp;
  await prepareState(base, state);

  const ctx: TestContext = {
    base,
    options,
    state,
    emitHost: (h) => {
      hosts.push(h);
      emit({ type: "host", host: h });
    },
  };

  for (const def of selected) {
    emit({ type: "test-start", testId: def.id, title: def.title, controlArea: def.area });
    const started = performance.now();
    let r: TestResult;
    try {
      r = await def.run(ctx);
    } catch (err) {
      r = {
        testId: def.id,
        controlArea: def.area,
        title: def.title,
        mode: def.mode,
        status: "info",
        findings: [],
        needsInput: false,
      };
      r.findings.push({
        id: `err-${def.id}`,
        testId: def.id,
        controlArea: def.area,
        title: `${def.title} (error)`,
        severity: "info",
        status: "info",
        description: `Test could not complete: ${err instanceof Error ? err.message : String(err)}`,
        remediation: "Retry; the target may be unreachable or returned an unexpected response.",
        references: [],
      });
    }
    r.durationMs = Math.round(performance.now() - started);
    results.push(r);
    findings.push(...r.findings.filter((f) => f.status === "fail" || f.status === "warn" || f.status === "manual"));
    updateSummary(summary, r);
    summary.endpointsDiscovered = state.discoveredEndpoints.length;
    emit({ type: "test-result", result: r, summary: { ...summary, byControlArea: { ...summary.byControlArea } } });
  }

  const scan: ScanResult = {
    id: scanId,
    target: base.url,
    startedAt,
    finishedAt: new Date().toISOString(),
    fingerprint: fp,
    results,
    findings,
    hosts,
    summary,
  };
  emit({ type: "done", scan });
  return scan;
}

export { AREA_NAME, TEST_DEF_BY_ID };
