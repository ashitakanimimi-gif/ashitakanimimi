import type {
  Finding,
  FindingStatus,
  GraphQLRequest,
  HostGeo,
  TestMode,
  TestResult,
} from "@shared/types.js";
import type { GraphQLSchema } from "graphql";
import { makeFinding, type FindingInput } from "../../lib/findings.js";
import { sendRequest, type SentResponse } from "../../lib/graphqlClient.js";
import { snippet } from "../../lib/findings.js";

export interface ScanOptions {
  /** Authorization header value for a second, lower-privileged identity (authz tests). */
  secondAuthHeader?: string;
  /** Variable name holding an object reference to swap (IDOR). */
  objectIdField?: string;
  /** Alternate object reference value belonging to another user (IDOR). */
  objectIdValue?: string;
  /** User-supplied out-of-band callback host (SSRF). */
  callbackHost?: string;
  /** Explicit opt-in for the higher-impact probes. */
  enableBruteForce?: boolean;
  enableInjection?: boolean;
  enableWordlist?: boolean;
}

export interface ScanState {
  fingerprint?: string;
  schema?: GraphQLSchema;
  introspectionEnabled?: boolean;
  /** A field name on the Query type we can safely probe. */
  sampleQueryField?: string;
  /** A field name reachable for deep nesting (self-referential type), if found. */
  cyclicField?: string;
  discoveredEndpoints: string[];
}

export interface TestContext {
  base: GraphQLRequest;
  options: ScanOptions;
  state: ScanState;
  emitHost: (h: HostGeo) => void;
}

export interface TestDef {
  id: string;
  area: string;
  title: string;
  mode: TestMode;
  run: (ctx: TestContext) => Promise<TestResult>;
}

/** Build the evidence block from a sent request + response. */
export function evidenceFrom(req: GraphQLRequest, res: SentResponse, note?: string): Finding["evidence"] {
  return {
    note,
    request: {
      method: req.method,
      url: req.url,
      headers: safeHeaders(req.headers),
      body: snippet(JSON.stringify({ operationName: req.operationName, variables: req.variables, query: req.query })),
    },
    response: {
      status: res.status,
      headers: safeHeaders(res.headers),
      bodySnippet: snippet(res.bodyText),
    },
  };
}

/** Redact obviously secret header values for storage/evidence. */
function safeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (/authorization|cookie|api[-_]?key|token/i.test(k) && v) {
      out[k] = v.length > 12 ? v.slice(0, 6) + "…redacted" : "…redacted";
    } else {
      out[k] = v;
    }
  }
  return out;
}

export async function probe(
  req: GraphQLRequest,
  opts?: { timeoutMs?: number }
): Promise<SentResponse> {
  return sendRequest(req, { timeoutMs: opts?.timeoutMs });
}

export function result(def: TestDef, status: FindingStatus, findings: Finding[], extra?: Partial<TestResult>): TestResult {
  return {
    testId: def.id,
    controlArea: def.area,
    title: def.title,
    mode: def.mode,
    status,
    findings,
    ...extra,
  };
}

/** A clean pass result with no findings. */
export function pass(def: TestDef, note?: string): TestResult {
  return result(def, "pass", note ? [infoFinding(def, note, "pass")] : []);
}

export function infoFinding(def: TestDef, description: string, status: FindingStatus = "info"): Finding {
  return makeFinding({
    testId: def.id,
    controlArea: def.area,
    title: def.title,
    severity: "info",
    status,
    description,
    remediation: "No action required.",
  });
}

/** Build a finding from a FindingInput, inheriting the test's identity. */
export function finding(def: TestDef, input: Omit<FindingInput, "testId" | "controlArea"> & { controlArea?: string }): Finding {
  return makeFinding({ ...input, testId: def.id, controlArea: input.controlArea ?? def.area });
}

/** A manual/guided result: scripted guidance + evidence-capture prompt. */
export function manual(def: TestDef, guidance: string, remediation: string, refs: string[] = []): TestResult {
  const f = makeFinding({
    testId: def.id,
    controlArea: def.area,
    title: def.title,
    severity: "info",
    status: "manual",
    description: guidance,
    remediation,
    references: refs,
  });
  return result(def, "manual", [f], { needsInput: true });
}

/** Detect common SQL-error / stack-trace signatures in a response body. */
export function hasSqlErrorSignature(body: string): boolean {
  return /(sql syntax|sqlstate|pg::|psql|mysql|mariadb|sqlite|ora-\d|odbc|syntax error at or near|unterminated quoted string)/i.test(
    body
  );
}

export function hasStackTraceSignature(body: string): boolean {
  return /(at [\w$.]+\([^)]*:\d+:\d+\)|traceback \(most recent call last\)|\.java:\d+\)|goroutine \d+|stacktrace|at Object\.<anonymous>)/i.test(
    body
  );
}
