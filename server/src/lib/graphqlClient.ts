import type { GraphQLRequest } from "@shared/types.js";

export interface SentResponse {
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  bodyText: string;
  json?: unknown;
  durationMs: number;
  error?: string;
}

const DEFAULT_TIMEOUT_MS = 12000;
const MAX_BODY_CHARS = 200_000;

function buildBody(req: GraphQLRequest): { body?: string; url: string; headers: Record<string, string> } {
  const headers: Record<string, string> = { ...req.headers };

  if (req.method === "GET") {
    const u = new URL(req.url);
    u.searchParams.set("query", req.query);
    if (req.operationName) u.searchParams.set("operationName", req.operationName);
    if (req.variables) u.searchParams.set("variables", JSON.stringify(req.variables));
    // GET carries no JSON body; drop content-type.
    delete headers["content-type"];
    delete headers["Content-Type"];
    return { url: u.toString(), headers };
  }

  const ct = Object.keys(headers).find((h) => h.toLowerCase() === "content-type");
  const ctVal = ct ? headers[ct] : undefined;

  if (ctVal && ctVal.includes("x-www-form-urlencoded")) {
    const params = new URLSearchParams();
    params.set("query", req.query);
    if (req.operationName) params.set("operationName", req.operationName);
    if (req.variables) params.set("variables", JSON.stringify(req.variables));
    return { url: req.url, headers, body: params.toString() };
  }

  // Default: JSON body.
  if (!ct) headers["content-type"] = "application/json";
  const payload: Record<string, unknown> = { query: req.query };
  if (req.operationName) payload.operationName = req.operationName;
  if (req.variables) payload.variables = req.variables;
  return { url: req.url, headers, body: JSON.stringify(payload) };
}

export async function sendRequest(
  req: GraphQLRequest,
  opts: { timeoutMs?: number; extraHeaders?: Record<string, string> } = {}
): Promise<SentResponse> {
  const started = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  const built = buildBody(req);
  const headers = { ...built.headers, ...(opts.extraHeaders ?? {}) };
  // Hop-by-hop / host headers that fetch must set itself.
  for (const h of ["host", "Host", "content-length", "Content-Length", "connection", "Connection"]) {
    delete headers[h];
  }

  try {
    const res = await fetch(built.url, {
      method: req.method,
      headers,
      body: built.body,
      signal: controller.signal,
      redirect: "manual",
    });
    const raw = await res.text();
    const bodyText = raw.length > MAX_BODY_CHARS ? raw.slice(0, MAX_BODY_CHARS) : raw;
    const respHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => (respHeaders[k] = v));
    let json: unknown;
    try {
      json = JSON.parse(bodyText);
    } catch {
      /* not JSON */
    }
    return {
      ok: res.ok,
      status: res.status,
      headers: respHeaders,
      bodyText,
      json,
      durationMs: Math.round(performance.now() - started),
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      headers: {},
      bodyText: "",
      durationMs: Math.round(performance.now() - started),
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timeout);
  }
}

/** True when the response body looks like a GraphQL response (has data or errors). */
export function looksLikeGraphQL(res: SentResponse): boolean {
  if (res.json && typeof res.json === "object") {
    const obj = res.json as Record<string, unknown>;
    return "data" in obj || "errors" in obj;
  }
  return false;
}
