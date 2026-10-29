import type {
  GraphQLRequest,
  ScanEvent,
  SchemaReport,
  ScanResult,
  Recommendation,
} from "@shared/types.js";

async function jpost<T>(url: string, body: unknown): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json?.error ?? `Request failed (${res.status})`);
  return json as T;
}

export async function parseRaw(raw: string): Promise<{ request: GraphQLRequest; metrics: any }> {
  return jpost("/api/repeater/parse", { raw });
}

export async function sendRepeater(request: GraphQLRequest): Promise<{ response: any; metrics: any }> {
  return jpost("/api/repeater/send", { request });
}

export async function analyze(input: { schema?: string; jsSource?: string }): Promise<SchemaReport> {
  return jpost("/api/analyze", input);
}

export async function advisor(scan: ScanResult): Promise<{ scan: ScanResult; recommendations: Recommendation[] }> {
  return jpost("/api/advisor", { scan });
}

export async function getProxyConfig(): Promise<{ upstream: string | null; recent: any[] }> {
  const res = await fetch("/api/proxy/config");
  return res.json();
}

export async function setProxyConfig(upstream: string | null): Promise<{ upstream: string | null }> {
  return jpost("/api/proxy/config", { upstream });
}

export async function getCatalog(): Promise<{ controlAreas: any[] }> {
  const res = await fetch("/api/catalog");
  return res.json();
}

/** Start a scan and stream ScanEvents via the SSE-over-POST response. */
export async function startScan(
  body: { base: GraphQLRequest; acknowledged: boolean; selectedTestIds?: string[]; options?: any },
  onEvent: (e: ScanEvent) => void,
  signal?: AbortSignal
): Promise<void> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok || !res.body) {
    const txt = await res.text().catch(() => "");
    throw new Error(`Scan failed to start (${res.status}). ${txt}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const parts = buffer.split("\n\n");
    buffer = parts.pop() ?? "";
    for (const part of parts) {
      const line = part.split("\n").find((l) => l.startsWith("data:"));
      if (!line) continue;
      try {
        onEvent(JSON.parse(line.slice(5).trim()) as ScanEvent);
      } catch {
        /* ignore partial */
      }
    }
  }
}
