import type { ProxyEvent } from "@shared/types.js";
import { analyzeQuery, batchSize } from "../../lib/complexity.js";

const DEPTH_THRESHOLD = 10;
const COMPLEXITY_THRESHOLD = 60;
const ALIAS_THRESHOLD = 15;
const BATCH_THRESHOLD = 5;

type Subscriber = (e: ProxyEvent) => void;

class ProxyBus {
  private subscribers = new Set<Subscriber>();
  private _upstream: string | undefined;
  private history: ProxyEvent[] = [];

  get upstream(): string | undefined {
    return this._upstream;
  }
  setUpstream(url: string | undefined): void {
    this._upstream = url;
  }

  subscribe(fn: Subscriber): () => void {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  recent(): ProxyEvent[] {
    return this.history.slice(-100);
  }

  publish(e: ProxyEvent): void {
    this.history.push(e);
    if (this.history.length > 500) this.history.shift();
    for (const s of this.subscribers) {
      try {
        s(e);
      } catch {
        /* ignore */
      }
    }
  }
}

export const proxyBus = new ProxyBus();

let counter = 0;

export function evaluateRequest(rawBody: string, method: string): ProxyEvent {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    parsed = undefined;
  }

  const bsize = batchSize(parsed);
  const first = Array.isArray(parsed) ? parsed[0] : parsed;
  const query = (first as any)?.query ?? "";
  const operationName = (first as any)?.operationName;
  const m = analyzeQuery(typeof query === "string" ? query : "");

  const flags: string[] = [];
  if (m.depth > DEPTH_THRESHOLD) flags.push(`deep (${m.depth})`);
  if (m.complexity > COMPLEXITY_THRESHOLD) flags.push(`complex (${m.complexity})`);
  if (m.aliasCount > ALIAS_THRESHOLD) flags.push(`aliases (${m.aliasCount})`);
  if (bsize > BATCH_THRESHOLD) flags.push(`batch (${bsize})`);
  if (!m.valid && query) flags.push("invalid query");

  counter += 1;
  return {
    id: `pe-${Date.now().toString(36)}-${counter}`,
    at: new Date().toISOString(),
    method,
    operationName,
    operationType: m.operationType,
    depth: m.depth,
    fieldCount: m.fieldCount,
    aliasCount: m.aliasCount,
    batchSize: bsize,
    complexity: m.complexity,
    flagged: flags.length > 0,
    flags,
  };
}
