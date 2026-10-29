// AST-based query metrics: depth, field count, alias count, operation type, complexity.
import { parse, type DocumentNode, type SelectionSetNode, Kind } from "graphql";

export interface QueryMetrics {
  valid: boolean;
  operationType: string; // query | mutation | subscription | unknown
  operationName?: string;
  depth: number;
  fieldCount: number;
  aliasCount: number;
  /** Heuristic cost score. */
  complexity: number;
  error?: string;
}

export function analyzeQuery(query: string): QueryMetrics {
  let doc: DocumentNode;
  try {
    doc = parse(query);
  } catch (err) {
    return {
      valid: false,
      operationType: "unknown",
      depth: 0,
      fieldCount: 0,
      aliasCount: 0,
      complexity: 0,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  let depth = 0;
  let fieldCount = 0;
  let aliasCount = 0;
  let operationType = "unknown";
  let operationName: string | undefined;

  const walk = (sel: SelectionSetNode | undefined, d: number): void => {
    if (!sel) return;
    if (d > depth) depth = d;
    for (const node of sel.selections) {
      if (node.kind === Kind.FIELD) {
        fieldCount++;
        if (node.alias) aliasCount++;
        walk(node.selectionSet, d + 1);
      } else if (node.kind === Kind.INLINE_FRAGMENT) {
        walk(node.selectionSet, d);
      }
      // Fragment spreads are counted shallowly (definitions walked below).
    }
  };

  for (const def of doc.definitions) {
    if (def.kind === Kind.OPERATION_DEFINITION) {
      operationType = def.operation;
      operationName = def.name?.value ?? operationName;
      walk(def.selectionSet, 1);
    } else if (def.kind === Kind.FRAGMENT_DEFINITION) {
      walk(def.selectionSet, 1);
    }
  }

  const complexity = fieldCount + depth * 3 + aliasCount * 2;

  return {
    valid: true,
    operationType,
    operationName,
    depth,
    fieldCount,
    aliasCount,
    complexity,
  };
}

/** Detect array-batched GraphQL request bodies (list of operations). */
export function batchSize(body: unknown): number {
  return Array.isArray(body) ? body.length : 1;
}

/** Build a deeply nested query using a repeated field for DoS depth testing. */
export function buildDeepQuery(field: string, depth: number): string {
  let inner = "__typename";
  for (let i = 0; i < depth; i++) {
    inner = `${field} { ${inner} }`;
  }
  return `query Deep { ${inner} }`;
}

/** Build an aliased query repeating a field N times (rate-limit / cost test). */
export function buildAliasQuery(field: string, count: number): string {
  const aliases = Array.from({ length: count }, (_, i) => `a${i}: ${field}`).join("\n  ");
  return `query Aliased {\n  ${aliases}\n}`;
}
