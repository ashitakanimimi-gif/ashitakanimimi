// Extract embedded GraphQL operations from a pasted JS bundle / source text.

const OP_REGEX =
  /\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)?\s*(\([^)]*\))?\s*\{/g;

const GQL_TAG_REGEX = /(?:gql|graphql)\s*`([\s\S]*?)`/g;

/** Find the end of a balanced `{...}` block starting at the position of the first `{`. */
function sliceBalanced(src: string, braceStart: number): string | undefined {
  let depth = 0;
  for (let i = braceStart; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return src.slice(braceStart, i + 1);
    }
  }
  return undefined;
}

export function extractOperations(source: string): string[] {
  const found = new Set<string>();

  // 1) gql`...` / graphql`...` tagged templates.
  let m: RegExpExecArray | null;
  while ((m = GQL_TAG_REGEX.exec(source))) {
    const body = m[1].trim();
    if (body) found.add(body);
  }

  // 2) Bare query/mutation/subscription operations.
  OP_REGEX.lastIndex = 0;
  while ((m = OP_REGEX.exec(source))) {
    const braceIdx = source.indexOf("{", m.index);
    if (braceIdx === -1) continue;
    const block = sliceBalanced(source, braceIdx);
    if (!block) continue;
    const header = source.slice(m.index, braceIdx).trim();
    const op = `${header} ${block}`;
    // Avoid trivially tiny matches.
    if (op.length > 12) found.add(op);
  }

  return Array.from(found).slice(0, 200);
}
