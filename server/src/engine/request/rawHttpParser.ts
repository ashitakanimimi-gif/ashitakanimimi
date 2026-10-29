import type { GraphQLRequest, HttpMethod } from "@shared/types.js";

export interface ParseResult {
  ok: boolean;
  request?: GraphQLRequest;
  error?: string;
}

/**
 * Parse a pasted raw HTTP request (Burp "copy as raw" style) into a GraphQLRequest.
 *
 * Example input:
 *   POST http://host:port/graphql HTTP/1.1
 *   Host: host:port
 *   content-type: application/json
 *
 *   {"operationName":"X","variables":{...},"query":"mutation X ..."}
 */
export function parseRawHttp(raw: string): ParseResult {
  if (!raw || !raw.trim()) return { ok: false, error: "Empty request." };

  const normalized = raw.replace(/\r\n/g, "\n");
  const headerEnd = normalized.indexOf("\n\n");
  const headPart = headerEnd === -1 ? normalized : normalized.slice(0, headerEnd);
  const bodyPart = headerEnd === -1 ? "" : normalized.slice(headerEnd + 2);

  const lines = headPart.split("\n").filter((l) => l.length > 0);
  if (lines.length === 0) return { ok: false, error: "No request line found." };

  // Request line: METHOD PATH-or-URL HTTP/x.y
  const requestLine = lines[0].trim();
  const parts = requestLine.split(/\s+/);
  if (parts.length < 2) return { ok: false, error: `Malformed request line: "${requestLine}"` };

  const method = parts[0].toUpperCase();
  if (method !== "POST" && method !== "GET") {
    return { ok: false, error: `Unsupported method "${method}" (use POST or GET).` };
  }
  let target = parts[1];

  // Collect headers (case-insensitive keys, preserve original casing of the first seen).
  const headers: Record<string, string> = {};
  let hostHeader: string | undefined;
  let scheme = "http";
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(":");
    if (idx === -1) continue;
    const key = lines[i].slice(0, idx).trim();
    const value = lines[i].slice(idx + 1).trim();
    headers[key] = value;
    const lk = key.toLowerCase();
    if (lk === "host") hostHeader = value;
    if (lk === "x-forwarded-proto") scheme = value;
    if (lk === "origin" && value.startsWith("https")) scheme = "https";
  }

  // Build an absolute URL.
  let url: string;
  if (/^https?:\/\//i.test(target)) {
    url = target;
  } else {
    if (!hostHeader) return { ok: false, error: "Relative path given but no Host header present." };
    if (!target.startsWith("/")) target = "/" + target;
    url = `${scheme}://${hostHeader}${target}`;
  }

  // Parse body as GraphQL.
  let query = "";
  let variables: Record<string, unknown> | undefined;
  let operationName: string | undefined;

  const trimmedBody = bodyPart.trim();
  if (trimmedBody) {
    try {
      const parsed = JSON.parse(trimmedBody);
      const obj = Array.isArray(parsed) ? parsed[0] : parsed;
      query = typeof obj?.query === "string" ? obj.query : "";
      variables = obj?.variables;
      operationName = obj?.operationName;
    } catch {
      // Maybe form-encoded: query=...&variables=...
      try {
        const params = new URLSearchParams(trimmedBody);
        query = params.get("query") ?? "";
        const v = params.get("variables");
        variables = v ? JSON.parse(v) : undefined;
        operationName = params.get("operationName") ?? undefined;
      } catch {
        return { ok: false, error: "Could not parse request body as JSON or form-encoded GraphQL." };
      }
    }
  }

  if (method === "GET" && !query) {
    // Query may be in the URL querystring.
    try {
      const u = new URL(url);
      query = u.searchParams.get("query") ?? "";
      const v = u.searchParams.get("variables");
      variables = v ? JSON.parse(v) : undefined;
      operationName = u.searchParams.get("operationName") ?? undefined;
    } catch {
      /* ignore */
    }
  }

  if (!query) {
    return { ok: false, error: "No GraphQL query found in the request body or URL." };
  }

  const request: GraphQLRequest = {
    method: method as HttpMethod,
    url,
    headers,
    query,
    variables,
    operationName,
    raw,
  };
  return { ok: true, request };
}
