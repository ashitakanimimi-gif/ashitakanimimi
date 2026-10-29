import type { GraphQLRequest } from "@shared/types.js";

export function clone(req: GraphQLRequest): GraphQLRequest {
  return {
    ...req,
    headers: { ...req.headers },
    variables: req.variables ? structuredClone(req.variables) : undefined,
  };
}

function headerKey(req: GraphQLRequest, name: string): string | undefined {
  return Object.keys(req.headers).find((h) => h.toLowerCase() === name.toLowerCase());
}

export function getHeader(req: GraphQLRequest, name: string): string | undefined {
  const k = headerKey(req, name);
  return k ? req.headers[k] : undefined;
}

export function setHeader(req: GraphQLRequest, name: string, value: string): GraphQLRequest {
  const next = clone(req);
  const k = headerKey(next, name) ?? name;
  next.headers[k] = value;
  return next;
}

export function removeHeader(req: GraphQLRequest, name: string): GraphQLRequest {
  const next = clone(req);
  const k = headerKey(next, name);
  if (k) delete next.headers[k];
  return next;
}

export function setQuery(req: GraphQLRequest, query: string, operationName?: string): GraphQLRequest {
  const next = clone(req);
  next.query = query;
  if (operationName !== undefined) next.operationName = operationName;
  return next;
}

export function setVariables(req: GraphQLRequest, variables: Record<string, unknown>): GraphQLRequest {
  const next = clone(req);
  next.variables = variables;
  return next;
}

/** Swap in a probe operation while keeping the real auth/headers. */
export function withOperation(
  req: GraphQLRequest,
  query: string,
  operationName?: string,
  variables?: Record<string, unknown>
): GraphQLRequest {
  const next = clone(req);
  next.query = query;
  next.operationName = operationName;
  next.variables = variables;
  return next;
}

/** Convert to a GET request (moves the operation into the querystring). */
export function toGET(req: GraphQLRequest): GraphQLRequest {
  const next = clone(req);
  next.method = "GET";
  return removeHeader(next, "content-type");
}

/** Switch the content type to x-www-form-urlencoded (CSRF probe). */
export function toFormEncoded(req: GraphQLRequest): GraphQLRequest {
  return setHeader(req, "content-type", "application/x-www-form-urlencoded");
}

/** Replace the Origin header (CORS probe). */
export function withOrigin(req: GraphQLRequest, origin: string): GraphQLRequest {
  return setHeader(req, "origin", origin);
}

export function hostOf(req: GraphQLRequest): string {
  try {
    return new URL(req.url).host;
  } catch {
    return getHeader(req, "host") ?? "";
  }
}
