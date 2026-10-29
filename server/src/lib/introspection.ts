// Canonical introspection query strings + schema builder helpers.
import { buildClientSchema, type IntrospectionQuery, type GraphQLSchema } from "graphql";

export const FULL_INTROSPECTION_QUERY = `
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
}`.trim();

/** Full query without directive locations (onOperation/onFragment/onField removed). */
export const INTROSPECTION_NO_DIRECTIVES = FULL_INTROSPECTION_QUERY.replace(
  /directives \{ name description locations args \{ \.\.\.InputValue \} \}/,
  "directives { name }"
);

export const MINIMAL_INTROSPECTION = `{ __schema { types { name fields { name } } } }`;

export const INLINE_INTROSPECTION = `{ __schema { queryType { name } types { name kind } } }`;

/** Regex-filter bypass attempt: newline right after the __schema keyword. */
export const BYPASS_INTROSPECTION = `{ __schema\n{ types { name } } }`;

export const TYPENAME_QUERY = `{ __typename }`;

export function tryBuildSchema(introspection: unknown): GraphQLSchema | undefined {
  try {
    // Accept either { data: { __schema } } or { __schema }.
    const data =
      introspection && typeof introspection === "object" && "data" in (introspection as object)
        ? (introspection as { data: unknown }).data
        : introspection;
    return buildClientSchema(data as IntrospectionQuery);
  } catch {
    return undefined;
  }
}
