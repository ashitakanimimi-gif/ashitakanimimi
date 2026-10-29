import {
  buildSchema,
  buildClientSchema,
  type GraphQLSchema,
  type IntrospectionQuery,
  isObjectType,
  isListType,
  isNonNullType,
  GraphQLObjectType,
} from "graphql";
import type { Finding, SchemaReport, SchemaStat } from "@shared/types.js";
import { makeFinding } from "../../lib/findings.js";
import { vuln } from "../advisor/knowledgeBase.js";

const SENSITIVE_FIELD = /pass(word|wd)?|secret|token|api[_-]?key|ssn|credit[_-]?card|cvv|private[_-]?key|salt|hash/i;

function loadSchema(input: string): { schema?: GraphQLSchema; error?: string } {
  const trimmed = input.trim();
  // Try introspection JSON first.
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      const data = parsed.data ?? parsed;
      return { schema: buildClientSchema(data as IntrospectionQuery) };
    } catch (err) {
      // Fall through to SDL parsing (could be SDL that starts with "{").
    }
  }
  try {
    return { schema: buildSchema(trimmed) };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

export function analyzeSchema(input: string): SchemaReport {
  const { schema, error } = loadSchema(input);
  if (!schema) {
    return { ok: false, error: error ?? "Could not parse schema.", findings: [] };
  }

  const findings: Finding[] = [];
  const typeMap = schema.getTypeMap();
  const queryType = schema.getQueryType();
  const mutationType = schema.getMutationType();
  const subscriptionType = schema.getSubscriptionType();

  let typeCount = 0;
  let deprecated = 0;

  const addFinding = (vulnKey: Parameters<typeof vuln>[0], title: string, description: string, op?: string) => {
    const v = vuln(vulnKey);
    findings.push(
      makeFinding({
        testId: "ANALYZE",
        controlArea: "discovery",
        title,
        severity: v.severity,
        status: "warn",
        description,
        remediation: v.remediation,
        affectedOperation: op,
        references: v.references,
        cwe: v.cwe,
        cvss: v.cvss,
      })
    );
  };

  for (const [name, type] of Object.entries(typeMap)) {
    if (name.startsWith("__")) continue; // introspection types
    typeCount++;
    if (isObjectType(type)) {
      const fields = (type as GraphQLObjectType).getFields();
      for (const [fieldName, field] of Object.entries(fields)) {
        if (field.deprecationReason) deprecated++;
        if (SENSITIVE_FIELD.test(fieldName)) {
          addFinding(
            "overFetch",
            `Sensitive field exposed: ${name}.${fieldName}`,
            `The schema exposes a field named "${fieldName}" on type "${name}", which matches a sensitive-data pattern. Confirm it is intended for client use and protected by field-level authorization.`,
            `${name}.${fieldName}`
          );
        }
        // Unpaginated list fields (DoS vector).
        let t = field.type;
        if (isNonNullType(t)) t = t.ofType;
        if (isListType(t)) {
          const argNames = field.args.map((a) => a.name.toLowerCase());
          const hasPagination = argNames.some((a) =>
            ["first", "last", "limit", "take", "size", "count", "pagesize", "perpage"].includes(a)
          );
          if (!hasPagination) {
            addFinding(
              "pagination",
              `List field without pagination: ${name}.${fieldName}`,
              `The list field "${name}.${fieldName}" exposes no pagination/limit argument, enabling unbounded result sizes.`,
              `${name}.${fieldName}`
            );
          }
        }
      }
    }
  }

  if (mutationType) {
    addFinding(
      "missingAuthz",
      "Mutations present — verify authorization",
      `The schema exposes ${Object.keys(mutationType.getFields()).length} mutation(s). Each state-changing mutation must enforce authentication and authorization server-side.`,
      mutationType.name
    );
  }

  const stats: SchemaStat = {
    types: typeCount,
    queries: queryType ? Object.keys(queryType.getFields()).length : 0,
    mutations: mutationType ? Object.keys(mutationType.getFields()).length : 0,
    subscriptions: subscriptionType ? Object.keys(subscriptionType.getFields()).length : 0,
    deprecated,
  };

  return { ok: true, stats, findings };
}
