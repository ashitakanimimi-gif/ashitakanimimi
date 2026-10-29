import { describe, it, expect } from "vitest";
import { analyzeSchema } from "./schemaAnalyzer.js";
import { extractOperations } from "./jsSourceExtract.js";
import { analyzeQuery, buildDeepQuery, buildAliasQuery } from "../../lib/complexity.js";

const SDL = `
  type User { id: ID!, name: String, password: String }
  type Query { users: [User!]!, me: User }
  type Mutation { deleteUser(id: ID!): Boolean }
`;

describe("analyzeSchema", () => {
  it("flags sensitive fields, unpaginated lists, and mutations", () => {
    const report = analyzeSchema(SDL);
    expect(report.ok).toBe(true);
    expect(report.stats?.mutations).toBe(1);
    const titles = report.findings.map((f) => f.title).join(" | ");
    expect(titles).toMatch(/Sensitive field/);
    expect(titles).toMatch(/without pagination/);
    expect(titles).toMatch(/Mutations present/);
  });
});

describe("extractOperations", () => {
  it("pulls gql operations from source text", () => {
    const src = `const Q = gql\`query GetMe { me { id } }\`; const other = "mutation DoThing { doThing { ok } }";`;
    const ops = extractOperations(src);
    expect(ops.join(" ")).toMatch(/GetMe/);
    expect(ops.join(" ")).toMatch(/DoThing/);
  });
});

describe("complexity", () => {
  it("measures depth, fields and aliases", () => {
    const m = analyzeQuery(`query { a { b { c } } d: a { b { c } } }`);
    expect(m.valid).toBe(true);
    expect(m.depth).toBeGreaterThanOrEqual(3);
    expect(m.aliasCount).toBe(1);
  });

  it("builds deep and aliased queries", () => {
    expect(buildDeepQuery("self", 3)).toContain("self { self { self {");
    expect(buildAliasQuery("field", 3)).toContain("a0: field");
  });
});
