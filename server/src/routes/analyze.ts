import type { FastifyInstance } from "fastify";
import type { SchemaReport } from "@shared/types.js";
import { analyzeSchema } from "../engine/analyzer/schemaAnalyzer.js";
import { extractOperations } from "../engine/analyzer/jsSourceExtract.js";

export async function analyzeRoutes(app: FastifyInstance): Promise<void> {
  app.post("/api/analyze", async (request, reply) => {
    const body = request.body as any;
    const schema: string | undefined = body?.schema;
    const jsSource: string | undefined = body?.jsSource;

    if (!schema && !jsSource) {
      reply.code(400);
      return { error: "Provide a schema (SDL or introspection JSON) and/or a JS bundle to analyze." };
    }

    let report: SchemaReport = { ok: true, findings: [] };
    if (schema && schema.trim()) {
      report = analyzeSchema(schema);
    }
    if (jsSource && jsSource.trim()) {
      report.extractedOperations = extractOperations(jsSource);
    }
    return report;
  });
}
