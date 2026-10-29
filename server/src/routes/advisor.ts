import type { FastifyInstance } from "fastify";
import type { ScanResult } from "@shared/types.js";
import { buildRecommendations, enrichWithCves } from "../engine/advisor/rules.js";

export async function advisorRoutes(app: FastifyInstance): Promise<void> {
  app.post("/api/advisor", async (request, reply) => {
    const body = request.body as any;
    const scan: ScanResult = body?.scan;
    if (!scan?.findings) {
      reply.code(400);
      return { error: "A scan result is required." };
    }
    const enriched = enrichWithCves(scan);
    const recommendations = buildRecommendations(enriched);
    return { scan: enriched, recommendations };
  });
}
