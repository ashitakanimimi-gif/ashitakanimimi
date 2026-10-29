import type { FastifyInstance } from "fastify";
import type { ScanEvent } from "@shared/types.js";
import { runScan } from "../engine/scanner/runner.js";
import { buildRecommendations, enrichWithCves } from "../engine/advisor/rules.js";

export async function scanRoutes(app: FastifyInstance): Promise<void> {
  // Streams Server-Sent Events describing scan progress, then a final "done".
  app.post("/api/scan", async (request, reply) => {
    const body = request.body as any;
    const base = body?.base;
    const acknowledged = body?.acknowledged === true;

    if (!base?.url || !base?.query) {
      reply.code(400);
      return { error: "A base request with url and query is required." };
    }
    if (!acknowledged) {
      reply.code(403);
      return { error: "Authorization acknowledgement is required before scanning." };
    }

    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });

    const write = (e: ScanEvent) => {
      reply.raw.write(`data: ${JSON.stringify(e)}\n\n`);
    };

    try {
      const scan = await runScan({
        base,
        acknowledged,
        selectedTestIds: body?.selectedTestIds,
        options: body?.options,
        onEvent: (e) => {
          // Intercept the final "done" to enrich + attach recommendations.
          if (e.type === "done") {
            const enriched = enrichWithCves(e.scan);
            const recommendations = buildRecommendations(enriched);
            write({ type: "done", scan: { ...enriched, recommendations } as any });
          } else {
            write(e);
          }
        },
      });
      void scan;
    } catch (err) {
      write({ type: "error", message: err instanceof Error ? err.message : String(err) });
    } finally {
      reply.raw.end();
    }

    return reply;
  });
}
