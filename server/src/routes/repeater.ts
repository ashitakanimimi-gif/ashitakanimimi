import type { FastifyInstance } from "fastify";
import type { GraphQLRequest } from "@shared/types.js";
import { parseRawHttp } from "../engine/request/rawHttpParser.js";
import { sendRequest } from "../lib/graphqlClient.js";
import { analyzeQuery } from "../lib/complexity.js";

export async function repeaterRoutes(app: FastifyInstance): Promise<void> {
  app.post("/api/repeater/parse", async (request, reply) => {
    const body = request.body as any;
    const raw: string = body?.raw ?? "";
    const result = parseRawHttp(raw);
    if (!result.ok) {
      reply.code(400);
      return { error: result.error };
    }
    return { request: result.request, metrics: analyzeQuery(result.request!.query) };
  });

  app.post("/api/repeater/send", async (request, reply) => {
    const body = request.body as any;
    const req: GraphQLRequest = body?.request;
    if (!req?.url || !req?.query) {
      reply.code(400);
      return { error: "A request with url and query is required." };
    }
    const res = await sendRequest(req);
    return { response: res, metrics: analyzeQuery(req.query) };
  });
}
