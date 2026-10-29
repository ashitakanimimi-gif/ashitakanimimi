import Fastify from "fastify";
import cors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import { scanRoutes } from "./routes/scan.js";
import { analyzeRoutes } from "./routes/analyze.js";
import { repeaterRoutes } from "./routes/repeater.js";
import { proxyRoutes } from "./routes/proxy.js";
import { advisorRoutes } from "./routes/advisor.js";
import { CONTROL_AREAS } from "@shared/controlAreas.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? "0.0.0.0";

const app = Fastify({
  logger: { transport: process.env.NODE_ENV === "production" ? undefined : { target: "pino-pretty" } },
  bodyLimit: 5 * 1024 * 1024,
});

await app.register(cors, { origin: true, credentials: true });

app.get("/api/health", async () => ({ ok: true, time: new Date().toISOString() }));
app.get("/api/catalog", async () => ({ controlAreas: CONTROL_AREAS }));

await app.register(scanRoutes);
await app.register(analyzeRoutes);
await app.register(repeaterRoutes);
await app.register(advisorRoutes);
await app.register(proxyRoutes);

// Serve the built frontend in production (single-image deployment).
const webDist = join(__dirname, "../../web/dist");
if (existsSync(webDist)) {
  await app.register(fastifyStatic, { root: webDist, prefix: "/" });
  app.setNotFoundHandler((request, reply) => {
    // SPA fallback for non-API, non-proxy routes.
    if (request.url.startsWith("/api") || request.url.startsWith("/proxy")) {
      reply.code(404).send({ error: "Not found" });
      return;
    }
    reply.sendFile("index.html");
  });
}

try {
  await app.listen({ port: PORT, host: HOST });
  app.log.info(`GraphQL Security Suite listening on http://${HOST}:${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
