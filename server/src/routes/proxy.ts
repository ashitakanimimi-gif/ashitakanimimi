import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { proxyBus, evaluateRequest } from "../engine/proxy/interceptor.js";

export async function proxyRoutes(app: FastifyInstance): Promise<void> {
  // --- Config (JSON) ---
  app.get("/api/proxy/config", async () => ({ upstream: proxyBus.upstream ?? null, recent: proxyBus.recent() }));

  app.post("/api/proxy/config", async (request, reply) => {
    const body = request.body as any;
    const upstream: string | undefined = body?.upstream;
    if (upstream) {
      try {
        new URL(upstream);
      } catch {
        reply.code(400);
        return { error: "Invalid upstream URL." };
      }
    }
    proxyBus.setUpstream(upstream || undefined);
    return { upstream: proxyBus.upstream ?? null };
  });

  // --- Live feed (SSE) ---
  app.get("/api/proxy/events", async (request, reply) => {
    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    // Replay recent events, then stream new ones.
    for (const e of proxyBus.recent()) reply.raw.write(`data: ${JSON.stringify(e)}\n\n`);
    const unsub = proxyBus.subscribe((e) => reply.raw.write(`data: ${JSON.stringify(e)}\n\n`));
    const ping = setInterval(() => reply.raw.write(": ping\n\n"), 15000);
    request.raw.on("close", () => {
      clearInterval(ping);
      unsub();
    });
    return reply;
  });

  // --- Forwarding (raw body, any content type) ---
  await app.register(async (proxy) => {
    proxy.removeAllContentTypeParsers();
    proxy.addContentTypeParser("*", { parseAs: "string" }, (_req, body, done) => done(null, body));

    const handler = async (request: FastifyRequest, reply: FastifyReply) => {
      const upstream = proxyBus.upstream;
      if (!upstream) {
        reply.code(400);
        return { error: "No upstream configured. Set one via POST /api/proxy/config." };
      }
      const suffix = (request.params as any)["*"] ?? "";
      const qs = request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : "";
      const base = upstream.replace(/\/$/, "");
      const targetUrl = base + (suffix ? "/" + suffix : "") + qs;

      const rawBody = typeof request.body === "string" ? request.body : "";
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(request.headers)) {
        if (["host", "content-length", "connection"].includes(k.toLowerCase())) continue;
        if (typeof v === "string") headers[k] = v;
      }

      const event = evaluateRequest(rawBody, request.method);
      try {
        const upstreamRes = await fetch(targetUrl, {
          method: request.method,
          headers,
          body: ["GET", "HEAD"].includes(request.method) ? undefined : rawBody,
        });
        const text = await upstreamRes.text();
        event.status = upstreamRes.status;
        proxyBus.publish(event);
        reply.code(upstreamRes.status);
        upstreamRes.headers.forEach((val, key) => {
          if (!["content-encoding", "transfer-encoding", "content-length"].includes(key.toLowerCase())) {
            reply.header(key, val);
          }
        });
        return reply.send(text);
      } catch (err) {
        event.status = 0;
        event.flags.push("upstream error");
        event.flagged = true;
        proxyBus.publish(event);
        reply.code(502);
        return { error: "Upstream request failed", detail: err instanceof Error ? err.message : String(err) };
      }
    };

    proxy.all("/proxy", handler);
    proxy.all("/proxy/*", handler);
  });
}
