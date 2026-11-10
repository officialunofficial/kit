import { cachedResponse } from "@officialunofficial/og";
import { renderOgImage } from "@officialunofficial/og/render";
import { brandCard, WIDTH, HEIGHT } from "./card";
import shapes from "./shapes.svg";
import wordmark from "./wordmark.svg";

/** Seconds a client or a shared cache may reuse the card. */
const MAX_AGE = 3600;
const headers = {
  "Content-Type": "image/png",
  "Cache-Control": `public, max-age=${MAX_AGE}`,
};

type Context = { waitUntil(promise: Promise<unknown>): void };

function render(): Promise<Response> {
  return renderOgImage(brandCard(shapes, wordmark), {
    fonts: [],
    width: WIDTH,
    height: HEIGHT,
    cacheControl: headers["Cache-Control"],
  });
}

export default {
  async fetch(request: Request, _env: unknown, ctx: Context): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/og.png") {
      return new Response("Not found", { status: 404 });
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", {
        status: 405,
        headers: { Allow: "GET, HEAD" },
      });
    }
    if (request.method === "HEAD") {
      return new Response(null, { headers });
    }
    // The card takes no input, so every query string shares one cache entry.
    const cached = await cachedResponse(request, render, {
      waitUntil: ctx.waitUntil.bind(ctx),
      maxAge: MAX_AGE,
      key: url.origin + url.pathname,
    });
    // A stored copy carries the lifetime of its cache entry. Send the public one.
    const response = new Response(cached.body, cached);
    response.headers.set("Cache-Control", headers["Cache-Control"]);
    response.headers.delete("X-Og-Stored-At");
    return response;
  },
};
