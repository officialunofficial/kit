import { renderOgImage } from "@officialunofficial/og/render";
import { brandCard, WIDTH, HEIGHT } from "./card";
import shapes from "./shapes.svg";
import wordmark from "./wordmark.svg";

export default {
  async fetch(request: Request): Promise<Response> {
    if (new URL(request.url).pathname !== "/og.png") {
      return new Response("Not found", { status: 404 });
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", {
        status: 405,
        headers: { Allow: "GET, HEAD" },
      });
    }
    const response = await renderOgImage(brandCard(shapes, wordmark), {
      fonts: [],
      width: WIDTH,
      height: HEIGHT,
      cacheControl: "public, max-age=3600",
    });
    return request.method === "HEAD"
      ? new Response(null, { headers: response.headers })
      : response;
  },
};
