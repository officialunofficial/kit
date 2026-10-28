import { renderOgImage } from "@officialunofficial/og/render";
import { brandCard, WIDTH, HEIGHT } from "./card";
import shapes from "./shapes.svg";
import wordmark from "./wordmark.svg";

const headers = {
  "Content-Type": "image/png",
  "Cache-Control": "public, max-age=3600",
};
let image: Promise<ArrayBuffer> | undefined;

/** Render once per server instance; concurrent requests share the same image. */
function renderedImage(): Promise<ArrayBuffer> {
  image ??= renderOgImage(brandCard(shapes, wordmark), {
    fonts: [],
    width: WIDTH,
    height: HEIGHT,
    cacheControl: headers["Cache-Control"],
  }).then((response) => response.arrayBuffer()).catch((error) => {
    image = undefined;
    throw error;
  });
  return image;
}

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
    return new Response(request.method === "HEAD" ? null : await renderedImage(), {
      headers,
    });
  },
};
