import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { brandCard } from "./card";

test("brand card embeds both assets without external image requests", () => {
  const shapes = readFileSync(new URL("./shapes.svg", import.meta.url), "utf8");
  const wordmark = readFileSync(new URL("./wordmark.svg", import.meta.url), "utf8");
  const html = brandCard(shapes, wordmark);
  const sources = [...html.matchAll(/src="([^"]+)"/g)].map((match) => match[1]);
  expect(sources).toHaveLength(2);
  expect(sources.every((source) => source.startsWith("data:image/svg+xml"))).toBe(true);
  expect(html).not.toMatch(/src="https?:/);
  expect(html).toContain("width:1200px");
  expect(html).toContain("height:630px");
  expect(html).toContain("background-color:#0067ed");
});
