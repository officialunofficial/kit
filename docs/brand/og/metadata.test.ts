import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { pageMetadata } from "./metadata";

const tags = pageMetadata("https://kit.storage/", "https://kit.storage/brand/og-kit-v1.png");

test("page metadata names the card with its type, size and alt text", () => {
  for (const tag of [
    '<meta property="og:type" content="website" />',
    '<meta property="og:url" content="https://kit.storage/" />',
    '<meta property="og:image" content="https://kit.storage/brand/og-kit-v1.png" />',
    '<meta property="og:image:type" content="image/png" />',
    '<meta property="og:image:width" content="1200" />',
    '<meta property="og:image:height" content="630" />',
  ]) {
    expect(tags).toContain(tag);
  }
  expect(tags).toMatch(/og:image:alt" content="White geometric solids/);
});

test("page metadata refuses a URL that is not absolute HTTP", () => {
  expect(() => pageMetadata("/", "https://kit.storage/brand/og-kit-v1.png")).toThrow();
  expect(() => pageMetadata("https://kit.storage/", "brand/og-kit-v1.png")).toThrow();
});

test("the brand guide shows the generated tags", () => {
  const guide = readFileSync(new URL("../WEB.md", import.meta.url), "utf8");
  expect(guide).toContain(tags);
});
