import { openGraphMetaTags } from "@officialunofficial/og";
import { HEIGHT, WIDTH } from "./card";

export const IMAGE_ALT =
  "White geometric solids beside the KIT wordmark on an Uno-blue background.";

/** The Open Graph tags of the page at `url` that shows the card at `image`. */
export function pageMetadata(url: string, image: string): string {
  return openGraphMetaTags({
    title: "KIT — Signed version control",
    url,
    description: "Content-addressed version control with signed commits and attestations.",
    siteName: "KIT",
    images: [{ url: image, type: "image/png", width: WIDTH, height: HEIGHT, alt: IMAGE_ALT }],
  });
}
