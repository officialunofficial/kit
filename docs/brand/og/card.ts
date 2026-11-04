import { HStack, Img, svgToDataUri } from "@officialunofficial/og";

export const WIDTH = 1200;
export const HEIGHT = 630;
export const UNO_BLUE = "#0067ed";

/** Build the fixed brand card with embedded vector artwork. */
export function brandCard(shapes: string, wordmark: string): string {
  return HStack(
    {
      width: WIDTH,
      height: HEIGHT,
      padding: 72,
      gap: 64,
      justifyContent: "center",
      backgroundColor: UNO_BLUE,
    },
    Img(svgToDataUri(shapes), 500, 326, { flexShrink: 0 }),
    Img(svgToDataUri(wordmark), 440, 131, { flexShrink: 0 }),
  );
}
