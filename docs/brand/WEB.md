# Favicons and social cards

## Favicon

The favicon uses the outlined K from the wordmark in white on an Uno-blue
rounded tile. The full four-solid composition and grid are omitted so the
mark remains legible at tab sizes.

| Asset | Purpose |
|---|---|
| [favicon.svg](favicon/favicon.svg) | Scalable browser icon |
| [favicon.ico](favicon/favicon.ico) | Fallback with 16, 32, and 48 pixel images |
| [16 pixel PNG](favicon/favicon-16.png) | Small browser tab preview |
| [32 pixel PNG](favicon/favicon-32.png) | Raster browser icon |
| [48 pixel PNG](favicon/favicon-48.png) | Larger browser icon |
| [Apple touch PNG](favicon/apple-touch-icon.png) | 180 pixel square touch icon |

The touch icon has a full blue square background so the platform can apply
its mask. The browser favicon retains transparent rounded corners.

Copy the files to the site's public root and include:

```html
<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">
<link rel="icon" href="/favicon.svg" type="image/svg+xml" sizes="any">
<link rel="apple-touch-icon" href="/apple-touch-icon.png" sizes="180x180">
<meta name="theme-color" content="#0067ed">
```

## Open Graph card

![KIT Open Graph example](og/example.png)

The example is 1200 by 630 pixels. It uses a solid Uno-blue background,
white solids, blue construction edges, and the outlined white KIT wordmark.
A 72 pixel layout inset keeps the composition away from the canvas edges.
The layout omits the border and grid to keep the card clear at preview sizes.

The rendered PNG is committed as a ready-to-use example. The source under
[og/](og/) uses `@officialunofficial/og` for the layout and response rendering.
Both images are embedded as SVG data URIs. Outlined lettering avoids a font
request and preserves the custom wordmark.

### Run the example

```sh
python3 docs/brand/generate-web-assets.py
cd docs/brand/og
bun install --frozen-lockfile
bun run test
bun run build
bun run dev
```

In another terminal, from the repository root:

```sh
curl --fail http://localhost:8791/og.png -o docs/brand/og/example.png
```

The generator needs Python 3 and `rsvg-convert`. It derives favicon and white
OG artwork from the existing brand SVGs. The development server runs locally.
The build checks packaging without deploying anything. The example serves
only GET and HEAD requests to **/og.png**, returning PNG content and a one-hour
public cache header. Unknown paths return 404; other methods return 405.

The exported PNG can be served as a static file without running the example
server in production. Use a versioned URL when replacing a static card because
social platforms cache previews. Keep the downloaded PNG visually aligned
with the current card source.

### Page metadata

After hosting the image, use its absolute HTTPS URL. The paths below assume
the site publishes this PNG at **/brand/og-kit-v1.png**. Adapt the canonical
page URL, title, description, and image path for the actual page.

```html
<meta property="og:type" content="website">
<meta property="og:site_name" content="KIT">
<meta property="og:title" content="KIT — Signed version control">
<meta property="og:description" content="Content-addressed version control with signed commits and attestations.">
<meta property="og:url" content="https://kit.storage/">
<meta property="og:image" content="https://kit.storage/brand/og-kit-v1.png">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="White geometric solids beside the KIT wordmark on an Uno-blue background.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="KIT — Signed version control">
<meta name="twitter:description" content="Content-addressed version control with signed commits and attestations.">
<meta name="twitter:image" content="https://kit.storage/brand/og-kit-v1.png">
<meta name="twitter:image:alt" content="White geometric solids beside the KIT wordmark on an Uno-blue background.">
```

Serve the page metadata in the initial HTML. The image URL must return the
PNG directly without authentication. Check the published page and card with
social preview inspectors after integrating them. These assets do not install
a favicon, change site metadata, or publish an endpoint by themselves.

## Canonical artwork

The favicon and card source are recorded in the
[logo Kit](https://uno.fun/01a15ada-9a3a-73f1-b3a0-9110d4efd027/kit-logo)
at revision `ee8bef442098f13d6d6bf2054bea5043bd56f6cbf85ac555541a25667c63183a`.
The browser ICO and SVG files are local exports from that source.

## References

- [Open Graph protocol](https://ogp.me/) defines image and page metadata.
- [Package API](https://www.npmjs.com/package/@officialunofficial/og)
  documents the layout primitives, data URIs, and rendering response.
- [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/)
  describes local configuration and asset module rules.
