# kit whitepaper

`kit-whitepaper.tex` is the whitepaper "kit: An Offline-Verifiable
Repository". It describes the object model, signing, disclosure and closure
verification, and the assurance evidence. The specs in
[`docs/specs/`](../specs/README.md) stay normative. Where the paper and a spec
disagree, the spec wins.

The paper links to files at one pinned commit, set by `\sha` in the preamble.
Update `\sha` when a cited file changes.

The paper text and figures are licensed under CC BY 4.0. The scripts in
`tools/` follow the repository licence (MIT or Apache-2.0). Bump the version and
date in `\date` for each version you publish.

## Build

The build needs TeX Live with `latexmk`, BibTeX and the `latex-extra` packages.

```sh
cd docs/paper
latexmk -pdf -interaction=nonstopmode kit-whitepaper.tex
```

The PDF is build output and stays untracked. Releases attach it.

## Measurements

The scripts in `tools/` reproduce the sizes in the paper. Run them from the
repository root:

```sh
python3 -I -B docs/paper/tools/measure_disclosure.py .
python3 -I -B docs/paper/tools/sibling_count.py 16384
```

`measure_disclosure.py` decodes each accepting disclosure golden vector with
`scripts/golden/disclosure_ref.py` and splits its size into commit, steps and
payload. `sibling_count.py` applies the sibling-selection rule of
SPEC-MERKLE-OBJECTS §5.3 to count the siblings a chunk step carries.
