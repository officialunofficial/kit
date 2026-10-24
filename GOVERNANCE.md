# Governance

kit is a project of Official Unofficial, Inc. The maintainers listed in
[`MAINTAINERS.md`](MAINTAINERS.md) decide what the project accepts.

## Decisions

- A maintainer merges a change after review.
- A change to a format, a signing rule, a trust rule or the release pipeline
  needs review from a second maintainer when one exists.
- A format change updates the spec and the golden vectors in the same commit.
  See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Security reports follow [`SECURITY.md`](SECURITY.md). Maintainers handle them
  in private until a fix is ready.

## Releases

A maintainer cuts a release from a signed tag. The `release.yml` workflow
accepts only a tag that an allowlisted key signed. The allowlist is the
`KIT_RELEASE_GPG_FINGERPRINTS` repository variable. The steps are in
[`docs/RELEASE.md`](docs/RELEASE.md).

## Changes to maintainers

The maintainers add or remove a maintainer by a change to
[`MAINTAINERS.md`](MAINTAINERS.md). A maintainer who leaves also leaves the
release-key allowlist in the same change.

## Licensing

Contributions use the project license: MIT OR Apache-2.0. There is no CLA.
