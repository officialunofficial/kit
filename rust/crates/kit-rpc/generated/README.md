# Generated protocol code

The files in this directory are generated output. We keep them in the
repository on purpose, as a recorded exception to the rule against
checked-in generated output.

## Why the files are here

The files come from the `.proto` schemas. The code generator (`buffa-build`)
runs `protoc` or `buf`. Those tools are not part of a normal Rust build. The
schemas also use protobuf edition 2023, and many hosts ship a `protoc` that
is too old to read it. docs.rs is one of them. A build that generated the
code would fail on those hosts.

The build script copies these files into the build output. A normal build
needs no `protoc`.

## How the files stay correct

`scripts/check-generated-fresh.sh` regenerates the code and compares it with
these files. The Rust workflow runs it on every pull request, so a schema
change without matching generated files fails CI.

## How to refresh the files

Run `scripts/regen-rpc-proto.sh` and `scripts/regen-transport-proto.sh`.
Both scripts need `protoc` 27 or newer. Commit the result in the same commit
as the schema change.

Never edit these files by hand.
