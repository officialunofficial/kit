# Generated protocol code

The files in this directory come from the `.proto` schemas. The build
script copies them into the build output. This lets a normal build run
without `protoc`.

A normal build needs these files. The schemas use protobuf edition
2023. Many build hosts ship a `protoc` that is too old to read it.

To refresh the files, run `scripts/regen-rpc-proto.sh` and
`scripts/regen-transport-proto.sh`. Both scripts need `protoc` 27 or
newer. Commit the result in the same commit as the schema change.
