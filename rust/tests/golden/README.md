# Golden vectors

Each directory holds byte-exact vectors for one format or protocol. A format
change updates the spec and the vectors in the same commit. Each vector set
passes two checks:

- A Rust test in the crate that owns the format.
- A reference check in `scripts/golden`. The reference check is a Python
  script that shares no code with the Rust crates. It reads only the spec.

Run all reference checks with `bash scripts/check-golden.sh`. The script
header lists the setup. Every check uses the pure-Python BLAKE3 of
`scripts/golden/blake3_subtree_ref.py`. Two checks also compare that BLAKE3
with the official `b3sum` tool. CI installs `b3sum` at a pinned version before
it runs them.

`scripts/golden/write_manifest.py` updates the digests in a `MANIFEST.txt`.
Use its `--check` option to find stale digests.

| Directory | Spec | Reference check |
|---|---|---|
| `attest` | SPEC-ATTESTATIONS | `attest_ref.py` |
| `auth-v2` | SPEC-TRANSPORT-CONNECT | `auth_v2_ref.py`, `blake3_subtree_ref.py` (`part.json`) |
| `closure` | SPEC-DISCLOSURE, SPEC-PACKFILE | `closure_ref.py` |
| `disclosure` | SPEC-DISCLOSURE | `disclosure_ref.py` |
| `fastcdc` | SPEC-FASTCDC | `objects_ref.py` |
| `git-bridge` | SPEC-GIT-BRIDGE | `git_bridge_ref.py` |
| `git-import` | SPEC-GIT-IMPORT | `git_bridge_ref.py` |
| `grants` | SPEC-WRITE-GRANTS | `grants_ref.py` |
| `http-objects` | SPEC-HTTP-OBJECTS, SPEC-DISCLOSURE | `http_objects_ref.py` |
| `objects` | SPEC-OBJECTS, SPEC-SIGNING | `objects_ref.py` |
| `pack-v2` | SPEC-PACKFILE, SPEC-DELTA | `pack_ref.py` |
| `proofs` | SPEC-MERKLE-OBJECTS | `proofs_ref.py` |
| `redaction` | SPEC-TRANSPORT-CONNECT, SPEC-HTTP-OBJECTS | `scripts/check-redaction-goldens.py` |
| `refs-index` | SPEC-INDEX, SPEC-REFS | `refs_index_ref.py` |
| `sparse` | SPEC-SPARSE-CHECKOUT | `sparse_ref.py` |
| `ssh-serve` | SPEC-TRANSPORT, SPEC-RPC, SPEC-REFS | `ssh_serve_ref.py` |
| `tags` | SPEC-OBJECTS, SPEC-SIGNING | `objects_ref.py` |
| `transport` | SPEC-TRANSPORT-CONNECT, SPEC-TRANSPORT | `transport_ref.py` |
| `uploads` | SPEC-TRANSPORT-CONNECT | `blake3_subtree_ref.py` |
| `blame-stash` | none | none (see its README) |
| `diff-merge` | none | none (see its README) |

## Facts that a reference check takes from the fixture

A reference check cannot derive some inputs from the spec. These inputs are
fixed values of the fixture. Each check names them in its script.

- The signing seeds of the fixtures, for example `[0x42; 32]` for the import
  key and `[0xAB; 32]` for the attestation key.
- The git objects that are not in `git-import` and `git-bridge`. The
  directories hold commits and tags, but not every tree. A check takes the id of
  such a tree from the vector. It still checks the signature and every other
  field of the commit.
- The state of each `ssh-serve` session before the session starts. The
  `ssh_serve_ref.py` script lists the refs and packs of each session.
- The server answers of `ssh-serve` carry free text in `Error.message`. The
  check requires valid UTF-8 text and compares the error code and the details.

## Vectors without a spec-defined format

`git-import/REFUSALS.txt` names the typed refusal that the Rust code returns for
four hostile inputs. The directory does not hold the input objects. SPEC-GIT-IMPORT
section 3 states the rules that the refusals apply. The reference check does not
cover this file.

`blame-stash` and `diff-merge/status_three_states.txt` hold the text output of
operations. No spec defines this text. Their READMEs give the reason.
